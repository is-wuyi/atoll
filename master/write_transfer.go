package master

import (
	"errors"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"atoll/internal/scheduler"
	"atoll/master/meta"
	"atoll/pkg/peerhttp"
	"atoll/pkg/types"
)

func supportsWriteTransfers(r *http.Request) bool {
	for _, h := range r.Header.Values(types.FeaturesHeader) {
		for _, feature := range strings.FieldsFunc(h, func(c rune) bool { return c == ',' || c == ' ' || c == '\t' }) {
			if feature == types.WriteTransferFeature {
				return true
			}
		}
	}
	return false
}

type transferLinkStore struct {
	mu    sync.Mutex
	links map[string]scheduler.LinkObservation
	// measured retains the newest fresh payload measurement per direction/path
	// even if a later zero-throughput failure becomes the visible link. Health
	// probes may not clear measured payload evidence before its own TTL.
	measured map[string]scheduler.LinkObservation
}

func (s *Server) transferObservationsAt(now time.Time) []scheduler.LinkObservation {
	s.transferLinks.mu.Lock()
	defer s.transferLinks.mu.Unlock()
	for key, link := range s.transferLinks.measured {
		if !now.Before(link.ValidUntil) {
			delete(s.transferLinks.measured, key)
		}
	}
	var links []scheduler.LinkObservation
	for key, link := range s.transferLinks.links {
		if !now.Before(link.ValidUntil) {
			delete(s.transferLinks.links, key)
			continue
		}
		links = append(links, link)
	}
	sort.Slice(links, func(i, j int) bool {
		a, b := links[i], links[j]
		return a.From+"\x00"+a.To+"\x00"+a.Path < b.From+"\x00"+b.To+"\x00"+b.Path
	})
	return links
}

func (a *Autonomy) transferLinksAt(now time.Time) []scheduler.LinkObservation {
	if a.transferObservations == nil {
		return nil
	}
	return a.transferObservations(now)
}

func (s *Server) RecordTransferObservation(observation types.TransferObservation, now time.Time) error {
	if observation.FromNodeID == 0 || observation.ToNodeID == 0 || observation.FromNodeID == observation.ToNodeID {
		return errors.New("node observation needs distinct assigned endpoints")
	}
	for _, id := range []uint64{observation.FromNodeID, observation.ToNodeID} {
		if _, err := s.store.GetNode(id); err != nil {
			return err
		}
	}
	if missingTransferPath(observation.Path) {
		if !s.validMissingTransferFailure(observation, now) {
			return errors.New("invalid or stale transfer observation")
		}
		// A failed probe is valid evidence, but it has no proven path and is
		// therefore not stored as a selectable directional link.
		return nil
	}
	link, err := s.transferLink(observation, now)
	if err != nil {
		return err
	}
	s.transferLinks.mu.Lock()
	defer s.transferLinks.mu.Unlock()
	if s.transferLinks.links == nil {
		s.transferLinks.links = map[string]scheduler.LinkObservation{}
	}
	if s.transferLinks.measured == nil {
		s.transferLinks.measured = map[string]scheduler.LinkObservation{}
	}
	for key, existing := range s.transferLinks.links {
		if !now.Before(existing.ValidUntil) {
			delete(s.transferLinks.links, key)
		}
	}
	for key, existing := range s.transferLinks.measured {
		if !now.Before(existing.ValidUntil) {
			delete(s.transferLinks.measured, key)
		}
	}
	key := link.From + "\x00" + link.To + "\x00" + link.Path
	if len(s.transferLinks.links) >= 4096 {
		if _, exists := s.transferLinks.links[key]; !exists {
			return errors.New("directional observation limit exceeded")
		}
	}
	if link.ThroughputBPS > 0 && len(s.transferLinks.measured) >= 4096 {
		if _, exists := s.transferLinks.measured[key]; !exists {
			return errors.New("measured directional observation limit exceeded")
		}
	}
	if old, exists := s.transferLinks.links[key]; exists {
		if link.ObservedAt.Before(old.ObservedAt) {
			return errors.New("out-of-order transfer observation")
		}
	}
	// A successful health probe carries no payload throughput. Only a fresh
	// measured payload result outranks it; a zero-throughput failure must be
	// replaceable by a newer same-path success so recovery can rediscover a path.
	if link.Available && link.ThroughputBPS == 0 {
		if old, exists := s.transferLinks.links[key]; exists && old.ThroughputBPS > 0 {
			return nil
		}
		if measured, exists := s.transferLinks.measured[key]; exists && measured.ThroughputBPS > 0 {
			return nil
		}
	}
	s.transferLinks.links[key] = link
	if link.ThroughputBPS > 0 {
		s.transferLinks.measured[key] = link
	}
	return nil
}

// transferObservationLimits is the shared enablement/TTL contract used by
// RecordTransferObservation and by client-supplied observations.
func (s *Server) transferObservationLimits(observation types.TransferObservation) (bool, time.Duration) {
	ttl := 30 * time.Second
	enabled := s.autonomy != nil && s.autonomy.config.ProtectionFeedback && observation.FromNodeID != 0
	if s.writePlanner != nil && s.writePlanner.config.TransferPlanning {
		enabled = true
		ttl = s.writePlanner.config.TransferObservationTTL
	}
	return enabled, ttl
}

func validTransferObservationSample(observation types.TransferObservation, now time.Time, ttl time.Duration) bool {
	return !now.IsZero() && !observation.ObservedAt.IsZero() && !observation.ObservedAt.After(now.Add(time.Second)) && now.Sub(observation.ObservedAt) <= ttl &&
		!math.IsNaN(observation.RTTMs) && !math.IsInf(observation.RTTMs, 0) && observation.RTTMs >= 0 && observation.ThroughputBPS <= 1<<40
}

func validTransferPath(path string) bool {
	return path == scheduler.TransferHTTP || path == scheduler.TransferHTTPS || path == scheduler.TransferDirect || path == scheduler.TransferRelay
}

// missingTransferPath recognizes a failed probe whose transport could not prove
// the path it took. It must never be guessed from a successful observation.
func missingTransferPath(path string) bool {
	return path == "" || path == string(peerhttp.PathUnknown)
}

// validMissingTransferFailure accepts a failed probe whose transport could not
// prove a path. It is evidence only: callers must not store or guess a path.
func (s *Server) validMissingTransferFailure(observation types.TransferObservation, now time.Time) bool {
	enabled, ttl := s.transferObservationLimits(observation)
	return enabled && validTransferObservationSample(observation, now, ttl) && !observation.Available && observation.ThroughputBPS == 0
}

func transferNodeFresh(node types.NodeInfo, now time.Time, maxAge time.Duration) bool {
	return !node.LastHeartbeat.IsZero() && !node.LastHeartbeat.After(now.Add(time.Second)) && now.Sub(node.LastHeartbeat) <= maxAge
}

func (s *Server) transferLink(observation types.TransferObservation, now time.Time) (scheduler.LinkObservation, error) {
	var out scheduler.LinkObservation
	enabled, ttl := s.transferObservationLimits(observation)
	if !enabled || !validTransferObservationSample(observation, now, ttl) || !validTransferPath(observation.Path) {
		return out, errors.New("invalid or stale transfer observation")
	}
	if s.security != nil && observation.Path == scheduler.TransferHTTP {
		return out, errors.New("secure transfer observation cannot use plaintext HTTP")
	}
	from := "client"
	if observation.FromNodeID != 0 {
		from = strconv.FormatUint(observation.FromNodeID, 10)
	}
	return scheduler.LinkObservation{From: from, To: strconv.FormatUint(observation.ToNodeID, 10), Path: observation.Path, Available: observation.Available, RTTMs: observation.RTTMs, ThroughputBPS: observation.ThroughputBPS, Confidence: 1, ObservedAt: observation.ObservedAt, ValidUntil: observation.ObservedAt.Add(ttl)}, nil
}

func (s *Server) handleWriteTransferNodes(w http.ResponseWriter, r *http.Request) {
	actor, err := s.writeActor(r)
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	id, idErr := strconv.ParseUint(r.URL.Query().Get("upload_id"), 10, 64)
	revision, revisionErr := strconv.ParseUint(r.URL.Query().Get("revision"), 10, 64)
	if idErr != nil || revisionErr != nil {
		writePlanningError(w, http.StatusBadRequest, "invalid_write_request", "write binding required")
		return
	}
	upload, err := s.store.GetPlannedWrite(actor, types.WriteBinding{UploadID: id, PlanID: r.URL.Query().Get("plan_id"), Revision: revision}, time.Now())
	if err != nil || upload.State != types.WritePending {
		if err == nil {
			err = meta.ErrWritePlanConflict
		}
		writePlanningMetaError(w, err)
		return
	}
	snapshot, err := s.store.AutonomySnapshot()
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	var nodes []types.NodeInfo
	for _, node := range snapshot.Nodes {
		if !node.LastHeartbeat.IsZero() && time.Since(node.LastHeartbeat) < s.nodeMaxAge {
			nodes = append(nodes, node)
		}
	}
	if len(nodes) > 256 {
		writePlanningError(w, http.StatusServiceUnavailable, "write_unavailable", "transfer discovery limit exceeded")
		return
	}
	ttl := uint64(30)
	if s.writePlanner != nil {
		ttl = uint64(s.writePlanner.config.TransferObservationTTL / time.Second)
	}
	writeJSON(w, http.StatusOK, types.WriteTransferNodes{Nodes: nodes, ObservationTTLSeconds: ttl})
}

func (s *Server) handleNodeTransferPeers(w http.ResponseWriter, r *http.Request) {
	if s.writePlanner == nil || !s.writePlanner.config.TransferPlanning {
		httpError(w, http.StatusConflict, "transfer planning is disabled")
		return
	}
	snapshot, err := s.store.AutonomySnapshot()
	if err != nil {
		httpError(w, http.StatusServiceUnavailable, "node discovery unavailable")
		return
	}
	if len(snapshot.Nodes) > 256 {
		httpError(w, http.StatusServiceUnavailable, "node discovery limit exceeded")
		return
	}
	writeJSON(w, http.StatusOK, types.WriteTransferNodes{Nodes: snapshot.Nodes})
}

func (s *Server) handleNodeTransferObservation(w http.ResponseWriter, r *http.Request) {
	var observation types.TransferObservation
	if decodeJSON(w, r, &observation) != nil {
		httpError(w, http.StatusBadRequest, "invalid transfer observation")
		return
	}
	if s.security != nil {
		device, err := s.store.DeviceForSession(bearer(r), time.Now())
		if err != nil || device.NodeID != observation.FromNodeID {
			httpError(w, http.StatusForbidden, "observation source differs from authenticated device")
			return
		}
	}
	if err := s.RecordTransferObservation(observation, time.Now()); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"recorded": true})
}

func (s *Server) writeTransferNetwork(client *types.WriteTransferObservation, snapshot meta.AutonomySnapshot, now time.Time) (*scheduler.TransferNetwork, error) {
	if client == nil || client.Budget.UploadBPS == 0 || client.Budget.UploadBPS > 1<<40 || client.Budget.DownloadBPS == 0 || client.Budget.DownloadBPS > 1<<40 || client.Budget.MaxConcurrent < 1 || client.Budget.MaxConcurrent > 4 || len(client.Links) > 256 {
		return nil, errors.New("write transfer requires measured client links and finite bandwidth budgets")
	}
	n := &scheduler.TransferNetwork{Origin: "client", MaxUploadTargets: min(4, client.Budget.MaxConcurrent), MaxConcurrent: 8, PlanTTLSeconds: 300, MinConfidence: .7,
		Endpoints: []scheduler.EndpointBandwidth{{ID: "client", UploadBPS: client.Budget.UploadBPS, DownloadBPS: client.Budget.DownloadBPS, MaxConcurrent: client.Budget.MaxConcurrent}}}
	profiles := map[uint64]meta.NodePlacementProfile{}
	for _, profile := range snapshot.Profiles {
		profiles[profile.NodeID] = profile
	}
	known := map[uint64]bool{}
	eligible := map[uint64]bool{}
	endpointIDs := map[string]bool{"client": true}
	loads, err := s.store.WriteTransferLoads(now)
	if err != nil {
		return nil, err
	}
	for _, node := range snapshot.Nodes {
		known[node.ID] = true
		// Offline or stale records are neither candidates nor budget-bearing
		// endpoints. A stale record without a profile must not poison planning.
		if !transferNodeFresh(node, now, s.nodeMaxAge) {
			continue
		}
		profile := profiles[node.ID]
		if profile.UploadBPS == 0 || profile.DownloadBPS == 0 || profile.MaxTransferConcurrency < 1 || profile.MaxTransferConcurrency > 32 {
			return nil, errors.New("every eligible node needs finite transfer budgets")
		}
		eligible[node.ID] = true
		endpointIDs[strconv.FormatUint(node.ID, 10)] = true
		held := loads[node.ID]
		n.Endpoints = append(n.Endpoints, scheduler.EndpointBandwidth{ID: strconv.FormatUint(node.ID, 10), UploadBPS: profile.UploadBPS, DownloadBPS: profile.DownloadBPS, InFlightUploadBPS: held.UploadBPS, InFlightDownloadBPS: held.DownloadBPS, MaxConcurrent: profile.MaxTransferConcurrency})
	}
	seen := map[string]bool{}
	for _, observation := range client.Links {
		if observation.FromNodeID != 0 || !known[observation.ToNodeID] {
			return nil, errors.New("client may only report its own assigned-node links")
		}
		if missingTransferPath(observation.Path) {
			if !s.validMissingTransferFailure(observation, now) {
				return nil, errors.New("invalid or stale transfer observation")
			}
			// A failed probe is accepted as evidence, but an unknown/empty path is
			// never guessed and never becomes a selectable network link.
			continue
		}
		link, err := s.transferLink(observation, now)
		if err != nil {
			return nil, err
		}
		// Stale nodes are not selectable. Their valid links are ignored rather
		// than allowed to fail a request that still has usable paths.
		if !eligible[observation.ToNodeID] {
			continue
		}
		key := link.From + "\x00" + link.To + "\x00" + link.Path
		if seen[key] {
			return nil, errors.New("duplicate client link observation")
		}
		seen[key] = true
		n.Links = append(n.Links, link)
	}
	s.transferLinks.mu.Lock()
	for key, link := range s.transferLinks.links {
		if !now.Before(link.ValidUntil) {
			delete(s.transferLinks.links, key)
			continue
		}
		if !endpointIDs[link.From] || !endpointIDs[link.To] {
			continue
		}
		n.Links = append(n.Links, link)
	}
	s.transferLinks.mu.Unlock()
	sort.Slice(n.Links, func(i, j int) bool {
		a, b := n.Links[i], n.Links[j]
		return a.From+"\x00"+a.To+"\x00"+a.Path < b.From+"\x00"+b.To+"\x00"+b.Path
	})
	return n, nil
}
