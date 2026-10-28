package master

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"atoll/internal/scheduler"
	"atoll/master/meta"
	"atoll/pkg/types"
)

type WritePlanningConfig struct {
	MaxReplicas            int
	ProbeTimeout           time.Duration
	TransferPlanning       bool
	TransferObservationTTL time.Duration
}

type writePlanner struct {
	config WritePlanningConfig
}

// Configure before constructing Handler or starting background workers.
func (s *Server) EnableWritePlanning(cfg WritePlanningConfig) error {
	if s.writePlanner != nil {
		return errors.New("write planning already enabled")
	}
	if cfg.MaxReplicas == 0 {
		cfg.MaxReplicas = 8
	}
	if cfg.ProbeTimeout == 0 {
		cfg.ProbeTimeout = 3 * time.Second
	}
	if cfg.TransferObservationTTL == 0 {
		cfg.TransferObservationTTL = 30 * time.Second
	}
	if cfg.TransferObservationTTL < time.Second || cfg.TransferObservationTTL > 5*time.Minute {
		return errors.New("invalid transfer observation TTL")
	}
	if cfg.MaxReplicas < 1 || cfg.MaxReplicas > 32 || cfg.ProbeTimeout <= 0 || s.nodeMaxAge <= 0 {
		return errors.New("invalid write planning resource limits")
	}
	if err := s.store.EnableWritePlanning(); err != nil {
		return err
	}
	if cfg.TransferPlanning {
		if err := s.store.EnableTransferPlanning(); err != nil {
			return err
		}
	}
	s.writePlanner = &writePlanner{config: cfg}
	return nil
}

func supportsWritePlans(r *http.Request) bool {
	for _, header := range r.Header.Values(types.FeaturesHeader) {
		for _, value := range strings.FieldsFunc(header, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			if value == types.WritePlanFeature {
				return true
			}
		}
	}
	return false
}

func isLegacyWrite(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	switch path.Clean(r.URL.Path) {
	case "/files", "/files/small", "/files/chunks", "/files/commit", "/auth/files/empty":
		return true
	}
	return false
}

func isWritePlanningRoute(p string) bool {
	switch p {
	case "/writes", "/writes/chunks", "/writes/chunks/recover", "/writes/status", "/writes/transfer-nodes", "/writes/commit", "/writes/abort", "/protection":
		return true
	}
	return false
}

func (s *Server) writePlanningGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		enabled, err := s.store.WritePlanningEnabled()
		transferEnabled, transferErr := s.store.TransferPlanningEnabled()
		configuredTransfer := s.writePlanner != nil && s.writePlanner.config.TransferPlanning
		if err != nil || transferErr != nil || enabled != (s.writePlanner != nil) || transferEnabled != configuredTransfer {
			writePlanningError(w, http.StatusServiceUnavailable, types.WritePlanRequired, "write planning state is unavailable or does not match server configuration")
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/capabilities" {
			if s.security != nil && r.TLS == nil && !s.security.config.AllowInsecure {
				httpError(w, http.StatusUpgradeRequired, "TLS required for security mode")
				return
			}
			features := []string{types.ObjectIDFeature, types.WritePlanFeature, types.WriteRecoveryFeature}
			if transferEnabled {
				features = append(features, types.WriteTransferFeature)
			}
			writeJSON(w, http.StatusOK, types.Capabilities{Features: features, WritePlanning: enabled})
			return
		}
		if enabled && isLegacyWrite(r) {
			writePlanningError(w, http.StatusUpgradeRequired, types.WritePlanRequired, "this database requires planned writes")
			return
		}
		if isWritePlanningRoute(r.URL.Path) {
			if !enabled {
				writePlanningError(w, http.StatusConflict, types.WritePlanRequired, "write planning is disabled")
				return
			}
			if !supportsWritePlans(r) {
				writePlanningError(w, http.StatusUpgradeRequired, types.WritePlanRequired, "write-plan-v1 client feature required")
				return
			}
			if transferEnabled && !supportsWriteTransfers(r) {
				writePlanningError(w, http.StatusUpgradeRequired, types.WritePlanRequired, "write-transfer-v1 client feature required")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writePlanningError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, types.WriteError{Error: message, Code: code})
}

func writePlanningMetaError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, meta.ErrAuthentication), errors.Is(err, meta.ErrOutsideSpace):
		writePlanningError(w, http.StatusForbidden, "access_denied", "access denied")
	case errors.Is(err, meta.ErrWriteNotReady):
		writePlanningError(w, http.StatusConflict, types.WriteNotReady, "the persisted confirmation conditions are not yet satisfied")
	case errors.Is(err, meta.ErrWritePlanRequired):
		writePlanningError(w, http.StatusUpgradeRequired, types.WritePlanRequired, "planned write required")
	case errors.Is(err, meta.ErrWriteExpired):
		writePlanningError(w, http.StatusGone, types.WriteExpired, "write plan expired")
	case errors.Is(err, meta.ErrWriteBudget), errors.Is(err, meta.ErrProtectionBudget):
		writePlanningError(w, http.StatusInsufficientStorage, types.WriteBudget, "insufficient reserved storage capacity")
	case errors.Is(err, meta.ErrWriteNoFeasible):
		writePlanningError(w, http.StatusUnprocessableEntity, types.WriteNoFeasible, "no feasible write layout")
	case errors.Is(err, meta.ErrWritePlanConflict), errors.Is(err, meta.ErrObjectChanged), errors.Is(err, meta.ErrOpConflict), errors.Is(err, meta.ErrExist), errors.Is(err, meta.ErrNotStaging):
		writePlanningError(w, http.StatusConflict, types.WritePlanConflict, "write plan or target changed")
	case errors.Is(err, meta.ErrNotExist):
		writePlanningError(w, http.StatusNotFound, "not_found", "entry or upload not found")
	case errors.Is(err, meta.ErrBadName), errors.Is(err, meta.ErrBadPath), errors.Is(err, meta.ErrChunkBadIndex), errors.Is(err, meta.ErrChunkBadSize), errors.Is(err, meta.ErrNotDir):
		writePlanningError(w, http.StatusBadRequest, "invalid_write_request", "invalid write request")
	default:
		writePlanningError(w, http.StatusServiceUnavailable, "write_unavailable", "write operation could not be confirmed")
	}
}

func decodeWriteJSON(w http.ResponseWriter, r *http.Request, value any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	fields, err := writeJSONFields(raw)
	if err != nil {
		return err
	}
	var required []string
	switch value.(type) {
	case *types.BeginWriteRequest:
		required = []string{"path", "op_id", "size"}
	case *types.PlanWriteChunkRequest:
		required = []string{"upload_id", "plan_id", "revision", "index", "logical_size", "stored_size", "encoding", "checksum"}
	case *types.RecoverWriteChunkRequest:
		required = []string{"upload_id", "plan_id", "revision", "index", "expected_epoch", "op_id", "failed_nodes"}
	case *types.CommitWriteRequest:
		required = []string{"upload_id", "plan_id", "revision", "op_id", "size", "chunk_count"}
	case *types.WriteBinding:
		required = []string{"upload_id", "plan_id", "revision"}
	case *types.ProtectionRequest:
		required = []string{"path", "tier"}
	}
	for _, name := range required {
		if !fields[name] {
			return fmt.Errorf("missing field %s", name)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func writeJSONFields(raw []byte) (map[string]bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("JSON object required")
	}
	fields := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := token.(string)
		if !ok || fields[name] || name != strings.ToLower(name) {
			return nil, errors.New("ambiguous JSON field")
		}
		fields[name] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, errors.New("null write field")
		}
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("request must contain exactly one JSON object")
	}
	return fields, nil
}

func (s *Server) writeActor(r *http.Request) (meta.WriteActor, error) {
	if s.security == nil {
		return meta.WriteActor{}, nil
	}
	user, err := s.store.UserForSession(bearer(r), time.Now())
	if err != nil {
		return meta.WriteActor{}, meta.ErrAuthentication
	}
	spaceID, err := requestSpace(r)
	if err != nil {
		return meta.WriteActor{}, meta.ErrAuthentication
	}
	return meta.WriteActor{UserID: user.ID, SpaceID: spaceID}, nil
}

func (s *Server) writePath(actor meta.WriteActor, remote string, write bool) (string, error) {
	root := ""
	if actor.UserID != 0 || actor.SpaceID != 0 {
		space, err := s.store.AuthorizeSpace(actor.UserID, actor.SpaceID, write)
		if err != nil {
			return "", err
		}
		root = space.InternalPath
	}
	return spacePath(root, remote)
}

func (s *Server) handleBeginWrite(w http.ResponseWriter, r *http.Request) {
	var req types.BeginWriteRequest
	if err := decodeWriteJSON(w, r, &req); err != nil {
		writePlanningError(w, http.StatusBadRequest, "invalid_write_request", "invalid planned write request")
		return
	}
	actor, err := s.writeActor(r)
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	remote, err := s.writePath(actor, req.Path, true)
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	parentPath, name := splitPath(remote)
	if name == "" || name == "." || name == ".." {
		writePlanningError(w, http.StatusBadRequest, "invalid_write_request", "file name required")
		return
	}
	parent, err := s.store.ResolvePath(parentPath)
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	upload, err := s.store.BeginPlannedWrite(actor, parent.ID, name, req, time.Now())
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, types.BeginWriteResponse{Upload: upload})
}

func (s *Server) handlePlanWriteChunk(w http.ResponseWriter, r *http.Request) {
	var req types.PlanWriteChunkRequest
	if err := decodeWriteJSON(w, r, &req); err != nil {
		writePlanningError(w, http.StatusBadRequest, "invalid_write_request", "invalid planned chunk request")
		return
	}
	actor, err := s.writeActor(r)
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	upload, err := s.store.GetPlannedWrite(actor, req.WriteBinding, time.Now())
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	for _, existing := range upload.Chunks {
		if existing.Index == req.Index {
			plan, chunk, err := s.store.ReserveWriteChunk(actor, req, existing, 0, s.nodeMaxAge, time.Now())
			if err != nil {
				writePlanningMetaError(w, err)
				return
			}
			s.writeChunkResponse(w, plan, chunk)
			return
		}
	}
	if req.Index < 0 || req.Index >= types.MaxChunksPerFile || req.LogicalSize <= 0 || req.LogicalSize > types.ChunkSize {
		writePlanningError(w, http.StatusBadRequest, "invalid_write_request", "unsupported chunk size")
		return
	}
	if err := types.ValidateChunkGeometry(req.Encoding, req.LogicalSize, req.StoredSize); err != nil {
		writePlanningError(w, http.StatusBadRequest, "invalid_write_request", "unsupported chunk encoding: "+err.Error())
		return
	}
	snapshot, err := s.store.AutonomySnapshot()
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	now := time.Now()
	world, err := s.newWriteSnapshot(r.Context(), snapshot, now)
	if err == nil && s.writePlanner.config.TransferPlanning {
		world.Network, err = s.writeTransferNetwork(req.Network, snapshot, now)
	}
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	objectID := types.ChunkID(upload.ID, req.Index)
	obj := scheduler.ObjectRequirement{ObjectID: strconv.FormatUint(objectID, 10), ContentVersion: 1,
		SizeBytes: uint64(req.StoredSize), Intent: scheduler.ProtectionIntent{Tier: string(upload.Policy.Tier)}}
	decision, err := scheduler.PlanWriteAt(&world, obj, now)
	if err != nil {
		writePlanningError(w, http.StatusServiceUnavailable, "write_planner_unavailable", "write planner could not evaluate this request")
		return
	}
	if decision.Status != scheduler.StatusPlanProposed || decision.Plan == nil {
		writePlanningError(w, http.StatusUnprocessableEntity, types.WriteNoFeasible, "no feasible write plan: "+strings.Join(decision.Reasons, "; "))
		return
	}
	if report := scheduler.ValidateWriteDecisionAt(&world, obj, decision, now); !report.Passed {
		writePlanningError(w, http.StatusUnprocessableEntity, types.WriteNoFeasible, "write plan failed independent validation")
		return
	}
	choice, err := writeChunkChoice(req, objectID, decision)
	if err != nil {
		writePlanningError(w, http.StatusServiceUnavailable, "write_planner_unavailable", "unsupported write plan")
		return
	}
	if supportsWriteRecovery(r) {
		choice.Recovery = &types.WriteRecovery{Epoch: 1, HardUntil: now.Add(types.WriteRecoveryMaxTime)}
		if choice.Transfer != nil {
			choice.Transfer.ExpiresAt = choice.Recovery.HardUntil
		}
	}
	plan, chunk, err := s.store.ReserveWriteChunk(actor, req, choice, snapshot.ProfileRevision, s.nodeMaxAge, time.Now())
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	s.writeChunkResponse(w, plan, chunk)
}

func writeChunkChoice(req types.PlanWriteChunkRequest, objectID uint64, decision scheduler.WriteDecision) (types.WriteChunkPlan, error) {
	plan := decision.Plan
	if plan == nil || plan.RequiresECBackend || plan.TargetLayout.Scheme != scheduler.SchemeReplicate {
		return types.WriteChunkPlan{}, errors.New("write plan is not executable replication")
	}
	out := types.WriteChunkPlan{Index: req.Index,
		Object:                types.ContentObject{ID: objectID, Version: 1, LogicalSize: req.LogicalSize, StoredSize: req.StoredSize, Encoding: req.Encoding, Checksum: req.Checksum, ChecksumKnown: true},
		Layout:                types.ReplicaLayout{ObjectID: objectID, Epoch: plan.TargetLayout.LayoutEpoch, Scheme: string(scheduler.SchemeReplicate)},
		RequiredConfirmations: decision.RequiredConfirmations, Reasons: append([]string(nil), decision.Reasons...)}
	for _, placement := range plan.TargetLayout.Replicas {
		id, err := strconv.ParseUint(placement.NodeID, 10, 64)
		if err != nil || id == 0 {
			return out, errors.New("invalid target node")
		}
		out.Layout.Nodes = append(out.Layout.Nodes, id)
	}
	for _, target := range decision.ConfirmationNodes {
		id, err := strconv.ParseUint(target, 10, 64)
		if err != nil || id == 0 {
			return out, errors.New("invalid confirmation node")
		}
		out.Confirmations = append(out.Confirmations, id)
	}
	if len(out.Confirmations) == 0 || out.RequiredConfirmations != len(out.Confirmations) || len(out.Layout.Nodes) == 0 || !types.ContainsUint64(out.Confirmations, out.Layout.Nodes[0]) {
		return out, errors.New("invalid confirmation set")
	}
	if decision.Transfer != nil {
		t := &types.WriteTransferPlan{ExpiresAt: decision.Transfer.ExpiresAt}
		for _, target := range decision.Transfer.UploadTargets {
			id, err := strconv.ParseUint(target, 10, 64)
			if err != nil || id == 0 {
				return out, errors.New("invalid upload ingress")
			}
			t.UploadTargets = append(t.UploadTargets, id)
		}
		for _, leg := range decision.Transfer.Legs {
			to, err := strconv.ParseUint(leg.To, 10, 64)
			if err != nil || to == 0 {
				return out, errors.New("invalid replica transfer target")
			}
			var from uint64
			if leg.From != "client" {
				from, err = strconv.ParseUint(leg.From, 10, 64)
				if err != nil || from == 0 {
					return out, errors.New("invalid replica transfer source")
				}
			}
			t.Legs = append(t.Legs, types.WriteTransferLeg{FromNodeID: from, ToNodeID: to, Path: leg.Path, BPS: leg.BPS})
		}
		out.Transfer = t
	}
	return out, nil
}

func (s *Server) writeChunkResponse(w http.ResponseWriter, plan types.WriteChunkPlan, chunk types.ChunkInfo) {
	nodes, err := s.store.NodeInfos(plan.Layout.Nodes)
	if err != nil || len(nodes) != len(plan.Layout.Nodes) {
		writePlanningError(w, http.StatusServiceUnavailable, "write_unavailable", "planned nodes are unavailable")
		return
	}
	writeJSON(w, http.StatusOK, types.PlanWriteChunkResponse{Plan: plan, Chunk: chunk, Nodes: nodes})
}

func (s *Server) handleCommitWrite(w http.ResponseWriter, r *http.Request) {
	var req types.CommitWriteRequest
	if err := decodeWriteJSON(w, r, &req); err != nil {
		writePlanningError(w, http.StatusBadRequest, "invalid_write_request", "invalid planned commit request")
		return
	}
	actor, err := s.writeActor(r)
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	inode, old, replaced, err := s.store.CommitPlannedWrite(actor, req, s.nodeMaxAge, time.Now())
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	if replaced {
		s.reclaimReplacedObject(old)
	}
	writeJSON(w, http.StatusOK, types.CommitWriteResponse{Inode: inode})
}

func (s *Server) handleAbortWrite(w http.ResponseWriter, r *http.Request) {
	var req types.WriteBinding
	if err := decodeWriteJSON(w, r, &req); err != nil {
		writePlanningError(w, http.StatusBadRequest, "invalid_write_request", "invalid planned abort request")
		return
	}
	actor, err := s.writeActor(r)
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	if err := s.store.AbortPlannedWrite(actor, req, time.Now()); err != nil {
		writePlanningMetaError(w, err)
		return
	}
	if s.scanner != nil {
		s.scanner.wakeRetirements()
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "aborted"})
}

func (s *Server) handleProtection(w http.ResponseWriter, r *http.Request) {
	actor, err := s.writeActor(r)
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	req := types.ProtectionRequest{Path: r.URL.Query().Get("path")}
	write := r.Method == http.MethodPost
	if write {
		if err := decodeWriteJSON(w, r, &req); err != nil || (req.Tier != "" && !req.Tier.Valid()) {
			writePlanningError(w, http.StatusBadRequest, "invalid_protection", "unknown protection preference")
			return
		}
	}
	remote, err := s.writePath(actor, req.Path, write)
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	inode, err := s.store.ResolvePath(remote)
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	var result types.ProtectionResponse
	if write {
		result, err = s.store.SetProtection(actor, inode.ID, req.Tier, time.Now())
	} else {
		result, err = s.store.GetProtection(actor, inode.ID)
	}
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) newWriteSnapshot(ctx context.Context, snapshot meta.AutonomySnapshot, now time.Time) (scheduler.Snapshot, error) {
	if s.writePlanner == nil {
		return scheduler.Snapshot{}, errors.New("write planner unavailable")
	}
	world := scheduler.Snapshot{SchemaVersion: scheduler.SchemaVersion, GeneratedAt: now.Format(time.RFC3339Nano), TraceID: "new-write",
		Policy: scheduler.Policy{MaxReplicaCount: s.writePlanner.config.MaxReplicas, CodecLimits: scheduler.CodecLimits{MaxK: -1},
			PredictionHorizonSeconds: 3600, MinConfidence: 0.7, Search: scheduler.SearchParams{ExactComboLimit: 256, BeamWidth: 8, MaxCandidates: 128}}}
	profiles := make(map[uint64]meta.NodePlacementProfile)
	for _, profile := range snapshot.Profiles {
		profiles[profile.NodeID] = profile
	}
	observations := make(map[uint64]meta.NodeObservation)
	for _, observation := range snapshot.Observations {
		observations[observation.NodeID] = observation
	}
	capacity := make(map[uint64]meta.NodeCapacity)
	for _, item := range snapshot.Capacity {
		capacity[item.NodeID] = item
	}
	nodes := append([]types.NodeInfo(nil), snapshot.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	if len(nodes) > 256 {
		return world, errors.New("write planning node limit exceeded")
	}
	world.Nodes = make([]scheduler.Node, len(nodes))
	var wg sync.WaitGroup
	defer wg.Wait()
	slots := make(chan struct{}, 8)
	for i, node := range nodes {
		c, ok := capacity[node.ID]
		if !ok || c.Capacity < 0 || c.Free < 0 || c.Free > c.Capacity {
			return scheduler.Snapshot{}, errors.New("invalid node capacity snapshot")
		}
		world.Nodes[i] = scheduler.Node{ID: strconv.FormatUint(node.ID, 10), FailureDomains: profiles[node.ID].FailureDomains,
			HardCapacityBytes: uint64(c.Capacity), ReservedBytes: uint64(c.Capacity - c.Free), CostPerGBMonth: 1}
		for _, sample := range observations[node.ID].Samples {
			world.Nodes[i].History = append(world.Nodes[i].History, scheduler.OnlineSample{At: sample.At.Format(time.RFC3339Nano), Online: sample.Online})
		}
		if node.LastHeartbeat.IsZero() || node.LastHeartbeat.After(now.Add(time.Second)) || now.Sub(node.LastHeartbeat) > s.nodeMaxAge {
			continue
		}
		if s.security != nil {
			if _, err := s.store.DeviceByNode(node.ID); err != nil {
				continue
			}
		}
		if s.writePlanner.config.TransferPlanning {
			world.Nodes[i].Online = true
			continue
		}
		wg.Add(1)
		go func(i int, node types.NodeInfo) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				return
			}
			started := time.Now()
			if s.healthProbe != nil {
				world.Nodes[i].Online = s.healthProbe(node.Addr)
			} else {
				probeCtx, cancel := context.WithTimeout(ctx, s.writePlanner.config.ProbeTimeout)
				defer cancel()
				req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, fmt.Sprintf("%s://%s/healthz", s.nodeScheme(), node.Addr), nil)
				if err == nil {
					resp, err := s.nodeHTTPClient(s.writePlanner.config.ProbeTimeout).Do(req)
					if err == nil {
						world.Nodes[i].Online = resp.StatusCode == http.StatusOK
						io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
						resp.Body.Close()
					}
				}
			}
			world.Nodes[i].RTTMs = float64(time.Since(started).Microseconds()) / 1000
		}(i, node)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return scheduler.Snapshot{}, err
	}
	return world, nil
}
