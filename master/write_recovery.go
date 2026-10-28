package master

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"atoll/internal/scheduler"
	"atoll/master/meta"
	"atoll/pkg/types"
)

func supportsWriteRecovery(r *http.Request) bool {
	for _, header := range r.Header.Values(types.FeaturesHeader) {
		for _, feature := range strings.FieldsFunc(header, func(c rune) bool { return c == ',' || c == ' ' || c == '\t' }) {
			if feature == types.WriteRecoveryFeature {
				return true
			}
		}
	}
	return false
}

func writeRecoveryExclusions(plan types.WriteChunkPlan, failed []uint64) []uint64 {
	out := append([]uint64(nil), plan.Recovery.Excluded...)
	for _, id := range failed {
		if !types.ContainsUint64(out, id) {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func removeRecoveryTransferLoad(network *scheduler.TransferNetwork, old types.WriteChunkPlan, chunk types.ChunkInfo, now time.Time) {
	if network == nil || old.Transfer == nil || !now.Before(old.Transfer.ExpiresAt) {
		return
	}
	for _, leg := range old.Transfer.Legs {
		if types.ContainsUint64(chunk.Done, leg.ToNodeID) && !types.ContainsUint64(chunk.Suspect, leg.ToNodeID) {
			continue
		}
		for i := range network.Endpoints {
			e := &network.Endpoints[i]
			if leg.FromNodeID != 0 && e.ID == strconv.FormatUint(leg.FromNodeID, 10) {
				e.InFlightUploadBPS -= min(e.InFlightUploadBPS, leg.BPS)
			}
			if e.ID == strconv.FormatUint(leg.ToNodeID, 10) {
				e.InFlightDownloadBPS -= min(e.InFlightDownloadBPS, leg.BPS)
			}
		}
	}
}

func removedWriteNodes(old, next []uint64) []uint64 {
	var removed []uint64
	for _, id := range old {
		if !types.ContainsUint64(next, id) {
			removed = append(removed, id)
		}
	}
	return removed
}

func (s *Server) handleRecoverWriteChunk(w http.ResponseWriter, r *http.Request) {
	if !supportsWriteRecovery(r) {
		writePlanningError(w, http.StatusUpgradeRequired, types.WritePlanRequired, "write-recovery-v1 client feature required")
		return
	}
	var req types.RecoverWriteChunkRequest
	if err := decodeWriteJSON(w, r, &req); err != nil {
		writePlanningError(w, http.StatusBadRequest, "invalid_write_request", "invalid recovery request")
		return
	}
	actor, err := s.writeActor(r)
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	now := time.Now()
	upload, old, current, replay, err := s.store.RecoverableWriteChunk(actor, req, now)
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	if replay {
		if err := s.store.EnsureDurable(); err != nil {
			writePlanningMetaError(w, err)
			return
		}
		s.writeChunkResponse(w, old, current)
		return
	}
	snapshot, err := s.store.AutonomySnapshot()
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	for i := range snapshot.Capacity {
		c := &snapshot.Capacity[i]
		if types.ContainsUint64(old.Layout.Nodes, c.NodeID) {
			credit := min(old.Object.StoredSize, c.Reserved)
			c.Reserved -= credit
			c.Free = min(c.Capacity, c.Free+credit)
		}
	}
	world, err := s.newWriteSnapshot(r.Context(), snapshot, now)
	if err == nil && old.Transfer != nil {
		world.Network, err = s.writeTransferNetwork(req.Network, snapshot, now)
		removeRecoveryTransferLoad(world.Network, old, current, now)
	}
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	excluded := writeRecoveryExclusions(old, req.FailedNodes)
	var retained []string
	for i := range world.Nodes {
		n := &world.Nodes[i]
		id, parseErr := strconv.ParseUint(n.ID, 10, 64)
		if parseErr != nil {
			writePlanningMetaError(w, meta.ErrWritePlanConflict)
			return
		}
		if types.ContainsUint64(excluded, id) {
			n.Online = false
		}
		if n.Online && types.ContainsUint64(current.Done, id) && !types.ContainsUint64(current.Suspect, id) {
			retained = append(retained, n.ID)
		}
	}
	obj := scheduler.ObjectRequirement{ObjectID: strconv.FormatUint(old.Object.ID, 10), ContentVersion: old.Object.Version, SizeBytes: uint64(old.Object.StoredSize), Intent: scheduler.ProtectionIntent{Tier: string(upload.Policy.Tier)}}
	decision, err := scheduler.PlanWriteRecoveryAt(&world, obj, len(old.Layout.Nodes), old.RequiredConfirmations, retained, now)
	if err != nil || decision.Status != scheduler.StatusPlanProposed || decision.Plan == nil {
		writePlanningMetaError(w, meta.ErrWriteNoFeasible)
		return
	}
	geometry := types.PlanWriteChunkRequest{WriteBinding: req.WriteBinding, Index: req.Index, LogicalSize: old.Object.LogicalSize, StoredSize: old.Object.StoredSize, Encoding: old.Object.Encoding, Checksum: old.Object.Checksum}
	choice, err := writeChunkChoice(geometry, old.Object.ID, decision)
	if err != nil {
		writePlanningMetaError(w, meta.ErrWritePlanConflict)
		return
	}
	choice.Layout.Epoch = old.Layout.Epoch + 1
	for _, id := range removedWriteNodes(old.Layout.Nodes, choice.Layout.Nodes) {
		if !types.ContainsUint64(excluded, id) {
			excluded = append(excluded, id)
		}
	}
	sort.Slice(excluded, func(i, j int) bool { return excluded[i] < excluded[j] })
	choice.Recovery = &types.WriteRecovery{Epoch: choice.Layout.Epoch, Attempts: old.Recovery.Attempts + 1, HardUntil: old.Recovery.HardUntil, Excluded: excluded, OperationID: req.OpID, RequestHash: meta.RecoveryRequestHash(req), FailedNodes: append([]uint64(nil), req.FailedNodes...)}
	if choice.Transfer != nil {
		choice.Transfer.ExpiresAt = old.Recovery.HardUntil
	}
	plan, chunk, err := s.store.RecoverWriteChunk(actor, req, old, choice, snapshot.ProfileRevision, s.nodeMaxAge, time.Now())
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	if s.scanner != nil {
		s.scanner.wakeRetirements()
	}
	s.writeChunkResponse(w, plan, chunk)
}
