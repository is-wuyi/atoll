package master

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"atoll/master/meta"
	"atoll/pkg/types"
)

// Only the node's content-bound receipt can restore Done; a successful probe response alone cannot.
func verifyReplicaAt(client *http.Client, scheme, addr string, objectID uint64) {
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s://%s/verify/%d", scheme, addr, objectID), nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}
}

func (s *Server) handleReplicationPlan(w http.ResponseWriter, r *http.Request) {
	id, idErr := strconv.ParseUint(r.URL.Query().Get("object_id"), 10, 64)
	nodeID, nodeErr := strconv.ParseUint(r.URL.Query().Get("node_id"), 10, 64)
	if idErr != nil || nodeErr != nil || id == 0 || nodeID == 0 {
		httpError(w, http.StatusBadRequest, "object_id and node_id required")
		return
	}
	var d types.ObjectIntegrity
	var err error
	if planID := r.URL.Query().Get("plan_id"); planID != "" {
		d, err = s.store.ProtectionDescriptor(planID, id, nodeID)
	} else {
		d, err = s.store.ObjectIntegrity(id)
	}
	if err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	if !types.ContainsUint64(d.Replicas, nodeID) {
		httpError(w, http.StatusForbidden, "node is not an assigned replica")
		return
	}
	out := types.ReplicationPlan{Protocol: types.IntegrityProtocol, Object: d}
	if r.URL.Query().Get("plan_id") == "" {
		out.WriteTransfer, err = s.store.WriteTransferForObject(id)
		if err != nil {
			httpErrorFromMeta(w, err)
			return
		}
	} else {
		out.Transfer, err = s.store.ProtectionTransfer(r.URL.Query().Get("plan_id"), id, nodeID)
		if err != nil {
			httpErrorFromMeta(w, err)
			return
		}
	}
	for _, targetID := range d.Replicas {
		target, err := s.store.GetNode(targetID)
		if err != nil || time.Since(target.LastHeartbeat) > s.nodeMaxAge {
			continue
		}
		if types.ContainsUint64(d.Done, targetID) && !types.ContainsUint64(d.Suspect, targetID) {
			out.Sources = append(out.Sources, target)
		}
		if targetID != nodeID && !types.ContainsUint64(d.Done, targetID) {
			allowed := out.WriteTransfer == nil
			if out.WriteTransfer != nil && time.Now().Before(out.WriteTransfer.ExpiresAt) {
				for _, leg := range out.WriteTransfer.Legs {
					if leg.FromNodeID == nodeID && leg.ToNodeID == targetID {
						allowed = true
					}
				}
			}
			if allowed {
				out.Targets = append(out.Targets, target)
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleVerifiedReplica(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Object types.ObjectIntegrity `json:"object"`
		NodeID uint64                `json:"node_id"`
		Usage  *types.NodeUsage      `json:"usage,omitempty"`
	}
	if err := decodeJSON(w, r, &req); err != nil || req.NodeID == 0 || req.Object.ObjectID == 0 || req.Object.Size < 0 {
		httpError(w, http.StatusBadRequest, "object and node_id required")
		return
	}
	if !req.Object.ChecksumKnown {
		httpError(w, http.StatusBadRequest, "verified receipt requires a recorded checksum")
		return
	}
	marked, err := s.store.MarkVerifiedObjectDoneWithUsage(req.Object, req.NodeID, req.Usage)
	if err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	if !marked {
		httpError(w, http.StatusConflict, "object changed or replica was reassigned")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"marked": marked})
}

func (s *Server) handlePresentReplica(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Object types.ObjectIntegrity `json:"object"`
		NodeID uint64                `json:"node_id"`
	}
	if err := decodeJSON(w, r, &req); err != nil || req.NodeID == 0 || req.Object.ObjectID == 0 || req.Object.Size < 0 || req.Object.ChecksumKnown {
		httpError(w, http.StatusBadRequest, "length-only receipt requires unrecorded checksum")
		return
	}
	marked, err := s.store.MarkObjectPresent(req.Object, req.NodeID)
	if err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	if !marked {
		httpError(w, http.StatusConflict, "stale receipt or suspect replica")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"marked": true, "verified": false})
}

func (s *Server) handlePhysicalSuspect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Object types.ObjectIntegrity `json:"object"`
		NodeID uint64                `json:"node_id"`
	}
	if err := decodeJSON(w, r, &req); err != nil || req.NodeID == 0 || req.Object.ObjectID == 0 || req.Object.Size < 0 {
		httpError(w, http.StatusBadRequest, "object and node_id required")
		return
	}
	marked, err := s.store.MarkPhysicalObjectSuspect(req.Object, req.NodeID)
	if err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"marked": marked})
}

func (s *Server) handleChunkSuspect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InodeID    uint64  `json:"inode_id"`
		Generation *uint64 `json:"generation"`
		Index      *int    `json:"chunk_index"`
		ObjectID   uint64  `json:"object_id"`
		NodeID     uint64  `json:"node_id"`
		Size       *int64  `json:"size"`
		Checksum   *uint32 `json:"checksum"`
	}
	if err := decodeJSON(w, r, &req); err != nil || req.InodeID == 0 || req.Generation == nil ||
		req.Index == nil || *req.Index < 0 || req.ObjectID == 0 || req.NodeID == 0 ||
		req.Size == nil || *req.Size <= 0 || req.Checksum == nil {
		httpError(w, http.StatusBadRequest, "complete chunk identity and checksum required")
		return
	}
	marked, err := s.store.MarkChunkSuspect(req.InodeID, *req.Generation, *req.Index, req.ObjectID, req.NodeID, *req.Size, *req.Checksum)
	if err != nil && !errors.Is(err, meta.ErrNotExist) {
		httpErrorFromMeta(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"marked": marked})
}
