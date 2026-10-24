package types

import (
	"errors"
	"strings"
)

func ValidateWriteChunkPlan(req PlanWriteChunkRequest, plan WriteChunkPlan) error {
	if req.UploadID < StagingInodeBase || req.UploadID > MaxStagingInode || req.Revision != 1 || req.PlanID == "" || len(req.PlanID) > 128 || strings.ContainsAny(req.PlanID, " \t\r\n") {
		return errors.New("invalid write binding")
	}
	if req.Index < 0 || req.Index >= MaxChunksPerFile || req.LogicalSize <= 0 || req.LogicalSize > ChunkSize {
		return errors.New("unsupported write object geometry")
	}
	if err := ValidateChunkGeometry(req.Encoding, req.LogicalSize, req.StoredSize); err != nil {
		return errors.New("unsupported write object geometry: " + err.Error())
	}
	o := plan.Object
	if plan.Index != req.Index || o.ID != ChunkID(req.UploadID, req.Index) || o.Version != 1 || o.LogicalSize != req.LogicalSize || o.StoredSize != req.StoredSize || o.Encoding != req.Encoding || !o.ChecksumKnown || o.Checksum != req.Checksum {
		return errors.New("write object differs from requested content")
	}
	if plan.Layout.ObjectID != o.ID || plan.Layout.Epoch != 1 || plan.Layout.Scheme != "replicate" || len(plan.Layout.Nodes) == 0 || len(plan.Layout.Nodes) > 32 {
		return errors.New("unsupported write layout")
	}
	targets := make(map[uint64]bool, len(plan.Layout.Nodes))
	for _, id := range plan.Layout.Nodes {
		if id == 0 || targets[id] {
			return errors.New("write targets must be distinct nodes")
		}
		targets[id] = true
	}
	if plan.RequiredConfirmations < 1 || plan.RequiredConfirmations != len(plan.Confirmations) {
		return errors.New("every named confirmation must be required")
	}
	seen := make(map[uint64]bool, len(plan.Confirmations))
	for _, id := range plan.Confirmations {
		if !targets[id] || seen[id] {
			return errors.New("write confirmation is duplicated or outside layout")
		}
		seen[id] = true
	}
	if !seen[plan.Layout.Nodes[0]] {
		return errors.New("primary target must be a required confirmation")
	}
	if plan.Transfer != nil {
		p := plan.Transfer
		if len(p.UploadTargets) < 1 || len(p.UploadTargets) > 4 || len(p.Legs) != len(targets) || p.ExpiresAt.IsZero() {
			return errors.New("invalid write transfer geometry")
		}
		roots := map[uint64]bool{}
		for _, id := range p.UploadTargets {
			if !seen[id] || roots[id] {
				return errors.New("upload ingress must be a distinct required replica")
			}
			roots[id] = true
		}
		completed := map[uint64]bool{}
		for _, leg := range p.Legs {
			if !targets[leg.ToNodeID] || completed[leg.ToNodeID] || leg.FromNodeID == leg.ToNodeID || leg.BPS == 0 || leg.BPS > 1<<40 || (leg.Path != "http" && leg.Path != "https" && leg.Path != "direct" && leg.Path != "circuit") || roots[leg.ToNodeID] != (leg.FromNodeID == 0) || leg.FromNodeID != 0 && !roots[leg.FromNodeID] {
				return errors.New("invalid write transfer leg")
			}
			completed[leg.ToNodeID] = true
		}
	}
	return nil
}
