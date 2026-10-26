package meta

import (
	"fmt"
	"time"

	"atoll/internal/scheduler"
	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

func assignFeedbackSourceTx(tx *bolt.Tx, plan *ProtectionPlan, target *ProtectionTarget, budget *ProtectionExecutionBudget, view *protectionLeaseView, now time.Time, sources []types.NodeInfo) error {
	path := scheduler.TransferHTTP
	if budget != nil && budget.Path != "" {
		path = budget.Path
	}
	state := scheduler.TransferFlightState{PlanID: plan.ID, ObjectID: plan.Expected.ObjectID, Generation: plan.Expected.Generation, IntegrityEpoch: plan.Expected.IntegrityEpoch, Attempt: target.Attempts, Size: plan.Expected.Size, Target: fmt.Sprint(target.NodeID), Path: path, ObservationTTL: 5 * time.Minute, MinConfidence: .7, MaxSourceConcurrent: budgetSourceCap(budget), MaxTargetConcurrent: budgetTargetCap(budget), FlowCeiling: budgetCeiling(budget)}
	if budget != nil {
		state.Links = append(state.Links, budget.Links...)
	}
	appendEndpoint := func(id uint64) error {
		profile, err := endpointBudgetTx(tx, id)
		if err != nil {
			return err
		}
		load := view.Loads[id]
		state.Endpoints = append(state.Endpoints, scheduler.FlightEndpoint{ID: fmt.Sprint(id), UploadBPS: profile.upload, DownloadBPS: profile.download, HeldUploadBPS: load.UploadBPS, HeldDownloadBPS: load.DownloadBPS, Uploads: load.Uploads, Downloads: load.Downloads, QueuedUploads: view.QueuedSources[id], QueuedDownloads: view.QueuedTargets[id], MaxConcurrent: profile.maxConcurrent})
		return nil
	}
	if err := appendEndpoint(target.NodeID); err != nil {
		return err
	}
	addresses := map[string]types.NodeInfo{}
	for _, source := range sources {
		if err := appendEndpoint(source.ID); err != nil {
			return err
		}
		id := fmt.Sprint(source.ID)
		state.EligibleSources = append(state.EligibleSources, id)
		addresses[id] = source
	}
	decision, err := scheduler.DecideTransferFlight(state, now)
	if err != nil {
		return err
	}
	if err := scheduler.ValidateTransferDecision(state, decision, now); err != nil {
		return err
	}
	if decision.Action != scheduler.TransferReassign {
		return errNoProtectionSource
	}
	chosen := addresses[decision.Source]
	target.SourceID, target.SourceAddr = chosen.ID, chosen.Addr
	target.UploadBPS, target.DownloadBPS = decision.UploadBPS, decision.DownloadBPS
	up, err := endpointBudgetTx(tx, chosen.ID)
	if err != nil {
		return err
	}
	tLoad := view.Loads[target.NodeID]
	tLoad.Downloads++
	if tLoad.DownloadBPS, err = addTransferRate(tLoad.DownloadBPS, target.DownloadBPS); err != nil {
		return err
	}
	view.Loads[target.NodeID] = tLoad
	sLoad := view.Loads[chosen.ID]
	sLoad.Uploads++
	if up.upload > 0 {
		if sLoad.UploadBPS, err = addTransferRate(sLoad.UploadBPS, target.UploadBPS); err != nil {
			return err
		}
	}
	view.Loads[chosen.ID] = sLoad
	return nil
}
