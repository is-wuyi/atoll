package scheduler

import (
	"errors"
	"math"
	"sort"
	"strconv"
	"time"
)

const (
	TransferKeep     = "keep"
	TransferRenew    = "renew"
	TransferReassign = "reassign"
	TransferDefer    = "defer"
	maxFlightRate    = uint64(1 << 40)
)

type FlightEndpoint struct {
	ID                             string
	UploadBPS, DownloadBPS         uint64
	HeldUploadBPS, HeldDownloadBPS uint64
	Uploads, Downloads             int
	QueuedUploads, QueuedDownloads int
	MaxConcurrent                  int
}

// EligibleSources is an authorization input, not a connectivity inference.
type TransferFlightState struct {
	PlanID                                   string
	ObjectID, Generation, IntegrityEpoch     uint64
	Attempt                                  uint32
	Size, BytesDone, PreviousBytes           int64
	Source, Target, Path                     string
	Active                                   bool
	LeaseStart, LeaseUntil, HardUntil        time.Time
	ProgressAt                               time.Time
	GoodputBPS                               uint64
	Renewals, MaxRenewals                    uint32
	RenewWindow, RenewBefore, ObservationTTL time.Duration
	EligibleSources                          []string
	Endpoints                                []FlightEndpoint
	Links                                    []LinkObservation
	MinConfidence                            float64
	MaxSourceConcurrent, MaxTargetConcurrent int
	FlowCeiling                              uint64
	UploadBPS, DownloadBPS                   uint64
}

type TransferDecision struct {
	Action                               string `json:"action"`
	Reason                               string `json:"reason"`
	PlanID                               string `json:"plan_id"`
	ObjectID, Generation, IntegrityEpoch uint64
	Attempt                              uint32 `json:"attempt"`
	Source, Target, Path                 string
	UploadBPS, DownloadBPS               uint64
	LeaseUntil                           time.Time `json:"lease_until,omitzero"`
	EstimatedFinish                      time.Time `json:"estimated_finish,omitzero"`
	Measured                             bool      `json:"measured"`
}

func flightDecision(s TransferFlightState, action, reason string) TransferDecision {
	return TransferDecision{Action: action, Reason: reason, PlanID: s.PlanID, ObjectID: s.ObjectID, Generation: s.Generation, IntegrityEpoch: s.IntegrityEpoch, Attempt: s.Attempt, Source: s.Source, Target: s.Target, Path: s.Path, UploadBPS: s.UploadBPS, DownloadBPS: s.DownloadBPS, LeaseUntil: s.LeaseUntil}
}

func flightDuration(bytes int64, rate uint64) (time.Duration, bool) {
	if bytes < 0 || rate == 0 || rate > maxFlightRate {
		return 0, false
	}
	seconds := uint64(bytes) / rate
	if uint64(bytes)%rate != 0 {
		seconds++
	}
	if seconds > uint64(math.MaxInt64/int64(time.Second)) {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

func completionWithMargin(now time.Time, bytes int64, rate uint64) (time.Time, bool) {
	need, ok := flightDuration(bytes, rate)
	if !ok {
		return time.Time{}, false
	}
	margin := need / 10
	if margin < 10*time.Second {
		margin = 10 * time.Second
	}
	if need > time.Duration(math.MaxInt64)-margin {
		return time.Time{}, false
	}
	return now.Add(need + margin), true
}

func validFlight(s TransferFlightState, now time.Time) error {
	if now.IsZero() || s.PlanID == "" || s.ObjectID == 0 || s.Target == "" || !transferPath(s.Path) || s.MaxSourceConcurrent < 0 || s.MaxSourceConcurrent > 32 || s.MaxTargetConcurrent < 0 || s.MaxTargetConcurrent > 32 || s.Size < 0 || s.PreviousBytes < 0 || s.BytesDone < s.PreviousBytes || s.BytesDone > s.Size || s.GoodputBPS > maxFlightRate || s.UploadBPS > maxFlightRate || s.DownloadBPS > maxFlightRate || s.FlowCeiling > maxFlightRate || s.ObservationTTL <= 0 || s.ObservationTTL > 5*time.Minute || s.RenewWindow < 0 || s.RenewWindow > 30*time.Minute || s.RenewBefore < 0 || s.MaxRenewals > 64 || len(s.Endpoints) > 256 || len(s.EligibleSources) > 256 || len(s.Links) > 4096 || !finiteNonNeg(s.MinConfidence) || s.MinConfidence > 1 {
		return errors.New("invalid transfer flight")
	}
	if s.Active && (s.Attempt == 0 || s.Source == "" || s.Source == s.Target || !transferPath(s.Path) || s.LeaseStart.IsZero() || s.HardUntil.IsZero() || !s.LeaseUntil.After(s.LeaseStart) || s.LeaseUntil.After(s.HardUntil) || s.HardUntil.Sub(s.LeaseStart) > 30*time.Minute || s.ProgressAt.After(now)) {
		return errors.New("invalid active transfer lease")
	}
	ids := map[string]bool{}
	for _, e := range s.Endpoints {
		if e.ID == "" || ids[e.ID] || e.UploadBPS > maxFlightRate || e.DownloadBPS > maxFlightRate || e.HeldUploadBPS > maxFlightRate || e.HeldDownloadBPS > maxFlightRate || e.Uploads < 0 || e.Downloads < 0 || e.QueuedUploads < 0 || e.QueuedDownloads < 0 || e.Uploads > 4096 || e.Downloads > 4096 || e.QueuedUploads > 4096 || e.QueuedDownloads > 4096 || e.MaxConcurrent < 0 || e.MaxConcurrent > 32 {
			return errors.New("invalid transfer endpoint")
		}
		ids[e.ID] = true
	}
	seen := map[string]bool{}
	for _, id := range s.EligibleSources {
		if id == "" || id == s.Target || seen[id] || !ids[id] {
			return errors.New("invalid eligible transfer source")
		}
		seen[id] = true
	}
	if !s.Active && !ids[s.Target] {
		return errors.New("missing target budget")
	}
	return nil
}

// DecideTransferFlight has no clock, database or network side effects.
func DecideTransferFlight(s TransferFlightState, now time.Time) (TransferDecision, error) {
	if err := validFlight(s, now); err != nil {
		return TransferDecision{}, err
	}
	d := flightDecision(s, TransferKeep, "lease_valid")
	if !s.Active {
		return selectFlightSource(s, now), nil
	}
	if !now.Before(s.LeaseUntil) || !now.Before(s.HardUntil) {
		d.Action, d.Reason = TransferDefer, "lease_expired"
		return d, nil
	}
	if s.GoodputBPS == 0 || s.ProgressAt.IsZero() || now.Sub(s.ProgressAt) >= s.ObservationTTL {
		d.Reason = "goodput_unknown"
		return d, nil
	}
	finish, ok := completionWithMargin(now, s.Size-s.BytesDone, s.GoodputBPS)
	if !ok || finish.After(s.HardUntil) {
		d.Action, d.Reason = TransferDefer, "hard_deadline_unreachable"
		return d, nil
	}
	d.EstimatedFinish, d.Measured = finish, true
	if s.BytesDone == s.Size || !finish.After(s.LeaseUntil) {
		d.Reason = "completion_within_lease"
		return d, nil
	}
	if s.BytesDone == s.PreviousBytes || s.RenewWindow == 0 || s.Renewals >= s.MaxRenewals || s.LeaseUntil.Sub(now) > s.RenewBefore {
		d.Reason = "await_renewal_window"
		return d, nil
	}
	until := now.Add(s.RenewWindow)
	if until.After(s.HardUntil) {
		until = s.HardUntil
	}
	if until.After(s.LeaseUntil) {
		d.Action, d.Reason, d.LeaseUntil = TransferRenew, "measured_progress", until
	}
	return d, nil
}

func flightIDLess(a, b string) bool {
	x, xerr := strconv.ParseUint(a, 10, 64)
	y, yerr := strconv.ParseUint(b, 10, 64)
	if xerr == nil && yerr == nil {
		return x < y
	}
	return a < b
}

func flightShare(total, held uint64, slots int) uint64 {
	if total == 0 || held >= total {
		return 0
	}
	available := total - held
	share := available / uint64(max(1, slots))
	if share == 0 {
		share = 1
	}
	return share
}

func flightCap(declared, limit int) int {
	if declared == 0 {
		return limit
	}
	if limit == 0 {
		return declared
	}
	return min(declared, limit)
}

func flightLink(s TransferFlightState, from string, now time.Time) *LinkObservation {
	var best *LinkObservation
	for i := range s.Links {
		l := &s.Links[i]
		if l.From != from || l.To != s.Target || l.Path != s.Path || l.ObservedAt.IsZero() || l.ObservedAt.After(now) || !now.Before(l.ValidUntil) || l.ValidUntil.Sub(l.ObservedAt) > s.ObservationTTL || !l.ValidUntil.After(l.ObservedAt) || !finiteNonNeg(l.Confidence) || l.Confidence < s.MinConfidence || l.Confidence > 1 || l.ThroughputBPS > maxFlightRate {
			continue
		}
		if best == nil || l.ObservedAt.After(best.ObservedAt) {
			best = l
		}
	}
	return best
}

func flightSourceRate(s TransferFlightState, source string, now time.Time) (uint64, uint64, bool, int, bool) {
	var src, dst FlightEndpoint
	for _, e := range s.Endpoints {
		if e.ID == source {
			src = e
		}
		if e.ID == s.Target {
			dst = e
		}
	}
	if src.ID == "" || dst.ID == "" {
		return 0, 0, false, 0, false
	}
	upCap, downCap := flightCap(src.MaxConcurrent, s.MaxSourceConcurrent), flightCap(dst.MaxConcurrent, s.MaxTargetConcurrent)
	if upCap > 0 && src.Uploads >= upCap || downCap > 0 && dst.Downloads >= downCap {
		return 0, 0, false, 0, false
	}
	upSlots, downSlots := max(1, src.Uploads+src.QueuedUploads), max(1, dst.Downloads+dst.QueuedDownloads)
	if upCap > 0 {
		upSlots = min(upSlots, upCap)
	}
	if downCap > 0 {
		downSlots = min(downSlots, downCap)
	}
	up := flightShare(src.UploadBPS, src.HeldUploadBPS, upSlots)
	down := flightShare(dst.DownloadBPS, dst.HeldDownloadBPS, downSlots)
	if src.UploadBPS > 0 && up == 0 || dst.DownloadBPS > 0 && down == 0 {
		return 0, 0, false, 0, false
	}
	flow := down
	if src.UploadBPS > 0 && up < flow {
		flow = up
	}
	if s.FlowCeiling > 0 && flow > s.FlowCeiling {
		flow = s.FlowCeiling
	}
	if dst.DownloadBPS == 0 {
		flow = 0
	}
	rate := flow
	measured := false
	if link := flightLink(s, source, now); link != nil {
		if !link.Available {
			return 0, 0, false, 0, false
		}
		if link.ThroughputBPS > 0 {
			rate = link.ThroughputBPS
			if src.UploadBPS > 0 {
				rate = min(rate, up)
			}
			if dst.DownloadBPS > 0 {
				rate = min(rate, down)
			}
			if s.FlowCeiling > 0 {
				rate = min(rate, s.FlowCeiling)
			}
			measured = true
		}
	}
	return flow, rate, measured, src.Uploads, true
}

func selectFlightSource(s TransferFlightState, now time.Time) TransferDecision {
	d := flightDecision(s, TransferDefer, "no_eligible_source")
	d.Source, d.UploadBPS, d.DownloadBPS = "", 0, 0
	d.LeaseUntil = time.Time{}
	ids := append([]string(nil), s.EligibleSources...)
	sort.Slice(ids, func(i, j int) bool { return flightIDLess(ids[i], ids[j]) })
	bestCost := math.Inf(1)
	for _, id := range ids {
		flow, rate, measured, uploads, ok := flightSourceRate(s, id, now)
		if !ok {
			continue
		}
		cost := float64(uploads+1) * float64(s.Size)
		if rate > 0 {
			cost /= float64(rate)
		}
		if d.Action == TransferReassign && cost >= bestCost {
			continue
		}
		d.Action, d.Reason, d.Source = TransferReassign, "bounded_source_selection", id
		d.UploadBPS, d.DownloadBPS, d.Measured = flow, flow, measured
		d.EstimatedFinish = time.Time{}
		if rate > 0 {
			if need, ok := flightDuration(s.Size, rate); ok {
				d.EstimatedFinish = now.Add(need)
			}
		}
		bestCost = cost
	}
	return d
}

func decisionEstimateMatches(s TransferFlightState, d TransferDecision, now time.Time, rate uint64) bool {
	var expected time.Time
	if s.Active && rate > 0 {
		if finish, ok := completionWithMargin(now, s.Size-s.BytesDone, rate); ok && !finish.After(s.HardUntil) {
			expected = finish
		}
	} else if rate > 0 {
		if duration, ok := flightDuration(s.Size, rate); ok {
			expected = now.Add(duration)
		}
	}
	return d.EstimatedFinish.Equal(expected)
}

// ValidateTransferDecision rechecks constraints; estimates are never an authorization proof.
func ValidateTransferDecision(s TransferFlightState, d TransferDecision, now time.Time) error {
	if err := validFlight(s, now); err != nil {
		return err
	}
	if d.PlanID != s.PlanID || d.ObjectID != s.ObjectID || d.Generation != s.Generation || d.IntegrityEpoch != s.IntegrityEpoch || d.Attempt != s.Attempt || d.Target != s.Target || d.Path != s.Path {
		return errors.New("transfer decision identity mismatch")
	}
	if d.Action == TransferReassign {
		if s.Active {
			return errors.New("cannot rebind an active attempt")
		}
		eligible := false
		for _, id := range s.EligibleSources {
			eligible = eligible || id == d.Source
		}
		flow, rate, measured, _, ok := flightSourceRate(s, d.Source, now)
		if !eligible || !ok || !decisionEstimateMatches(s, d, now, rate) || d.UploadBPS != flow || d.DownloadBPS != flow || d.Measured != measured || !d.LeaseUntil.IsZero() {
			return errors.New("transfer source exceeds eligibility or budget")
		}
		return nil
	}
	if d.Action != TransferKeep && d.Action != TransferRenew && d.Action != TransferDefer {
		return errors.New("unsupported transfer decision")
	}
	if s.Active {
		rate := uint64(0)
		if s.GoodputBPS > 0 && !s.ProgressAt.IsZero() && now.Sub(s.ProgressAt) < s.ObservationTTL && now.Before(s.LeaseUntil) && now.Before(s.HardUntil) {
			rate = s.GoodputBPS
		}
		if !decisionEstimateMatches(s, d, now, rate) {
			return errors.New("transfer estimate does not match observations")
		}
	}
	if !s.Active {
		if d.Action != TransferDefer || d.Source != "" || d.UploadBPS != 0 || d.DownloadBPS != 0 || !d.LeaseUntil.IsZero() {
			return errors.New("invalid unassigned transfer decision")
		}
		return nil
	}
	if d.Source != s.Source || d.UploadBPS != s.UploadBPS || d.DownloadBPS != s.DownloadBPS {
		return errors.New("active transfer binding changed")
	}
	if d.Action != TransferRenew {
		if !d.LeaseUntil.Equal(s.LeaseUntil) {
			return errors.New("unapproved lease change")
		}
		if d.Action == TransferKeep && (!now.Before(s.LeaseUntil) || !now.Before(s.HardUntil)) {
			return errors.New("keeping an expired transfer")
		}
		return nil
	}
	if !now.Before(s.LeaseUntil) || !now.Before(s.HardUntil) || s.BytesDone <= s.PreviousBytes || s.BytesDone >= s.Size || s.GoodputBPS == 0 || s.ProgressAt.IsZero() || now.Sub(s.ProgressAt) >= s.ObservationTTL || s.RenewWindow <= 0 || s.Renewals >= s.MaxRenewals || s.LeaseUntil.Sub(now) > s.RenewBefore || !d.LeaseUntil.After(s.LeaseUntil) || d.LeaseUntil.After(s.HardUntil) || d.LeaseUntil.After(now.Add(s.RenewWindow)) {
		return errors.New("unbounded or unmeasured transfer renewal")
	}
	finish, ok := completionWithMargin(now, s.Size-s.BytesDone, s.GoodputBPS)
	if !ok || finish.After(s.HardUntil) || !finish.After(s.LeaseUntil) {
		return errors.New("renewal cannot complete within hard deadline")
	}
	return nil
}
