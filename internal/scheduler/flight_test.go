package scheduler

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
	"time"
)

func flightFixture() (TransferFlightState, time.Time) {
	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	return TransferFlightState{PlanID: "p", ObjectID: 1, Generation: 2, IntegrityEpoch: 3, Attempt: 1, Size: 1000, BytesDone: 45, PreviousBytes: 30, Source: "2", Target: "4", Path: TransferHTTP, Active: true, LeaseStart: now.Add(-45 * time.Second), LeaseUntil: now.Add(15 * time.Second), HardUntil: now.Add(20 * time.Minute), ProgressAt: now, GoodputBPS: 1, MaxRenewals: 2, RenewWindow: time.Minute, RenewBefore: 20 * time.Second, ObservationTTL: 30 * time.Second, UploadBPS: 100, DownloadBPS: 100}, now
}

func TestTransferFlightRenewalCadenceAndHardBound(t *testing.T) {
	base, now := flightFixture()
	cases := []struct {
		name   string
		mutate func(*TransferFlightState)
		action string
	}{
		{"near expiry", func(*TransferFlightState) {}, TransferRenew},
		{"early heartbeat", func(s *TransferFlightState) { s.LeaseUntil = now.Add(40 * time.Second) }, TransferKeep},
		{"unchanged bytes", func(s *TransferFlightState) { s.PreviousBytes = s.BytesDone }, TransferKeep},
		{"unknown goodput", func(s *TransferFlightState) { s.GoodputBPS = 0 }, TransferKeep},
		{"stale goodput", func(s *TransferFlightState) { s.ProgressAt = now.Add(-30 * time.Second) }, TransferKeep},
		{"within lease", func(s *TransferFlightState) { s.GoodputBPS = 1000 }, TransferKeep},
		{"renewal cap", func(s *TransferFlightState) { s.Renewals = s.MaxRenewals }, TransferKeep},
		{"total deadline unreachable", func(s *TransferFlightState) { s.HardUntil = now.Add(5 * time.Minute) }, TransferDefer},
		{"expired lease", func(s *TransferFlightState) { s.LeaseUntil = now }, TransferDefer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			tc.mutate(&s)
			d, err := DecideTransferFlight(s, now)
			if err != nil || d.Action != tc.action {
				t.Fatalf("decision=%+v err=%v", d, err)
			}
			if err := ValidateTransferDecision(s, d, now); err != nil {
				t.Fatalf("own decision rejected: %v", err)
			}
			if d.Action == TransferRenew && (!d.LeaseUntil.Equal(now.Add(time.Minute)) || !d.Measured || d.EstimatedFinish.After(s.HardUntil)) {
				t.Fatalf("unbounded renewal: %+v", d)
			}
		})
	}
}

func TestTransferFlightValidatorRejectsForgedRenewal(t *testing.T) {
	s, now := flightFixture()
	d, err := DecideTransferFlight(s, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*TransferDecision){
		func(d *TransferDecision) { d.ObjectID++ },
		func(d *TransferDecision) { d.Generation++ },
		func(d *TransferDecision) { d.IntegrityEpoch++ },
		func(d *TransferDecision) { d.Attempt++ },
		func(d *TransferDecision) { d.Source = "3" },
		func(d *TransferDecision) { d.Target = "5" },
		func(d *TransferDecision) { d.Path = TransferRelay },
		func(d *TransferDecision) { d.UploadBPS++ },
		func(d *TransferDecision) { d.LeaseUntil = s.HardUntil.Add(time.Second) },
		func(d *TransferDecision) { d.LeaseUntil = now.Add(2 * time.Minute) },
		func(d *TransferDecision) { d.Action = TransferReassign },
		func(d *TransferDecision) { d.EstimatedFinish = now.Add(time.Second) },
	} {
		forged := d
		mutate(&forged)
		if err := ValidateTransferDecision(s, forged, now); err == nil {
			t.Fatalf("forgery accepted: %+v", forged)
		}
	}
	// An estimate supplied by a planner does not justify a renewal with unknown goodput.
	unknown := s
	unknown.GoodputBPS = 0
	d.EstimatedFinish = now.Add(time.Second)
	if err := ValidateTransferDecision(unknown, d, now); err == nil {
		t.Fatal("trusted planner's estimate")
	}
}

func sourceFlightFixture() (TransferFlightState, time.Time) {
	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	s := TransferFlightState{PlanID: "p", ObjectID: 1, Size: 1000, Target: "4", Path: TransferHTTP, ObservationTTL: 30 * time.Second, MinConfidence: .7, EligibleSources: []string{"3", "2"}, Endpoints: []FlightEndpoint{{ID: "4", UploadBPS: 1000, DownloadBPS: 1000, MaxConcurrent: 4}, {ID: "2", UploadBPS: 1000, DownloadBPS: 1000, MaxConcurrent: 4}, {ID: "3", UploadBPS: 1000, DownloadBPS: 1000, MaxConcurrent: 4}}, Links: []LinkObservation{{From: "2", To: "4", Path: TransferHTTP, Available: true, ThroughputBPS: 100, Confidence: 1, ObservedAt: now.Add(-time.Second), ValidUntil: now.Add(29 * time.Second)}, {From: "3", To: "4", Path: TransferHTTP, Available: true, ThroughputBPS: 500, Confidence: 1, ObservedAt: now.Add(-time.Second), ValidUntil: now.Add(29 * time.Second)}}}
	return s, now
}

func TestTransferFlightSelectsMeasuredDirectionalSource(t *testing.T) {
	s, now := sourceFlightFixture()
	d, err := DecideTransferFlight(s, now)
	if err != nil || d.Action != TransferReassign || d.Source != "3" || !d.Measured || d.DownloadBPS != 1000 {
		t.Fatalf("measurement not used or budget changed: %+v %v", d, err)
	}
	if err := ValidateTransferDecision(s, d, now); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*TransferDecision){func(d *TransferDecision) { d.Source = "99" }, func(d *TransferDecision) { d.DownloadBPS++ }, func(d *TransferDecision) { d.UploadBPS++ }, func(d *TransferDecision) { d.Target = "5" }, func(d *TransferDecision) { d.EstimatedFinish = now.Add(time.Second) }} {
		bad := d
		mutate(&bad)
		if err := ValidateTransferDecision(s, bad, now); err == nil {
			t.Fatalf("invalid source allocation accepted: %+v", bad)
		}
	}
	// Reversing or expiring observations makes speed unknown, not a measurement.
	for _, linkMutate := range []func(*LinkObservation){func(l *LinkObservation) { l.From, l.To = l.To, l.From }, func(l *LinkObservation) { l.ValidUntil = now }, func(l *LinkObservation) { l.ObservedAt = now.Add(time.Second) }, func(l *LinkObservation) { l.Path = TransferRelay }} {
		copy := s
		copy.Links = append([]LinkObservation(nil), s.Links...)
		for i := range copy.Links {
			linkMutate(&copy.Links[i])
		}
		d, err := DecideTransferFlight(copy, now)
		if err != nil || d.Source != "2" || d.Measured {
			t.Fatalf("invalid observation trusted: %+v %v", d, err)
		}
	}
}

func TestTransferFlightSharedBudgetAndDeterminism(t *testing.T) {
	s, now := sourceFlightFixture()
	s.Links = nil
	s.Endpoints[0].HeldDownloadBPS = 600
	s.Endpoints[0].Downloads = 1
	s.Endpoints[0].QueuedDownloads = 1
	before, _ := json.Marshal(s)
	first, err := DecideTransferFlight(s, now)
	if err != nil || first.DownloadBPS != 200 || first.UploadBPS != 200 || first.Measured {
		t.Fatalf("shared budget allocation: %+v %v", first, err)
	}
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("planner mutated input")
	}
	s.EligibleSources[0], s.EligibleSources[1] = s.EligibleSources[1], s.EligibleSources[0]
	s.Endpoints[0], s.Endpoints[2] = s.Endpoints[2], s.Endpoints[0]
	second, err := DecideTransferFlight(s, now)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("order-dependent decision: %+v %+v %v", first, second, err)
	}
	for i := range s.Endpoints {
		if s.Endpoints[i].ID == "4" {
			s.Endpoints[i].Downloads = 4
		}
	}
	d, err := DecideTransferFlight(s, now)
	if err != nil || d.Action != TransferDefer {
		t.Fatalf("concurrency cap ignored: %+v %v", d, err)
	}
}

func TestTransferFlightUnconfiguredBudgetStillBoundsMeasuredSource(t *testing.T) {
	s, now := sourceFlightFixture()
	s.Endpoints[0].DownloadBPS = 0
	s.Endpoints[1].UploadBPS = 100
	s.Links[0].ThroughputBPS = 1 << 20
	s.Links[1].ThroughputBPS = 50
	d, err := DecideTransferFlight(s, now)
	if err != nil || d.Source != "2" || d.DownloadBPS != 0 || d.UploadBPS != 0 || !d.Measured || !d.EstimatedFinish.Equal(now.Add(10*time.Second)) {
		t.Fatalf("measurement exceeded known source budget: %+v %v", d, err)
	}
	if err := ValidateTransferDecision(s, d, now); err != nil {
		t.Fatal(err)
	}
	s.Path = "ftp"
	if _, err := DecideTransferFlight(s, now); err == nil {
		t.Fatal("unsupported inactive path accepted")
	}
}

func TestTransferFlightRejectsOverflowEstimate(t *testing.T) {
	s, now := flightFixture()
	s.Size = math.MaxInt64
	s.BytesDone, s.PreviousBytes, s.GoodputBPS = 1, 0, 1
	d, err := DecideTransferFlight(s, now)
	if err != nil || d.Action != TransferDefer || !d.EstimatedFinish.IsZero() {
		t.Fatalf("overflow estimate: %+v %v", d, err)
	}
}
