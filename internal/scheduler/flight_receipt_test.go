package scheduler

import (
	"testing"
	"time"
)

func TestTransferFlightFinalBytesReserveReceiptTime(t *testing.T) {
	s, now := flightFixture()
	s.BytesDone, s.PreviousBytes = s.Size, s.Size-1
	s.LeaseUntil = now.Add(time.Second)
	s.GoodputBPS = 100
	d, err := DecideTransferFlight(s, now)
	if err != nil || d.Action != TransferRenew || !d.LeaseUntil.After(s.LeaseUntil) {
		t.Fatalf("last bytes still need verification and receipt time: %+v %v", d, err)
	}
	if err := ValidateTransferDecision(s, d, now); err != nil {
		t.Fatalf("validator rejected bounded final-byte renewal: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*TransferFlightState)
	}{
		{"no new bytes", func(s *TransferFlightState) { s.PreviousBytes = s.Size }},
		{"renewal cap", func(s *TransferFlightState) { s.Renewals = s.MaxRenewals }},
		{"expired", func(s *TransferFlightState) { s.LeaseUntil = now }},
		{"hard deadline", func(s *TransferFlightState) { s.HardUntil = now.Add(2 * time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := s
			tc.mutate(&state)
			decision, err := DecideTransferFlight(state, now)
			if err != nil || decision.Action == TransferRenew {
				t.Fatalf("final bytes bypassed renewal limits: %+v %v", decision, err)
			}
			if err := ValidateTransferDecision(state, d, now); err == nil {
				t.Fatal("forged final-byte renewal bypassed limits")
			}
		})
	}
}
