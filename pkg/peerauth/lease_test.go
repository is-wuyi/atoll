package peerauth

import (
	"testing"
	"time"
)

// The center rejects a registration/publish whose NotAfter is beyond its own
// now+EndpointLease. A peer that asks for the exact full lease is vulnerable
// to clock skew and request transit, so requests must leave a bounded margin.
func TestRequestNotAfterKeepsLeaseMargin(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	got := RequestNotAfter(now)
	want := now.Add(EndpointLease - LeaseRequestMargin)
	if !got.Equal(want) {
		t.Fatalf("RequestNotAfter = %v, want %v", got, want)
	}
	if LeaseRequestMargin <= 0 || LeaseRequestMargin >= EndpointLease {
		t.Fatalf("lease margin %v must stay within (0, %v)", LeaseRequestMargin, EndpointLease)
	}
	if !got.Before(now.Add(EndpointLease)) {
		t.Fatal("requested lease must remain strictly shorter than the center's hard window")
	}
	if got.Location() != time.UTC {
		t.Fatalf("lease deadline must be UTC, got %v", got.Location())
	}
}
