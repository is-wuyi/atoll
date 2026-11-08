package peertransport

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"atoll/pkg/peerauth"
	"github.com/libp2p/go-libp2p/core/event"
	ma "github.com/multiformats/go-multiaddr"
)

// These tests pin the candidate-lifecycle invariants that the main/auxiliary
// observation split depends on. They intentionally drive recordWithFence with
// the fixture from observed_test.go instead of a live host: the fence contract
// is about state captured before a possibly slow Identify read, not about the
// transport that performed the read.

var (
	fencePublicA = ma.StringCast("/ip4/1.1.1.1/tcp/44123")
	fencePublicB = ma.StringCast("/ip4/1.1.1.1/tcp/44124")
	fencePrivate = ma.StringCast("/ip4/192.168.0.4/tcp/44123")
)

func fenceEvent(conn *candidateConn, address ma.Multiaddr) event.EvtPeerIdentificationCompleted {
	return event.EvtPeerIdentificationCompleted{Peer: conn.RemotePeer(), Conn: conn, ObservedAddr: address}
}

func fenceCloneConn(src *candidateConn, id string) *candidateConn {
	return &candidateConn{id: id, local: src.local, remote: src.remote, localID: src.localID, remoteID: src.remoteID, key: src.key}
}

func fenceRecord(t *testing.T, o *trustedObservations, conn *candidateConn, address ma.Multiaddr) bool {
	t.Helper()
	return o.recordWithFence(fenceEvent(conn, address), o.fence())
}

func fenceIdentifiedCount(o *trustedObservations) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.identified)
}

func fenceRevision(o *trustedObservations) uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.revision
}

// TestObservationConnIdentityNotConnID pins that two connections with the same
// Conn.ID() (main and auxiliary hosts share a PeerID) are independent records:
// recording or disconnecting one must never overwrite or remove the other.
func TestObservationConnIdentityNotConnID(t *testing.T) {
	o, first, _ := observationFixture(t)
	second := fenceCloneConn(first, first.id)
	if first == second {
		t.Fatal("fixture produced an aliased connection")
	}
	if first.ID() != second.ID() {
		t.Fatal("fixture connections must share Conn.ID to exercise the collision")
	}
	if !fenceRecord(t, o, first, fencePublicA) {
		t.Fatal("first observation rejected")
	}
	if !fenceRecord(t, o, second, fencePublicB) {
		t.Fatal("second observation with the same Conn.ID rejected")
	}
	if got := o.Addrs(1); len(got) != 2 {
		t.Fatalf("record of same-ID peers kept %d addresses, want 2: %v", len(got), got)
	}

	o.Disconnected(nil, first)
	got := o.Addrs(1)
	if len(got) != 1 || !got[0].Equal(fencePublicB) {
		t.Fatalf("Disconnect of one same-ID conn removed the other: %v", got)
	}

	if !fenceRecord(t, o, first, fencePublicA) {
		t.Fatal("re-record of the disconnected connection rejected")
	}
	o.Disconnected(nil, second)
	got = o.Addrs(1)
	if len(got) != 1 || !got[0].Equal(fencePublicA) {
		t.Fatalf("Disconnect of the second same-ID conn removed the first: %v", got)
	}
}

// TestObservationWaitIdentifyUsesConnIdentity pins that waitIdentify cannot be
// satisfied by an identified entry belonging to a different connection object
// that happens to share Conn.ID().
func TestObservationWaitIdentifyUsesConnIdentity(t *testing.T) {
	o, identified, _ := observationFixture(t)
	sameID := fenceCloneConn(identified, identified.id)
	if !fenceRecord(t, o, identified, fencePublicA) {
		t.Fatal("identified observation rejected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := o.waitIdentify(ctx, sameID); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waitIdentify matched a different conn with the same Conn.ID: %v", err)
	}
	if err := o.waitIdentify(context.Background(), identified); err != nil {
		t.Fatalf("waitIdentify did not recognize the identified conn: %v", err)
	}
	if !fenceRecord(t, o, sameID, fencePublicB) {
		t.Fatal("second conn was not recorded")
	}
	if err := o.waitIdentify(context.Background(), sameID); err != nil {
		t.Fatalf("waitIdentify did not recognize the second conn after its own identify: %v", err)
	}
}

// TestObservationLeaseInterruptionDoesNotRevive pins that a lease lapse
// followed by a same-binding directory refresh clears old observations instead
// of making them live again without a new Identify read.
func TestObservationLeaseInterruptionDoesNotRevive(t *testing.T) {
	o, conn, infra := observationFixture(t)
	if !fenceRecord(t, o, conn, fencePublicA) {
		t.Fatal("observation rejected")
	}
	if got := o.Addrs(1); len(got) != 1 {
		t.Fatalf("candidate count = %d, want 1", len(got))
	}
	o.mu.Lock()
	o.until = time.Now().Add(-time.Second)
	o.mu.Unlock()
	if got := o.Addrs(1); len(got) != 0 {
		t.Fatalf("expired lease still served a candidate: %v", got)
	}

	before := fenceRevision(o)
	o.setInfrastructure(infra)
	if got := fenceRevision(o); got != before+1 {
		t.Fatalf("revision after lease interruption = %d, want %d", got, before+1)
	}
	if got := o.Addrs(1); len(got) != 0 {
		t.Fatalf("expired candidate revived by a same-binding refresh: %v", got)
	}
	if !fenceRecord(t, o, conn, fencePublicA) {
		t.Fatal("fresh observation after the refresh was rejected")
	}
	if got := o.Addrs(1); len(got) != 1 {
		t.Fatalf("fresh candidate count = %d, want 1", len(got))
	}
}

// TestObservationOrdinaryRefreshKeepsCandidateAndFence pins the other side of
// the fence: an uninterrupted directory refresh must not bump the revision,
// clear candidates, or invalidate a query-start fence captured just before it.
func TestObservationOrdinaryRefreshKeepsCandidateAndFence(t *testing.T) {
	o, conn, infra := observationFixture(t)
	if !fenceRecord(t, o, conn, fencePublicA) {
		t.Fatal("observation rejected")
	}
	fence := o.fence()
	before := fenceRevision(o)
	o.setInfrastructure(infra)
	if got := fenceRevision(o); got != before {
		t.Fatalf("ordinary refresh bumped revision %d -> %d", before, got)
	}
	if !o.currentFence(fence) {
		t.Fatal("ordinary refresh invalidated a query-start fence")
	}
	if got := o.Addrs(1); len(got) != 1 || !got[0].Equal(fencePublicA) {
		t.Fatalf("ordinary refresh changed candidates: %v", got)
	}
	if !o.recordWithFence(fenceEvent(conn, fencePublicB), fence) {
		t.Fatal("record with a fence captured before an ordinary refresh was rejected")
	}
	if got := o.Addrs(1); len(got) != 1 || !got[0].Equal(fencePublicB) {
		t.Fatalf("candidate was not replaced after the ordinary refresh: %v", got)
	}
}

// TestObservationInfrastructureAndGenerationChangesReject pins that address or
// Relay changes, authorizer generation changes, and a closed connection remove
// or reject observations, while a fresh observation under the new state works.
func TestObservationInfrastructureAndGenerationChangesReject(t *testing.T) {
	o, conn, infra := observationFixture(t)
	if !fenceRecord(t, o, conn, fencePublicA) {
		t.Fatal("observation rejected")
	}

	changed := infra
	changed.Addresses = []string{"/ip4/8.8.8.8/tcp/4321"}
	o.setInfrastructure(changed)
	if got := o.Addrs(1); len(got) != 0 {
		t.Fatalf("address change kept a candidate: %v", got)
	}
	if !fenceRecord(t, o, conn, fencePublicA) {
		t.Fatal("fresh observation after address change rejected")
	}

	relayChanged := changed
	relayChanged.Relay = !changed.Relay
	o.setInfrastructure(relayChanged)
	if got := o.Addrs(1); len(got) != 0 {
		t.Fatalf("Relay change kept a candidate: %v", got)
	}

	o.setInfrastructure(infra)
	if !fenceRecord(t, o, conn, fencePublicA) {
		t.Fatal("fresh observation after restoring the binding rejected")
	}
	o.auth.setAuthorizer(allowIDs(infra.PeerID))
	if got := o.Addrs(1); len(got) != 0 {
		t.Fatalf("authorizer generation change kept a candidate: %v", got)
	}
	if !fenceRecord(t, o, conn, fencePublicA) {
		t.Fatal("fresh observation under the new authorizer generation rejected")
	}

	conn.closed.Store(true)
	if fenceRecord(t, o, conn, fencePublicA) {
		t.Fatal("closed connection was recorded as a candidate")
	}
	if got := o.Addrs(1); len(got) != 0 {
		t.Fatalf("closed connection kept a candidate: %v", got)
	}
}

// TestObservationRecordWithFenceRejectsQueryStartStateChange pins that a fence
// captured before a slow Identify read cannot be used to insert an observation
// after the infrastructure revision, authorizer generation, or lease changed.
func TestObservationRecordWithFenceRejectsQueryStartStateChange(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*trustedObservations, peerauth.Infrastructure)
	}{
		{
			name: "address change",
			mutate: func(o *trustedObservations, infra peerauth.Infrastructure) {
				changed := infra
				changed.Addresses = []string{"/ip4/8.8.8.8/tcp/4321"}
				o.setInfrastructure(changed)
			},
		},
		{
			name: "authorizer generation",
			mutate: func(o *trustedObservations, infra peerauth.Infrastructure) {
				o.auth.setAuthorizer(allowIDs(infra.PeerID))
			},
		},
		{
			name: "lease expiry",
			mutate: func(o *trustedObservations, _ peerauth.Infrastructure) {
				o.mu.Lock()
				o.until = time.Now().Add(-time.Second)
				o.mu.Unlock()
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, conn, infra := observationFixture(t)
			fence := o.fence()
			tc.mutate(o, infra)
			if o.recordWithFence(fenceEvent(conn, fencePublicA), fence) {
				t.Fatal("observation accepted with a stale query-start fence")
			}
			if got := fenceIdentifiedCount(o); got != 0 {
				t.Fatalf("stale observation entered identified: %d entries", got)
			}
			o.setInfrastructure(infra)
			if !fenceRecord(t, o, conn, fencePublicA) {
				t.Fatal("fresh observation after the state change rejected")
			}
		})
	}
}

// TestObservationRecordWithContextRejectsCancelledCaller pins that the manual
// observation path cannot insert a candidate with a caller context that is
// already dead or dies while the authorizer decision is in flight.
func TestObservationRecordWithContextRejectsCancelledCaller(t *testing.T) {
	o, conn, infra := observationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if o.recordWithContext(ctx, fenceEvent(conn, fencePublicA), o.fence()) {
		t.Fatal("observation accepted with an already-cancelled caller context")
	}
	if got := o.Addrs(1); len(got) != 0 {
		t.Fatalf("cancelled caller inserted a candidate: %v", got)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	o.auth.setAuthorizer(func(context.Context, string) bool {
		close(entered)
		<-release
		return true
	})
	fence := o.fence()
	liveCtx, liveCancel := context.WithCancel(context.Background())
	defer liveCancel()
	result := make(chan bool, 1)
	go func() {
		result <- o.recordWithContext(liveCtx, fenceEvent(conn, fencePublicA), fence)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("observation did not reach the authorizer")
	}
	liveCancel()
	close(release)
	released = true
	select {
	case ok := <-result:
		if ok {
			t.Fatal("observation accepted although the caller context died in flight")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("observation did not return after caller cancellation")
	}
	if got := o.Addrs(1); len(got) != 0 {
		t.Fatalf("in-flight cancelled caller inserted a candidate: %v", got)
	}
	// A cancelled decision may be negative-cached; a fresh generation and
	// fence must still admit a later observation.
	o.auth.setAuthorizer(allowIDs(infra.PeerID))
	if !fenceRecord(t, o, conn, fencePublicB) {
		t.Fatal("fresh observation after caller cancellation rejected")
	}
}

// TestObservationUnusableSlotsDoNotEvictValidCandidate pins that identified
// slots consumed by unusable observations (private/mismatched mappings) do not
// prevent a later valid observation from becoming a candidate.
func TestObservationUnusableSlotsDoNotEvictValidCandidate(t *testing.T) {
	o, base, _ := observationFixture(t)
	for i := 0; i < maxAdvertisedAddresses; i++ {
		conn := fenceCloneConn(base, fmt.Sprintf("unusable-%d", i))
		if fenceRecord(t, o, conn, fencePrivate) {
			t.Fatalf("private observation %d was accepted", i)
		}
	}
	if got := fenceIdentifiedCount(o); got != maxAdvertisedAddresses {
		t.Fatalf("identified slots = %d, want %d", got, maxAdvertisedAddresses)
	}
	valid := fenceCloneConn(base, "valid-after-unusable")
	if !fenceRecord(t, o, valid, fencePublicA) {
		t.Fatal("a full identified set of unusable observations evicted a valid candidate")
	}
	got := o.Addrs(1)
	if len(got) != 1 || !got[0].Equal(fencePublicA) {
		t.Fatalf("valid candidate after unusable slots = %v", got)
	}
}

// TestObservationNewAuthorizerGenerationClearsOldSlots pins that a generation
// change frees identified slots tagged with the previous generation instead of
// leaving them to block or pollute later observations.
func TestObservationNewAuthorizerGenerationClearsOldSlots(t *testing.T) {
	o, base, infra := observationFixture(t)
	for i := 0; i < maxAdvertisedAddresses; i++ {
		conn := fenceCloneConn(base, fmt.Sprintf("old-generation-%d", i))
		if fenceRecord(t, o, conn, fencePrivate) {
			t.Fatalf("private observation %d was accepted", i)
		}
	}
	if got := fenceIdentifiedCount(o); got != maxAdvertisedAddresses {
		t.Fatalf("identified slots = %d, want %d", got, maxAdvertisedAddresses)
	}

	o.auth.setAuthorizer(allowIDs(infra.PeerID))
	valid := fenceCloneConn(base, "new-generation")
	if !fenceRecord(t, o, valid, fencePublicA) {
		t.Fatal("new-generation observation was rejected by old-generation slots")
	}
	if got := fenceIdentifiedCount(o); got != 1 {
		t.Fatalf("old-generation identified slots retained: %d entries", got)
	}
	got := o.Addrs(1)
	if len(got) != 1 || !got[0].Equal(fencePublicA) {
		t.Fatalf("new-generation candidate = %v", got)
	}
}
