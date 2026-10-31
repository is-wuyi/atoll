package peertransport

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/peerauth"
)

func testDirectory(infraID string, eps ...string) peerauth.Directory {
	d := peerauth.Directory{
		Protocol: peerauth.Feature,
		Infrastructure: peerauth.Infrastructure{
			PeerID:    infraID,
			PublicKey: bytes32(infraID),
		},
	}
	for _, id := range eps {
		d.Endpoints = append(d.Endpoints, peerauth.Endpoint{
			PeerID:     id,
			PublicKey:  bytes32(id),
			ValidUntil: time.Now().Add(2 * time.Minute),
		})
	}
	return d
}

func bytes32(seed string) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(seed[0]) ^ byte(i)
	}
	return b
}

func TestAuthorizeAuthoritativeOverAllowSet(t *testing.T) {
	g := newProtocolGate(context.Background())
	g.setDirectory(testDirectory("infra", "peerA"))

	// No authorizer: the allow-set decides.
	if !g.authorize(context.Background(), "peerA") {
		t.Fatal("allow-set should admit peerA")
	}
	if g.authorize(context.Background(), "unknown") {
		t.Fatal("allow-set should reject unknown")
	}

	// Install an authorizer that admits only peerB: it admits a peer the
	// allow-set has never seen (fresh registration) while rejecting even a
	// directory peer (revocation), because the authorizer is authoritative.
	g.setAuthorizer(func(_ context.Context, id string) bool { return id == "peerB" })
	if !g.authorize(context.Background(), "peerB") {
		t.Fatal("authorizer should admit a peer missing from the allow-set")
	}
	if g.authorize(context.Background(), "peerA") {
		t.Fatal("authorizer is authoritative: a revoked allow-set peer must be rejected")
	}
}

func TestAuthorizeNegativeCache(t *testing.T) {
	old := negCacheTTL
	negCacheTTL = 30 * time.Millisecond
	defer func() { negCacheTTL = old }()

	g := newProtocolGate(context.Background())
	var allow atomic.Bool
	g.setAuthorizer(func(context.Context, string) bool { return allow.Load() })

	if g.authorize(context.Background(), "peerX") {
		t.Fatal("authorizer should reject initially")
	}
	// The peer becomes authorized, but the rejection is negative-cached.
	allow.Store(true)
	if g.authorize(context.Background(), "peerX") {
		t.Fatal("negative cache should suppress an immediate re-query")
	}
	// After the cache window the authorizer is consulted again and admits it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if g.authorize(context.Background(), "peerX") {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("authorizer was never consulted after the negative cache window")
}

func TestAllowedPeerNeverCallsAuthorizer(t *testing.T) {
	g := newProtocolGate(context.Background())
	g.setDirectory(testDirectory("infra", "peerA"))
	var calls atomic.Int32
	g.setAuthorizer(func(context.Context, string) bool {
		calls.Add(1)
		return true
	})
	if !g.allowedPeer("peerA") {
		t.Fatal("allowedPeer should admit a directory peer")
	}
	if calls.Load() != 0 {
		t.Fatal("allowedPeer must not call the authorizer")
	}
}

func TestSetDirectoryExpiry(t *testing.T) {
	g := newProtocolGate(context.Background())
	g.setDirectory(testDirectory("infra", "peerA"))
	if !g.allowedPeer("peerA") {
		t.Fatal("peerA should be admitted")
	}
	if !g.allowedPeer("infra") {
		t.Fatal("infra peer should be admitted with the endpoint lease")
	}
	if g.allowedPeer("absent") {
		t.Fatal("absent peer must not be admitted")
	}
}

// TestSetAuthorizerSwapDropsCachedState verifies a swapped or removed
// authorizer is never reachable through cached state: the new callback decides
// immediately despite a long-lived cached denial from the old one, and removal
// falls back to the allow-set.
func TestSetAuthorizerSwapDropsCachedState(t *testing.T) {
	old := negCacheTTL
	negCacheTTL = time.Hour
	t.Cleanup(func() { negCacheTTL = old })

	g := newProtocolGate(context.Background())
	var allow atomic.Bool
	g.setAuthorizer(func(context.Context, string) bool { return allow.Load() })

	if g.authorize(context.Background(), "peerX") {
		t.Fatal("authorizer should deny initially")
	}
	// The denial is negative-cached for an hour.
	allow.Store(true)
	if g.authorize(context.Background(), "peerX") {
		t.Fatal("cached denial should suppress the immediate re-query")
	}
	// Swapping the authorizer drops the cache: the new callback decides
	// immediately, never the stale denial of the old one.
	g.setAuthorizer(func(context.Context, string) bool { return true })
	if !g.authorize(context.Background(), "peerX") {
		t.Fatal("swapped authorizer must decide immediately")
	}
	// Removing the authorizer falls back to the (empty) allow-set: deny.
	g.setAuthorizer(nil)
	if g.authorize(context.Background(), "peerX") {
		t.Fatal("removed authorizer must not keep admitting")
	}
}

// TestAuthorizeOldCallbackLateReturnDenied pins the generation barrier: a
// pre-swap caller whose old callback returns true after the swap is denied,
// and the post-swap caller is decided by the new callback, never joined to
// the old query.
func TestAuthorizeOldCallbackLateReturnDenied(t *testing.T) {
	g := newProtocolGate(context.Background())
	release := make(chan struct{})
	var oldCalls, newCalls atomic.Int32
	g.setAuthorizer(func(context.Context, string) bool {
		oldCalls.Add(1)
		<-release
		return true
	})
	preSwap := make(chan bool, 1)
	go func() {
		preSwap <- g.authorize(context.Background(), "peerX")
	}()
	deadline := time.Now().Add(2 * time.Second)
	for oldCalls.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("old callback was never entered")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Swap while the old query is in flight; the new callback denies.
	g.setAuthorizer(func(context.Context, string) bool {
		newCalls.Add(1)
		return false
	})
	if g.authorize(context.Background(), "peerX") {
		t.Fatal("post-swap caller must be denied by the new callback")
	}
	if newCalls.Load() != 1 {
		t.Fatalf("new callback ran %d times, want 1 (not joined to the old query)", newCalls.Load())
	}

	close(release)
	// The pre-swap caller's late-arriving allow is stale: denied.
	if <-preSwap {
		t.Fatal("a late result from the swapped-out callback must be denied")
	}
	// And nothing cached the old allow: the new callback still decides.
	if g.authorize(context.Background(), "peerX") {
		t.Fatal("old callback result must not authorize later callers")
	}
}

// TestAuthorizeFailClosedOnCancelledContext pins the context rules: a
// cancelled caller context or a closed runtime denies, before and after the
// decision, and a callback returning true on a dead context is not trusted.
func TestAuthorizeFailClosedOnCancelledContext(t *testing.T) {
	g := newProtocolGate(context.Background())
	g.setAuthorizer(func(context.Context, string) bool { return true })
	ctx, cancel := context.WithCancel(context.Background())
	if !g.authorize(ctx, "peerX") {
		t.Fatal("live caller should be admitted")
	}
	cancel()
	if g.authorize(ctx, "peerX") {
		t.Fatal("cancelled caller context must deny")
	}

	// A runtime whose context is closed denies even a permissive authorizer
	// and the allow-set path.
	rctx, rcancel := context.WithCancel(context.Background())
	closed := newProtocolGate(rctx)
	closed.setAuthorizer(func(context.Context, string) bool { return true })
	closed.setDirectory(testDirectory("infra", "peerA"))
	rcancel()
	if closed.authorize(context.Background(), "peerA") {
		t.Fatal("closed runtime must deny a directory peer")
	}

	// A callback that cancels its own context mid-call and still claims allow
	// is not trusted: the bounded window died, the result is denied.
	mctx, mcancel := context.WithCancel(context.Background())
	tricky := newProtocolGate(context.Background())
	tricky.setAuthorizer(func(ctx context.Context, _ string) bool {
		mcancel()
		return true
	})
	if tricky.authorize(mctx, "peerX") {
		t.Fatal("a true from a dead context must be denied")
	}
}

// TestInvokeAuthorizerBoundedSlots pins the bounded concurrency: when every
// slot is held by stuck callbacks, further checks fail closed without
// invoking the callback.
func TestInvokeAuthorizerBoundedSlots(t *testing.T) {
	g := newProtocolGate(context.Background())
	release := make(chan struct{})
	var calls atomic.Int32
	g.setAuthorizer(func(context.Context, string) bool {
		calls.Add(1)
		<-release
		return true
	})
	var wg sync.WaitGroup
	for i := 0; i < authorizerSlots; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if !g.authorize(context.Background(), fmt.Sprintf("holder-%d", i)) {
				t.Error("holder should be admitted once released")
			}
		}(i)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if len(g.cbSlots) == authorizerSlots {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("slots never filled: %d/%d", len(g.cbSlots), authorizerSlots)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if g.authorize(context.Background(), "overflow") {
		t.Fatal("overflow check must fail closed when all slots are held")
	}
	close(release)
	wg.Wait()
	// A slot is free again: a fresh id is decided by the callback (the
	// overflow id itself stays denied in the cache for its TTL).
	if !g.authorize(context.Background(), "fresh-after-release") {
		t.Fatal("a fresh check should succeed once a slot frees")
	}
}

// TestAllowedPeerFailClosedOnClosedCtx verifies the allow-set path denies once
// the runtime context is closed, without ever consulting the authorizer.
func TestAllowedPeerFailClosedOnClosedCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	g := newProtocolGate(ctx)
	g.setDirectory(testDirectory("infra", "peerA"))
	if !g.allowedPeer("peerA") {
		t.Fatal("peerA should be admitted while live")
	}
	cancel()
	if g.allowedPeer("peerA") {
		t.Fatal("allowedPeer must deny after the runtime context is closed")
	}
}
