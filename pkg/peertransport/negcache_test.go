package peertransport

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestNegCacheSingleflight requires that concurrent checks for the same PeerID
// share exactly one authorizer query (no per-goroutine duplicate queries).
func TestNegCacheSingleflight(t *testing.T) {
	c := newNegCache(16, time.Second)
	var calls atomic.Int32
	query := func() bool {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		return false
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.check(context.Background(), "same", 1, query) {
				t.Error("expected denial")
			}
		}()
	}
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Fatalf("authorizer called %d times, want 1 (single-flight)", n)
	}
}

// TestNegCacheBounded requires the cache never exceed its capacity, even when
// flooded with distinct unknown PeerIDs.
func TestNegCacheBounded(t *testing.T) {
	c := newNegCache(8, time.Second)
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("peer-%d", i)
		if c.check(context.Background(), id, 1, func() bool { return false }) {
			t.Fatalf("peer %s should be denied", id)
		}
	}
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n > 8 {
		t.Fatalf("negative cache grew to %d entries, cap is 8", n)
	}
}

// TestNegCacheExpiredDeleted requires expired entries to be removed once the
// cache is large enough to sweep, rather than accumulating stale denials.
func TestNegCacheExpiredDeleted(t *testing.T) {
	c := newNegCache(4, 20*time.Millisecond)
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("peer-%d", i)
		if c.check(context.Background(), id, 1, func() bool { return false }) {
			t.Fatalf("peer %s should be denied", id)
		}
	}
	time.Sleep(30 * time.Millisecond) // past the TTL
	// A new id triggers the sweep (cap/2 = 2), removing the expired entries.
	if c.check(context.Background(), "fresh", 1, func() bool { return false }) {
		t.Fatal("fresh peer should be denied")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, e := range c.entries {
		if id != "fresh" && e.done() {
			t.Fatalf("expired entry %s was not deleted", id)
		}
	}
}

// TestNegCachePositiveNotCached requires a positive result to be re-queried on
// the next check (the authorizer stays authoritative), never remembered.
func TestNegCachePositiveNotCached(t *testing.T) {
	c := newNegCache(16, time.Minute)
	var calls atomic.Int32
	query := func() bool {
		calls.Add(1)
		return true
	}
	if !c.check(context.Background(), "ok", 1, query) {
		t.Fatal("authorized peer should be admitted")
	}
	if !c.check(context.Background(), "ok", 1, query) {
		t.Fatal("authorized peer should be admitted on the second check")
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("authorizer called %d times, want 2 (positive results not cached)", n)
	}
}

// TestNegCacheNeverAllowsWhenDenied hammers one id through constant entry
// replacement (tiny TTL) from many goroutines while the authorizer always
// denies: no check may ever return allow, however entries are replaced and
// joined under concurrency. This pins the invariant that a waiter reads the
// result of exactly the query it joined.
func TestNegCacheNeverAllowsWhenDenied(t *testing.T) {
	c := newNegCache(16, 2*time.Millisecond)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if c.check(context.Background(), "same", 1, func() bool { return false }) {
					t.Error("check returned allow for a denying authorizer")
					return
				}
			}
		}()
	}
	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestNegCacheInFlightNotEvicted requires in-flight entries to be kept: with
// every slot in-flight an overflow id runs uncached, and once the in-flight
// queries complete their entries are all still present and recorded.
func TestNegCacheInFlightNotEvicted(t *testing.T) {
	c := newNegCache(4, time.Minute)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("inflight-%d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.check(context.Background(), id, 1, func() bool {
				<-release
				return false
			}) {
				t.Error("expected denial")
			}
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		c.mu.Lock()
		n := len(c.entries)
		c.mu.Unlock()
		if n == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("in-flight entries were never recorded")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Every slot is in-flight: the overflow id runs uncached (once) and
	// nothing is evicted.
	var uncached atomic.Int32
	if c.check(context.Background(), "overflow", 1, func() bool { uncached.Add(1); return false }) {
		t.Fatal("expected denial")
	}
	if uncached.Load() != 1 {
		t.Fatalf("overflow query ran %d times, want 1", uncached.Load())
	}

	close(release)
	wg.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) != 4 {
		t.Fatalf("entries = %d, want 4 (in-flight entries must not be evicted)", len(c.entries))
	}
	for id, e := range c.entries {
		if !e.done() {
			t.Fatalf("entry %s still in flight after release", id)
		}
		if !e.deny {
			t.Fatalf("entry %s did not record the denial", id)
		}
	}
}

// TestNegCacheGenerationNeverJoins pins the generation contract: a caller of a
// new authorizer generation never joins an old generation's in-flight query,
// and an old denial is never served to a new generation.
func TestNegCacheGenerationNeverJoins(t *testing.T) {
	c := newNegCache(16, time.Minute)
	blocked := make(chan struct{})
	var oldCalls, newCalls atomic.Int32
	done := make(chan bool, 1)
	go func() {
		done <- c.check(context.Background(), "p", 1, func() bool {
			oldCalls.Add(1)
			<-blocked
			return true
		})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if oldCalls.Load() == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("old-generation query never started")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// A new-generation caller runs its own query instead of joining, and its
	// denial is its own.
	if c.check(context.Background(), "p", 2, func() bool {
		newCalls.Add(1)
		return false
	}) {
		t.Fatal("new-generation caller must not adopt the old query's result")
	}
	if newCalls.Load() != 1 {
		t.Fatalf("new-generation query ran %d times, want 1", newCalls.Load())
	}

	close(blocked)
	// The old caller still receives the result of the query it joined.
	if !<-done {
		t.Fatal("old-generation caller lost its own query result")
	}

	// The gen-2 denial is cached for gen 2 without a new query...
	if c.check(context.Background(), "p", 2, func() bool {
		newCalls.Add(1)
		return false
	}) {
		t.Fatal("gen-2 denial should be cached")
	}
	if newCalls.Load() != 1 {
		t.Fatalf("cached gen-2 denial re-queried %d times", newCalls.Load()-1)
	}
	// ...and gen 1 replaces the foreign entry rather than joining it.
	if c.check(context.Background(), "p", 1, func() bool {
		oldCalls.Add(1)
		return false
	}) {
		t.Fatal("gen-1 must re-query past a gen-2 entry")
	}
	if oldCalls.Load() != 2 {
		t.Fatalf("gen-1 query ran %d times, want 2", oldCalls.Load())
	}
}

// TestNegCacheJoinerCtxCancelledDenies pins the joiner fail-closed rule: a
// caller whose context is cancelled while joined never receives an allow.
func TestNegCacheJoinerCtxCancelledDenies(t *testing.T) {
	c := newNegCache(16, time.Minute)
	blocked := make(chan struct{})
	done := make(chan bool, 1)
	go func() {
		done <- c.check(context.Background(), "p", 1, func() bool {
			<-blocked
			return true
		})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		c.mu.Lock()
		_, ok := c.entries["p"]
		c.mu.Unlock()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("query was never recorded")
		}
		time.Sleep(5 * time.Millisecond)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the caller is dead before the allow arrives
	close(blocked)
	// Whether the joiner wakes on the closed wait or its dead context, the
	// post-check denies. It never runs its own query.
	if c.check(ctx, "p", 1, func() bool { t.Error("joined caller must not re-query"); return true }) {
		t.Fatal("cancelled joiner must deny")
	}
	if !<-done {
		t.Fatal("the joined query itself must complete with its own result")
	}
}
