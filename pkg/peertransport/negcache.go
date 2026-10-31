package peertransport

import (
	"context"
	"sync"
	"time"
)

// negCacheMax bounds the negative authorization cache. The runtime resource
// manager is finite, but it bounds per-peer resources, not the set of distinct
// PeerIDs a directory or a peer flood can name; the negative cache therefore
// needs its own bound and its own expiry so unknown PeerIDs cannot grow it
// without limit.
const negCacheMax = 4096

// negCache is a bounded, generation-tagged, single-flight negative cache used
// by protocolGate: concurrent checks for the same (id, generation) share one
// in-flight query, rejections are remembered for a TTL, and entries from a
// previous authorizer generation are never joined — a swapped-out callback can
// neither decide for a later caller nor leave its result behind. The map never
// exceeds cap entries: expired entries are swept lazily and, when full, the
// oldest completed entry is evicted (in-flight entries are never evicted, so
// no waiter is left dangling); when every slot is in-flight the query runs
// uncached. The query always runs outside any lock. Positive results are
// never cached. A completed entry is immutable: a re-check replaces the map
// slot with a fresh entry, so every waiter reads the result of exactly the
// query it joined.
type negCache struct {
	mu      sync.Mutex
	entries map[string]*negEntry
	cap     int
	ttl     time.Duration
}

type negEntry struct {
	gen  uint64    // authorizer generation this query belongs to
	deny bool      // result, valid once wait is closed
	at   time.Time // when the result was recorded
	wait chan struct{}
}

func newNegCache(cap int, ttl time.Duration) *negCache {
	return &negCache{entries: map[string]*negEntry{}, cap: cap, ttl: ttl}
}

func (e *negEntry) done() bool {
	select {
	case <-e.wait:
		return true
	default:
		return false
	}
}

// check runs query at most once per (id, gen) and returns whether the id is
// authorized. A rejection is negative-cached for the TTL. A cancelled context
// denies (fail-closed) without touching the cached state.
func (c *negCache) check(ctx context.Context, id string, gen uint64, query func() bool) bool {
	c.mu.Lock()
	if len(c.entries) >= c.cap/2 {
		c.sweepLocked()
	}
	e, ok := c.entries[id]
	if ok && (e.gen != gen || e.done()) {
		if e.gen == gen && e.deny && time.Since(e.at) < c.ttl {
			c.mu.Unlock()
			return false
		}
		// Another generation, an expired denial or a previously allowed
		// result: replace the slot with a fresh entry so waiters never share
		// a rewritten or foreign result.
		ok = false
	}
	if ok {
		// Join the in-flight query and read its own entry: the result of
		// exactly the query this caller joined.
		wait := e.wait
		c.mu.Unlock()
		select {
		case <-wait:
			if ctx.Err() != nil {
				return false
			}
			return !e.deny
		case <-ctx.Done():
			return false
		}
	}
	if len(c.entries) >= c.cap && !c.evictLocked() {
		// Every slot is in-flight: run this query uncached rather than evict
		// an entry some waiter is joined to.
		c.mu.Unlock()
		return query()
	}
	e = &negEntry{gen: gen, wait: make(chan struct{})}
	c.entries[id] = e
	c.mu.Unlock()

	denied := !query()
	c.mu.Lock()
	e.deny = denied
	e.at = time.Now()
	c.mu.Unlock()
	// The entry cannot have been replaced while it was in-flight:
	// replacement, sweep and eviction all require done().
	close(e.wait)
	return !denied
}

// reset drops every cached entry. In-flight queries keep their own entry
// objects (already joined waiters still receive their result), but no later
// check can join a query started before the reset.
func (c *negCache) reset() {
	c.mu.Lock()
	c.entries = map[string]*negEntry{}
	c.mu.Unlock()
}

func (c *negCache) sweepLocked() {
	now := time.Now()
	for k, e := range c.entries {
		if e.done() && now.Sub(e.at) >= c.ttl {
			delete(c.entries, k)
		}
	}
}

// evictLocked removes one completed entry to make room and reports whether
// there is room. It returns false when the map is still full after the sweep,
// meaning every entry is in-flight.
func (c *negCache) evictLocked() bool {
	c.sweepLocked()
	if len(c.entries) < c.cap {
		return true
	}
	var oldestKey string
	var oldest time.Time
	found := false
	for k, e := range c.entries {
		if !e.done() {
			continue
		}
		if !found || e.at.Before(oldest) {
			oldestKey, oldest, found = k, e.at, true
		}
	}
	if !found {
		return false
	}
	delete(c.entries, oldestKey)
	return true
}
