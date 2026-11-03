package peertransport

import (
	"sync"

	"atoll/pkg/peerauth"
)

// Closing the event sink prevents a late library callback from changing a
// diagnostic file after Runtime.Close has handed the snapshot to its owner.
type runtimeEvents struct {
	observe func(RuntimeEvent)
	mu      sync.Mutex
	closed  bool
	active  sync.WaitGroup
}

func (e *runtimeEvents) emit(event RuntimeEvent) {
	if e == nil || e.observe == nil {
		return
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.active.Add(1)
	e.mu.Unlock()
	defer e.active.Done()
	if len(event.Candidates) > peerauth.MaxAddresses {
		event.Candidates = event.Candidates[:peerauth.MaxAddresses]
	}
	event.Candidates = append([]string(nil), event.Candidates...)
	e.observe(event)
}

func (e *runtimeEvents) close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
	e.active.Wait()
}
