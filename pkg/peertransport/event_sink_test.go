package peertransport

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestRuntimeEventCloseJoinsAcceptedCallback(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	returned := make(chan struct{})
	var calls atomic.Int64
	sink := &runtimeEvents{observe: func(RuntimeEvent) {
		calls.Add(1)
		close(entered)
		<-release
	}}
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	go sink.emit(RuntimeEvent{Kind: "accepted"})
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("observer never entered")
	}
	go func() { sink.close(); close(returned) }()
	// close must reject new callbacks before waiting for the accepted one.
	deadline := time.Now().Add(5 * time.Second)
	for {
		sink.mu.Lock()
		closed := sink.closed
		sink.mu.Unlock()
		if closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sink did not enter its closed state")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-returned:
		t.Fatal("close returned while an accepted callback was in flight")
	default:
	}
	sink.emit(RuntimeEvent{Kind: "late"})
	close(release)
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("close did not join callback")
	}
	if calls.Load() != 1 {
		t.Fatal("late callback escaped the finalized sink")
	}
}

func TestRuntimeEventCandidatesAreCopiedAndBounded(t *testing.T) {
	addresses := make([]string, 20)
	addresses[0] = "original"
	var got RuntimeEvent
	sink := &runtimeEvents{observe: func(e RuntimeEvent) { got = e }}
	sink.emit(RuntimeEvent{Candidates: addresses})
	addresses[0] = "changed"
	sink.close()
	if len(got.Candidates) != 16 || got.Candidates[0] != "original" {
		t.Fatal("observation was unbounded or retained caller's candidate slice")
	}
}
