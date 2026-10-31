package peer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"atoll/internal/peertrace"
)

type peerDiagnostics struct {
	mu      sync.Mutex
	events  []peertrace.Event
	samples []peerStackSample
	timers  map[string]*time.Timer
	seen    map[string]bool
	closed  bool
	pending int
	cond    *sync.Cond
}

type peerStackSample struct {
	ID    string `json:"request_id"`
	Side  string `json:"side"`
	Stack string `json:"goroutines"`
}

func newPeerDiagnostics(t *testing.T) *peerDiagnostics {
	t.Helper()
	d := &peerDiagnostics{timers: make(map[string]*time.Timer), seen: make(map[string]bool)}
	d.cond = sync.NewCond(&d.mu)
	t.Cleanup(func() { d.finish(t) })
	return d
}

func (d *peerDiagnostics) context(ctx context.Context) context.Context {
	return peertrace.WithObserver(ctx, d.observe)
}

func (d *peerDiagnostics) observe(event peertrace.Event) {
	key := event.Side + ":" + event.ID
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	if len(d.events) == 512 {
		copy(d.events, d.events[1:])
		d.events = d.events[:511]
	}
	d.events = append(d.events, event)
	if event.Phase == "start" {
		if old := d.timers[key]; old != nil {
			old.Stop()
		}
		d.timers[key] = time.AfterFunc(3*time.Second, func() { d.capture(event) })
	} else if event.Phase == "done" {
		if timer := d.timers[key]; timer != nil {
			timer.Stop()
			delete(d.timers, key)
		}
	}
	d.mu.Unlock()
	if event.Error == "deadline_exceeded" || event.Error == "network_timeout" {
		d.capture(event)
	}
}

func (d *peerDiagnostics) capture(event peertrace.Event) {
	key := event.Side + ":" + event.ID
	d.mu.Lock()
	if d.closed || d.seen[key] || len(d.samples)+d.pending >= 3 {
		d.mu.Unlock()
		return
	}
	d.seen[key] = true
	d.pending++
	d.mu.Unlock()
	stack := make([]byte, 512<<10)
	n := runtime.Stack(stack, true)
	d.mu.Lock()
	d.samples = append(d.samples, peerStackSample{ID: event.ID, Side: event.Side, Stack: string(stack[:n])})
	d.pending--
	d.cond.Broadcast()
	d.mu.Unlock()
}

func (d *peerDiagnostics) finish(t *testing.T) {
	d.mu.Lock()
	d.closed = true
	for _, timer := range d.timers {
		timer.Stop()
	}
	for d.pending > 0 {
		d.cond.Wait()
	}
	events := append([]peertrace.Event(nil), d.events...)
	samples := append([]peerStackSample(nil), d.samples...)
	d.mu.Unlock()
	if !t.Failed() && len(samples) == 0 && os.Getenv("ATOLL_PEER_TRACE_DIR") == "" {
		return
	}
	report := struct {
		Test    string            `json:"test"`
		Events  []peertrace.Event `json:"events"`
		Samples []peerStackSample `json:"samples,omitempty"`
	}{t.Name(), events, samples}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Logf("peer diagnostics encoding: %v", err)
		return
	}
	if dir := os.Getenv("ATOLL_PEER_TRACE_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err == nil {
			name := strings.Map(func(r rune) rune {
				if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
					return r
				}
				return '_'
			}, t.Name())
			file, err := os.CreateTemp(dir, name+"-*.json")
			if err == nil {
				_, writeErr := file.Write(append(raw, '\n'))
				closeErr := file.Close()
				if writeErr == nil && closeErr == nil {
					t.Logf("peer diagnostics: %s", filepath.Base(file.Name()))
					return
				}
			}
		}
	}
	t.Log(fmt.Sprintf("peer diagnostics:\n%s", raw))
}
