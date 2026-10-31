package peer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"atoll/internal/peertrace"
)

func TestPeerDiagnosticsCaptureBoundedAndCorrelated(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ATOLL_PEER_TRACE_DIR", dir)
	d := &peerDiagnostics{timers: make(map[string]*time.Timer), seen: make(map[string]bool)}
	d.cond = sync.NewCond(&d.mu)
	for i := 0; i < 10; i++ {
		id := strconv.Itoa(i + 1)
		d.observe(peertrace.Event{ID: id, Side: "client", Method: "GET", Path: "/peers/directory", Phase: "done", Error: "deadline_exceeded"})
	}
	d.mu.Lock()
	if len(d.samples) != 3 || d.pending != 0 {
		t.Fatalf("unbounded or unfinished stack capture: samples=%d pending=%d", len(d.samples), d.pending)
	}
	for _, sample := range d.samples {
		if sample.ID == "" || sample.Side != "client" || !strings.Contains(sample.Stack, "TestPeerDiagnosticsCaptureBoundedAndCorrelated") {
			t.Fatalf("uncorrelated stack sample: id=%q side=%q", sample.ID, sample.Side)
		}
	}
	d.mu.Unlock()
	d.finish(t)
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("missing diagnostic report: %v %v", files, err)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Events  []peertrace.Event `json:"events"`
		Samples []peerStackSample `json:"samples"`
	}
	if err := json.Unmarshal(raw, &report); err != nil || len(report.Events) != 10 || len(report.Samples) != 3 {
		t.Fatalf("incomplete persisted report: events=%d samples=%d err=%v", len(report.Events), len(report.Samples), err)
	}
	d.observe(peertrace.Event{ID: "11", Side: "server", Phase: "start"})
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.events) != 10 || len(d.timers) != 0 {
		t.Fatal("observation after close changed diagnostic state")
	}
}
