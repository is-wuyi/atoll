// cmd/atoll-scheduler is the shadow-scheduler CLI.
//
// It replays a JSON trace (snapshot) through the scheduler and prints the
// scored candidates, the selected layout, the suggested (shadow-only) plan
// and the reasons as JSON. It never mutates anything, never talks to a
// cluster, and never executes erasure coding.
//
// Usage:
//
//	go run ./cmd/atoll-scheduler -input examples/scheduler/trace-healthy-repair.json
//	go run ./cmd/atoll-scheduler -input trace.json -output out.json -pretty
//	# deterministic replay (fixed evaluation time, byte-stable output):
//	go run ./cmd/atoll-scheduler -input trace.json -now 2026-10-06T12:00:00Z
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"atoll/internal/scheduler"
)

// Output is the CLI envelope around the scheduler decisions.
type Output struct {
	SchemaVersion int                  `json:"schema_version"`
	Shadow        bool                 `json:"shadow"` // always true: suggestion-only
	TraceID       string               `json:"trace_id,omitempty"`
	GeneratedAt   string               `json:"generated_at"`
	Decisions     []scheduler.Decision `json:"decisions"`
}

func main() {
	input := flag.String("input", "", "path to the input trace JSON (snapshot); required")
	output := flag.String("output", "", "path to write the result JSON (default: stdout)")
	pretty := flag.Bool("pretty", true, "indent the JSON output")
	nowFlag := flag.String("now", "", "optional RFC3339 evaluation time; fixes history-based predictions so replays are byte-identical (default: current time)")
	flag.Parse()

	if *input == "" {
		fmt.Fprintln(os.Stderr, "atoll-scheduler: -input <trace.json> is required")
		flag.Usage()
		os.Exit(2)
	}

	raw, err := os.ReadFile(*input)
	if err != nil {
		fatal("read input", err)
	}
	var snap scheduler.Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		fatal("parse input JSON", err)
	}

	var decisions []scheduler.Decision
	// One evaluation time drives both the scheduler and the output stamp:
	// with -now the whole output is a deterministic replay; without it the
	// wall clock is read exactly once.
	evalNow := time.Now()
	if *nowFlag != "" {
		var err2 error
		evalNow, err2 = time.Parse(time.RFC3339, *nowFlag)
		if err2 != nil {
			fatal("parse -now (want RFC3339, e.g. 2026-10-06T12:00:00Z)", err2)
		}
	}
	decisions, err = scheduler.RunAt(&snap, evalNow)
	if err != nil {
		fatal("schedule", err)
	}

	out := Output{
		SchemaVersion: scheduler.SchemaVersion,
		Shadow:        true,
		TraceID:       snap.TraceID,
		GeneratedAt:   evalNow.UTC().Format(time.RFC3339),
		Decisions:     decisions,
	}

	var b []byte
	if *pretty {
		b, err = json.MarshalIndent(out, "", "  ")
	} else {
		b, err = json.Marshal(out)
	}
	if err != nil {
		fatal("encode output", err)
	}
	b = append(b, '\n')

	if *output == "" {
		_, _ = os.Stdout.Write(b)
		return
	}
	if err := os.WriteFile(*output, b, 0o644); err != nil {
		fatal("write output", err)
	}
}

func fatal(stage string, err error) {
	fmt.Fprintf(os.Stderr, "atoll-scheduler: %s: %v\n", stage, err)
	os.Exit(1)
}
