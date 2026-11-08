package peerhttp

import (
	"context"
	"testing"
)

func TestControlContextKeepsCancellationButDropsDataPathAndReporter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ctx = WithPath(ctx, PathDirect)
	reports := 0
	ctx = WithReporter(ctx, &Reporter{Observe: func(Observation) { reports++ }})
	ctx = WithRequestID(ctx, "data-request-1")
	// A data dial context carries the private request meta; a control request
	// derived from it must not inherit any of it.
	ctx = context.WithValue(ctx, metaKey, &requestMeta{requestID: "data-request-1", method: "GET"})
	ctx = withDialBounds(ctx)
	control := ControlContext(ctx)
	if _, required := RequiredPath(control); required {
		t.Fatal("control request inherited data path")
	}
	if RequestID(control) != "" {
		t.Fatal("control request inherited the data request ID")
	}
	if metaFrom(control) != nil {
		t.Fatal("control request inherited the data request meta")
	}
	if bounds, _ := control.Value(dialBoundsKey).(*dialBounds); bounds != nil {
		t.Fatal("control request inherited private data dial bounds")
	}
	transport := &Transport{}
	transport.report(control, Observation{Master: true})
	if reports != 0 {
		t.Fatal("control lookup polluted data path observation")
	}
	cancel()
	if control.Err() != context.Canceled {
		t.Fatal("control context lost parent cancellation")
	}
	if path, _ := RequiredPath(ctx); path != PathDirect {
		t.Fatal("original data path mutated")
	}
	if RequestID(ctx) != "data-request-1" {
		t.Fatal("original data request ID mutated")
	}
}
