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
	control := ControlContext(ctx)
	if _, required := RequiredPath(control); required {
		t.Fatal("control request inherited data path")
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
}
