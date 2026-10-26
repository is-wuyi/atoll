package node

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPullLeaseContinuesOnlyWithRenewedLeaseAndProgress(t *testing.T) {
	now := time.Now()
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	counter := &progressCounter{}
	counter.last.Store(now.UnixNano())
	hard := now.Add(time.Second)
	lease := newPullLease(now.Add(200*time.Millisecond), hard, 400*time.Millisecond, counter, cancel)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { defer close(done); lease.watch(ctx, stop) }()
	if err := lease.extend(now.Add(700*time.Millisecond), hard); err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(250 * time.Millisecond)
	select {
	case <-ctx.Done():
		t.Fatalf("old lease cutoff still active: %v", context.Cause(ctx))
	case <-timer.C:
	}
	counter.Write([]byte("payload"))
	if err := lease.extend(now.Add(900*time.Millisecond), hard); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), errPullIdle) {
			t.Fatalf("idle cause = %v", context.Cause(ctx))
		}
	case <-time.After(time.Second):
		t.Fatal("idle stream held a renewed lease indefinitely")
	}
	<-done
}

func TestPullLeaseCannotReviveExpiredOrExtendHardDeadline(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	now := time.Now()
	counter := &progressCounter{}
	counter.last.Store(now.UnixNano())
	hard := now.Add(150 * time.Millisecond)
	lease := newPullLease(hard, hard, time.Second, counter, cancel)
	if err := lease.extend(hard.Add(time.Second), hard); !errors.Is(err, errLeaseExpired) {
		t.Fatalf("extended hard deadline: %v", err)
	}
	if err := lease.extend(hard, hard.Add(time.Second)); !errors.Is(err, errLeaseExpired) {
		t.Fatalf("replaced hard deadline: %v", err)
	}
	stop := make(chan struct{})
	go lease.watch(ctx, stop)
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), errLeaseExpired) {
			t.Fatalf("hard deadline cause: %v", context.Cause(ctx))
		}
	case <-time.After(time.Second):
		t.Fatal("hard attempt deadline not enforced")
	}
	if err := lease.extend(time.Now().Add(time.Second), hard); !errors.Is(err, errLeaseExpired) {
		t.Fatalf("expired lease revived: %v", err)
	}
}
