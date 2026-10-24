package transferbudget

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestLimiterSharesRateAndSlots(t *testing.T) {
	limiter, err := New(2000, 2)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := limiter.Acquire(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			defer release()
			count, err := io.Copy(io.Discard, limiter.Reader(context.Background(), bytes.NewReader(make([]byte, 500)), 2000))
			if err != nil || count != 500 {
				t.Errorf("read %d %v", count, err)
			}
		}()
	}
	wg.Wait()
	if elapsed := time.Since(started); elapsed < 400*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("shared budget elapsed %s", elapsed)
	}
}

func TestLimiterCancellationAndIdempotentRelease(t *testing.T) {
	limiter, err := New(10, 1)
	if err != nil {
		t.Fatal(err)
	}
	release, err := limiter.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := limiter.Acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	release()
	release()
	if release, err := limiter.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
	ctx, cancel2 := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel2()
	_, err = io.Copy(io.Discard, limiter.Reader(ctx, bytes.NewReader(make([]byte, 100)), 10))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestLimiterRejectsInvalidBudgets(t *testing.T) {
	for _, test := range []struct {
		rate  uint64
		slots int
	}{{0, 1}, {MaxRate + 1, 1}, {100, 0}, {100, 33}} {
		if _, err := New(test.rate, test.slots); err == nil {
			t.Fatalf("accepted %+v", test)
		}
	}
}
