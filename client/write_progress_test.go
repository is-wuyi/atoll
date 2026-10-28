package client

import (
	"context"
	"errors"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const writeProgressTestIdle = 80 * time.Millisecond

func writeProgressWaitDone(t *testing.T, ctx context.Context, within time.Duration) error {
	t.Helper()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-time.After(within):
		t.Fatalf("context not cancelled within %s", within)
		return nil
	}
}

// writeProgressSlowReader yields one byte per Read after a fixed delay.
type writeProgressSlowReader struct {
	interval time.Duration
	mu       sync.Mutex
	reads    int
}

func (r *writeProgressSlowReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	r.reads++
	r.mu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	time.Sleep(r.interval)
	p[0] = 'x'
	return 1, nil
}

func (r *writeProgressSlowReader) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reads
}

// writeProgressStuckReader blocks until it is released.
type writeProgressStuckReader struct {
	release chan struct{}
}

func (r *writeProgressStuckReader) Read(p []byte) (int, error) {
	<-r.release
	return 0, io.EOF
}

// writeProgressBytesErrorReader returns bytes and an error in the same call.
type writeProgressBytesErrorReader struct {
	data []byte
	err  error
}

func (r *writeProgressBytesErrorReader) Read(p []byte) (int, error) {
	return copy(p, r.data), r.err
}

func TestWriteProgressSlowReadsSurvivePastIdleWindow(t *testing.T) {
	ctx, w, cancel := newWriteProgressContext(context.Background(), 0, writeProgressTestIdle)
	src := &writeProgressSlowReader{interval: 20 * time.Millisecond}
	reader := w.Reader(src)
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		for {
			if _, err := reader.Read(buf); err != nil {
				done <- err
				return
			}
		}
	}()
	time.Sleep(4 * writeProgressTestIdle)
	if ctx.Err() != nil {
		t.Fatalf("slow reader crossed the idle window: %v", context.Cause(ctx))
	}
	if src.count() < 2 {
		t.Fatalf("slow reader made %d reads", src.count())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reader goroutine did not exit")
	}
}

func TestWriteProgressIdleStartsBeforeFirstRead(t *testing.T) {
	ctx, _, cancel := newWriteProgressContext(context.Background(), 0, writeProgressTestIdle)
	defer cancel()
	cause := writeProgressWaitDone(t, ctx, 10*writeProgressTestIdle)
	if !errors.Is(cause, errWriteProgressIdle) {
		t.Fatalf("idle cause = %v", cause)
	}
}

func TestWriteProgressIdleAfterEOFStillCoversServerWait(t *testing.T) {
	ctx, w, cancel := newWriteProgressContext(context.Background(), 0, writeProgressTestIdle)
	defer cancel()
	reader := w.Reader(strings.NewReader("payload"))
	buf := make([]byte, 16)
	n, err := reader.Read(buf)
	if err != nil || n == 0 {
		t.Fatalf("read = %d, %v", n, err)
	}
	if _, err := reader.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
	cause := writeProgressWaitDone(t, ctx, 10*writeProgressTestIdle)
	if !errors.Is(cause, errWriteProgressIdle) {
		t.Fatalf("cause after EOF = %v", cause)
	}
}

func TestWriteProgressStuckReadIsCancelled(t *testing.T) {
	ctx, w, cancel := newWriteProgressContext(context.Background(), 0, writeProgressTestIdle)
	defer cancel()
	src := &writeProgressStuckReader{release: make(chan struct{})}
	reader := w.Reader(src)
	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := reader.Read(buf)
		readDone <- err
	}()
	cause := writeProgressWaitDone(t, ctx, 10*writeProgressTestIdle)
	if !errors.Is(cause, errWriteProgressIdle) {
		t.Fatalf("cause = %v", cause)
	}
	close(src.release)
	select {
	case err := <-readDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("read error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stuck read did not return")
	}
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, errWriteProgressIdle) {
		t.Fatalf("read after cancel = %v", err)
	}
}

func TestWriteProgressHardDeadlineIsNotExtendedByProgress(t *testing.T) {
	ctx, w, cancel := newWriteProgressContext(context.Background(), 120*time.Millisecond, writeProgressTestIdle)
	defer cancel()
	src := &writeProgressSlowReader{interval: 20 * time.Millisecond}
	reader := w.Reader(src)
	go func() {
		buf := make([]byte, 1)
		for {
			if _, err := reader.Read(buf); err != nil {
				return
			}
		}
	}()
	cause := writeProgressWaitDone(t, ctx, 5*time.Second)
	if !errors.Is(cause, context.DeadlineExceeded) {
		t.Fatalf("hard deadline cause = %v", cause)
	}
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("hard deadline err = %v", ctx.Err())
	}
}

func TestWriteProgressParentCancel(t *testing.T) {
	parent, parentCancel := context.WithCancel(context.Background())
	ctx, _, cancel := newWriteProgressContext(parent, 0, writeProgressTestIdle)
	defer cancel()
	parentCancel()
	cause := writeProgressWaitDone(t, ctx, time.Second)
	if !errors.Is(cause, context.Canceled) {
		t.Fatalf("parent cancel cause = %v", cause)
	}
	if ctx.Err() != context.Canceled {
		t.Fatalf("parent cancel err = %v", ctx.Err())
	}
}

func TestWriteProgressReaderReturnsBytesWithError(t *testing.T) {
	const idle = 150 * time.Millisecond
	ctx, w, cancel := newWriteProgressContext(context.Background(), 0, idle)
	defer cancel()
	boom := errors.New("boom")
	reader := w.Reader(&writeProgressBytesErrorReader{data: []byte("abc"), err: boom})
	buf := make([]byte, 8)
	n, err := reader.Read(buf)
	if n != 3 || !errors.Is(err, boom) {
		t.Fatalf("read = %d, %v", n, err)
	}
	time.Sleep(idle / 2)
	n, err = reader.Read(buf)
	if n != 3 || !errors.Is(err, boom) {
		t.Fatalf("second read = %d, %v", n, err)
	}
	time.Sleep(idle / 2)
	if ctx.Err() != nil {
		t.Fatalf("idle fired despite progress: %v", context.Cause(ctx))
	}
	cause := writeProgressWaitDone(t, ctx, 10*idle)
	if !errors.Is(cause, errWriteProgressIdle) {
		t.Fatalf("cause = %v", cause)
	}
}

func TestWriteProgressCancelIsIdempotent(t *testing.T) {
	ctx, w, cancel := newWriteProgressContext(context.Background(), 0, writeProgressTestIdle)
	cancel()
	cancel()
	cancel()
	if ctx.Err() != context.Canceled {
		t.Fatalf("err = %v", ctx.Err())
	}
	select {
	case <-w.done:
	default:
		t.Fatal("watcher still running after cancel")
	}
}

func TestWriteProgressConcurrentReadsAndCancel(t *testing.T) {
	ctx, w, cancel := newWriteProgressContext(context.Background(), 0, writeProgressTestIdle)
	src := &writeProgressSlowReader{interval: time.Millisecond}
	reader := w.Reader(src)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 4)
			for i := 0; i < 64; i++ {
				if _, err := reader.Read(buf); err != nil {
					return
				}
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cancel()
		}()
	}
	wg.Wait()
	cancel()
	if ctx.Err() == nil {
		t.Fatal("context not cancelled")
	}
	select {
	case <-w.done:
	default:
		t.Fatal("watcher still running")
	}
}

func TestWriteProgressNonPositiveTimeoutsDisableTheirWindow(t *testing.T) {
	ctx, _, cancel := newWriteProgressContext(context.Background(), 0, 0)
	defer cancel()
	select {
	case <-ctx.Done():
		t.Fatalf("context cancelled without a deadline: %v", context.Cause(ctx))
	case <-time.After(2 * writeProgressTestIdle):
	}
}

func TestWriteProgressDoesNotLeakWatcher(t *testing.T) {
	before := runtime.NumGoroutine()
	for i := 0; i < 32; i++ {
		ctx, _, cancel := newWriteProgressContext(context.Background(), time.Duration(i+1)*time.Millisecond, time.Duration(i+1)*time.Millisecond)
		if i%3 == 0 {
			cancel()
		} else {
			<-ctx.Done()
			cancel()
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before+1 {
		t.Fatalf("goroutines leaked: %d -> %d", before, after)
	}
}
