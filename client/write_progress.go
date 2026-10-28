package client

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

var errWriteProgressIdle = errors.New("planned write made no payload progress")

// writeProgress bounds one planned PUT. Payload progress renews the idle
// window, the idle window expires when the body reader stops making progress,
// and the hard deadline caps the whole attempt no matter how much progress
// happens. Progress only proves the reader is alive; it never means the node
// acknowledged the payload, so the idle window also covers the wait for the
// server response after the body reached EOF.
type writeProgress struct {
	mu        sync.Mutex
	last      time.Time
	idleFired bool

	idle   time.Duration
	ctx    context.Context
	cancel context.CancelCauseFunc
	wake   chan struct{}
	stop   chan struct{}
	done   chan struct{}
}

// newWriteProgressContext derives the context for one planned PUT. A
// non-positive hardTimeout disables the hard deadline and a non-positive
// idleTimeout disables the idle window. The idle window starts immediately and
// is renewed by every read that returns bytes.
func newWriteProgressContext(parent context.Context, hardTimeout, idleTimeout time.Duration) (context.Context, *writeProgress, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	base := parent
	hardCancel := context.CancelFunc(func() {})
	if hardTimeout > 0 {
		base, hardCancel = context.WithDeadline(parent, time.Now().Add(hardTimeout))
	}
	ctx, cancel := context.WithCancelCause(base)
	w := &writeProgress{
		last:   time.Now(),
		idle:   idleTimeout,
		ctx:    ctx,
		cancel: cancel,
		wake:   make(chan struct{}, 1),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go w.watch()
	var once sync.Once
	stop := context.CancelFunc(func() {
		once.Do(func() {
			close(w.stop)
			cancel(context.Canceled)
			hardCancel()
		})
		<-w.done
	})
	return ctx, w, stop
}

// Reader wraps a request body so that every read returning bytes renews the
// idle window.
func (w *writeProgress) Reader(src io.Reader) io.Reader {
	return &writeProgressReader{src: src, progress: w}
}

func (w *writeProgress) progressed() {
	w.mu.Lock()
	if w.idleFired {
		w.mu.Unlock()
		return
	}
	w.last = time.Now()
	w.mu.Unlock()
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *writeProgress) idleExpired(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.idleFired {
		return true
	}
	if now.Before(w.last.Add(w.idle)) {
		return false
	}
	w.idleFired = true
	return true
}

func (w *writeProgress) watch() {
	defer close(w.done)
	for {
		var timer *time.Timer
		var idle <-chan time.Time
		if w.idle > 0 {
			w.mu.Lock()
			deadline := w.last.Add(w.idle)
			w.mu.Unlock()
			timer = time.NewTimer(max(time.Until(deadline), 0))
			idle = timer.C
		}
		select {
		case <-w.ctx.Done():
			stopWriteProgressTimer(timer)
			return
		case <-w.stop:
			stopWriteProgressTimer(timer)
			return
		case <-w.wake:
			stopWriteProgressTimer(timer)
		case <-idle:
			stopWriteProgressTimer(timer)
			if w.idleExpired(time.Now()) {
				w.cancel(errWriteProgressIdle)
				return
			}
		}
	}
}

func stopWriteProgressTimer(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}

type writeProgressReader struct {
	src      io.Reader
	progress *writeProgress
}

func (r *writeProgressReader) Read(p []byte) (int, error) {
	if err := r.progress.ctx.Err(); err != nil {
		return 0, context.Cause(r.progress.ctx)
	}
	n, err := r.src.Read(p)
	if n > 0 {
		r.progress.progressed()
	}
	return n, err
}
