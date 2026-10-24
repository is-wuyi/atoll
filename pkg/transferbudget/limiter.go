package transferbudget

import (
	"context"
	"errors"
	"io"
	"math"
	"sync"
	"time"
)

const MaxRate = uint64(1 << 40)

type Limiter struct {
	rate  uint64
	slots chan struct{}
	mu    sync.Mutex
	next  time.Time
}

func New(bytesPerSecond uint64, concurrent int) (*Limiter, error) {
	if bytesPerSecond == 0 || bytesPerSecond > MaxRate || concurrent < 1 || concurrent > 32 {
		return nil, errors.New("invalid transfer rate or concurrency budget")
	}
	return &Limiter{rate: bytesPerSecond, slots: make(chan struct{}, concurrent)}, nil
}

func (l *Limiter) Acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case l.slots <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-l.slots }) }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *Limiter) Rate() uint64 { return l.rate }

func (l *Limiter) Reader(ctx context.Context, r io.Reader, flowBPS uint64) io.Reader {
	if flowBPS == 0 || flowBPS > l.rate {
		flowBPS = l.rate
	}
	return &reader{ctx: ctx, source: r, shared: l, rate: flowBPS}
}

type reader struct {
	ctx    context.Context
	source io.Reader
	shared *Limiter
	rate   uint64
	next   time.Time
}

func duration(bytes int, rate uint64) time.Duration {
	return time.Duration(math.Ceil(float64(bytes) * float64(time.Second) / float64(rate)))
}

func wait(ctx context.Context, until time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if delay := time.Until(until); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return ctx.Err()
}

func (r *reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, r.ctx.Err()
	}
	quantum := min(uint64(16<<10), max(uint64(1), min(r.rate, r.shared.rate)/20))
	if uint64(len(p)) > quantum {
		p = p[:int(quantum)]
	}
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	r.shared.mu.Lock()
	now := time.Now()
	start := now
	if r.shared.next.After(start) {
		start = r.shared.next
	}
	if r.next.After(start) {
		start = r.next
	}
	r.shared.next = start.Add(duration(len(p), r.shared.rate))
	r.next = start.Add(duration(len(p), r.rate))
	r.shared.mu.Unlock()
	// Cancelled reservations are not refunded into concurrent streams: the bound stays conservative.
	if err := wait(r.ctx, start); err != nil {
		return 0, err
	}
	return r.source.Read(p)
}
