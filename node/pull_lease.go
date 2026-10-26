package node

import (
	"context"
	"errors"
	"sync"
	"time"

	"atoll/pkg/types"
)

const (
	feedbackPullMaxTime  = 30 * time.Minute
	feedbackPullIdleTime = time.Minute
)

var errPullIdle = errors.New("object transfer made no payload progress")

// A lease extension never extends the attempt's hard deadline.
type pullLease struct {
	mu      sync.Mutex
	until   time.Time
	hard    time.Time
	idle    time.Duration
	counter *progressCounter
	wake    chan struct{}
	cancel  context.CancelCauseFunc
}

func newPullLease(until, hard time.Time, idle time.Duration, counter *progressCounter, cancel context.CancelCauseFunc) *pullLease {
	return &pullLease{until: until, hard: hard, idle: idle, counter: counter, wake: make(chan struct{}, 1), cancel: cancel}
}

func (l *pullLease) signal() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

func (l *pullLease) extend(until, hard time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if !now.Before(l.until) || !now.Before(until) || !hard.Equal(l.hard) || until.After(l.hard) || until.Before(l.until) {
		return errLeaseExpired
	}
	l.until = until
	select {
	case l.wake <- struct{}{}:
	default:
	}
	return nil
}

func (l *pullLease) watch(ctx context.Context, stop <-chan struct{}) {
	for {
		l.mu.Lock()
		deadline := minTime(l.until, l.hard)
		l.mu.Unlock()
		last := l.counter.last.Load()
		if last != 0 {
			deadline = minTime(deadline, time.Unix(0, last).Add(l.idle))
		}
		timer := time.NewTimer(max(time.Until(deadline), 0))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-stop:
			timer.Stop()
			return
		case <-l.wake:
			timer.Stop()
		case <-timer.C:
			l.mu.Lock()
			expired := !time.Now().Before(minTime(l.until, l.hard))
			l.mu.Unlock()
			if expired {
				l.cancel(errLeaseExpired)
				return
			}
			last := l.counter.last.Load()
			if last != 0 && !time.Now().Before(time.Unix(0, last).Add(l.idle)) {
				l.cancel(errPullIdle)
				return
			}
		}
	}
}

func samePullAttempt(a, b types.ObjectIntegrity) bool {
	return a.PlanID == b.PlanID && a.PlanAttempt == b.PlanAttempt && a.PlanAttemptToken == b.PlanAttemptToken && a.ObjectID == b.ObjectID && a.InodeID == b.InodeID && a.Generation == b.Generation && a.Size == b.Size && a.ChecksumKnown && b.ChecksumKnown && a.Checksum == b.Checksum && a.Chunked == b.Chunked && a.ChunkIndex == b.ChunkIndex
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
