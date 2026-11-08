package peertransport

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
)

// Circuit control handshakes honor the caller's budget. The library clears the
// deadline when a tunnel is ready; the resulting payload must outlive dial ctx.
type relayHandshakeStream struct {
	network.Stream
	ctx      context.Context
	deadline time.Time
	detached atomic.Bool
	stop     func() bool
	canceled chan struct{}
	once     sync.Once
}

func boundRelayHandshake(ctx context.Context, stream network.Stream) *relayHandshakeStream {
	deadline, _ := ctx.Deadline()
	bounded := &relayHandshakeStream{Stream: stream, ctx: ctx, deadline: deadline, canceled: make(chan struct{})}
	bounded.stop = context.AfterFunc(ctx, func() {
		defer close(bounded.canceled)
		_ = stream.Reset()
	})
	return bounded
}

func (s *relayHandshakeStream) finish() {
	s.once.Do(func() {
		if !s.stop() {
			<-s.canceled
		}
	})
}

func (s *relayHandshakeStream) SetDeadline(at time.Time) error {
	if !s.detached.Load() {
		if at.IsZero() {
			s.finish()
			s.detached.Store(true)
			if err := s.ctx.Err(); err != nil {
				_ = s.Stream.Reset()
				return err
			}
		} else if !s.deadline.IsZero() && at.After(s.deadline) {
			at = s.deadline
		}
	}
	return s.Stream.SetDeadline(at)
}

func (s *relayHandshakeStream) Close() error {
	err := s.Stream.Close()
	s.finish()
	return err
}

func (s *relayHandshakeStream) Reset() error {
	err := s.Stream.Reset()
	s.finish()
	return err
}

func (s *relayHandshakeStream) ResetWithError(code network.StreamErrorCode) error {
	err := s.Stream.ResetWithError(code)
	s.finish()
	return err
}
