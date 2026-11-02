package peertransport

import (
	"context"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// Reservation's library deadline is process-global and longer than a caller's
// budget. Clamp each control stream and cancel it, without closing the peer.
type reservationHost struct {
	host.Host
	stream *reservationStream
}

func (h *reservationHost) NewStream(ctx context.Context, p peer.ID, protocols ...protocol.ID) (network.Stream, error) {
	stream, err := h.Host.NewStream(ctx, p, protocols...)
	if err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	bounded := &reservationStream{Stream: stream, deadline: deadline, canceled: make(chan struct{})}
	bounded.stop = context.AfterFunc(ctx, func() {
		defer close(bounded.canceled)
		_ = stream.Reset()
	})
	h.stream = bounded
	return bounded, nil
}

func (h *reservationHost) finish() {
	if h.stream != nil {
		h.stream.finish()
	}
}

type reservationStream struct {
	network.Stream
	deadline time.Time
	stop     func() bool
	canceled chan struct{}
	once     sync.Once
}

func (s *reservationStream) SetDeadline(at time.Time) error {
	if !s.deadline.IsZero() && (at.IsZero() || at.After(s.deadline)) {
		at = s.deadline
	}
	return s.Stream.SetDeadline(at)
}
func (s *reservationStream) finish() {
	s.once.Do(func() {
		if s.stop != nil && !s.stop() {
			<-s.canceled
		}
	})
}
func (s *reservationStream) Close() error { err := s.Stream.Close(); s.finish(); return err }
