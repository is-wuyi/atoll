package peertransport

import (
	"bytes"
	"context"
	"sync"
	"time"

	"atoll/pkg/peerauth"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/p2p/host/eventbus"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

const infrastructurePrepareTimeout = 10 * time.Second

type observedCandidate struct {
	conn       network.Conn
	local      ma.Multiaddr
	address    ma.Multiaddr
	generation uint64
	revision   uint64
}

type observationFence struct {
	infra      peerauth.Infrastructure
	until      time.Time
	generation uint64
	revision   uint64
}

// A connected, authenticated infrastructure peer is one trusted observer, not
// four independent witnesses. These addresses remain candidates for AutoNAT and
// DCUtR; observing a mapping does not assert public reachability.
type trustedObservations struct {
	ctx        context.Context
	cancel     context.CancelFunc
	auth       *protocolGate
	publicOnly bool
	observe    func(RuntimeEvent)

	mu         sync.Mutex
	infra      peerauth.Infrastructure
	until      time.Time
	revision   uint64
	candidates map[network.Conn]observedCandidate
	identified map[network.Conn]uint64
	changed    chan struct{}
	network    network.Network
	sub        event.Subscription
	wg         sync.WaitGroup
	closeOnce  sync.Once
}

func newTrustedObservations(ctx context.Context, auth *protocolGate, publicOnly bool, observe func(RuntimeEvent)) *trustedObservations {
	ctx, cancel := context.WithCancel(ctx)
	return &trustedObservations{ctx: ctx, cancel: cancel, auth: auth, publicOnly: publicOnly, observe: observe,
		candidates: make(map[network.Conn]observedCandidate), identified: make(map[network.Conn]uint64), changed: make(chan struct{})}
}

func (o *trustedObservations) setInfrastructure(infra peerauth.Infrastructure) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !sameInfrastructure(o.infra, infra) || !time.Now().Before(o.until) {
		o.revision++
		o.candidates = make(map[network.Conn]observedCandidate)
		o.identified = make(map[network.Conn]uint64)
	}
	o.infra = peerauth.CopyDirectory(peerauth.Directory{Infrastructure: infra}).Infrastructure
	o.until = time.Now().Add(peerauth.EndpointLease)
	o.signalLocked()
}

func (o *trustedObservations) signalLocked() {
	close(o.changed)
	o.changed = make(chan struct{})
}

func (o *trustedObservations) fence() observationFence {
	o.mu.Lock()
	defer o.mu.Unlock()
	return observationFence{infra: o.infra, until: o.until, generation: o.auth.currentGen(), revision: o.revision}
}

func (o *trustedObservations) currentFenceLocked(fence observationFence) bool {
	return o.ctx.Err() == nil && fence.generation == o.auth.currentGen() && fence.revision == o.revision &&
		sameInfrastructure(fence.infra, o.infra) && time.Now().Before(fence.until) && time.Now().Before(o.until)
}

func (o *trustedObservations) currentFence(fence observationFence) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.currentFenceLocked(fence)
}

func (o *trustedObservations) start(bus event.Bus, n network.Network) error {
	sub, err := bus.Subscribe(new(event.EvtPeerIdentificationCompleted), eventbus.BufSize(32))
	if err != nil {
		return err
	}
	o.sub, o.network = sub, n
	n.Notify(o)
	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		for {
			select {
			case <-o.ctx.Done():
				return
			case value, ok := <-sub.Out():
				if !ok {
					return
				}
				if identification, ok := value.(event.EvtPeerIdentificationCompleted); ok {
					o.record(identification)
				}
			}
		}
	}()
	return nil
}

func (o *trustedObservations) record(identification event.EvtPeerIdentificationCompleted) {
	o.recordWithFence(identification, o.fence())
}

func (o *trustedObservations) recordWithFence(identification event.EvtPeerIdentificationCompleted, fence observationFence) bool {
	return o.recordWithContext(o.ctx, identification, fence)
}

func (o *trustedObservations) recordWithContext(ctx context.Context, identification event.EvtPeerIdentificationCompleted, fence observationFence) bool {
	conn := identification.Conn
	if ctx.Err() != nil || conn == nil || conn.IsClosed() || !o.currentFence(fence) || hasCircuitComponent(conn.RemoteMultiaddr()) {
		return false
	}
	infra := fence.infra
	if infra.PeerID == "" || identification.Peer.String() != infra.PeerID || conn.RemotePeer().String() != infra.PeerID {
		return false
	}
	key := conn.RemotePublicKey()
	if key == nil {
		return false
	}
	raw, err := key.Raw()
	if err != nil || !bytes.Equal(raw, infra.PublicKey) || !o.auth.allowedPeer(infra.PeerID) || !o.auth.authorize(ctx, infra.PeerID) {
		return false
	}
	if o.publicOnly && !publicOnlyRemote(conn.RemoteMultiaddr()) {
		return false
	}
	address := identification.ObservedAddr
	usable := o.usableObservation(conn, address)
	o.mu.Lock()
	if ctx.Err() != nil || !o.currentFenceLocked(fence) || conn.IsClosed() {
		o.mu.Unlock()
		return false
	}
	for previous, generation := range o.identified {
		if previous.IsClosed() || generation != fence.generation {
			delete(o.identified, previous)
			delete(o.candidates, previous)
		}
	}
	for previous, candidate := range o.candidates {
		if previous.IsClosed() || candidate.generation != fence.generation || candidate.revision != fence.revision {
			delete(o.candidates, previous)
			delete(o.identified, previous)
		}
	}
	// Connection IDs are only unique within a host; main and auxiliary hosts
	// share a PeerID but must never overwrite or remove each other's records.
	if len(o.identified) < maxAdvertisedAddresses {
		o.identified[conn] = fence.generation
	}
	if usable {
		if _, exists := o.candidates[conn]; !exists && len(o.candidates) >= maxAdvertisedAddresses {
			o.mu.Unlock()
			return false
		}
		o.candidates[conn] = observedCandidate{conn: conn, local: conn.LocalMultiaddr(), address: address, generation: fence.generation, revision: fence.revision}
	} else {
		delete(o.candidates, conn)
	}
	o.signalLocked()
	o.mu.Unlock()
	if usable && o.observe != nil {
		o.observe(RuntimeEvent{Time: time.Now().UTC(), Kind: "public_candidate_observed", LocalPeerID: conn.LocalPeer().String(), RemotePeerID: conn.RemotePeer().String(), ConnectionID: conn.ID(), LocalAddress: conn.LocalMultiaddr().String(), RemoteAddress: conn.RemoteMultiaddr().String(), Candidates: []string{address.String()}, Success: true})
	}
	return usable
}

func sameListenTransport(a, b ma.Multiaddr) bool {
	if a == nil || b == nil {
		return false
	}
	ap, bp := a.Protocols(), b.Protocols()
	if len(ap) != len(bp) || len(ap) < 2 || ap[1].Code != bp[1].Code {
		return false
	}
	if ap[0].Code != bp[0].Code {
		return false
	}
	at, ae := a.ValueForProtocol(ap[1].Code)
	bt, be := b.ValueForProtocol(bp[1].Code)
	if ae != nil || be != nil || at != bt {
		return false
	}
	return manet.IsIPUnspecified(a) || manet.IsIPUnspecified(b) || a.Equal(b)
}

func (o *trustedObservations) usableObservation(conn network.Conn, address ma.Multiaddr) bool {
	if address == nil || o.publicOnly && !publicOnlyRemote(address) {
		return false
	}
	if _, err := peerauth.NormalizeAddresses([]string{address.String()}, o.publicOnly); err != nil {
		return false
	}
	local := conn.LocalMultiaddr()
	if local == nil {
		return false
	}
	lp, ap := local.Protocols(), address.Protocols()
	if len(lp) != len(ap) || len(lp) < 2 || lp[0].Code != ap[0].Code || lp[1].Code != ap[1].Code {
		return false
	}
	if o.network == nil {
		return false
	}
	for _, listen := range o.network.ListenAddresses() {
		if sameListenTransport(listen, local) {
			return true
		}
	}
	return false
}

func (o *trustedObservations) Addrs(_ int) []ma.Multiaddr                 { return o.snapshot(nil) }
func (o *trustedObservations) AddrsFor(local ma.Multiaddr) []ma.Multiaddr { return o.snapshot(local) }
func (o *trustedObservations) snapshot(local ma.Multiaddr) []ma.Multiaddr {
	fence := o.fence()
	if !o.currentFence(fence) || !o.auth.allowedPeer(fence.infra.PeerID) || !o.auth.authorize(o.ctx, fence.infra.PeerID) {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.currentFenceLocked(fence) {
		return nil
	}
	out := make([]ma.Multiaddr, 0, len(o.candidates))
	for conn, candidate := range o.candidates {
		if candidate.conn.IsClosed() || candidate.generation != fence.generation || candidate.revision != fence.revision {
			delete(o.candidates, conn)
			delete(o.identified, conn)
			continue
		}
		if local != nil && !sameListenTransport(local, candidate.local) {
			continue
		}
		out = append(out, candidate.address)
	}
	return ma.Unique(out)
}

func (o *trustedObservations) waitIdentify(ctx context.Context, conn network.Conn) error {
	for {
		o.mu.Lock()
		generation, ok := o.identified[conn]
		changed := o.changed
		o.mu.Unlock()
		if ok && generation == o.auth.currentGen() && !conn.IsClosed() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-o.ctx.Done():
			return errRuntimeClosed
		case <-changed:
		}
	}
}

func (o *trustedObservations) Close() error {
	o.closeOnce.Do(func() {
		o.cancel()
		if o.network != nil {
			o.network.StopNotify(o)
		}
		if o.sub != nil {
			_ = o.sub.Close()
		}
		o.wg.Wait()
		o.mu.Lock()
		o.candidates = make(map[network.Conn]observedCandidate)
		o.identified = make(map[network.Conn]uint64)
		o.signalLocked()
		o.mu.Unlock()
	})
	return nil
}

func (*trustedObservations) Listen(network.Network, ma.Multiaddr)      {}
func (*trustedObservations) ListenClose(network.Network, ma.Multiaddr) {}
func (*trustedObservations) Connected(network.Network, network.Conn)   {}
func (o *trustedObservations) Disconnected(_ network.Network, conn network.Conn) {
	o.mu.Lock()
	delete(o.candidates, conn)
	delete(o.identified, conn)
	o.signalLocked()
	o.mu.Unlock()
}

var _ network.Notifiee = (*trustedObservations)(nil)
