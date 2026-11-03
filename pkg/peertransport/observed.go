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
	candidates map[string]observedCandidate
	identified map[string]network.Conn
	changed    chan struct{}
	network    network.Network
	sub        event.Subscription
	wg         sync.WaitGroup
	closeOnce  sync.Once
}

func newTrustedObservations(ctx context.Context, auth *protocolGate, publicOnly bool, observe func(RuntimeEvent)) *trustedObservations {
	ctx, cancel := context.WithCancel(ctx)
	return &trustedObservations{ctx: ctx, cancel: cancel, auth: auth, publicOnly: publicOnly, observe: observe,
		candidates: make(map[string]observedCandidate), identified: make(map[string]network.Conn), changed: make(chan struct{})}
}

func (o *trustedObservations) setInfrastructure(infra peerauth.Infrastructure) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.infra.PeerID != infra.PeerID || !bytes.Equal(o.infra.PublicKey, infra.PublicKey) {
		o.candidates = make(map[string]observedCandidate)
		o.identified = make(map[string]network.Conn)
	}
	o.infra = peerauth.CopyDirectory(peerauth.Directory{Infrastructure: infra}).Infrastructure
	o.until = time.Now().Add(peerauth.EndpointLease)
	o.signalLocked()
}

func (o *trustedObservations) signalLocked() {
	close(o.changed)
	o.changed = make(chan struct{})
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
	conn := identification.Conn
	if conn == nil || conn.IsClosed() || o.ctx.Err() != nil || hasCircuitComponent(conn.RemoteMultiaddr()) {
		return
	}
	o.mu.Lock()
	infra, until := o.infra, o.until
	o.mu.Unlock()
	if infra.PeerID == "" || !time.Now().Before(until) || identification.Peer.String() != infra.PeerID || conn.RemotePeer().String() != infra.PeerID {
		return
	}
	key := conn.RemotePublicKey()
	if key == nil {
		return
	}
	generation := o.auth.currentGen()
	raw, err := key.Raw()
	if err != nil || !bytes.Equal(raw, infra.PublicKey) || !o.auth.authorize(o.ctx, infra.PeerID) || generation != o.auth.currentGen() {
		return
	}
	if o.publicOnly && !publicOnlyRemote(conn.RemoteMultiaddr()) {
		return
	}
	address := identification.ObservedAddr
	usable := o.usableObservation(conn, address)
	o.mu.Lock()
	if o.ctx.Err() != nil || generation != o.auth.currentGen() || o.infra.PeerID != infra.PeerID || !bytes.Equal(o.infra.PublicKey, infra.PublicKey) || !time.Now().Before(o.until) || conn.IsClosed() {
		o.mu.Unlock()
		return
	}
	if len(o.identified) >= maxAdvertisedAddresses {
		for id, previous := range o.identified {
			if previous.IsClosed() {
				delete(o.identified, id)
				delete(o.candidates, id)
			}
		}
	}
	if _, exists := o.identified[conn.ID()]; !exists && len(o.identified) >= maxAdvertisedAddresses {
		o.mu.Unlock()
		return
	}
	o.identified[conn.ID()] = conn
	if usable {
		o.candidates[conn.ID()] = observedCandidate{conn: conn, local: conn.LocalMultiaddr(), address: address, generation: generation}
	} else {
		delete(o.candidates, conn.ID())
	}
	o.signalLocked()
	o.mu.Unlock()
	if usable && o.observe != nil {
		o.observe(RuntimeEvent{Time: time.Now().UTC(), Kind: "public_candidate_observed", LocalPeerID: conn.LocalPeer().String(), RemotePeerID: conn.RemotePeer().String(), ConnectionID: conn.ID(), LocalAddress: conn.LocalMultiaddr().String(), RemoteAddress: conn.RemoteMultiaddr().String(), Candidates: []string{address.String()}, Success: true})
	}
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
	if address == nil || !publicOnlyRemote(address) {
		return false
	}
	if _, err := peerauth.NormalizeAddresses([]string{address.String()}, true); err != nil {
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
	if o.ctx.Err() != nil {
		return nil
	}
	o.mu.Lock()
	infra, until := o.infra, o.until
	o.mu.Unlock()
	generation := o.auth.currentGen()
	if !time.Now().Before(until) || !o.auth.allowedPeer(infra.PeerID) || !o.auth.authorize(o.ctx, infra.PeerID) || generation != o.auth.currentGen() {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.ctx.Err() != nil || generation != o.auth.currentGen() || o.infra.PeerID != infra.PeerID || !bytes.Equal(o.infra.PublicKey, infra.PublicKey) || !time.Now().Before(o.until) {
		return nil
	}
	out := make([]ma.Multiaddr, 0, len(o.candidates))
	for id, candidate := range o.candidates {
		if candidate.conn.IsClosed() {
			delete(o.candidates, id)
			delete(o.identified, id)
			continue
		}
		if candidate.generation != generation || local != nil && !sameListenTransport(local, candidate.local) {
			continue
		}
		out = append(out, candidate.address)
	}
	return ma.Unique(out)
}

func (o *trustedObservations) waitIdentify(ctx context.Context, conn network.Conn) error {
	for {
		o.mu.Lock()
		_, ok := o.identified[conn.ID()]
		changed := o.changed
		o.mu.Unlock()
		if ok && !conn.IsClosed() {
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
		o.candidates = make(map[string]observedCandidate)
		o.identified = make(map[string]network.Conn)
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
	delete(o.candidates, conn.ID())
	delete(o.identified, conn.ID())
	o.signalLocked()
	o.mu.Unlock()
}

var _ network.Notifiee = (*trustedObservations)(nil)
