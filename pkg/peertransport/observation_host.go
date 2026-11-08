package peertransport

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"atoll/pkg/peerauth"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	basichost "github.com/libp2p/go-libp2p/p2p/host/basic"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/libp2p/go-libp2p/p2p/protocol/identify"
	identifypb "github.com/libp2p/go-libp2p/p2p/protocol/identify/pb"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/quicreuse"
	"github.com/libp2p/go-msgio/pbio"
	ma "github.com/multiformats/go-multiaddr"
	"go.uber.org/fx"
)

const quicObservationTimeout = 2 * time.Second

type observationGate struct {
	auth       *protocolGate
	publicOnly bool
}

func (g *observationGate) allowed(remote peer.ID) bool {
	g.auth.dirMu.RLock()
	infrastructure := g.auth.infrastructure
	g.auth.dirMu.RUnlock()
	return remote.String() == infrastructure && g.auth.allowedPeer(infrastructure) && g.auth.authorize(g.auth.ctx, infrastructure)
}

func (g *observationGate) valid(address ma.Multiaddr) bool {
	if !addressHasQUIC(address) {
		return false
	}
	_, err := peerauth.NormalizeAddresses([]string{address.String()}, g.publicOnly)
	return err == nil
}

func (g *observationGate) InterceptPeerDial(remote peer.ID) bool { return g.allowed(remote) }
func (g *observationGate) InterceptAddrDial(remote peer.ID, address ma.Multiaddr) bool {
	return g.allowed(remote) && g.valid(address)
}
func (*observationGate) InterceptAccept(network.ConnMultiaddrs) bool { return false }
func (g *observationGate) InterceptSecured(direction network.Direction, remote peer.ID, conn network.ConnMultiaddrs) bool {
	return direction == network.DirOutbound && g.allowed(remote) && g.valid(conn.RemoteMultiaddr())
}
func (g *observationGate) InterceptUpgraded(conn network.Conn) (bool, control.DisconnectReason) {
	return g.InterceptSecured(conn.Stat().Direction, conn.RemotePeer(), conn), 0
}

type quicObservationHost struct {
	host.Host
	observed *trustedObservations
	once     sync.Once
	err      error
}

func (h *quicObservationHost) Close() error {
	h.once.Do(func() {
		h.Network().StopNotify(h.observed)
		for _, conn := range h.Network().Conns() {
			h.observed.Disconnected(h.Network(), conn)
		}
		h.err = h.Host.Close()
	})
	return h.err
}

func newObservationHost(priv crypto.PrivKey, shared *quicreuse.ConnManager, auth *protocolGate, observed *trustedObservations, publicOnly bool) (host.Host, error) {
	if shared == nil {
		return nil, errors.New("peertransport: missing shared QUIC listener manager")
	}
	var constructed *basichost.BasicHost
	h, err := libp2p.New(
		libp2p.Identity(priv), libp2p.NoListenAddrs, libp2p.DisableRelay(),
		libp2p.Transport(quic.NewTransport),
		libp2p.QUICReuse(func() (*quicreuse.ConnManager, error) { return shared, nil }),
		libp2p.ConnectionGater(&observationGate{auth: auth, publicOnly: publicOnly}),
		libp2p.ResourceManager(finiteResourceManager(probeConnectionBudget)),
		libp2p.ConnectionManager(noTrimConnMgr()),
		libp2p.DialRanker(swarm.NoDelayDialRanker),
		// Discovery must sample unknown public UDP paths; read-only detection
		// permanently blocks a new host before it can collect any observations.
		libp2p.SwarmOpts(swarm.WithDialTimeout(quicObservationTimeout)),
		libp2p.WithFxOption(fx.Invoke(func(h *basichost.BasicHost) { constructed = h })),
	)
	if err != nil {
		if constructed != nil {
			_ = constructed.Close()
		}
		return nil, fmt.Errorf("peertransport: QUIC observation host: %w", err)
	}
	// An empty same-identity Identify snapshot must not replace the center's
	// view of the main host's protocols and listening addresses.
	if basic, ok := h.(interface{ IDService() identify.IDService }); ok {
		_ = basic.IDService().Close()
	}
	h.RemoveStreamHandler(identify.ID)
	h.RemoveStreamHandler(identify.IDPush)
	h.Network().Notify(observed)
	return &quicObservationHost{Host: h, observed: observed}, nil
}

func (r *Runtime) observationHostFor() (host.Host, error) {
	r.lifeMu.Lock()
	defer r.lifeMu.Unlock()
	if r.closed {
		return nil, errRuntimeClosed
	}
	if r.observationHost != nil {
		return r.observationHost, nil
	}
	main, ok := r.mainHost.(*runtimeHost)
	if !ok {
		return nil, errors.New("peertransport: missing main listener owner")
	}
	h, err := newObservationHost(r.ident.priv, main.quicManager, r.auth, r.observed, r.cfg.PublicOnly)
	if err != nil {
		return nil, err
	}
	r.observationHost = h
	return h, nil
}

func readIdentifyObservation(ctx context.Context, conn network.Conn) ([]byte, error) {
	stream, err := conn.NewStream(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(canceled)
		_ = stream.Reset()
	})
	defer func() {
		if !stop() {
			<-canceled
		}
	}()
	if err := negotiateStream(ctx, stream, identify.ID); err != nil {
		return nil, err
	}
	if err := stream.SetProtocol(identify.ID); err != nil {
		_ = stream.Reset()
		return nil, err
	}
	if err := stream.Scope().SetService(identify.ServiceName); err != nil {
		_ = stream.Reset()
		return nil, err
	}
	if err := stream.Scope().ReserveMemory(8<<10, network.ReservationPriorityAlways); err != nil {
		_ = stream.Reset()
		return nil, err
	}
	defer stream.Scope().ReleaseMemory(8 << 10)
	if deadline, ok := ctx.Deadline(); ok {
		if err := stream.SetDeadline(deadline); err != nil {
			_ = stream.Reset()
			return nil, err
		}
	}
	// The first bounded delimited frame contains ObservedAddr. Signed records
	// and repeated protocol/address lists are not merged into the data host.
	var message identifypb.Identify
	if err := pbio.NewDelimitedReader(stream, 8<<10).ReadMsg(&message); err != nil {
		_ = stream.Reset()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	raw := message.GetObservedAddr()
	if len(raw) == 0 || len(raw) > peerauth.MaxAddressLength {
		return nil, errors.New("peertransport: invalid observation length")
	}
	return raw, nil
}

func readQUICObservation(ctx context.Context, conn network.Conn, publicOnly bool) (ma.Multiaddr, error) {
	raw, err := readIdentifyObservation(ctx, conn)
	if err != nil {
		return nil, err
	}
	return limitedObservedAddress(raw, publicOnly)
}

// Re-read Identify on the exact main connection after a lease or authorization
// interruption. The library's IdentifyWait is one-shot for a live connection.
func (r *Runtime) prepareInfrastructureIdentity(ctx context.Context, conn network.Conn, fence observationFence) error {
	raw, err := readIdentifyObservation(ctx, conn)
	if err != nil {
		return err
	}
	address, err := ma.NewMultiaddrBytes(raw)
	if err != nil {
		return ErrInfrastructureInvalid
	}
	if _, err := peerauth.NormalizeAddresses([]string{address.String()}, r.cfg.PublicOnly); err != nil {
		return ErrInfrastructureInvalid
	}
	r.observed.recordWithContext(ctx, event.EvtPeerIdentificationCompleted{Peer: conn.RemotePeer(), Conn: conn, ObservedAddr: address}, fence)
	if !r.observed.currentFence(fence) || conn.IsClosed() || !r.auth.authorize(ctx, fence.infra.PeerID) {
		return ErrInfrastructureInvalid
	}
	return nil
}

func (r *Runtime) observeQUICInfrastructure(ctx context.Context, infra peerauth.Infrastructure, fence observationFence) (err error) {
	started := time.Now()
	var conn network.Conn
	attempted := false
	defer func() {
		if r.cfg.Observe == nil || !attempted {
			return
		}
		event := RuntimeEvent{Time: time.Now().UTC(), Kind: "infrastructure_quic_observation", LocalPeerID: r.PeerID(), RemotePeerID: infra.PeerID, Success: err == nil, ErrorKind: runtimeErrorKind(err), Elapsed: time.Since(started)}
		if conn != nil {
			event.ConnectionID = conn.ID()
			event.LocalAddress = conn.LocalMultiaddr().String()
			event.RemoteAddress = conn.RemoteMultiaddr().String()
			event.Transport = conn.ConnState().Transport
		}
		r.cfg.Observe(event)
	}()
	if !r.observed.currentFence(fence) || !sameInfrastructure(fence.infra, infra) {
		return ErrInfrastructureInvalid
	}
	ai, err := infraAddrInfo(infra)
	if err != nil {
		return ErrInfrastructureInvalid
	}
	var addrs []ma.Multiaddr
	for _, address := range ai.Addrs {
		if addressHasQUIC(address) {
			addrs = append(addrs, address)
		}
	}
	var hasListener bool
	for _, address := range r.mainHost.Network().ListenAddresses() {
		hasListener = hasListener || addressHasQUIC(address)
	}
	if len(addrs) == 0 || !hasListener {
		return nil
	}
	attempted = true
	select {
	case r.observationMu <- struct{}{}:
		defer func() { <-r.observationMu }()
	case <-ctx.Done():
		return ctx.Err()
	}
	observer, err := r.observationHostFor()
	if err != nil {
		return err
	}
	observer.Peerstore().AddAddrs(ai.ID, addrs, time.Minute)
	conn, err = observer.Network().DialPeer(ctx, ai.ID)
	if err != nil {
		return err
	}
	if err := verifyStreamPeer(conn, ai.ID, infra.PublicKey); err != nil {
		return ErrInfrastructureInvalid
	}
	if !sameUDPListener(conn, r.mainHost.Network().ListenAddresses()) || conn.ConnState().Transport != "quic-v1" {
		return errors.New("peertransport: QUIC observation used a different UDP socket")
	}
	address, err := readQUICObservation(ctx, conn, r.cfg.PublicOnly)
	if err != nil {
		return err
	}
	if !r.observed.recordWithContext(ctx, event.EvtPeerIdentificationCompleted{Peer: ai.ID, Conn: conn, ObservedAddr: address}, fence) {
		return ErrInfrastructureInvalid
	}
	return nil
}
