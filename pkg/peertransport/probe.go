package peertransport

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"atoll/pkg/peerauth"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/libp2p/go-libp2p/p2p/protocol/autonatv2"
	"github.com/libp2p/go-libp2p/p2p/protocol/identify"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/quicreuse"
	libp2ptcp "github.com/libp2p/go-libp2p/p2p/transport/tcp"
	ma "github.com/multiformats/go-multiaddr"
)

const probeConnectionBudget = 16

// Probe connections share the registered identity, never the data connection
// pool. AutoNAT closes a peer after each callback, which must not close uploads.
type probeHost struct {
	host.Host
	once sync.Once
	err  error
}

func (p *probeHost) Connect(ctx context.Context, info peer.AddrInfo) error {
	p.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.TempAddrTTL)
	_, err := p.Network().DialPeer(ctx, info.ID)
	return err
}

func (p *probeHost) NewStream(ctx context.Context, id peer.ID, protocols ...protocol.ID) (network.Stream, error) {
	stream, err := p.Network().NewStream(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(protocols) != 1 || protocols[0] != autonatv2.DialBackProtocol {
		stream.Reset()
		return nil, errors.New("peertransport: probe only supports dial-back")
	}
	if err := negotiateStream(ctx, stream, protocols[0]); err != nil {
		return nil, err
	}
	if err := stream.SetProtocol(protocols[0]); err != nil {
		stream.Reset()
		return nil, err
	}
	return stream, nil
}

func (p *probeHost) Close() error {
	p.once.Do(func() { p.err = p.Host.Close() })
	return p.err
}

type probeGate struct {
	auth         *protocolGate
	allowPrivate bool
}

func (g *probeGate) InterceptPeerDial(p peer.ID) bool {
	return g.auth.authorize(g.auth.ctx, p.String())
}
func (g *probeGate) InterceptAddrDial(p peer.ID, address ma.Multiaddr) bool {
	return g.InterceptPeerDial(p) && g.validAddress(address)
}
func (g *probeGate) validAddress(address ma.Multiaddr) bool {
	if address == nil || hasCircuitComponent(address) {
		return false
	}
	if _, err := peerauth.NormalizeAddresses([]string{address.String()}, !g.allowPrivate); err != nil {
		return false
	}
	return g.allowPrivate || publicOnlyRemote(address)
}
func (*probeGate) InterceptAccept(network.ConnMultiaddrs) bool { return false }
func (g *probeGate) InterceptSecured(dir network.Direction, p peer.ID, conn network.ConnMultiaddrs) bool {
	return dir == network.DirOutbound && g.validAddress(conn.RemoteMultiaddr()) && g.InterceptPeerDial(p)
}
func (g *probeGate) InterceptUpgraded(conn network.Conn) (bool, control.DisconnectReason) {
	return g.InterceptSecured(conn.Stat().Direction, conn.RemotePeer(), conn), 0
}

func newProbeHost(priv crypto.PrivKey, auth *protocolGate, allowPrivate bool) (*probeHost, error) {
	h, err := libp2p.New(
		libp2p.Identity(priv), libp2p.NoListenAddrs, libp2p.DisableRelay(),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Transport(libp2ptcp.NewTCPTransport), libp2p.Transport(quic.NewTransport),
		libp2p.ConnectionGater(&probeGate{auth: auth, allowPrivate: allowPrivate}),
		libp2p.ResourceManager(finiteResourceManager(probeConnectionBudget)),
		libp2p.ConnectionManager(noTrimConnMgr()),
		libp2p.DialRanker(swarm.NoDelayDialRanker),
		libp2p.SwarmOpts(swarm.WithReadOnlyBlackHoleDetector(), swarm.WithDialTimeout(10*time.Second)),
	)
	if err != nil {
		return nil, fmt.Errorf("peertransport: probe host: %w", err)
	}
	// A callback host must not Identify itself as the center with an empty
	// protocol/address set, which would overwrite the center's live peerstore.
	if basic, ok := h.(interface{ IDService() identify.IDService }); ok {
		_ = basic.IDService().Close()
	}
	h.RemoveStreamHandler(identify.ID)
	h.RemoveStreamHandler(identify.IDPush)
	return &probeHost{Host: h}, nil
}

// runtimeHost owns the graph-injected service through BasicHost.Close. The
// duplicate Host.Close calls made by AutoNAT and failed starts meet once here.
type runtimeHost struct {
	host.Host
	probe       *probeHost
	service     *autonatv2.AutoNAT
	observed    *trustedObservations
	quicManager *quicreuse.ConnManager
	once        sync.Once
	err         error
}

func (h *runtimeHost) Close() error {
	h.once.Do(func() {
		_ = h.observed.Close()
		h.err = errors.Join(h.Host.Close(), h.probe.Close())
	})
	return h.err
}

func newProbeService(priv crypto.PrivKey, auth *protocolGate, allowPrivate bool, observe func(RuntimeEvent)) (*autonatv2.AutoNAT, *probeHost, error) {
	p, err := newProbeHost(priv, auth, allowPrivate)
	if err != nil {
		return nil, nil, err
	}
	opts := []autonatv2.AutoNATOption{autonatv2.WithServerRateLimit(30, 6, 6, 1), autonatv2.WithMetricsTracer(&probeEvents{observe: observe})}
	if allowPrivate {
		opts = append(opts, autonatv2.AllowPrivateAddrs)
	}
	service, err := autonatv2.New(p, opts...)
	if err != nil {
		_ = p.Close()
		return nil, nil, err
	}
	return service, p, nil
}
