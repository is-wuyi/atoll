package peertransport

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"atoll/pkg/peerauth"
)

const listenerQueueSize = 16

// authorizerSlots bounds the concurrent authorizer callbacks: a callback is
// expected to honor its context, but a stuck one can never hold more than
// this many slots; beyond them checks fail closed.
const authorizerSlots = 64

// Package-level so tests can shorten the authorizer bound and the negative
// cache window without sleeping to mask a slow path.
var (
	authorizerTimeout = 3 * time.Second
	negCacheTTL       = time.Second
)

// protocolGate is the precise, protocol-level authorization gate. Every
// checkpoint that needs to decide whether a peer may use peer service (the
// connection gaters, the relay ACL and the listener) goes through authorize:
// when an online authorizer is installed it is authoritative, and the
// directory allow-set is never allowed to admit a peer the authorizer
// rejects. Decisions fail closed on a cancelled runtime or caller context,
// and a swapped-out callback can never decide for a later caller (its
// generation tags the negative cache).
type protocolGate struct {
	ctx context.Context // runtime context, bounds authorizer calls from gates

	// authTimeout is snapshotted from the package variable at construction so a
	// test can shorten it without racing a live authorizer call.
	authTimeout time.Duration

	dirMu   sync.RWMutex
	allowed map[string]time.Time // peerID -> expiry

	onlineMu sync.RWMutex
	online   func(context.Context, string) bool
	gen      uint64 // authorizer generation, guarded by onlineMu

	neg     *negCache
	cbSlots chan struct{}
}

func newProtocolGate(ctx context.Context) *protocolGate {
	return &protocolGate{
		ctx:         ctx,
		authTimeout: authorizerTimeout,
		allowed:     map[string]time.Time{},
		neg:         newNegCache(negCacheMax, negCacheTTL),
		cbSlots:     make(chan struct{}, authorizerSlots),
	}
}

// setDirectory snapshots the validated directory into an immutable allow-set.
func (g *protocolGate) setDirectory(d peerauth.Directory) {
	allowed := make(map[string]time.Time, len(d.Endpoints)+1)
	for _, ep := range d.Endpoints {
		allowed[ep.PeerID] = ep.ValidUntil
	}
	// The infrastructure peer has no expiry of its own; trust it for one
	// endpoint lease window (the caller refreshes the directory periodically).
	allowed[d.Infrastructure.PeerID] = time.Now().Add(peerauth.EndpointLease)
	g.dirMu.Lock()
	g.allowed = allowed
	g.dirMu.Unlock()
}

// allowedPeer is the pure in-memory directory allow-set check. It never calls
// the authorizer and never admits anyone once the runtime context is closed.
func (g *protocolGate) allowedPeer(id string) bool {
	if g.ctx.Err() != nil {
		return false
	}
	g.dirMu.RLock()
	exp, ok := g.allowed[id]
	g.dirMu.RUnlock()
	return ok && time.Now().Before(exp)
}

// setAuthorizer swaps the authorizer: the generation bump guarantees a later
// caller never joins a query run by a previous callback, and the reset drops
// recorded denials.
func (g *protocolGate) setAuthorizer(fn func(context.Context, string) bool) {
	g.onlineMu.Lock()
	g.online = fn
	g.gen++
	g.onlineMu.Unlock()
	g.neg.reset()
}

// authorize is the single authoritative authorization decision. It is safe to
// call from any goroutine, never holds a lock across the authorizer call and
// fails closed on a cancelled runtime or caller context — before the decision
// and again on a positive result.
func (g *protocolGate) authorize(ctx context.Context, id string) bool {
	if ctx == nil {
		ctx = g.ctx
	}
	if ctx.Err() != nil || g.ctx.Err() != nil {
		return false
	}
	g.onlineMu.RLock()
	cb, gen := g.online, g.gen
	g.onlineMu.RUnlock()
	if cb == nil {
		return g.allowedPeer(id) && ctx.Err() == nil && g.ctx.Err() == nil
	}
	ok := g.neg.check(ctx, id, gen, func() bool {
		return g.invokeAuthorizer(ctx, id, cb)
	})
	if ok && (g.currentGen() != gen || ctx.Err() != nil || g.ctx.Err() != nil) {
		// The authorizer was swapped or a context died while the decision was
		// in flight: the result is stale, never admit on it.
		return false
	}
	return ok
}

func (g *protocolGate) currentGen() uint64 {
	g.onlineMu.RLock()
	defer g.onlineMu.RUnlock()
	return g.gen
}

// invokeAuthorizer runs one bounded authorizer call on its own goroutine. The
// callback is expected to honor its context; a stuck one can neither exceed
// the bounded slot set nor hold the caller past the timeout. Both fail closed.
func (g *protocolGate) invokeAuthorizer(ctx context.Context, id string, cb func(context.Context, string) bool) bool {
	select {
	case g.cbSlots <- struct{}{}:
	default:
		return false
	}
	actx, cancel := context.WithTimeout(ctx, g.authTimeout)
	defer cancel()
	type result struct{ ok bool }
	ch := make(chan result, 1)
	go func() {
		defer func() { <-g.cbSlots }()
		ch <- result{cb(actx, id)}
	}()
	select {
	case r := <-ch:
		if actx.Err() != nil {
			return false
		}
		return r.ok
	case <-actx.Done():
		return false
	}
}

// peerListener adapts ProtoID streams to net.Listener with a bounded queue and
// a cancel-on-close lifecycle. Each stream is admitted only through the
// protocol gate after its identity is verified by the secure handshake. Close
// removes the stream handler, rejects further Accepts, waits for in-flight
// handlers and resets any queued connection, so no stream is served or leaked
// after close.
type peerListener struct {
	host      host.Host
	auth      *protocolGate
	ch        chan net.Conn
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once

	// mu guards closed/active and the cond used to join in-flight handlers.
	// closed is set before cancel so a handler dispatched concurrently with
	// Close either observes it and resets without touching the queue, or is
	// counted and joined by Close.
	mu     sync.Mutex
	cond   *sync.Cond
	active int
	closed bool
}

func newPeerListener(ctx context.Context, h host.Host, auth *protocolGate) *peerListener {
	lctx, cancel := context.WithCancel(ctx)
	l := &peerListener{
		host:   h,
		auth:   auth,
		ch:     make(chan net.Conn, listenerQueueSize),
		ctx:    lctx,
		cancel: cancel,
	}
	l.cond = sync.NewCond(&l.mu)
	h.SetStreamHandler(ProtoID, l.handleStream)
	return l
}

func (l *peerListener) handleStream(s network.Stream) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		s.Reset()
		return
	}
	l.active++
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		l.active--
		l.cond.Broadcast()
		l.mu.Unlock()
	}()

	conn := s.Conn()
	remote := conn.RemotePeer()
	if l.host.Peerstore().PubKey(remote) == nil {
		s.Reset()
		return
	}
	if !l.auth.authorize(l.ctx, remote.String()) {
		s.Reset()
		return
	}
	sc := &streamConn{
		Stream: s,
		peerID: remote,
		local:  conn.LocalMultiaddr(),
		remote: conn.RemoteMultiaddr(),
	}
	select {
	case l.ch <- sc:
	case <-l.ctx.Done():
		s.Reset()
	}
}

func (l *peerListener) Accept() (net.Conn, error) {
	select {
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	default:
	}
	select {
	case c := <-l.ch:
		if l.ctx.Err() != nil {
			// Closed while a queued conn was available: reject instead of
			// serving a connection that predates the close.
			if sc, ok := c.(*streamConn); ok {
				_ = sc.Reset()
			} else {
				_ = c.Close()
			}
			return nil, net.ErrClosed
		}
		return c, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (l *peerListener) Close() error {
	l.closeOnce.Do(func() {
		l.host.RemoveStreamHandler(ProtoID)
		l.mu.Lock()
		l.closed = true
		l.mu.Unlock()
		l.cancel()
		// Join in-flight handlers: they may still be sending to ch or resetting
		// a stream. Once active reaches zero no handler can send any more.
		l.mu.Lock()
		for l.active > 0 {
			l.cond.Wait()
		}
		l.mu.Unlock()
		// Drain any connection that was queued before the close.
		for {
			select {
			case c := <-l.ch:
				if sc, ok := c.(*streamConn); ok {
					_ = sc.Reset()
				} else {
					_ = c.Close()
				}
			default:
				return
			}
		}
	})
	return nil
}

func (l *peerListener) Addr() net.Addr { return p2pAddr(l.host.ID()) }

// streamConn adapts a libp2p stream to net.Conn and remembers the verified
// remote PeerID so ConnContext can extract it without trusting any HTTP header.
type streamConn struct {
	network.Stream
	peerID peer.ID
	local  ma.Multiaddr
	remote ma.Multiaddr
}

func (c *streamConn) LocalAddr() net.Addr  { return multiaddrAddr(c.local) }
func (c *streamConn) RemoteAddr() net.Addr { return multiaddrAddr(c.remote) }

func (c *streamConn) remotePeer() string { return c.peerID.String() }

type multiaddrAddr ma.Multiaddr

func (a multiaddrAddr) Network() string { return "libp2p" }
func (a multiaddrAddr) String() string  { return ma.Multiaddr(a).String() }

type p2pAddr peer.ID

func (a p2pAddr) Network() string { return "libp2p" }
func (a p2pAddr) String() string  { return peer.ID(a).String() }

// unwrapStreamConn digs through a TLS wrapper (http.Server.ServeTLS wraps each
// accepted conn in a tls.Conn) to reach the peer stream and its verified ID.
func unwrapStreamConn(conn net.Conn) (*streamConn, bool) {
	if tc, ok := conn.(*tls.Conn); ok {
		conn = tc.NetConn()
	}
	sc, ok := conn.(*streamConn)
	return sc, ok
}
