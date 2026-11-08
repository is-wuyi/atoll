// Package peerhttp carries HTTPS over verified peer streams without changing
// request URLs or ticket audiences. Master requests retain the base transport;
// peer connections use real outer TLS and do not share HTTP connection pools.
package peerhttp

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Path names the path a request actually took.
//
// PathDirect and PathRelay are peer connections. PathHTTP and PathHTTPS are
// ordinary TCP connections. A peer transport that does not expose the path it
// took must report PathUnknown; it must not guess. PathUnknown is never treated
// as a direct connection, and it fails any required path.
type Path string

const (
	// PathDirect is a direct peer-to-peer connection.
	PathDirect Path = "direct"
	// PathRelay is a connection carried by a relay hop.
	PathRelay Path = "circuit"
	// PathHTTP is an ordinary TCP connection carrying http.
	PathHTTP Path = "http"
	// PathHTTPS is an ordinary TCP connection carrying https.
	PathHTTPS Path = "https"
	// PathUnknown is reported when the peer transport does not expose the path
	// it took.
	PathUnknown Path = "unknown"
)

// PeerDial is the result of one peer dial attempt.
//
// Conn is nil when the connection could not be established; Err carries the
// reason then. Identity and Path are facts the peer transport verified at dial
// time, so they are immutable afterwards and cannot drift between the request
// that was made and the connection that was opened. Treat PeerDial as read-only.
//
// Conn must remain usable after ctx is canceled, exactly as
// net.Dialer.DialContext guarantees, so a returned connection outlives the dial.
type PeerDial struct {
	// Conn is the peer stream to wrap.
	Conn net.Conn
	// Err reports why Conn is nil.
	Err error
	// Identity is the peer identity the dialer verified, as it recorded it.
	Identity string
	// Path is the path the connection actually took.
	Path Path
	// ConnectionID, StreamID, LocalAddress and RemoteAddress are the dial facts
	// the peer transport recorded for the stream, as it recorded them. Like
	// Identity and Path they are immutable dial facts; a transport that does
	// not expose them must leave them empty rather than invent values.
	ConnectionID string
	StreamID     string
	LocalAddress string
	// RemoteAddress is the address the dial actually reached.
	RemoteAddress string
	// Fallback reports that the dial actually attempted its fallback, such as
	// the relay after a failed direct attempt, whether or not that attempt
	// succeeded. The path the dial actually took is still reported in Path.
	Fallback bool
}

// PeerDialer opens one connection to the peer a Resolver resolved. A nil
// PeerDialer means no peer path is available for that address.
type PeerDialer func(ctx context.Context) PeerDial

// Resolver resolves a registered node address to a peer dialer. The address is
// the canonical "host:port" string the deployment already uses for node
// addressing, so URL, scheme and Host stay untouched above this seam. The
// request context travels through unchanged.
type Resolver func(ctx context.Context, nodeAddr string) (PeerDialer, error)

// Phase distinguishes what one Observation reports, so a connection acceptance
// can never be mistaken for a completed transfer.
const (
	// PhaseDial marks the report of one connection attempt, accepted or failed.
	PhaseDial = "dial"
	// PhaseResponse marks the report of one response's completion: its body was
	// fully read, failed, or was closed.
	PhaseResponse = "response"
)

// ErrorKind categories for an Observation. A kind is a bounded category only:
// it never carries query, body, token or raw error material.
const (
	// ErrorNone is the empty kind: nothing failed. For PhaseDial it means the
	// connection was accepted; for PhaseResponse it means the response was
	// read to a proven EOF.
	ErrorNone = ""
	// ErrorBodyClosed reports a response closed before a complete read could
	// be proven, which is the honest outcome for an early Close.
	ErrorBodyClosed = "body_closed"
	// ErrorCanceled reports the context was canceled.
	ErrorCanceled = "canceled"
	// ErrorTimeout reports a deadline exceeded or a network timeout.
	ErrorTimeout = "timeout"
	// ErrorTLS reports a TLS-level failure.
	ErrorTLS = "tls"
	// ErrorResolve reports the peer resolver failed.
	ErrorResolve = "resolve"
	// ErrorRefused reports the dial was refused by policy, such as a required
	// path that could not be met.
	ErrorRefused = "refused"
	// ErrorConnect reports the connection attempt itself failed.
	ErrorConnect = "connect"
	// ErrorRead reports a response read failure, body or headers.
	ErrorRead = "read"
	// ErrorUnknown reports a failure that fits no other category.
	ErrorUnknown = "unknown"
)

// Observation reports what one request actually did on the wire. It is never
// evidence that a request worked: a dial report is emitted before the request
// is even sent, and a completion report marks only that a response body ended.
// Use it for routing and load accounting, not for goodput.
//
// A request can produce several observations: one per connection attempt
// (PhaseDial, accepted or failed) and one when its response completes
// (PhaseResponse). Master requests report once, when handed to the base
// transport, and carry no Phase.
type Observation struct {
	// Scheme is "http" or "https".
	Scheme string
	// Target is the canonical "host:port" the request was addressed to.
	Target string
	// Path is the path the request actually took, or PathUnknown when it is
	// not known. A failed attempt never claims a path it did not take.
	Path Path
	// Master reports that the request matched the pinned master origin and was
	// handed to the base transport as configured, proxy and all. A non-master
	// request never touches a proxy.
	Master bool
	// RequestID is the request's ID: the one the caller set with WithRequestID,
	// or an automatically allocated one when a reporter is installed and the
	// caller set none. It is empty when nothing opted in.
	RequestID string
	// Method is the request's HTTP method.
	Method string
	// RequestPath is the request's URL path alone. It never carries a query,
	// userinfo or any other request material.
	RequestPath string
	// Identity is the peer identity verified for the serving connection. It is
	// empty on a failed dial, where nothing was verified.
	Identity string
	// ConnectionID and StreamID are the connection facts the peer transport
	// reported for the serving connection, empty when it does not expose them.
	ConnectionID string
	StreamID     string
	// LocalAddress and RemoteAddress are the socket addresses of the serving
	// connection, as the dial reported them.
	LocalAddress  string
	RemoteAddress string
	// Fallback reports that the serving connection was reached through a
	// fallback attempt, as the dial reported it.
	Fallback bool
	// FallbackUpgraded is derived from the dial's reported facts: it holds when
	// a fallback dial ended up on PathDirect, for example by hole punching.
	FallbackUpgraded bool
	// Phase tells which event this observation reports: PhaseDial or
	// PhaseResponse. Master observations carry no Phase.
	Phase string
	// Status is the HTTP status code of a completed response, 0 otherwise.
	Status int
	// ErrorKind is the bounded category of the failure, ErrorNone when none.
	ErrorKind string
}

// Reporter callbacks may run in dial goroutines after a request has returned or
// been cancelled. Observe is immutable once installed and must synchronize its
// own state; accepting a connection is not a successful-transfer receipt.
type Reporter struct {
	Observe func(Observation)
}

type ctxKey int

const (
	pathKey ctxKey = iota
	reporterKey
	requestIDKey
	metaKey
	responseReporterKey
	dialBoundsKey
)

type dialBounds struct {
	deadline    time.Time
	hasDeadline bool
	parent      context.Context
}

func withDialBounds(ctx context.Context) context.Context {
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline && ctx.Done() == nil {
		return ctx
	}
	return context.WithValue(ctx, dialBoundsKey, &dialBounds{deadline: deadline, hasDeadline: hasDeadline, parent: ctx})
}

func dialBoundsContext(ctx context.Context) (context.Context, context.CancelFunc) {
	bounds, _ := ctx.Value(dialBoundsKey).(*dialBounds)
	if bounds == nil {
		return ctx, func() {}
	}
	var dial context.Context
	var cancel context.CancelFunc
	if bounds.hasDeadline {
		dial, cancel = context.WithDeadline(ctx, bounds.deadline)
	} else {
		dial, cancel = context.WithCancel(ctx)
	}
	stop := context.AfterFunc(bounds.parent, cancel)
	if bounds.parent.Err() != nil {
		cancel()
	}
	return dial, func() {
		stop()
		cancel()
	}
}

// WithPath records the path a request requires. PathDirect and PathRelay pin a
// peer path and fail closed when it cannot be met. PathHTTPS pins an ordinary
// TCP connection and skips the peer dialer. PathHTTP is refused for https
// peers. An empty path means no requirement.
func WithPath(ctx context.Context, p Path) context.Context {
	return context.WithValue(ctx, pathKey, p)
}

// ControlContext derives the context for control-plane requests: it drops the
// data path requirement, the data reporter, the data request ID and the private
// request meta, so control traffic can neither ride a pinned peer path nor be
// attributed to a data request. Cancellation from the parent is kept.
func ControlContext(ctx context.Context) context.Context {
	ctx = WithPath(ctx, "")
	ctx = WithRequestID(ctx, "")
	// A control request can be derived from a data dial context, which carries
	// the private meta of the data request; drop it explicitly.
	ctx = context.WithValue(ctx, metaKey, (*requestMeta)(nil))
	ctx = context.WithValue(ctx, dialBoundsKey, (*dialBounds)(nil))
	ctx = context.WithValue(ctx, responseReporterKey, (*Reporter)(nil))
	return WithReporter(ctx, &Reporter{})
}

// RequiredPath reports the path a request requires, if any.
func RequiredPath(ctx context.Context) (Path, bool) {
	p, ok := ctx.Value(pathKey).(Path)
	return p, ok && p != ""
}

// WithRequestID records the caller's request ID for the request tree, so
// observations can name the request they belong to. RequestID returns it back.
// The ID travels in an unexported context key and never leaves in a header.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestID returns the request ID recorded by WithRequestID, or "" when none.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// requestMeta is the per-RoundTrip record of what one observed non-master
// request is and which connection served it. RoundTrip stores it in the request
// context under an unexported key so the dial report and the response completion
// describe the same request without trusting headers or re-parsing the URL at
// dial time.
//
// The serving connection is identified by net/http's own GotConn hook, which
// recovers the dial facts from the connection itself; nothing ever guesses it
// from dial ordering.
type requestMeta struct {
	// scheme, target, requestID, method and requestPath are fixed before the
	// meta becomes reachable from a context, so they are read without a lock
	// afterwards.
	scheme      string
	target      string
	requestID   string
	method      string
	requestPath string

	mu      sync.Mutex
	serving PeerDial // the dial whose connection GotConn committed to this request
	gotConn bool
}

// dialFactsConn carries the dial facts on the connection itself, so GotConn can
// identify which dial a request landed on instead of trusting dial ordering. It
// is a pure pass-through: net/http still owns and drives the connection.
type dialFactsConn struct {
	net.Conn
	dial PeerDial
}

// connDial recovers the dial facts carried by a connection wrapper. TLS sits
// between net/http's GotConn and the dialed stream, so the wrapper is reached by
// unwrapping NetConn; the depth bound stops a pathological unwrap cycle.
func connDial(c net.Conn) (PeerDial, bool) {
	for i := 0; c != nil && i < 8; i++ {
		if fc, ok := c.(*dialFactsConn); ok {
			return fc.dial, true
		}
		u, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			return PeerDial{}, false
		}
		c = u.NetConn()
	}
	return PeerDial{}, false
}

// markGotConn is the httptrace hook fired when net/http commits this request to
// a connection, before the request is written and long before a response
// returns, so it happens-before any response completion report.
func (m *requestMeta) markGotConn(info httptrace.GotConnInfo) {
	pd, ok := connDial(info.Conn)
	if !ok {
		return // a connection that cannot be identified stays unknown
	}
	m.mu.Lock()
	m.serving = pd
	m.gotConn = true
	m.mu.Unlock()
}

// servingConn returns the dial facts of the connection net/http committed this
// request to, or the zero PeerDial when GotConn never identified one: reports
// say unknown rather than guessing the last dial.
func (m *requestMeta) servingConn() PeerDial {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.gotConn {
		return PeerDial{}
	}
	return m.serving
}

// responseObservation builds a response-phase observation for this request. The
// connection facts are the ones GotConn identified, and they stay empty, with
// the path unknown, when it did not.
func (m *requestMeta) responseObservation(status int, kind string) Observation {
	pd := m.servingConn()
	return Observation{
		Scheme:           m.scheme,
		Target:           m.target,
		Path:             pathOrUnknown(pd.Path),
		RequestID:        m.requestID,
		Method:           m.method,
		RequestPath:      m.requestPath,
		Identity:         pd.Identity,
		ConnectionID:     pd.ConnectionID,
		StreamID:         pd.StreamID,
		LocalAddress:     pd.LocalAddress,
		RemoteAddress:    pd.RemoteAddress,
		Fallback:         pd.Fallback,
		FallbackUpgraded: pd.Fallback && pd.Path == PathDirect,
		Phase:            PhaseResponse,
		Status:           status,
		ErrorKind:        kind,
	}
}

// metaFrom returns the request meta installed by RoundTrip, or nil for a
// context that carries none.
func metaFrom(ctx context.Context) *requestMeta {
	m, _ := ctx.Value(metaKey).(*requestMeta)
	return m
}

var requestIDCounter atomic.Uint64

// newRequestID returns a random 128-bit request ID. A crypto/rand failure is
// practically impossible, but a counting fallback is safer than emitting a
// colliding or empty ID.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("req-%d", requestIDCounter.Add(1))
	}
	return hex.EncodeToString(b[:])
}

// WithReporter attaches a path reporter to a request tree; it overrides the
// Transport's own reporter for that request only.
func WithReporter(ctx context.Context, r *Reporter) context.Context {
	return context.WithValue(ctx, reporterKey, r)
}

// WithResponseReporter adds a serving-response observer without replacing the
// caller's diagnostic reporter. It receives no dial attempts or control traffic.
func WithResponseReporter(ctx context.Context, observe func(Observation)) context.Context {
	previous, _ := ctx.Value(responseReporterKey).(*Reporter)
	return context.WithValue(ctx, responseReporterKey, &Reporter{Observe: func(observation Observation) {
		if previous != nil && previous.Observe != nil {
			previous.Observe(observation)
		}
		if observe != nil {
			observe(observation)
		}
	}})
}

func responseReporterFrom(ctx context.Context) *Reporter {
	r, _ := ctx.Value(responseReporterKey).(*Reporter)
	return r
}

func (t *Transport) requestReporter(ctx context.Context) *Reporter {
	primary := t.observer(ctx)
	response, _ := ctx.Value(responseReporterKey).(*Reporter)
	if response == nil || response.Observe == nil {
		return primary
	}
	return &Reporter{Observe: func(observation Observation) {
		t.reportTo(reporterFrom(ctx), observation)
		if observation.Phase == PhaseResponse && !observation.Master {
			response.Observe(observation)
		}
	}}
}

func reporterFrom(ctx context.Context) *Reporter {
	r, _ := ctx.Value(reporterKey).(*Reporter)
	return r
}

// Transport implements http.RoundTripper. It preserves the request URL, scheme
// and Host unchanged, so every existing origin, scheme and Host check above it
// applies to the same request. Transport is safe for concurrent use.
type Transport struct {
	base     *http.Transport // master origin: the caller's transport, untouched
	peer     *http.Transport // peers: peer dial, no proxy, no pooling
	scheme   string          // pinned master scheme, "" pins nothing
	master   string          // pinned master canonical "host:port", "" pins nothing
	resolver Resolver
	reporter atomic.Pointer[Reporter]
}

// Option configures a Transport. Options are order-independent.
type Option func(*config) error

type config struct {
	master        string
	resolver      Resolver
	allowInsecure bool
}

// WithMaster pins the exact origin treated as the master, "scheme://host[:port]"
// with no path, query, fragment or userinfo. "" pins nothing, so every request
// is treated as a peer request.
func WithMaster(origin string) Option {
	return func(c *config) error { c.master = origin; return nil }
}

// WithResolver installs the peer resolver. Without one, an https peer request
// is dialed over plain TCP, and only when nothing in the context pinned a peer
// path.
func WithResolver(r Resolver) Option {
	return func(c *config) error { c.resolver = r; return nil }
}

// AllowInsecureTLS permits a TLSClientConfig with InsecureSkipVerify set. Refused
// by default: skipping verification removes the only thing that binds an https
// request to the advertised address, and the setting is shared with the peer
// path.
func AllowInsecureTLS() Option {
	return func(c *config) error { c.allowInsecure = true; return nil }
}

// NewTransport builds a Transport over base, which must be the transport that
// already carries the deployment's dial and TLS settings. base is used as-is for
// pinned master requests; a second transport derived from it carries the peer
// dial.
//
// NewTransport returns an error rather than panicking so misconfiguration shows
// up at wiring time.
func NewTransport(base *http.Transport, options ...Option) (*Transport, error) {
	if base == nil {
		return nil, errors.New("peerhttp: base *http.Transport is required")
	}
	if base.DialTLS != nil || base.DialTLSContext != nil {
		return nil, errors.New("peerhttp: base must not set DialTLS or DialTLSContext, which would bypass the peer dial and the outer TLS handshake")
	}
	var c config
	for _, o := range options {
		if o == nil {
			continue
		}
		if err := o(&c); err != nil {
			return nil, err
		}
	}
	if err := validateTLS(base.TLSClientConfig, c.allowInsecure); err != nil {
		return nil, err
	}
	scheme, master, err := validateMaster(c.master)
	if err != nil {
		return nil, err
	}
	t := &Transport{base: base, scheme: scheme, master: master, resolver: c.resolver}
	p := base.Clone()
	p.Proxy = nil // a peer request must never be handed to a proxy
	// No pooling: pooled connections cannot report the path they took.
	p.DisableKeepAlives = true
	p.DialContext = t.peerDial
	p.DialTLSContext = t.dialPeerTLS
	t.peer = p
	return t, nil
}

// CloseIdleConnections closes idle connections on both the master and the peer
// transport.
func (t *Transport) CloseIdleConnections() {
	t.base.CloseIdleConnections()
	t.peer.CloseIdleConnections()
}

// Close closes idle connections. It satisfies http.RoundTripper.
func (t *Transport) Close() { t.CloseIdleConnections() }

// SetReporter swaps the sink for per-request path reports. The pointer swap is
// atomic and safe to call while RoundTrips are in flight; it swaps the pointer
// only, never the Observe field, so do not mutate an installed *Reporter. A nil
// pointer clears the sink.
func (t *Transport) SetReporter(r *Reporter) { t.reporter.Store(r) }

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("peerhttp: nil request")
	}
	if req.URL == nil {
		return nil, errors.New("peerhttp: request has no URL")
	}
	if req.URL.Host == "" {
		return nil, errors.New("peerhttp: request needs an absolute URL with a host")
	}
	scheme := strings.ToLower(req.URL.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("peerhttp: unsupported request scheme %q", req.URL.Scheme)
	}
	if err := ambiguousURL(req.URL); err != nil {
		return nil, err
	}
	target, err := canonicalHost(scheme, req.URL.Host)
	if err != nil {
		return nil, err
	}

	// Exact origin match decides the master path. Scheme is part of the match,
	// so http://master can never take the master's dial settings.
	if t.master != "" && scheme == t.scheme && strings.EqualFold(target, t.master) {
		if want, required := RequiredPath(req.Context()); required && (want == PathDirect || want == PathRelay) {
			return nil, fmt.Errorf("peerhttp: %s is the pinned master origin and cannot take the %s peer path", target, want)
		}
		t.report(req.Context(), Observation{
			Scheme:      scheme,
			Target:      target,
			Path:        pathFor(scheme),
			Master:      true,
			RequestID:   RequestID(req.Context()),
			Method:      req.Method,
			RequestPath: req.URL.Path,
		})
		return t.base.RoundTrip(req)
	}

	if scheme != "https" {
		return nil, fmt.Errorf("peerhttp: http is not permitted for peer %s; use https", target)
	}
	if req.URL.User != nil {
		return nil, fmt.Errorf("peerhttp: peer URL %s must not carry userinfo", target)
	}

	// net/http strips dial cancellation and deadlines but keeps values. Restore
	// the request bounds only while establishing a peer connection and TLS.
	req = req.WithContext(withDialBounds(req.Context()))
	// Without an observer no diagnostic meta, trace or body wrapper is added.
	reporter := t.requestReporter(req.Context())
	if reporter == nil {
		return t.peer.RoundTrip(req)
	}
	if responseReporterFrom(req.Context()) != nil {
		req = req.WithContext(WithReporter(req.Context(), reporter))
	}

	meta := &requestMeta{
		scheme:      scheme,
		target:      target,
		requestID:   RequestID(req.Context()),
		method:      req.Method,
		requestPath: req.URL.Path,
	}
	// Auto IDs are opt-in: reaching here means something observes the request.
	if meta.requestID == "" {
		meta.requestID = newRequestID()
	}
	ctx := req.Context()
	ctx = context.WithValue(ctx, metaKey, meta)
	// The request ID goes back into the context, auto-allocated or not, so the
	// resolver and the runtime behind it read the same ID the reports carry.
	ctx = WithRequestID(ctx, meta.requestID)
	// GotConn is net/http's own word for "this request now owns a connection".
	// It identifies the connection that will carry the request by unwrapping
	// the dial facts from it, so a retried dial cannot be reported for a
	// response that already went out on another one. WithClientTrace composes
	// with any trace the caller set.
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: meta.markGotConn})
	res, err := t.peer.RoundTrip(req.WithContext(ctx))
	if err != nil {
		// A failed dial already reported itself as PhaseDial; a failure after
		// an accepted dial — a TLS handshake failure or a response header
		// timeout — would otherwise stay silent, so report the response
		// outcome once. RoundTrip fails at most once per attempt.
		var df *dialFailure
		if !errors.As(err, &df) {
			t.reportTo(reporterFrom(req.Context()), meta.responseObservation(0, readKind(err)))
		}
		return nil, err
	}
	if res.Body == nil {
		return res, nil
	}
	res.Body = t.observeBody(res, meta, req)
	return res, nil
}

// peerDial is the DialContext installed on the peer transport. Every attempt
// is reported; accepting a connection is not transfer evidence.
func (t *Transport) peerDial(ctx context.Context, network, addr string) (net.Conn, error) {
	ctx, cancel := dialBoundsContext(ctx)
	defer cancel()
	return t.openPeer(ctx, network, addr)
}

func (t *Transport) dialPeerTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	ctx, cancel := dialBoundsContext(ctx)
	defer cancel()
	conn, err := t.openPeer(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{}
	if t.peer.TLSClientConfig != nil {
		config = t.peer.TLSClientConfig.Clone()
	}
	if config.ServerName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		config.ServerName = host
	}
	config.NextProtos = nil
	secured := tls.Client(conn, config)
	handshake := ctx
	if timeout := t.peer.TLSHandshakeTimeout; timeout > 0 {
		var stop context.CancelFunc
		handshake, stop = context.WithTimeout(ctx, timeout)
		defer stop()
	}
	if err := secured.HandshakeContext(handshake); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return secured, nil
}

func (t *Transport) openPeer(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, pd, err := t.dialConn(ctx, network, addr)
	if err != nil {
		kind := ErrorUnknown
		var df *dialFailure
		if errors.As(err, &df) {
			kind = df.kind
		}
		t.reportDialFailure(ctx, addr, pd, kind)
		return nil, err
	}
	if meta := metaFrom(ctx); meta != nil {
		// The facts ride on the connection itself so GotConn can identify the
		// serving dial by unwrapping, instead of trusting dial ordering.
		conn = &dialFactsConn{Conn: conn, dial: pd}
	}
	t.reportDialAccept(ctx, addr, pd)
	return conn, nil
}

// dialConn performs one connection attempt and returns the connection, the
// facts reported for it, and the failure reason. On failure the returned
// PeerDial carries whatever path the attempt claimed, so the report never has
// to guess one.
func (t *Transport) dialConn(ctx context.Context, network, addr string) (net.Conn, PeerDial, error) {
	// Belt and braces: the master must never be dialed as a peer.
	masterAddr, masterErr := canonicalHost("https", addr)
	if t.master != "" && masterErr == nil && strings.EqualFold(masterAddr, t.master) {
		return nil, PeerDial{Path: PathUnknown}, &dialFailure{err: errMasterViaPeer, kind: ErrorRefused}
	}
	if network != "tcp" {
		return nil, PeerDial{Path: PathUnknown}, &dialFailure{
			err:  fmt.Errorf("peerhttp: unsupported network %q", network),
			kind: ErrorRefused,
		}
	}
	want, required := RequiredPath(ctx)
	switch want {
	case PathHTTPS: // the caller pinned an ordinary TCP path
		return t.ordinary(ctx, addr, false)
	case PathHTTP:
		return nil, PeerDial{Path: PathUnknown}, &dialFailure{
			err:  fmt.Errorf("peerhttp: %s is https; %s is not available for it", addr, PathHTTP),
			kind: ErrorRefused,
		}
	}
	if t.resolver == nil {
		if required {
			return nil, PeerDial{Path: PathUnknown}, &dialFailure{
				err:  fmt.Errorf("peerhttp: %s requires the %s peer path, but no resolver is configured", addr, want),
				kind: ErrorRefused,
			}
		}
		return t.ordinary(ctx, addr, true)
	}
	dial, err := t.resolver(ctx, addr)
	if err != nil {
		return nil, PeerDial{Path: PathUnknown}, &dialFailure{
			err:  fmt.Errorf("peerhttp: resolve %s: %w", addr, err),
			kind: resolveKind(err),
		}
	}
	if dial == nil {
		if required {
			return nil, PeerDial{Path: PathUnknown}, &dialFailure{
				err:  fmt.Errorf("peerhttp: %s requires the %s peer path, but has no peer dialer", addr, want),
				kind: ErrorRefused,
			}
		}
		return t.ordinary(ctx, addr, true)
	}
	pd := dial(ctx)
	if pd.Conn == nil {
		if pd.Err != nil {
			return nil, pd, &dialFailure{err: fmt.Errorf("peerhttp: dial %s: %w", addr, pd.Err), kind: connectKind(pd.Err)}
		}
		return nil, pd, &dialFailure{err: fmt.Errorf("peerhttp: dial %s: no connection returned", addr), kind: ErrorConnect}
	}
	if err := checkDial(addr, pd); err != nil {
		_ = pd.Conn.Close()
		return nil, pd, &dialFailure{err: err, kind: ErrorRefused}
	}
	if required && pd.Path != want {
		_ = pd.Conn.Close()
		return nil, pd, &dialFailure{
			err:  fmt.Errorf("peerhttp: dial %s: took the %s path, %s was required", addr, pd.Path, want),
			kind: ErrorRefused,
		}
	}
	return pd.Conn, pd, nil
}

// ordinary hands an https peer request to a direct plain TCP dial, never
// through the base transport's proxy, so a PathHTTPS observation here really
// means a direct connection. It is reached only when nothing pinned a peer path
// in the context, or when the caller pinned PathHTTPS itself.
func (t *Transport) ordinary(ctx context.Context, addr string, fallback bool) (net.Conn, PeerDial, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		// No connection came to be, so no path was taken: the report stays
		// unknown even though the attempt was headed for the ordinary path.
		return nil, PeerDial{Path: PathUnknown, Fallback: fallback}, &dialFailure{err: err, kind: connectKind(err)}
	}
	// The local and remote addresses are this dial's own socket facts, so
	// filling them here is measurement, not invention.
	pd := PeerDial{
		Path:          PathHTTPS,
		Fallback:      fallback,
		LocalAddress:  conn.LocalAddr().String(),
		RemoteAddress: conn.RemoteAddr().String(),
	}
	return conn, pd, nil
}

// reportDialAccept reports one connection that was accepted. A dial report is
// not transfer evidence: the request has not even been sent yet.
func (t *Transport) reportDialAccept(ctx context.Context, addr string, pd PeerDial) {
	o := Observation{
		Scheme:           "https",
		Target:           addr,
		Path:             pathOrUnknown(pd.Path),
		Phase:            PhaseDial,
		Identity:         pd.Identity,
		ConnectionID:     pd.ConnectionID,
		StreamID:         pd.StreamID,
		LocalAddress:     pd.LocalAddress,
		RemoteAddress:    pd.RemoteAddress,
		Fallback:         pd.Fallback,
		FallbackUpgraded: pd.Fallback && pd.Path == PathDirect,
	}
	reportMeta(ctx, &o)
	t.report(ctx, o)
}

// reportDialFailure reports one connection attempt that failed. Identity is
// deliberately left out: nothing was verified about a failed attempt, and the
// raw error text stays out too, ErrorKind is the whole story.
func (t *Transport) reportDialFailure(ctx context.Context, addr string, pd PeerDial, kind string) {
	o := Observation{
		Scheme:    "https",
		Target:    addr,
		Path:      pathOrUnknown(pd.Path),
		Phase:     PhaseDial,
		Fallback:  pd.Fallback,
		ErrorKind: kind,
	}
	reportMeta(ctx, &o)
	t.report(ctx, o)
}

// reportMeta fills the request facts a meta in the context carries.
func reportMeta(ctx context.Context, o *Observation) {
	meta := metaFrom(ctx)
	if meta == nil {
		return
	}
	o.RequestID, o.Method, o.RequestPath = meta.request()
}

// checkDial verifies the immutable facts a peer dialer reported: a verified
// peer identity and a recognized peer path. It fails closed on ambiguity.
func checkDial(addr string, pd PeerDial) error {
	if pd.Identity == "" {
		return fmt.Errorf("%s: the peer dial reported no verified identity", addr)
	}
	switch pd.Path {
	case PathDirect, PathRelay, PathUnknown:
	case PathHTTP, PathHTTPS:
		return fmt.Errorf("%s: the peer dial reported the %s path, which is not a peer path", addr, pd.Path)
	default:
		return fmt.Errorf("%s: unrecognized peer path %q", addr, pd.Path)
	}
	if pd.Err != nil {
		return fmt.Errorf("%s: the peer dial returned both a connection and an error", addr)
	}
	return nil
}

// report sends an observation to the request's reporter, then to the Transport's.
func (t *Transport) report(ctx context.Context, o Observation) {
	t.reportTo(reporterFrom(ctx), o)
}

// reportTo sends an observation to r first; a request-level reporter, even one
// without an Observe, shields the Transport's reporter for that request.
func (t *Transport) reportTo(r *Reporter, o Observation) {
	if r != nil {
		if r.Observe != nil {
			r.Observe(o)
		}
		return
	}
	if tr := t.reporter.Load(); tr != nil && tr.Observe != nil {
		tr.Observe(o)
	}
}

// observer reports the reporter a request's observations would go to, or nil
// when nothing observes it. A request-level reporter with a nil Observe shields
// the Transport's, matching reportTo.
func (t *Transport) observer(ctx context.Context) *Reporter {
	if r := reporterFrom(ctx); r != nil {
		if r.Observe != nil {
			return r
		}
		return nil
	}
	if r := t.reporter.Load(); r != nil && r.Observe != nil {
		return r
	}
	return nil
}

// pathOrUnknown keeps an honestly unknown path unknown instead of guessing.
func pathOrUnknown(p Path) Path {
	if p == "" {
		return PathUnknown
	}
	return p
}

// request returns the fixed request facts of the meta.
func (m *requestMeta) request() (id, method, path string) {
	return m.requestID, m.method, m.requestPath
}

// dialFailure pairs a connection failure with its bounded ErrorKind, so reports
// never re-derive a category from error text and callers keep a normal error.
type dialFailure struct {
	err  error
	kind string
}

func (e *dialFailure) Error() string { return e.err.Error() }
func (e *dialFailure) Unwrap() error { return e.err }

// classifyError maps an error to a bounded ErrorKind category. It reads only
// error identities, never text, so no query, body, token or raw error material
// can leak into an Observation.
func classifyError(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return ErrorCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return ErrorTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ErrorTimeout
	}
	var te tls.RecordHeaderError
	if errors.As(err, &te) {
		return ErrorTLS
	}
	var ae tls.AlertError
	if errors.As(err, &ae) {
		return ErrorTLS
	}
	// Handshake failures reach a report after the dial was accepted, so the
	// certificate-level identities are what marks them as TLS failures.
	var cve *tls.CertificateVerificationError
	if errors.As(err, &cve) {
		return ErrorTLS
	}
	var uae x509.UnknownAuthorityError
	if errors.As(err, &uae) {
		return ErrorTLS
	}
	var cie x509.CertificateInvalidError
	if errors.As(err, &cie) {
		return ErrorTLS
	}
	var hne x509.HostnameError
	if errors.As(err, &hne) {
		return ErrorTLS
	}
	return ErrorUnknown
}

// connectKind classifies a connection failure, narrowing the unknown tail to a
// connect failure.
func connectKind(err error) string {
	if k := classifyError(err); k != ErrorUnknown {
		return k
	}
	return ErrorConnect
}

func resolveKind(err error) string {
	if kind := classifyError(err); kind == ErrorCanceled || kind == ErrorTimeout {
		return kind
	}
	return ErrorResolve
}

// readKind classifies a response body failure the same way for reads.
func readKind(err error) string {
	if k := classifyError(err); k != ErrorUnknown {
		return k
	}
	return ErrorRead
}

// observeBody wraps the response body so the response's completion is reported
// at most once, on the first EOF, read error or Close. A dial report is not
// transfer evidence, and neither is this report as a whole: only a proven EOF
// says the response ended cleanly on the wire, and it says nothing about any
// payload being validated.
// req is the request the response answers, so no report depends on res.Request,
// which a direct RoundTrip caller may never see set.
func (t *Transport) observeBody(res *http.Response, meta *requestMeta, req *http.Request) io.ReadCloser {
	// net/http hands out ReadWriteCloser bodies for protocol switches, where
	// the caller owns the tunnel after the headers.
	_, switchable := res.Body.(io.ReadWriteCloser)
	b := &observedBody{
		rc:       res.Body,
		t:        t,
		reporter: reporterFrom(req.Context()),
		meta:     meta,
		status:   res.StatusCode,
		// A response that cannot carry body bytes is complete the moment its
		// headers are read. A switched protocol keeps carrying bytes even at
		// ContentLength 0, so it is never proven complete by its headers.
		proven: !switchable && res.StatusCode != http.StatusSwitchingProtocols &&
			(res.ContentLength == 0 || req.Method == http.MethodHead),
	}
	if switchable {
		// Dropping Write would break the tunnel the caller was handed.
		return &observedBodyRWC{observedBody: b}
	}
	return b
}

// observedBody reports the completion of one response at most once. It keeps
// the response's own http semantics: Read and Close delegate to the original
// body, and Close always reaches it.
type observedBody struct {
	rc       io.ReadCloser
	t        *Transport
	reporter *Reporter // the request-level reporter, nil when none was installed
	meta     *requestMeta
	status   int
	proven   bool
	done     atomic.Bool
}

func (b *observedBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	switch {
	case errors.Is(err, io.EOF):
		// EOF from the body is the only proof that the response was complete.
		b.report(ErrorNone)
	case err != nil:
		b.report(readKind(err))
	}
	return n, err
}

func (b *observedBody) Close() error {
	err := b.rc.Close()
	switch {
	case err != nil:
		// A failed Close never proves a clean ending, proven-empty or not.
		b.report(readKind(err))
	case b.proven:
		b.report(ErrorNone)
	default:
		// A Close without a proven EOF cannot claim the response completed.
		b.report(ErrorBodyClosed)
	}
	return err
}

// report emits the completion observation once; the first outcome wins.
func (b *observedBody) report(kind string) {
	if !b.done.CompareAndSwap(false, true) {
		return
	}
	b.t.reportTo(b.reporter, b.meta.responseObservation(b.status, kind))
}

// observedBodyRWC preserves io.ReadWriteCloser for bodies that implement it.
type observedBodyRWC struct {
	*observedBody
}

func (b *observedBodyRWC) Write(p []byte) (int, error) {
	// Guaranteed by construction in observeBody.
	return b.rc.(io.ReadWriteCloser).Write(p)
}

// ambiguousURL rejects a URL that is not in one canonical form. A URL with two
// spellings of the same audience must never decide which dial path it takes.
func ambiguousURL(u *url.URL) error {
	if u.Opaque != "" {
		return errors.New("peerhttp: ambiguous URL: it has both an opaque part and a host")
	}
	if u.ForceQuery {
		return errors.New("peerhttp: ambiguous URL: it forces a query onto an otherwise query-less URL")
	}
	if u.RawPath != "" {
		return errors.New("peerhttp: ambiguous URL: RawPath is not accepted")
	}
	if u.Fragment != "" || u.RawFragment != "" || u.User != nil {
		return errors.New("peerhttp: ambiguous URL: fragment or userinfo is not accepted")
	}
	return nil
}

var errMasterViaPeer = errors.New("peerhttp: refusing to dial the master through a peer transport")

// ---- validation ----

// validateMaster enforces that origin is an exact origin, scheme://host[:port],
// and returns its scheme and canonical host:port. "" pins nothing.
func validateMaster(origin string) (string, string, error) {
	if origin == "" {
		return "", "", nil
	}
	u, err := url.Parse(origin)
	if err != nil {
		return "", "", fmt.Errorf("peerhttp: master %q: %w", origin, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", fmt.Errorf("peerhttp: master %q must be http://host or https://host", origin)
	}
	if err := ambiguousURL(u); err != nil {
		return "", "", fmt.Errorf("peerhttp: master %q: %w", origin, err)
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("peerhttp: master %q must be scheme://host", origin)
	}
	if u.User != nil {
		return "", "", fmt.Errorf("peerhttp: master %q must not carry userinfo", origin)
	}
	if u.Path != "" && u.Path != "/" {
		return "", "", fmt.Errorf("peerhttp: master %q must not carry a path", origin)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("peerhttp: master %q must not carry a query or fragment", origin)
	}
	host, err := canonicalHost(scheme, u.Host)
	if err != nil {
		return "", "", fmt.Errorf("peerhttp: master %q: %w", origin, err)
	}
	return scheme, host, nil
}

// validateTLS enforces that a client TLS configuration still binds a handshake
// to the request host.
func validateTLS(cfg *tls.Config, allowInsecure bool) error {
	if cfg == nil {
		return nil
	}
	if cfg.ServerName != "" {
		return fmt.Errorf("peerhttp: TLSClientConfig.ServerName %q must be empty so the handshake binds to the request host", cfg.ServerName)
	}
	if cfg.InsecureSkipVerify && !allowInsecure {
		return errors.New("peerhttp: TLSClientConfig.InsecureSkipVerify requires AllowInsecureTLS")
	}
	return nil
}

// canonicalHost renders host with the scheme's default port filled in, the way
// net/http hands it to DialContext. A bare IPv6 literal has no unambiguous
// default port and is rejected.
func canonicalHost(scheme, host string) (string, error) {
	hostOnly, port, err := net.SplitHostPort(host)
	if err != nil {
		if strings.Contains(host, ":") {
			return "", fmt.Errorf("peerhttp: ambiguous host %q: an IPv6 literal needs an explicit port", host)
		}
		hostOnly, port = host, ""
	}
	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			port = "0"
		}
	}
	return net.JoinHostPort(hostOnly, port), nil
}

// pathFor is the path an ordinary TCP connection carries.
func pathFor(scheme string) Path {
	if scheme == "https" {
		return PathHTTPS
	}
	return PathHTTP
}
