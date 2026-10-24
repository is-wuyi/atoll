// Package peerhttp carries HTTPS over verified peer streams without changing
// request URLs or ticket audiences. Master requests retain the base transport;
// peer connections use real outer TLS and do not share HTTP connection pools.
package peerhttp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
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
}

// PeerDialer opens one connection to the peer a Resolver resolved. A nil
// PeerDialer means no peer path is available for that address.
type PeerDialer func(ctx context.Context) PeerDial

// Resolver resolves a registered node address to a peer dialer. The address is
// the canonical "host:port" string the deployment already uses for node
// addressing, so URL, scheme and Host stay untouched above this seam. The
// request context travels through unchanged.
type Resolver func(ctx context.Context, nodeAddr string) (PeerDialer, error)

// Observation reports the path one request actually took. It is emitted when
// the connection for the request is accepted, before the request is sent and
// long before it succeeds, so it is not evidence that a request worked. Use it
// for routing and load accounting, not for goodput.
type Observation struct {
	// Scheme is "http" or "https".
	Scheme string
	// Target is the canonical "host:port" the request was addressed to.
	Target string
	// Path is the path the request actually took.
	Path Path
	// Master reports that the request matched the pinned master origin and was
	// handed to the base transport as configured, proxy and all. A non-master
	// request never touches a proxy.
	Master bool
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
)

// WithPath records the path a request requires. PathDirect and PathRelay pin a
// peer path and fail closed when it cannot be met. PathHTTPS pins an ordinary
// TCP connection and skips the peer dialer. PathHTTP is refused for https
// peers. An empty path means no requirement.
func WithPath(ctx context.Context, p Path) context.Context {
	return context.WithValue(ctx, pathKey, p)
}

func ControlContext(ctx context.Context) context.Context {
	ctx = WithPath(ctx, "")
	return WithReporter(ctx, &Reporter{})
}

// RequiredPath reports the path a request requires, if any.
func RequiredPath(ctx context.Context) (Path, bool) {
	p, ok := ctx.Value(pathKey).(Path)
	return p, ok && p != ""
}

// WithReporter attaches a path reporter to a request tree; it overrides the
// Transport's own reporter for that request only.
func WithReporter(ctx context.Context, r *Reporter) context.Context {
	return context.WithValue(ctx, reporterKey, r)
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
	if t.master != "" && scheme == t.scheme && target == t.master {
		if want, required := RequiredPath(req.Context()); required && (want == PathDirect || want == PathRelay) {
			return nil, fmt.Errorf("peerhttp: %s is the pinned master origin and cannot take the %s peer path", target, want)
		}
		t.report(req.Context(), Observation{Scheme: scheme, Target: target, Path: pathFor(scheme), Master: true})
		return t.base.RoundTrip(req)
	}

	if scheme != "https" {
		return nil, fmt.Errorf("peerhttp: http is not permitted for peer %s; use https", target)
	}
	if req.URL.User != nil {
		return nil, fmt.Errorf("peerhttp: peer URL %s must not carry userinfo", target)
	}
	return t.peer.RoundTrip(req)
}

// peerDial is the DialContext installed on the peer transport. net/http calls it
// as dial(ctx, "tcp", "host:port") with the scheme's default port filled in, and
// then wraps the returned connection in a real tls.Client for https requests.
func (t *Transport) peerDial(ctx context.Context, network, addr string) (net.Conn, error) {
	// Belt and braces: the master must never be dialed as a peer.
	if t.master != "" && addr == t.master {
		return nil, errMasterViaPeer
	}
	if network != "tcp" {
		return nil, fmt.Errorf("peerhttp: unsupported network %q", network)
	}
	want, required := RequiredPath(ctx)
	switch want {
	case PathHTTPS: // the caller pinned an ordinary TCP path
		return t.ordinary(ctx, addr)
	case PathHTTP:
		return nil, fmt.Errorf("peerhttp: %s is https; %s is not available for it", addr, PathHTTP)
	}
	if t.resolver == nil {
		if required {
			return nil, fmt.Errorf("peerhttp: %s requires the %s peer path, but no resolver is configured", addr, want)
		}
		return t.ordinary(ctx, addr)
	}
	dial, err := t.resolver(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("peerhttp: resolve %s: %w", addr, err)
	}
	if dial == nil {
		if required {
			return nil, fmt.Errorf("peerhttp: %s requires the %s peer path, but has no peer dialer", addr, want)
		}
		return t.ordinary(ctx, addr)
	}
	pd := dial(ctx)
	if pd.Conn == nil {
		if pd.Err != nil {
			return nil, fmt.Errorf("peerhttp: dial %s: %w", addr, pd.Err)
		}
		return nil, fmt.Errorf("peerhttp: dial %s: no connection returned", addr)
	}
	if err := checkDial(addr, pd); err != nil {
		_ = pd.Conn.Close()
		return nil, fmt.Errorf("peerhttp: dial %s: %w", addr, err)
	}
	if required && pd.Path != want {
		_ = pd.Conn.Close()
		return nil, fmt.Errorf("peerhttp: dial %s: took the %s path, %s was required", addr, pd.Path, want)
	}
	t.report(ctx, Observation{Scheme: "https", Target: addr, Path: pd.Path})
	return pd.Conn, nil
}

// ordinary hands an https peer request to a direct plain TCP dial, never
// through the base transport's proxy, so a PathHTTPS observation here really
// means a direct connection. It is reached only when nothing pinned a peer path
// in the context.
func (t *Transport) ordinary(ctx context.Context, addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	t.report(ctx, Observation{Scheme: "https", Target: addr, Path: PathHTTPS})
	return conn, nil
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
	if r := reporterFrom(ctx); r != nil {
		if r.Observe != nil {
			r.Observe(o)
		}
		return
	}
	if r := t.reporter.Load(); r != nil && r.Observe != nil {
		r.Observe(o)
	}
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
