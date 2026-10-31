package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"atoll/client"
	"atoll/master"
	"atoll/pkg/peerauth"
	"atoll/pkg/peertransport"
)

// peer 数据面默认预算。这些是上限而非吞吐承诺；直接超时覆盖慢链路，中继
// 超时覆盖 relay hop 的整条路径。
const (
	p2pDirectTimeout = 30 * time.Second
	p2pRelayTimeout  = 60 * time.Second
	p2pMaxConns      = 128
	// 关停有界窗口：HTTP Shutdown 与 Serve goroutine 退出都不得无限等待。
	p2pCloseTimeout = 5 * time.Second
)

// clientP2P is the client peer lifecycle seam. It is asserted at runtime so the
// CLI does not require a specific client.PeerClient implementation to compile,
// while still failing closed when the client is not peer-capable.
type clientP2P interface {
	EnableP2P(context.Context, peertransport.RuntimeAPI) error
	CloseP2P() error
}

// newPeerRuntime builds the independent runtime identity and transport. An
// empty identityPath yields an ephemeral identity (user clients).
func newPeerRuntime(ctx context.Context, p *p2pCLIFlags, identityPath string) (peertransport.RuntimeAPI, error) {
	cfg := peertransport.Config{
		IdentityPath:      identityPath,
		ListenAddresses:   p.listenAddresses(),
		AnnounceAddresses: p.announceAddresses(),
		PublicOnly:        p.publicOnly != nil && *p.publicOnly,
		DirectTimeout:     p2pDirectTimeout,
		RelayTimeout:      p2pRelayTimeout,
		MaxConnections:    p2pMaxConns,
	}
	rt, err := peertransport.New(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("peer runtime: %w", err)
	}
	return rt, nil
}

// infrastructureFromRuntime builds the Infrastructure a peer directory
// publishes for this process. Relay is always offered so peers that cannot
// dial directly have a bounded fallback.
func infrastructureFromRuntime(rt peertransport.RuntimeAPI) peerauth.Infrastructure {
	return peerauth.Infrastructure{
		PeerID:    rt.PeerID(),
		PublicKey: rt.PublicKey(),
		Addresses: rt.Addresses(),
		Relay:     true,
	}
}

// peerServe owns the peer HTTPS listener and its runtime, and shuts both down
// in a bounded order on Close. closeErr carries the merged close result so
// repeated/concurrent Close calls return the same verdict instead of the first
// caller's snapshot.
type peerServe struct {
	rt  peertransport.RuntimeAPI
	srv *http.Server
	ln  net.Listener
	// serveDone closes when the Serve goroutine has returned; Close waits for
	// it within the bounded window so no listener goroutine outlives shutdown.
	serveDone chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// startPeerListener serves handler over the runtime's raw stream listener with
// a fresh, non-shared TLS configuration. The certificate is loaded and validated
// synchronously so a bad -tls-cert fails the CLI here instead of only logging
// asynchronously after the process already reported success. ConnContext
// installs the real peer identity (read from the stream, never from a header)
// so the source peer id is present for ticket verification.
func startPeerListener(rt peertransport.RuntimeAPI, handler http.Handler, certFile, keyFile string) (*peerServe, error) {
	ln, err := rt.Listener()
	if err != nil {
		return nil, fmt.Errorf("peer listener: %w", err)
	}
	// 证书加载必须在返回前同步完成：异步 ServeTLS 只会 log，CLI 却已报成功。
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("peer listener certificate: %w", err)
	}
	// 独立 TLS 配置：绝不与主 HTTPS 监听共享（那会携带主证书与 http2 懒配置）。
	// ConnContext 装的是真实 TLS 对端身份。
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext:       rt.ConnContext,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}
	ps := &peerServe{rt: rt, srv: srv, ln: ln, serveDone: make(chan struct{})}
	go func() {
		defer close(ps.serveDone)
		// 证书已预载入 TLSConfig，文件参数留空，ServeTLS 不再自行加载。
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("peer HTTPS listener: %v", err)
		}
	}()
	return ps, nil
}

// Close stops the peer HTTP server within a bounded window, closes the runtime
// (which owns the peer loops and the stream listener, unblocking Serve), then
// waits a bounded window for the Serve goroutine to return. Any step that fails
// or exceeds the window is merged into the returned error — a timeout is never
// reported as success. The normal HTTPS listener is never touched here.
func (ps *peerServe) Close() error {
	if ps == nil {
		return nil
	}
	ps.closeOnce.Do(func() {
		var errs []error
		if ps.srv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), p2pCloseTimeout)
			if err := ps.srv.Shutdown(ctx); err != nil {
				// 有界窗口未排空：强收剩余连接，绝不虚报成功。
				errs = append(errs, err)
				if closeErr := ps.srv.Close(); closeErr != nil {
					errs = append(errs, closeErr)
				}
			}
			cancel()
		}
		if ps.rt != nil {
			errs = append(errs, ps.rt.Close())
		}
		if ps.serveDone != nil {
			select {
			case <-ps.serveDone:
			case <-time.After(p2pCloseTimeout):
				errs = append(errs, errors.New("peer serve goroutine did not exit within the close window"))
			}
		}
		ps.closeErr = errors.Join(errs...)
	})
	return ps.closeErr
}

// masterEnableP2P wires the Master peer directory. It must run after
// EnableSecurity and EnableWritePlanning and before AttachSecureTransports and
// any background worker, so a startup cannot serve peer routes without the
// runtime handler in place.
func masterEnableP2P(ctx context.Context, p *p2pCLIFlags, origin, identityPath, certFile, keyFile string, srv *master.Server) (*peerServe, error) {
	rt, err := newPeerRuntime(ctx, p, identityPath)
	if err != nil {
		return nil, err
	}
	if err := srv.EnablePeerDirectory(master.PeerConfig{
		Origin:         origin,
		Infrastructure: infrastructureFromRuntime(rt),
	}); err != nil {
		_ = rt.Close()
		return nil, fmt.Errorf("master peer directory: %w", err)
	}
	if err := srv.SetPeerRuntime(rt); err != nil {
		_ = rt.Close()
		return nil, fmt.Errorf("master peer runtime: %w", err)
	}
	// SetPeerRuntime already installs the directory authorizer and enables the
	// relay; the CLI must not repeat EnableRelay here.
	ps, err := startPeerListener(rt, srv.Handler(), certFile, keyFile)
	if err != nil {
		_ = rt.Close()
		return nil, err
	}
	return ps, nil
}

// nodePeerRuntime creates the runtime that a node must attach before
// EnableSecurity so the peer context is available to the device handshake.
func nodePeerRuntime(ctx context.Context, p *p2pCLIFlags, identityPath string) (peertransport.RuntimeAPI, error) {
	return newPeerRuntime(ctx, p, identityPath)
}

// nodePeerStarter is the minimal node surface nodeStartP2P needs. It deliberately
// excludes EnableP2P so the helper can never re-enable P2P (the caller owns the
// single EnableP2P before Register); this is a compile-time guard.
type nodePeerStarter interface {
	StartP2P(context.Context) error
	Handler() http.Handler
}

// nodeStartP2P starts the node peer data plane in the documented order. The
// caller must have already called EnableP2P (after EnableSecurity, before
// Register); this helper only runs StartP2P (after a successful Register) and
// binds the TLS peer listener.
func nodeStartP2P(ctx context.Context, rt peertransport.RuntimeAPI, n nodePeerStarter, certFile, keyFile string) (*peerServe, error) {
	if err := n.StartP2P(ctx); err != nil {
		return nil, fmt.Errorf("node peer start: %w", err)
	}
	return startPeerListener(rt, n.Handler(), certFile, keyFile)
}

// clientEnableP2P attaches a peer identity to a secure client and returns the
// runtime to close on every exit path. An explicit -p2p-identity is honored;
// otherwise the identity is ephemeral. It must run before any Mkdir/Put/
// mount.NewWithTLS that may take a peer path.
func clientEnableP2P(ctx context.Context, p *p2pCLIFlags, c *client.Client) (peertransport.RuntimeAPI, error) {
	rt, err := newPeerRuntime(ctx, p, p.identityPath(""))
	if err != nil {
		return nil, err
	}
	pc, ok := any(c).(clientP2P)
	if !ok {
		_ = rt.Close()
		return nil, errors.New("client does not support the peer transport")
	}
	if err := pc.EnableP2P(ctx, rt); err != nil {
		_ = rt.Close()
		return nil, fmt.Errorf("client peer enable: %w", err)
	}
	return rt, nil
}

// closeClientP2P shuts the client peer transport (and its runtime) down on an
// exit path. It never panics and is safe to call after a partial setup.
func closeClientP2P(c *client.Client, rt peertransport.RuntimeAPI) {
	if c != nil {
		if pc, ok := any(c).(clientP2P); ok {
			_ = pc.CloseP2P()
		}
	}
	if rt != nil {
		_ = rt.Close()
	}
}
