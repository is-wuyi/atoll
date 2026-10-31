package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"atoll/internal/peertrace"
	"atoll/pkg/access"
	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
	"atoll/pkg/peertransport"
)

const (
	peerDirectoryFresh       = 2 * time.Minute
	peerRefreshThrottle      = time.Second
	peerNegativeTTL          = 500 * time.Millisecond
	peerNegativeCap          = 4096
	peerRefreshTimeout       = 5 * time.Second
	peerPublisherInterval    = 25 * time.Second
	peerControlResponseLimit = 64 << 10
	peerDirectoryLimit       = peerauth.MaxDirectoryBytes
	// peerRelayReserveRefresh 是 relay 预约的短周期有界刷新间隔：中心（relay
	// hub）重启会丢失预约，只等到期才重预留会让节点在 hub 重启后最长一个整租期
	// 不可达。按此周期重建预约，把修复窗口压到分钟级。
	peerRelayReserveRefresh = 2 * time.Minute
)

var (
	errP2PNotEnabled       = errors.New("node P2P is not enabled")
	errP2PAlreadyStarted   = errors.New("node P2P is already started")
	errP2PClosed           = errors.New("node P2P is closed")
	errP2PRefreshThrottled = errors.New("node peer directory refresh throttled")
)

type peerHTTPError struct {
	status int
	path   string
}

func (e *peerHTTPError) Error() string {
	return fmt.Sprintf("peer control %s: status %d", e.path, e.status)
}

type nodeP2P struct {
	n       *Node
	runtime peertransport.RuntimeAPI

	mu                 sync.RWMutex
	directory          peerauth.Directory
	directoryAt        time.Time
	lastPublished      []string
	endpointValidUntil time.Time
	relayUntil         time.Time
	relayAt            time.Time // 最近一次成功预约时刻（短周期刷新的基准）
	started            bool
	// closed marks the P2P lifecycle terminal (after CloseP2P or a failed
	// StartP2P). Once set, the authorizer and resolver reject every peer and a
	// later StartP2P is refused — no residual peer authority survives.
	closed bool

	refreshMu   sync.Mutex
	refreshDone chan struct{}
	refreshErr  error
	lastForced  time.Time
	negative    map[string]time.Time

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// EnableP2P attaches the independent runtime peer identity and installs the
// dynamic resolver. It must run after EnableSecurity and before Register.
func (n *Node) EnableP2P(ctx context.Context, runtime peertransport.RuntimeAPI) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if n.sec == nil {
		return errors.New("node P2P requires EnableSecurity first")
	}
	if n.sec.masterScheme != "https" {
		return errors.New("node P2P requires an HTTPS master origin")
	}
	if n.sec.allowInsecure {
		return errors.New("node P2P requires a verified TLS master (allowInsecure is not permitted)")
	}
	if n.nodeID.Load() != 0 {
		return errors.New("node P2P must be enabled before Register")
	}
	if runtime == nil {
		return errors.New("node P2P runtime is required")
	}
	if err := peerauth.ValidateIdentity(runtime.PeerID(), runtime.PublicKey()); err != nil {
		return fmt.Errorf("node P2P runtime identity: %w", err)
	}

	n.p2pMu.Lock()
	defer n.p2pMu.Unlock()
	if n.p2p != nil {
		return errors.New("node P2P already enabled")
	}
	p := &nodeP2P{n: n, runtime: runtime, negative: make(map[string]time.Time)}
	n.p2p = p
	// 生命周期锚到调用方 ctx：CLI 的 signal ctx 取消（SIGTERM）能中止此后
	// Register 的在途注册，不等退出 defer 的 CloseP2P。
	n.anchorLifeContext(ctx)
	n.sec.setPeerRuntime(runtime)
	if err := n.SetPeerResolver(func(resolveCtx context.Context, nodeAddr string) (peerhttp.PeerDialer, error) {
		return p.resolve(resolveCtx, nodeAddr)
	}); err != nil {
		n.sec.clearPeerRuntime()
		n.p2p = nil
		return err
	}
	return nil
}

// StartP2P publishes the initial node endpoint and starts bounded directory,
// address and relay renewal. Register must have completed first. The caller
// context scopes the whole P2P lifetime: CloseP2P cancels it and joins.
func (n *Node) StartP2P(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	n.p2pMu.Lock()
	p := n.p2p
	if p == nil {
		n.p2pMu.Unlock()
		return errP2PNotEnabled
	}
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		n.p2pMu.Unlock()
		return errP2PAlreadyStarted
	}
	if p.closed {
		p.mu.Unlock()
		n.p2pMu.Unlock()
		return errP2PClosed
	}
	p.started = true
	p.ctx, p.cancel = context.WithCancel(ctx)
	// Reserve the publisher wait-group slot under the state lock, so a
	// concurrent CloseP2P that observes started=true waits on a non-zero count
	// and never returns before a publisher that starts afterwards.
	p.wg.Add(1)
	p.mu.Unlock()
	n.p2pMu.Unlock()

	// A startup failure releases the reserved slot and marks the lifecycle
	// terminal (closed), so a later StartP2P is refused and no peer authority
	// lingers.
	release := func(err error) error {
		p.mu.Lock()
		p.started = false
		p.closed = true
		cancel := p.cancel
		p.cancel = nil
		p.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		p.wg.Done()
		p.runtime.SetAuthorizer(func(context.Context, string) bool { return false })
		return err
	}
	if n.nodeID.Load() == 0 {
		return release(errors.New("node P2P requires successful Register"))
	}
	// Install the source authorizer before any dial or bootstrap so an inbound
	// authorizer can never recurse back into directory refresh while the initial
	// refresh and publication are still running.
	p.runtime.SetAuthorizer(func(authCtx context.Context, source string) bool {
		return p.authorizeSource(authCtx, source)
	})
	if err := p.refresh(p.ctx, true); err != nil {
		return release(fmt.Errorf("node P2P directory: %w", err))
	}
	if err := n.publishP2P(p.ctx, p); err != nil {
		return release(err)
	}
	if err := n.reserveRelay(p.ctx, p); err != nil {
		return release(err)
	}
	if err := n.publishIfAddressesChanged(p.ctx, p); err != nil {
		return release(err)
	}
	go n.peerPublisherLoop(p)
	return nil
}

// CloseP2P stops the publisher and waits for all P2P-owned goroutines, then
// cancels and joins the register lifecycle (heartbeat, device-session renew,
// 401 kick): a closed node never keeps renewing or kicking sessions in the
// background. The runtime is owned by the CLI and deliberately not closed here.
func (n *Node) CloseP2P() error {
	// 全程持有 p2pMu：串行化与 StartP2P/并行 CloseP2P。关停先置 closed（后续
	// StartP2P 见 closed 即拒，不再 wg.Add），再 join。
	n.p2pMu.Lock()
	defer n.p2pMu.Unlock()
	// 1) Register 生命周期：拒绝新循环，取消并 join heartbeat/renew/401 kick
	//    （含首次注册的占位计数——取消能实际中止在途注册 HTTP）。
	n.lifeMu.Lock()
	n.lifeClosed = true
	lifeCancel := n.lifeCancel
	n.lifeCancel = nil
	n.lifeMu.Unlock()
	if lifeCancel != nil {
		lifeCancel()
	}
	n.lifeWG.Wait()
	// 外部同步续期（checkTicket/authorizePeer → renewAfterRejection）不在 lifeWG
	// 上，但整段流程持 opMu：这里取一次 opMu 排干在途续期，CloseP2P 返回后不再
	// 有任何会话建立（后续调用被 establishSession/renewAfterRejection 的关停检查
	// 拒绝，最终写入亦拒关停）。
	if n.sec != nil {
		n.sec.opMu.Lock()
		n.sec.opMu.Unlock()
	}
	// 2) P2P publisher：取消并 join，安装拒绝型 authorizer（无残余 peer 权威）。
	p := n.p2p
	if p == nil {
		return nil
	}
	return n.stopP2P(p)
}

// stopP2P terminates the P2P lifecycle. It cancels the publisher context and
// always joins it, marks the lifecycle closed, and installs a rejecting
// authorizer so no peer authority survives the close (never a silent
// ordinary-TCP path). Two concurrent CloseP2P both wait; StartP2P cannot add to
// the wait group after the close begins (it is serialized on p2pMu and sees
// closed), so the join is deterministic.
func (n *Node) stopP2P(p *nodeP2P) error {
	p.mu.Lock()
	cancel := p.cancel
	p.started = false
	p.cancel = nil
	p.closed = true
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	// 总是 join：未启动时 wg 计数为 0 立即返回；已启动则必被取消并收尾。
	p.wg.Wait()
	p.runtime.SetAuthorizer(func(context.Context, string) bool { return false })
	return nil
}

func (n *Node) peerPublisherLoop(p *nodeP2P) {
	defer p.wg.Done()
	ticker := time.NewTicker(peerPublisherInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(p.ctx, peerRefreshTimeout)
			if err := p.refresh(ctx, true); err != nil && !errors.Is(err, context.Canceled) {
				logPeerP2P("directory refresh", err)
			} else if err == nil {
				if err := n.publishIfNeeded(ctx, p); err != nil && !errors.Is(err, context.Canceled) {
					logPeerP2P("endpoint publish", err)
				}
				if err := n.reserveRelay(ctx, p); err != nil && !errors.Is(err, context.Canceled) {
					logPeerP2P("relay reservation", err)
				}
				if err := n.publishIfAddressesChanged(ctx, p); err != nil && !errors.Is(err, context.Canceled) {
					logPeerP2P("endpoint republish", err)
				}
			}
			cancel()
		}
	}
}

func logPeerP2P(operation string, err error) {
	// Bounded, free of identity/private material; the publisher must not spin on
	// a repeating failure silently.
	if err != nil {
		log.Printf("node P2P %s: %v", operation, err)
	}
}

func (p *nodeP2P) refresh(ctx context.Context, force bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	p.mu.RLock()
	fresh := !p.directoryAt.IsZero() && time.Since(p.directoryAt) < peerDirectoryFresh
	p.mu.RUnlock()
	if !force && fresh {
		return nil
	}

	p.refreshMu.Lock()
	if p.refreshDone != nil {
		done := p.refreshDone
		p.refreshMu.Unlock()
		select {
		case <-done:
			p.refreshMu.Lock()
			err := p.refreshErr
			p.refreshMu.Unlock()
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if force && !p.lastForced.IsZero() && time.Since(p.lastForced) < peerRefreshThrottle {
		p.refreshMu.Unlock()
		return errP2PRefreshThrottled
	}
	if force {
		p.lastForced = time.Now()
	}
	done := make(chan struct{})
	p.refreshDone = done
	p.refreshMu.Unlock()

	refreshCtx, cancel := context.WithTimeout(peerhttp.ControlContext(ctx), peerRefreshTimeout)
	directory, err := p.n.fetchPeerDirectory(refreshCtx)
	cancel()
	if err == nil {
		err = p.runtime.SetDirectory(directory)
	}
	p.refreshMu.Lock()
	p.refreshErr = err
	if err == nil {
		p.mu.Lock()
		p.directory = cloneDirectory(directory)
		p.directoryAt = time.Now()
		p.mu.Unlock()
	}
	close(done)
	p.refreshDone = nil
	p.refreshMu.Unlock()
	return err
}

func (p *nodeP2P) directorySnapshot() peerauth.Directory {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return cloneDirectory(p.directory)
}

func (p *nodeP2P) sourceKnown(source string) bool {
	if source == "" {
		return true
	}
	now := time.Now()
	p.mu.RLock()
	defer p.mu.RUnlock()
	// The infrastructure (center) peer has no endpoint of its own but must be
	// accepted for control connections (verify/pull/retire). Its validity window
	// is the directory freshness, refreshed with the same directory.
	if p.directory.Infrastructure.PeerID == source && !p.directoryAt.IsZero() &&
		time.Since(p.directoryAt) < peerDirectoryFresh {
		return true
	}
	for _, endpoint := range p.directory.Endpoints {
		if endpoint.PeerID == source && now.Before(endpoint.ValidUntil) {
			return true
		}
	}
	return false
}

func (p *nodeP2P) negativeHit(source string) bool {
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()
	until := p.negative[source]
	if until.IsZero() || !time.Now().Before(until) {
		delete(p.negative, source)
		return false
	}
	return true
}

func (p *nodeP2P) markNegative(source string) {
	if source == "" {
		return
	}
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()
	if len(p.negative) >= peerNegativeCap {
		for key := range p.negative {
			delete(p.negative, key)
			break
		}
	}
	p.negative[source] = time.Now().Add(peerNegativeTTL)
}

func (p *nodeP2P) authorizeSource(ctx context.Context, source string) bool {
	if source == "" {
		return true
	}
	p.mu.RLock()
	closed := p.closed
	p.mu.RUnlock()
	if closed {
		return false
	}
	if p.sourceKnown(source) && p.runtime.AllowedPeer(source) {
		return true
	}
	if p.negativeHit(source) {
		return false
	}
	// Bounded refresh budget on the unknown-source path: wait for the next
	// refresh slot (cancelable via ctx, bounded by the authorizer budget) rather
	// than treating a throttle as "no permission". A just-registered client must
	// be accepted on its first attempt even when the initial forced refresh ran
	// moments ago.
	if err := p.refreshForAuthorize(ctx); err != nil {
		p.markNegative(source)
		return false
	}
	allowed := p.sourceKnown(source) && p.runtime.AllowedPeer(source)
	if !allowed {
		p.markNegative(source)
	}
	return allowed
}

// refreshForAuthorize performs one bounded directory refresh for the
// unknown-source authorizer path. If the global refresh throttle is active it
// waits for the next slot (cancelable, <= the caller budget) and retries,
// instead of returning a throttle error that would deny a just-registered peer.
func (p *nodeP2P) refreshForAuthorize(ctx context.Context) error {
	for {
		err := p.refresh(ctx, true)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errP2PRefreshThrottled) {
			return err
		}
		p.refreshMu.Lock()
		wait := peerRefreshThrottle - time.Since(p.lastForced)
		p.refreshMu.Unlock()
		if wait <= 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (p *nodeP2P) endpointFor(addr string) (peerauth.Endpoint, peerauth.Infrastructure, error) {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return peerauth.Endpoint{}, peerauth.Infrastructure{}, errP2PClosed
	}
	directory := cloneDirectory(p.directory)
	p.mu.RUnlock()
	for _, endpoint := range directory.Endpoints {
		if endpoint.Role == peerauth.RoleNode && endpoint.Addr == addr && time.Now().Before(endpoint.ValidUntil) {
			if !p.runtime.AllowedPeer(endpoint.PeerID) {
				return peerauth.Endpoint{}, peerauth.Infrastructure{}, fmt.Errorf("peer %s is not allowed", endpoint.PeerID)
			}
			return endpoint, directory.Infrastructure, nil
		}
	}
	return peerauth.Endpoint{}, peerauth.Infrastructure{}, fmt.Errorf("peer endpoint %q was not found", addr)
}

func (p *nodeP2P) resolve(ctx context.Context, nodeAddr string) (peerhttp.PeerDialer, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := p.refresh(ctx, false); err != nil && !errors.Is(err, errP2PRefreshThrottled) {
		return nil, fmt.Errorf("directory refresh: %w", err)
	}
	endpoint, infrastructure, err := p.endpointFor(nodeAddr)
	if err != nil {
		if refreshErr := p.refresh(ctx, true); refreshErr != nil && !errors.Is(refreshErr, errP2PRefreshThrottled) {
			return nil, refreshErr
		}
		endpoint, infrastructure, err = p.endpointFor(nodeAddr)
		if err != nil {
			return nil, err
		}
	}
	return func(dialCtx context.Context) peerhttp.PeerDial {
		if dialCtx == nil {
			dialCtx = context.Background()
		}
		path, required := peerhttp.RequiredPath(dialCtx)
		if !required {
			path = peerhttp.PathUnknown
		}
		result := p.runtime.Dial(dialCtx, endpoint, infrastructure, path)
		if result.Conn != nil && result.Err == nil {
			return result.PeerDial
		}
		if result.Conn != nil {
			_ = result.Conn.Close()
		}
		firstErr := result.Err
		refreshCtx, cancel := context.WithTimeout(dialCtx, peerRefreshTimeout)
		refreshErr := p.refresh(refreshCtx, true)
		cancel()
		if refreshErr != nil && !errors.Is(refreshErr, errP2PRefreshThrottled) {
			return peerhttp.PeerDial{Err: fmt.Errorf("peer dial failed: %v; directory refresh: %w", firstErr, refreshErr)}
		}
		updated, infra, lookupErr := p.endpointFor(nodeAddr)
		if lookupErr != nil {
			return peerhttp.PeerDial{Err: fmt.Errorf("peer dial failed: %v; refreshed endpoint: %w", firstErr, lookupErr)}
		}
		result = p.runtime.Dial(dialCtx, updated, infra, path)
		if result.Conn == nil && result.Err == nil {
			result.Err = firstErr
		}
		return result.PeerDial
	}, nil
}

func (n *Node) fetchPeerDirectory(ctx context.Context) (peerauth.Directory, error) {
	var directory peerauth.Directory
	status, raw, err := n.peerControlDo(ctx, http.MethodGet, "/peers/directory", nil, peerDirectoryLimit)
	if err != nil {
		return directory, err
	}
	if status < 200 || status >= 300 {
		return directory, &peerHTTPError{status: status, path: "/peers/directory"}
	}
	if err := decodePeerBytes(raw, &directory, peerDirectoryLimit); err != nil {
		return directory, err
	}
	if err := peerauth.ValidateDirectory(directory, time.Now()); err != nil {
		return directory, fmt.Errorf("validate peer directory: %w", err)
	}
	return directory, nil
}

func (n *Node) fetchNodeState(ctx context.Context) (peerauth.NodeState, error) {
	var state peerauth.NodeState
	status, raw, err := n.peerControlDo(ctx, http.MethodGet, "/peers/self", nil, peerControlResponseLimit)
	if err != nil {
		return state, err
	}
	if status < 200 || status >= 300 {
		return state, &peerHTTPError{status: status, path: "/peers/self"}
	}
	if err := decodePeerBytes(raw, &state, peerControlResponseLimit); err != nil {
		return state, err
	}
	return state, nil
}

func (n *Node) publishP2P(ctx context.Context, p *nodeP2P) error {
	state, err := n.fetchNodeState(ctx)
	if err != nil {
		return fmt.Errorf("fetch node peer state: %w", err)
	}
	addresses, err := normalizedPeerAddresses(p.runtime.Addresses())
	if err != nil {
		return fmt.Errorf("node peer addresses: %w", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		endpoint, status, publishErr := n.publishAddressAttempt(ctx, p, state.EndpointRevision, addresses)
		if publishErr == nil {
			p.mu.Lock()
			p.lastPublished = append([]string(nil), addresses...)
			p.endpointValidUntil = endpoint.ValidUntil
			p.mu.Unlock()
			return nil
		}
		if status != http.StatusConflict || attempt != 0 {
			return publishErr
		}
		state, err = n.fetchNodeState(ctx)
		if err != nil {
			return fmt.Errorf("refresh node peer state after CAS conflict: %w", err)
		}
	}
	return errors.New("peer address publication exhausted retries")
}

func (n *Node) publishIfNeeded(ctx context.Context, p *nodeP2P) error {
	addresses, err := normalizedPeerAddresses(p.runtime.Addresses())
	if err != nil {
		return fmt.Errorf("node peer addresses: %w", err)
	}
	p.mu.RLock()
	last := append([]string(nil), p.lastPublished...)
	validUntil := p.endpointValidUntil
	p.mu.RUnlock()
	if equalPeerAddresses(last, addresses) && time.Now().Before(validUntil.Add(-30*time.Second)) {
		return nil
	}
	return n.publishP2P(ctx, p)
}

func (n *Node) publishIfAddressesChanged(ctx context.Context, p *nodeP2P) error {
	addresses, err := normalizedPeerAddresses(p.runtime.Addresses())
	if err != nil {
		return fmt.Errorf("node peer addresses: %w", err)
	}
	p.mu.RLock()
	different := !equalPeerAddresses(p.lastPublished, addresses)
	p.mu.RUnlock()
	if !different {
		return nil
	}
	return n.publishP2P(ctx, p)
}

func (n *Node) reserveRelay(ctx context.Context, p *nodeP2P) error {
	now := time.Now()
	p.mu.RLock()
	until := p.relayUntil
	reservedAt := p.relayAt
	directory := cloneDirectory(p.directory)
	p.mu.RUnlock()
	// 预约未临期且仍在短周期刷新窗内 → 跳过。保存条件不变：仅成功 ReserveRelay
	// 后才落库；临期（30s 余量）照旧必须重预留。
	if now.Before(until.Add(-30*time.Second)) && now.Sub(reservedAt) < peerRelayReserveRefresh {
		return nil
	}
	reserved, err := p.runtime.ReserveRelay(peerhttp.ControlContext(ctx), directory.Infrastructure)
	if err != nil {
		return fmt.Errorf("reserve relay: %w", err)
	}
	p.mu.Lock()
	p.relayUntil = reserved
	p.relayAt = time.Now()
	p.mu.Unlock()
	return nil
}

func (n *Node) publishAddressAttempt(ctx context.Context, p *nodeP2P, expected uint64, addresses []string) (peerauth.Endpoint, int, error) {
	var endpoint peerauth.Endpoint
	binding := n.sec.peerBindingSnapshot()
	if binding == nil || binding.Revision == 0 {
		return endpoint, 0, errors.New("node peer binding is not available")
	}
	opID, err := newPeerOperationID()
	if err != nil {
		return endpoint, 0, err
	}
	req := peerauth.AddressPublication{
		PeerID:           p.runtime.PeerID(),
		BindingRevision:  binding.Revision,
		ExpectedRevision: expected,
		OperationID:      opID,
		Addresses:        append([]string(nil), addresses...),
		NotAfter:         time.Now().UTC().Add(peerauth.EndpointLease),
	}
	proof, err := peerauth.PublicationProof(n.masterURL, uint64(n.nodeID.Load()), req)
	if err != nil {
		return endpoint, 0, err
	}
	req.Signature, err = p.runtime.Sign(proof)
	if err != nil {
		return endpoint, 0, fmt.Errorf("sign peer address publication: %w", err)
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return endpoint, 0, err
	}
	// A network retry reuses exactly this operation, NotAfter and signature.
	for retry := 0; retry < 2; retry++ {
		status, respRaw, requestErr := n.peerControlDo(ctx, http.MethodPost, "/peers/address", raw, peerControlResponseLimit)
		if requestErr != nil {
			if retry == 0 && ctx.Err() == nil {
				continue
			}
			return endpoint, 0, requestErr
		}
		if status < 200 || status >= 300 {
			return endpoint, status, &peerHTTPError{status: status, path: "/peers/address"}
		}
		if err := decodePeerBytes(respRaw, &endpoint, peerControlResponseLimit); err != nil {
			return endpoint, status, err
		}
		if err := validateNodeEndpointResponse(n, p, req, expected, endpoint); err != nil {
			return endpoint, status, err
		}
		return endpoint, status, nil
	}
	return endpoint, 0, errors.New("peer address publication retry exhausted")
}

// validateNodeEndpointResponse binds the publication response to exactly the
// request that produced it: identity, role, node id, node address, binding and
// CAS revisions, published addresses and the lease window. Anything else is a
// protocol error and is rejected rather than cached.
func validateNodeEndpointResponse(n *Node, p *nodeP2P, req peerauth.AddressPublication, expected uint64, endpoint peerauth.Endpoint) error {
	now := time.Now()
	if endpoint.Role != peerauth.RoleNode ||
		endpoint.NodeID != uint64(n.nodeID.Load()) ||
		endpoint.PeerID != req.PeerID ||
		endpoint.Addr != n.advertise ||
		!bytes.Equal(endpoint.PublicKey, p.runtime.PublicKey()) ||
		endpoint.BindingRevision != req.BindingRevision ||
		endpoint.Revision != req.ExpectedRevision+1 ||
		!equalPeerAddresses(endpoint.Addresses, req.Addresses) ||
		!now.Before(endpoint.ValidUntil) ||
		endpoint.ValidUntil.After(req.NotAfter) {
		return errors.New("master returned a peer endpoint that does not match this publication")
	}
	return nil
}

// peerControlDo performs a master control request and reads the whole response
// body before the timeout is cancelled, so a caller can never observe a body
// whose context has already been torn down. limit bounds the read; the master
// and node must agree on the response size contract.
func (n *Node) peerControlDo(ctx context.Context, method, path string, body []byte, limit int64) (int, []byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(peerhttp.ControlContext(ctx), 30*time.Second)
	defer cancel()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, n.masterURL+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req, trace := peertrace.StartClient(req)
	resp, err := n.httpClient.Do(req)
	if err != nil {
		trace.Finish(0, err)
		return 0, nil, err
	}
	trace.Mark("response_headers")
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if readErr != nil {
		trace.Finish(resp.StatusCode, readErr)
		return resp.StatusCode, nil, readErr
	}
	if int64(len(raw)) > limit {
		err := errors.New("peer control response exceeds size limit")
		trace.Finish(resp.StatusCode, err)
		return resp.StatusCode, nil, err
	}
	trace.Mark("response_body")
	trace.Finish(resp.StatusCode, nil)
	return resp.StatusCode, raw, nil
}

// decodePeerBytes 用共享严格解析解码 peer 协议响应：拒绝重复字段、case alias、
// null、过深嵌套、尾随 JSON 与未知字段，并强制调用方传入的 limit（目录 8MiB /
// 控制响应 64KiB）。master 与节点必须对同一响应使用同一解释，否则 PeerID/
// revision 等字段会因 HTTP 层的不同解读在授权后获得不同含义。
func decodePeerBytes(raw []byte, out any, limit int64) error {
	return peerauth.DecodeJSONLimit(bytes.NewReader(raw), out, limit)
}

func normalizedPeerAddresses(addresses []string) ([]string, error) {
	return peerauth.NormalizeAddresses(append([]string(nil), addresses...), false)
}

func equalPeerAddresses(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func newPeerOperationID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func cloneDirectory(in peerauth.Directory) peerauth.Directory {
	out := in
	out.Endpoints = append([]peerauth.Endpoint(nil), in.Endpoints...)
	for i := range out.Endpoints {
		out.Endpoints[i].PublicKey = append([]byte(nil), in.Endpoints[i].PublicKey...)
		out.Endpoints[i].Addresses = append([]string(nil), in.Endpoints[i].Addresses...)
	}
	out.Infrastructure.PublicKey = append([]byte(nil), in.Infrastructure.PublicKey...)
	out.Infrastructure.Addresses = append([]string(nil), in.Infrastructure.Addresses...)
	return out
}

// SetPeerResolver installs a resolver over the existing secure HTTPS transport.
// EnableP2P calls it exactly once; it remains exported for compatible callers.
func (n *Node) SetPeerResolver(resolver peerhttp.Resolver) error {
	if n.sec == nil || n.sec.masterScheme != "https" || n.nodeID.Load() != 0 {
		return errors.New("peer transport requires a secure HTTPS node before registration")
	}
	base, ok := n.sec.base.(*http.Transport)
	if !ok {
		return errors.New("peer resolver must be configured once")
	}
	transport, err := peerhttp.NewTransport(base, peerhttp.WithMaster(n.masterURL), peerhttp.WithResolver(resolver))
	if err != nil {
		return err
	}
	n.sec.base = transport
	n.sec.authClient.Transport = transport
	if t, ok := n.httpClient.Transport.(*deviceTransport); ok {
		t.base = transport
	}
	if t, ok := n.bulkClient.Transport.(*access.Transport); ok {
		t.Base = transport
	}
	return nil
}
