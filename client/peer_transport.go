package client

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
	"strconv"
	"strings"
	"sync"
	"time"

	"atoll/internal/peertrace"
	"atoll/pkg/access"
	"atoll/pkg/auth"
	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
	"atoll/pkg/peertransport"
)

const (
	clientPeerFresh          = 2 * time.Minute
	clientPeerRefreshTimeout = 5 * time.Second
	clientPeerInterval       = 25 * time.Second
	clientPeerRetainMargin   = 60 * time.Second
	clientPeerResponseLimit  = 64 << 10
)

// clientPeerReleaseTimeout bounds the best-effort signed slot release in
// CloseP2P. It is a var so tests can shorten it; release failures are
// non-fatal (the master-side endpoint lease is the authoritative fallback).
var clientPeerReleaseTimeout = 5 * time.Second

// clientPeerDirectoryLimit 是目录响应的读取与解码上限：与 shared 契约一致取
// peerauth.MaxDirectoryBytes，两端必须用同一解释。
const clientPeerDirectoryLimit = peerauth.MaxDirectoryBytes

var (
	errClientPeerSession = errors.New("client P2P requires a session and a selected space")
	errClientP2PClosed   = errors.New("client P2P is closed")
)

type clientP2P struct {
	c       *Client
	runtime peertransport.RuntimeAPI

	mu              sync.RWMutex
	started         bool
	closed          bool
	registeredRev   uint64
	registeredOp    string
	registeredUntil time.Time
	regSession      string
	regSpace        uint64
	directory       peerauth.Directory
	directoryAt     time.Time

	// regMu serializes registration so a slow CAS cannot race a session switch
	// or a concurrent file-ticket registration. The fast path (already
	// registered for the current session) runs before the lock, so the common
	// file-operation path never contends. CloseP2P also acquires it once before
	// the slot release, so an in-flight registration always finishes (or is
	// refused) before the release reads the master revision.
	regMu sync.Mutex

	// releaseOnce makes the CloseP2P slot release run exactly once across all
	// concurrent closes; every closer waits on the same completion.
	releaseOnce sync.Once

	// wake is a bounded (capacity 1) signal the session-change hook sends so the
	// single loop re-registers under the new session. It replaces unbounded
	// goroutine spawning, which raced WaitGroup.Add against Wait/Close.
	wake chan struct{}

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	refreshMu   sync.Mutex
	refreshDone chan struct{}
	refreshErr  error
}

// EnableP2P attaches the runtime peer identity, registers this client peer with
// the master, primes the peer directory and installs the dynamic resolver. It
// must run on a NewSecure client after a session and a space are selected,
// before any file operation. Initial registration or directory fetch failure
// aborts EnableP2P (callers never wait on a stale cache) and restores the
// transport so a retry is safe.
func (c *Client) EnableP2P(ctx context.Context, runtime peertransport.RuntimeAPI) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if c.sec == nil || c.secTransport == nil {
		return errors.New("client P2P requires a NewSecure client")
	}
	if runtime == nil {
		return errors.New("client P2P runtime is required")
	}
	if err := peerauth.ValidateIdentity(runtime.PeerID(), runtime.PublicKey()); err != nil {
		return fmt.Errorf("client P2P runtime identity: %w", err)
	}
	// 绑定构造时固定的 master origin（而非可变的 c.MasterURL）：登记/释放的
	// proof 与控制请求目标都必须落在同一 HTTPS origin 上。
	if _, err := peerauth.CanonicalOrigin(c.pinnedMasterOrigin()); err != nil {
		return errors.New("client P2P requires an HTTPS master origin")
	}

	c.p2pMu.Lock()
	defer c.p2pMu.Unlock()
	if c.p2p != nil {
		return errors.New("client P2P already enabled")
	}
	p := &clientP2P{c: c, runtime: runtime, wake: make(chan struct{}, 1)}
	c.p2p = p
	p.ctx, p.cancel = context.WithCancel(ctx)

	// Remember the pre-resolver transport and hooks so a later failure can
	// restore them exactly, making a retry of EnableP2P safe.
	origBase := c.secTransport.base
	origPeerID := c.secTransport.peerID
	origEnsure := c.secTransport.ensureRegistered
	fail := func(err error) error {
		p.cancel()
		c.secTransport.base = origBase
		c.secTransport.peerID = origPeerID
		c.secTransport.ensureRegistered = origEnsure
		c.p2p = nil
		return err
	}

	if err := c.SetPeerResolver(func(resolveCtx context.Context, nodeAddr string) (peerhttp.PeerDialer, error) {
		return p.resolve(resolveCtx, nodeAddr)
	}); err != nil {
		return fail(err)
	}
	// Outbound tickets carry the real source peer id from this point on, and a
	// file operation first ensures the current registration before it dials a
	// node, so a just-registered peer is never gater-rejected on its first I/O.
	c.secTransport.peerID = func() string { return runtime.PeerID() }
	c.secTransport.ensureRegistered = p.ensureRegistered

	if err := p.ensureRegistration(p.ctx); err != nil {
		return fail(fmt.Errorf("client P2P register: %w", err))
	}
	if err := p.refreshDirectory(p.ctx, true); err != nil {
		return fail(fmt.Errorf("client P2P directory: %w", err))
	}
	p.mu.Lock()
	p.started = true
	p.mu.Unlock()
	p.wg.Add(1)
	go c.clientPeerLoop(p)
	return nil
}

// CloseP2P stops the background loop and joins it, then performs one bounded
// signed release of this client's active peer slot (POST /peers/client/release,
// ClientReleaseProof). The release is best-effort: any failure is left to the
// master-side endpoint lease (TTL) fallback and never fails the close. The
// master path stays usable; every later peer (node) request fails closed (never
// a silent ordinary TCP fallback). The runtime is owned by the CLI and is not
// closed here.
func (c *Client) CloseP2P() error {
	// 全程持有 p2pMu：串行化与 EnableP2P/并行 CloseP2P。关停先置 closed（后续
	// EnableP2P 无法再启动新 loop），再 join。两个并发 CloseP2P 都等 wg 归零，
	// 不会有一个提前返回；EnableP2P 被 p2pMu 挡住，不会在 Wait 后再 Add。
	c.p2pMu.Lock()
	defer c.p2pMu.Unlock()
	p := c.p2p
	if p == nil {
		return nil
	}
	p.mu.Lock()
	cancel := p.cancel
	p.cancel = nil
	p.closed = true
	p.started = false
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	// 总是 join：即使 loop 尚未启动，wg 计数为 0 也立即返回；已启动则必被取消并
	// 收尾。p2pMu 被持有期间 EnableP2P 不能 wg.Add，故 Wait 后不会再有新计数。
	p.wg.Wait()
	// 等待可能仍持 regMu 的在途登记离开临界区（其结果已被关停检查拒绝落库），
	// 释放才不会与在途登记交错读/写 master revision。之后新登记见 closed 即拒。
	p.regMu.Lock()
	p.regMu.Unlock()
	// Fail closed: the hooks stay installed and now report the closed state, so a
	// subsequent peer (node) request errors out here rather than silently
	// degrading to an ordinary TCP connection. Master requests keep working.
	// 有界释放只执行一次：并发 Close 共享同一次完成，不做重复释放。TTL 兜底。
	p.releaseOnce.Do(func() { p.releaseRegistration() })
	return nil
}

// releaseRegistration 有界地向 master 释放本 peer 的 active 客户端名额
// （POST /peers/client/release，ClientReleaseProof）。预期 revision 释放前现读
// （CAS 权威在 master）；网络失败用同一已签名请求重试一次（同 op 幂等），master
// 明确答复（含 409 CAS 陈旧）不重试。任何失败静默交给 TTL 兜底——关停绝不因此
// 失败或阻塞超过 clientPeerReleaseTimeout。释放后同 identity 正确 CAS+新签名的
// 重新登记仍是合法路径，这里不做任何额外禁用。
func (p *clientP2P) releaseRegistration() {
	ctx, cancel := context.WithTimeout(context.Background(), clientPeerReleaseTimeout)
	defer cancel()
	token, spaceID, hasSpace := p.c.sec.snapshot()
	if token == "" || !hasSpace || spaceID == 0 {
		return
	}
	origin, err := peerauth.CanonicalOrigin(p.c.pinnedMasterOrigin())
	if err != nil {
		return
	}
	current, err := p.clientSelfRevision(ctx, token, spaceID, hasSpace)
	if err != nil || current == 0 {
		return // 从未登记（revision 0）或查询失败：交给 TTL 兜底
	}
	opID, err := newPeerOpID()
	if err != nil {
		return
	}
	req := peerauth.ClientRegistration{
		PeerID:           p.runtime.PeerID(),
		PublicKey:        append([]byte(nil), p.runtime.PublicKey()...),
		ExpectedRevision: current,
		OperationID:      opID,
		NotAfter:         time.Now().UTC().Add(peerauth.EndpointLease),
	}
	proof, err := peerauth.ClientReleaseProof(origin, token, spaceID, req)
	if err != nil {
		return
	}
	req.Signature, err = p.runtime.Sign(proof)
	if err != nil {
		return
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return
	}
	// 网络失败用同一已签名请求重试一次；master 明确答复（含 409 CAS 陈旧）不重试。
	for attempt := 0; attempt < 2; attempt++ {
		status, _, requestErr := p.c.peerControlDoPinned(ctx, http.MethodPost, "/peers/client/release", raw, token, spaceID, hasSpace, clientPeerResponseLimit)
		if requestErr == nil {
			if status >= 200 && status < 300 {
				p.mu.Lock()
				p.registeredRev, p.registeredOp, p.registeredUntil = 0, "", time.Time{}
				p.regSession, p.regSpace = "", 0
				p.mu.Unlock()
			}
			return
		}
		if attempt == 0 && ctx.Err() == nil {
			continue
		}
		return
	}
}

// ensureRegistered is installed on the secure transport so a file operation
// that must dial a node first registers this client under the exact session it
// is about to present — on the file path, not on a background timer, so the
// first upload never depends on a stale cache.
func (p *clientP2P) ensureRegistered(ctx context.Context, token string, spaceID uint64, hasSpace bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if p.closedState() {
		return errClientP2PClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if token == "" || !hasSpace || spaceID == 0 {
		return errClientPeerSession
	}
	if p.alreadyRegistered(token, spaceID, hasSpace) {
		return nil
	}
	p.regMu.Lock()
	defer p.regMu.Unlock()
	// 拿到串行锁后再核对：等锁期间 CloseP2P 可能已置 closed，或调用方 ctx 已被
	// 取消。绝不在关停/取消后仍发起新登记；会话/space 若已切换，调用方传入的
	// 旧凭据即作废——必须显式失败（applyNodeAuth 将用同一快照换票，绝不让登记
	// 静默换 live 快照后、换票仍拿旧 token 的不一致请求发出）。
	if p.closedState() {
		return errClientP2PClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	liveToken, liveSpace, liveHasSpace := p.c.sec.snapshot()
	if liveToken == "" || !liveHasSpace || liveSpace == 0 {
		return errClientPeerSession
	}
	if liveToken != token || liveSpace != spaceID || liveHasSpace != hasSpace {
		return errClientPeerSession
	}
	if p.alreadyRegistered(token, spaceID, hasSpace) {
		return nil
	}
	return p.doRegistration(ctx, token, spaceID, hasSpace)
}

// closedState 报告 P2P 生命周期是否已终止（关停或启动失败后不可再登记）。
func (p *clientP2P) closedState() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.closed
}

// mergeLifecycle 把调用方 ctx 与 P2P 生命周期 ctx（p.ctx）合并：任一取消即取消
// 结果，使 CloseP2P 能立即中止在途登记，而非等调用方 ctx 自然结束。p.ctx 为 nil
// （未启用）时退化为调用方 ctx。
func (p *clientP2P) mergeLifecycle(ctx context.Context) (context.Context, context.CancelFunc) {
	if p.ctx == nil {
		return ctx, func() {}
	}
	merged, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(p.ctx, cancel)
	return merged, func() { stop(); cancel() }
}

// p2pSessionChanged invalidates the current peer registration so the loop
// re-registers under the new session/space (CAS to a new revision). It only
// signals a bounded wake channel; the single loop owns registration, so no
// goroutine is spawned and no WaitGroup.Add can race Wait.
func (c *Client) p2pSessionChanged() {
	c.p2pMu.Lock()
	p := c.p2p
	c.p2pMu.Unlock()
	if p == nil {
		return
	}
	p.mu.Lock()
	p.registeredRev = 0
	p.registeredOp = ""
	p.registeredUntil = time.Time{}
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default: // a wake is already pending; the loop will see the latest snapshot
	}
}

func (c *Client) clientPeerLoop(p *clientP2P) {
	defer p.wg.Done()
	ticker := time.NewTicker(clientPeerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.wake:
			// Session/space changed: re-register under the new snapshot, then
			// refresh the directory so a just-registered peer is visible.
			p.refreshCycle()
		case <-ticker.C:
			p.refreshCycle()
		}
	}
}

// refreshCycle 执行一次有界的重登记+目录刷新。失败有界且非致命（下个 tick 或
// 下次文件操作重试），但必须记日志，不得静默吞掉——持续失败时这是唯一线索。
func (p *clientP2P) refreshCycle() {
	ctx, cancel := context.WithTimeout(p.ctx, clientPeerRefreshTimeout)
	defer cancel()
	if err := p.ensureRegistration(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("client P2P re-register: %v", err)
	}
	if err := p.refreshDirectory(ctx, false); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("client P2P directory refresh: %v", err)
	}
}

// alreadyRegistered reports whether this client is currently registered for the
// exact session and space, with a registration still inside its validity window
// minus a retain margin so renewal happens before expiry.
func (p *clientP2P) alreadyRegistered(token string, spaceID uint64, hasSpace bool) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.started && !p.closed && p.registeredRev > 0 &&
		p.regSession == token && p.regSpace == spaceID && hasSpace &&
		time.Now().Before(p.registeredUntil.Add(-clientPeerRetainMargin))
}

// ensureRegistration registers this client peer under the current session/space
// using CAS on the peer's current revision. Serialized by regMu; a network
// failure retries the exact same signed operation (master replays idempotently),
// and only a 409 re-reads the revision and starts a fresh operation. A
// session/space change mid-flight aborts the store so a slow old registration
// cannot overwrite a newer one.
func (p *clientP2P) ensureRegistration(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	token, spaceID, hasSpace := p.c.sec.snapshot()
	if token == "" || !hasSpace || spaceID == 0 {
		return errClientPeerSession
	}
	if p.alreadyRegistered(token, spaceID, hasSpace) {
		return nil
	}
	p.regMu.Lock()
	defer p.regMu.Unlock()
	// Re-check after acquiring the lock: another goroutine may have registered,
	// or the lifecycle may have closed / the ctx cancelled while waiting. The
	// session/space must also be re-snapshotted live: never register with
	// credentials that were stale before the lock was acquired.
	if p.closedState() {
		return errClientP2PClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	liveToken, liveSpace, liveHasSpace := p.c.sec.snapshot()
	if liveToken == "" || !liveHasSpace || liveSpace == 0 {
		return errClientPeerSession
	}
	if p.alreadyRegistered(liveToken, liveSpace, liveHasSpace) {
		return nil
	}
	return p.doRegistration(ctx, liveToken, liveSpace, liveHasSpace)
}

func (p *clientP2P) doRegistration(ctx context.Context, token string, spaceID uint64, hasSpace bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// 合并生命周期 ctx：CloseP2P 取消 p.ctx 时立即中止在途登记（HTTP 调用随 ctx
	// 取消返回），而非等调用方 ctx 自然结束——保证关停不悬空、最终状态不被写。
	ctx, cancel := p.mergeLifecycle(ctx)
	defer cancel()
	// proof 的 origin 取构造时固定的 master origin（peerControlDoPinned 的目标
	// 与它一致），绝不跟随可变的 c.MasterURL。
	origin, err := peerauth.CanonicalOrigin(p.c.pinnedMasterOrigin())
	if err != nil {
		return fmt.Errorf("client P2P origin: %w", err)
	}
	current, err := p.clientSelfRevision(ctx, token, spaceID, hasSpace)
	if err != nil {
		return err
	}
	for op := 0; op < 2; op++ {
		opID, err := newPeerOpID()
		if err != nil {
			return err
		}
		req := peerauth.ClientRegistration{
			PeerID:           p.runtime.PeerID(),
			PublicKey:        append([]byte(nil), p.runtime.PublicKey()...),
			ExpectedRevision: current,
			OperationID:      opID,
			NotAfter:         time.Now().UTC().Add(peerauth.EndpointLease),
		}
		proof, err := peerauth.ClientProof(origin, token, spaceID, req)
		if err != nil {
			return err
		}
		req.Signature, err = p.runtime.Sign(proof)
		if err != nil {
			return fmt.Errorf("sign client peer registration: %w", err)
		}
		raw, err := json.Marshal(req)
		if err != nil {
			return err
		}
		// Network retries reuse exactly this signed operation; the master
		// replays it idempotently, so the operation id never changes.
		for attempt := 0; attempt < 3; attempt++ {
			status, respRaw, requestErr := p.c.peerControlDoPinned(ctx, http.MethodPost, "/peers/client", raw, token, spaceID, hasSpace, clientPeerResponseLimit)
			if requestErr != nil {
				if attempt < 2 && ctx.Err() == nil {
					continue
				}
				return requestErr
			}
			switch {
			case status == http.StatusConflict:
				// CAS conflict: another writer advanced the revision. Re-read and
				// start a fresh operation (new op id, new expected revision).
				if current, err = p.clientSelfRevision(ctx, token, spaceID, hasSpace); err != nil {
					return err
				}
				goto nextOp
			case status < 200 || status >= 300:
				return &peerHTTPError{status: status, path: "/peers/client"}
			}
			var endpoint peerauth.Endpoint
			if err := decodePeerBytes(respRaw, &endpoint, clientPeerResponseLimit); err != nil {
				return err
			}
			if err := validateClientEndpointResponse(p, req, current, endpoint); err != nil {
				return err
			}
			// 原子落库：p.mu 与 c.sec.mu 以固定顺序（p.mu→c.sec.mu）在同一临界区
			// 内完成「会话快照比对 + 登记赋值」，会话切换无法插入比对与赋值之间；
			// 全局登记 CAS 已保 server 侧，这里只保本地：生命周期已关停，或会话/
			// space 在在途时已切换（旧快照），一律不写。
			p.mu.Lock()
			if p.closed {
				p.mu.Unlock()
				return errClientP2PClosed
			}
			if !p.c.sec.updateRegistrationIfCurrent(token, spaceID, hasSpace, func() {
				p.registeredRev = endpoint.Revision
				p.registeredOp = opID
				p.registeredUntil = endpoint.ValidUntil
				p.regSession = token
				p.regSpace = spaceID
			}) {
				p.mu.Unlock()
				return errors.New("client P2P registration snapshot changed")
			}
			p.mu.Unlock()
			return nil
		}
	nextOp:
	}
	return errors.New("client peer registration retry exhausted")
}

func validateClientEndpointResponse(p *clientP2P, req peerauth.ClientRegistration, expected uint64, endpoint peerauth.Endpoint) error {
	now := time.Now()
	if endpoint.Role != peerauth.RoleClient ||
		endpoint.PeerID != req.PeerID ||
		!bytes.Equal(endpoint.PublicKey, req.PublicKey) ||
		endpoint.NodeID != 0 ||
		endpoint.Addr != "" ||
		len(endpoint.Addresses) != 0 ||
		endpoint.BindingRevision != 0 ||
		endpoint.Revision != req.ExpectedRevision+1 ||
		!now.Before(endpoint.ValidUntil) ||
		endpoint.ValidUntil.After(req.NotAfter) {
		return errors.New("master returned a client peer endpoint that does not match this registration")
	}
	return nil
}

func (p *clientP2P) clientSelfRevision(ctx context.Context, token string, spaceID uint64, hasSpace bool) (uint64, error) {
	status, raw, err := p.c.peerControlDoPinned(ctx, http.MethodGet,
		"/peers/client-self?peer_id="+strings.TrimSpace(p.runtime.PeerID()), nil, token, spaceID, hasSpace, clientPeerResponseLimit)
	if err != nil {
		return 0, err
	}
	if status < 200 || status >= 300 {
		return 0, &peerHTTPError{status: status, path: "/peers/client-self"}
	}
	var state peerauth.ClientState
	if err := decodePeerBytes(raw, &state, clientPeerResponseLimit); err != nil {
		return 0, err
	}
	return state.Revision, nil
}

func (p *clientP2P) refreshDirectory(ctx context.Context, force bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	p.mu.RLock()
	fresh := !p.directoryAt.IsZero() && time.Since(p.directoryAt) < clientPeerFresh
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
	done := make(chan struct{})
	p.refreshDone = done
	p.refreshMu.Unlock()

	refreshCtx, cancel := context.WithTimeout(peerhttp.ControlContext(ctx), clientPeerRefreshTimeout)
	directory, err := p.c.fetchPeerDirectory(refreshCtx)
	cancel()
	if err == nil {
		err = p.runtime.SetDirectory(directory)
	}
	p.refreshMu.Lock()
	p.refreshErr = err
	if err == nil {
		p.mu.Lock()
		p.directory = clonePeerDirectory(directory)
		p.directoryAt = time.Now()
		p.mu.Unlock()
	}
	close(done)
	p.refreshDone = nil
	p.refreshMu.Unlock()
	return err
}

func (c *Client) fetchPeerDirectory(ctx context.Context) (peerauth.Directory, error) {
	var directory peerauth.Directory
	token, spaceID, hasSpace := c.sec.snapshot()
	status, raw, err := c.peerControlDoPinned(ctx, http.MethodGet, "/peers/directory", nil, token, spaceID, hasSpace, clientPeerDirectoryLimit)
	if err != nil {
		return directory, err
	}
	if status < 200 || status >= 300 {
		return directory, &peerHTTPError{status: status, path: "/peers/directory"}
	}
	if err := decodePeerBytes(raw, &directory, clientPeerDirectoryLimit); err != nil {
		return directory, err
	}
	if err := peerauth.ValidateDirectory(directory, time.Now()); err != nil {
		return directory, fmt.Errorf("validate peer directory: %w", err)
	}
	return directory, nil
}

func (p *clientP2P) nodeEndpoint(nodeAddr string) (peerauth.Endpoint, peerauth.Infrastructure, error) {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return peerauth.Endpoint{}, peerauth.Infrastructure{}, errClientP2PClosed
	}
	directory := clonePeerDirectory(p.directory)
	p.mu.RUnlock()
	for _, endpoint := range directory.Endpoints {
		if endpoint.Role == peerauth.RoleNode && endpoint.Addr == nodeAddr && time.Now().Before(endpoint.ValidUntil) {
			if !p.runtime.AllowedPeer(endpoint.PeerID) {
				return peerauth.Endpoint{}, peerauth.Infrastructure{}, fmt.Errorf("peer %s is not allowed", endpoint.PeerID)
			}
			return endpoint, directory.Infrastructure, nil
		}
	}
	return peerauth.Endpoint{}, peerauth.Infrastructure{}, fmt.Errorf("peer endpoint %q was not found", nodeAddr)
}

func (p *clientP2P) resolve(ctx context.Context, nodeAddr string) (peerhttp.PeerDialer, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := p.refreshDirectory(ctx, false); err != nil {
		return nil, fmt.Errorf("directory refresh: %w", err)
	}
	endpoint, infrastructure, err := p.nodeEndpoint(nodeAddr)
	if err != nil {
		if refreshErr := p.refreshDirectory(ctx, true); refreshErr != nil {
			return nil, refreshErr
		}
		endpoint, infrastructure, err = p.nodeEndpoint(nodeAddr)
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
		refreshCtx, cancel := context.WithTimeout(dialCtx, clientPeerRefreshTimeout)
		refreshErr := p.refreshDirectory(refreshCtx, true)
		cancel()
		if refreshErr != nil {
			return peerhttp.PeerDial{Err: fmt.Errorf("peer dial failed: %v; directory refresh: %w", firstErr, refreshErr)}
		}
		updated, infra, lookupErr := p.nodeEndpoint(nodeAddr)
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

// peerControlDoPinned performs a master control request carrying an explicit
// token/space snapshot, so the proof signed over the same snapshot always
// matches the request credentials — a concurrent session switch can never make
// the request carry different credentials than the operation it signs. The
// target origin is the transport's construction-time master (never the mutable
// c.MasterURL), so the session token only ever lands on that origin, and the
// path must be a peer control endpoint. It goes through the base transport
// directly (never the live-session secure transport re-injection), so it is
// safe to call from the registration path itself.
func (c *Client) peerControlDoPinned(ctx context.Context, method, path string, body []byte, token string, spaceID uint64, hasSpace bool, limit int64) (int, []byte, error) {
	// 目标 origin 用构造时固定的 secTransport.master，与签名 proof 的 origin 同源；
	// path 限定 peer 控制端点，方法/路径不由调用方自由指定。
	origin := c.pinnedMasterOrigin()
	if origin == "" || c.secTransport.base == nil {
		return 0, nil, errors.New("client P2P control requires a secure transport")
	}
	if !strings.HasPrefix(path, "/peers/") {
		return 0, nil, fmt.Errorf("client P2P control refuses non-peer path %q", path)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(peerhttp.ControlContext(ctx), 30*time.Second)
	defer cancel()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, origin+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if hasSpace {
		req.Header.Set(access.SpaceHeader, strconv.FormatUint(spaceID, 10))
	} else {
		req.Header.Del(access.SpaceHeader)
	}
	req, trace := peertrace.StartClient(req)
	resp, err := c.secTransport.base.RoundTrip(req)
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
// 控制响应 64KiB）。master 与节点必须对同一响应使用同一解释，否则 PeerID/revision
// 的不同解读在授权后获得不同含义。
func decodePeerBytes(raw []byte, out any, limit int64) error {
	return peerauth.DecodeJSONLimit(bytes.NewReader(raw), out, limit)
}

type peerHTTPError struct {
	status int
	path   string
}

func (e *peerHTTPError) Error() string {
	return fmt.Sprintf("peer control %s: status %d", e.path, e.status)
}

func newPeerOpID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func clonePeerDirectory(in peerauth.Directory) peerauth.Directory {
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
// It preserves the base transport's TLS verification; a peer request never
// bypasses the real handshake. The pinned master origin (construction-time
// secTransport.master, not the mutable c.MasterURL) is handed to the peer
// transport. EnableP2P calls it exactly once.
func (c *Client) SetPeerResolver(resolver peerhttp.Resolver) error {
	origin := c.pinnedMasterOrigin()
	if origin == "" {
		return errors.New("peer transport requires a secure HTTPS client")
	}
	if _, err := peerauth.CanonicalOrigin(origin); err != nil {
		return errors.New("peer transport requires a verified HTTPS master origin")
	}
	base, ok := c.secTransport.base.(*http.Transport)
	if !ok {
		return errors.New("peer transport must be configured once before requests")
	}
	transport, err := peerhttp.NewTransport(base, peerhttp.WithMaster(origin), peerhttp.WithResolver(resolver))
	if err != nil {
		return err
	}
	c.secTransport.base = transport
	return nil
}

// p2pPeerID returns the configured runtime peer id, or "" when P2P is off.
func (c *Client) p2pPeerID() string {
	c.p2pMu.Lock()
	defer c.p2pMu.Unlock()
	if c.p2p == nil {
		return ""
	}
	return c.p2p.runtime.PeerID()
}

func (c *Client) transferProbeTransport() http.RoundTripper {
	if c.secTransport != nil {
		return c.secTransport.base
	}
	if transport, ok := c.HTTP.Transport.(*auth.Transport); ok && transport.Fallback != nil {
		return transport.Fallback
	}
	if c.HTTP.Transport != nil {
		return c.HTTP.Transport
	}
	return http.DefaultTransport
}
