// Package peer contains local, real-component integration tests for the P2P
// peer data plane: a genuine Master with a real bbolt store and TLS, real
// nodes, real user invite registration, real peer publication and directory,
// and the production node/client Runtime APIs. No fixture peer identities or
// hard-coded resolvers are used: every dial goes through the real runtime and
// the real Master directory.
package peer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"atoll/client"
	"atoll/internal/peertrace"
	"atoll/master"
	"atoll/master/meta"
	atollnode "atoll/node"
	"atoll/pkg/access"
	"atoll/pkg/contentcrypto"
	"atoll/pkg/peerauth"
	"atoll/pkg/peertransport"
	"atoll/pkg/types"
)

const (
	testAdminPassword = "admin-password-peer-123"
	testControlToken  = "control-token-peer-0123456789abcdef"
	testAdminToken    = "admin-token-peer-0123456789abcd"
	testUserPassword  = "user-password-peer-456"
)

// ---- real PKI (CA + leaf), no InsecureSkipVerify anywhere ----

type testPKI struct {
	caPool *x509.CertPool
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "atoll peer test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &testPKI{caPool: pool, caCert: caCert, caKey: caKey}
}

// leafCert issues a CA-signed leaf for the given hosts and returns the TLS cert
// plus PEM file paths suitable for http.Server.ServeTLS.
func (p *testPKI) leafCert(t *testing.T, hosts ...string) (tls.Certificate, string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	certFile := filepath.Join(t.TempDir(), "cert.pem")
	keyFile := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, certFile, keyFile
}

// verifiedTLS returns a client TLS config trusting the CA with no pinned
// ServerName (the request host binds the handshake) and no skip-verify.
func (p *testPKI) verifiedTLS() *tls.Config {
	return &tls.Config{RootCAs: p.caPool, MinVersion: tls.VersionTLS12}
}

// httpsClient returns an HTTP client trusting the CA for control-plane calls.
func (p *testPKI) httpsClient() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: p.verifiedTLS()}}
}

// ---- real Master with peer directory ----

type peerMaster struct {
	t           *testing.T
	pki         *testPKI
	store       *meta.Store
	srv         *master.Server
	url         string // https://host:port
	ctx         context.Context
	diagnostics *peerDiagnostics
}

// masterOpts 控制 master 装配选项：contentKEK 开启内容加密（AEAD 写路径），
// transferPlanning 开启写转移计划（节点间 replicate 经 peer 数据面 fan-out），
// maxReplicas 覆盖新写布局搜索上限（0 保持默认 4；测试 fixture 用）。
type masterOpts struct {
	contentKEK       *contentcrypto.KEK
	transferPlanning bool
	maxReplicas      int
}

// newPeerMaster builds a verified-TLS Master with security, write planning and
// the peer directory all enabled. The listener is bound first so the real port
// feeds the exact HTTPS origin; the runtime is attached before any handler is
// served and before StartSecurity auto-starts peer publishing.
func newPeerMaster(t *testing.T, pki *testPKI) *peerMaster {
	return newPeerMasterOpts(t, pki, masterOpts{})
}

// newPeerMasterOpts is newPeerMaster with explicit options (KEK, transfer plan).
func newPeerMasterOpts(t *testing.T, pki *testPKI, o masterOpts) *peerMaster {
	t.Helper()
	diagnostics := newPeerDiagnostics(t)
	dir := t.TempDir()
	store, err := meta.Open(filepath.Join(dir, "meta.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	if _, _, err := store.BootstrapSecurity("admin", testAdminPassword, time.Now()); err != nil {
		t.Fatalf("BootstrapSecurity: %v", err)
	}
	srv := master.NewServer(store, time.Hour)
	srv.SetAdminToken(testAdminToken)
	srv.SetTLS(pki.verifiedTLS())
	if o.contentKEK != nil {
		srv.SetContentKEK(o.contentKEK)
	}
	if err := srv.EnableSecurity(master.SecurityConfig{ControlToken: testControlToken, AllowInsecure: false}); err != nil {
		t.Fatalf("EnableSecurity: %v", err)
	}
	maxReplicas := o.maxReplicas
	if maxReplicas == 0 {
		maxReplicas = 4
	}
	if err := srv.EnableWritePlanning(master.WritePlanningConfig{MaxReplicas: maxReplicas, TransferPlanning: o.transferPlanning}); err != nil {
		t.Fatalf("EnableWritePlanning: %v", err)
	}

	// Bind the real listener to get the port, then finalize origin + runtime.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("master listen: %v", err)
	}
	origin := "https://" + ln.Addr().String()
	rt, err := peertransport.New(context.Background(), peertransport.Config{
		IdentityPath:    filepath.Join(dir, "master.peer.key"),
		ListenAddresses: []string{"/ip4/0.0.0.0/tcp/0"},
		DirectTimeout:   10 * time.Second,
		RelayTimeout:    20 * time.Second,
	})
	if err != nil {
		t.Fatalf("master runtime: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	if err := srv.EnablePeerDirectory(master.PeerConfig{
		Origin: origin,
		Infrastructure: peerauth.Infrastructure{
			PeerID: rt.PeerID(), PublicKey: rt.PublicKey(), Addresses: rt.Addresses(), Relay: true,
		},
	}); err != nil {
		t.Fatalf("EnablePeerDirectory: %v", err)
	}
	if err := srv.SetPeerRuntime(rt); err != nil {
		t.Fatalf("SetPeerRuntime: %v", err)
	}

	ctx, cancel := context.WithCancel(diagnostics.context(context.Background()))
	handler := peertrace.Handler(srv.Handler(), diagnostics.observe)
	srv.AttachSecureTransports()
	srv.StartSecurity(ctx)
	t.Cleanup(srv.WaitSecurity)

	_, certFile, keyFile := pki.leafCert(t, "127.0.0.1")
	srvHTTP := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srvHTTP.ServeTLS(ln, certFile, keyFile) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srvHTTP.Shutdown(ctx)
	})

	// Master peer data plane: serves the same handler over the runtime's raw
	// stream listener so nodes/clients can dial the Master as relay and exchange
	// peerhttp traffic. ConnContext installs the real source peer id.
	peerLn, err := rt.Listener()
	if err != nil {
		t.Fatalf("master peer listener: %v", err)
	}
	peerHTTP := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, ConnContext: rt.ConnContext}
	go func() { _ = peerHTTP.ServeTLS(peerLn, certFile, keyFile) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = peerHTTP.Shutdown(ctx)
	})

	// cancel 必须最后注册：cleanup 按 LIFO 执行，先 cancel 停掉后台循环，
	// 再 WaitSecurity 等待其退出，最后才关 runtime/store。
	t.Cleanup(cancel)

	return &peerMaster{t: t, pki: pki, store: store, srv: srv, url: "https://" + ln.Addr().String(), ctx: ctx, diagnostics: diagnostics}
}

// ---- HTTP control-plane helpers (user invite/register/login over the wire) ----

func (m *peerMaster) rawJSON(method, path, token string, spaceID uint64, body any) *http.Response {
	m.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			m.t.Fatalf("marshal: %v", err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, m.url+path, rd)
	if err != nil {
		m.t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if spaceID != 0 {
		req.Header.Set(access.SpaceHeader, fmt.Sprintf("%d", spaceID))
	}
	resp, err := m.pki.httpsClient().Do(req)
	if err != nil {
		m.t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// adminSessionToken logs in as the bootstrapped admin and returns a real user
// session token (us1). /auth/invites requires a platform-admin session, not the
// server's admin token (which only covers /admin/* destructive paths).
func (m *peerMaster) adminSessionToken() string {
	m.t.Helper()
	cl, err := client.NewSecure(m.url, m.pki.verifiedTLS(), false)
	if err != nil {
		m.t.Fatalf("admin NewSecure: %v", err)
	}
	res, err := cl.Login(context.Background(), "admin", testAdminPassword)
	if err != nil {
		m.t.Fatalf("admin login: %v", err)
	}
	return res.Token
}

// createUser invites and registers a user over HTTP, returning its space ID.
func (m *peerMaster) createUser(username string) uint64 {
	m.t.Helper()
	adminToken := m.adminSessionToken()
	resp := m.rawJSON(http.MethodPost, "/auth/invites", adminToken, 0,
		map[string]any{"expires_at": time.Now().Add(time.Hour)})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		m.t.Fatalf("create invite: %d %s", resp.StatusCode, body)
	}
	var inv struct {
		Invite string `json:"invite"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&inv); err != nil {
		m.t.Fatalf("decode invite: %v", err)
	}
	resp.Body.Close()

	resp = m.rawJSON(http.MethodPost, "/auth/register", "", 0, map[string]string{
		"invite": inv.Invite, "username": username, "password": testUserPassword,
	})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		m.t.Fatalf("register: %d %s", resp.StatusCode, body)
	}
	var reg struct {
		Space client.SpaceInfo `json:"space"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		m.t.Fatalf("decode register: %v", err)
	}
	resp.Body.Close()
	return reg.Space.ID
}

// login returns a real secure client with the user's session and space set.
func (m *peerMaster) login(username string) (*client.Client, client.LoginResult) {
	m.t.Helper()
	cl, err := client.NewSecure(m.url, m.pki.verifiedTLS(), false)
	if err != nil {
		m.t.Fatalf("NewSecure: %v", err)
	}
	res, err := cl.Login(context.Background(), username, testUserPassword)
	if err != nil {
		m.t.Fatalf("login: %v", err)
	}
	// 登录响应不一定携带默认 space（仅 register 响应保证）；回退到用户的个人
	// space ID，确保 UseSpace 始终绑定真实 space。
	spaceID := res.User.PersonalSpaceID
	if res.Space != nil {
		spaceID = res.Space.ID
	}
	if spaceID == 0 {
		m.t.Fatalf("login %s returned no space", username)
	}
	if err := cl.UseSpace(spaceID); err != nil {
		m.t.Fatalf("UseSpace: %v", err)
	}
	return cl, res
}

// ---- real node with peer data plane ----

type peerNode struct {
	node     *atollnode.Node
	rt       peertransport.RuntimeAPI
	addr     string // 节点向 master 注册的 data 监听地址（advertise，逻辑地址）
	dataLn   net.Listener
	dataHTTP *http.Server
	peerHTTP *http.Server
	closed   bool
}

// nodeDataAddr 返回节点向 master 声明的 data 监听地址（host:port）。这是逻辑
// 地址：跨重启稳定（master 按 addr 复用 NodeID），而 peer transport 多地址会变。
func (p *peerNode) nodeDataAddr() string { return p.addr }

// closeNode 关闭本 harness 装配的部分：data/peer HTTPS 服务器、CloseP2P
// （取消并 join 节点 heartbeat/renew/401-kick 循环与 P2P publisher）与 peer
// runtime。幂等；t.Cleanup 与测试内显式重启调用都可安全触发。重启测试先
// closeNode 旧实例，旧 transport 多地址随之失效，客户端缓存的旧地址拨号失败
// 即触发强刷。
func (m *peerMaster) closeNode(pn *peerNode) {
	m.t.Helper()
	if pn == nil || pn.closed {
		return
	}
	pn.closed = true
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if pn.dataHTTP != nil {
		_ = pn.dataHTTP.Shutdown(ctx)
	}
	if pn.peerHTTP != nil {
		_ = pn.peerHTTP.Shutdown(ctx)
	}
	if pn.dataLn != nil {
		_ = pn.dataLn.Close()
	}
	if pn.node != nil {
		_ = pn.node.CloseP2P()
	}
	if pn.rt != nil {
		_ = pn.rt.Close()
	}
}

// reqRecord 记录节点处理器收到的一个请求。source 是从流上读出的真实源 peer
// 身份（peerauth.SourcePeerID，经 ConnContext 注入，非 header）；data 面请求为空。
type reqRecord struct {
	method string
	path   string
	source string
}

// nodeLedger 并发安全地记录到达节点处理器的请求：handler goroutine 写，测试经
// snapshot 读副本，读写绝不裸并发。
type nodeLedger struct {
	mu   sync.Mutex
	recs []reqRecord
}

func (l *nodeLedger) add(method, path, source string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recs = append(l.recs, reqRecord{method: method, path: path, source: source})
}

// snapshot 返回记录副本，调用方可安全遍历与比对。
func (l *nodeLedger) snapshot() []reqRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]reqRecord(nil), l.recs...)
}

func (l *nodeLedger) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recs)
}

// hasMethodPath 报告是否存在 method + path 前缀匹配的记录。
func (l *nodeLedger) hasMethodPath(method, prefix string) bool {
	for _, r := range l.snapshot() {
		if r.method == method && strings.HasPrefix(r.path, prefix) {
			return true
		}
	}
	return false
}

// nodeOpts 控制节点装配：peerCertSelfSigned 让 peer 监听器出示非 CA 签发的
// 自签证书（bad-cert 负向）；transferBudget 在 Register 前配置节点传输预算
// （写转移计划需要）；ledger 记录每个到达节点 handler 的请求（method/path/
// 真实源 peer id），用于证明节点间 replicate 确实到达副本节点且源是节点而非
// 客户端（区别于客户端直传多 PUT）；handlerWrapper 可选，在 ledger 之外再包
// 一层（故障注入用），两个 listener 共用同一最终 handler 实例，普通节点为 nil。
type nodeOpts struct {
	peerCertSelfSigned bool
	transferBudget     *types.TransferBudget
	ledger             *nodeLedger
	handlerWrapper     func(http.Handler) http.Handler
}

// ledgedHandler 包一层并发安全记录 handler；未配置 ledger 时原样返回。
func (m *peerMaster) ledgedHandler(o nodeOpts, inner http.Handler) http.Handler {
	if o.ledger == nil {
		return inner
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.ledger.add(r.Method, r.URL.Path, peerauth.SourcePeerID(r.Context()))
		inner.ServeHTTP(w, r)
	})
}

// startNode builds a verified-TLS node, enables its peer runtime, registers and
// starts the peer data plane. The data HTTPS listener is bound first so the
// advertise address is the real one the Master records.
func (m *peerMaster) startNode(dataDir, invite string) *peerNode {
	return m.startNodeOpts(dataDir, invite, nodeOpts{})
}

// startNodeOpts is startNode with explicit options.
func (m *peerMaster) startNodeOpts(dataDir, invite string, o nodeOpts) *peerNode {
	m.t.Helper()
	dataLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		m.t.Fatalf("node data listen: %v", err)
	}
	return m.startNodeOn(dataDir, invite, o, dataLn)
}

// startNodeAddr 在指定的固定 data 逻辑地址上启动节点（重启测试：复用同一逻辑
// 地址，master 按 addr 复用 NodeID，而 peer transport 绑定新端口）。
func (m *peerMaster) startNodeAddr(dataDir, invite, addr string, o nodeOpts) *peerNode {
	m.t.Helper()
	dataLn, err := net.Listen("tcp", addr)
	if err != nil {
		m.t.Fatalf("node data listen on %s: %v", addr, err)
	}
	return m.startNodeOn(dataDir, invite, o, dataLn)
}

// startNodeOn 在调用方提供的 data 监听器上装配并启动一个真实节点。
func (m *peerMaster) startNodeOn(dataDir, invite string, o nodeOpts, dataLn net.Listener) *peerNode {
	m.t.Helper()
	// dataLn 一进 harness 即登记关闭：其后任何一步 Fatalf 都不泄漏监听。
	m.t.Cleanup(func() { _ = dataLn.Close() })
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		m.t.Fatalf("node dir: %v", err)
	}
	n := atollnode.New(filepath.Join(dataDir, "data"), m.url, dataLn.Addr().String(), 1<<30)
	// 节点创建即登记 CloseP2P：它取消并 join heartbeat/renew 循环，StartP2P
	// 失败的节点不得用 5s 心跳贯穿后续测试。
	m.t.Cleanup(func() { _ = n.CloseP2P() })
	n.SetTLS(m.pki.verifiedTLS())
	if err := n.EnableSecurity(filepath.Join(dataDir, "identity.key"), invite, false); err != nil {
		m.t.Fatalf("node EnableSecurity: %v", err)
	}
	if o.transferBudget != nil {
		if err := n.ConfigureTransferBudget(*o.transferBudget); err != nil {
			m.t.Fatalf("node transfer budget: %v", err)
		}
	}
	rt, err := peertransport.New(m.ctx, peertransport.Config{
		IdentityPath:    filepath.Join(dataDir, "peer.key"),
		ListenAddresses: []string{"/ip4/0.0.0.0/tcp/0"},
		DirectTimeout:   10 * time.Second,
		RelayTimeout:    20 * time.Second,
	})
	if err != nil {
		m.t.Fatalf("node runtime: %v", err)
	}
	m.t.Cleanup(func() { _ = rt.Close() })
	if err := n.EnableP2P(m.ctx, rt); err != nil {
		m.t.Fatalf("node EnableP2P: %v", err)
	}
	if err := n.Register(); err != nil {
		m.t.Fatalf("node Register: %v", err)
	}
	if err := n.StartP2P(m.ctx); err != nil {
		m.t.Fatalf("node StartP2P: %v", err)
	}

	pn := &peerNode{node: n, rt: rt, addr: dataLn.Addr().String(), dataLn: dataLn}

	_, certFile, keyFile := m.pki.leafCert(m.t, "127.0.0.1")
	// 两个 listener 共用同一最终 handler 实例（n.Handler → ledger → wrapper），
	// 故障注入 wrapper 也因此对 data/peer 两面一致生效。
	handler := m.ledgedHandler(o, n.Handler())
	if o.handlerWrapper != nil {
		handler = o.handlerWrapper(handler)
	}
	pn.dataHTTP = &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = pn.dataHTTP.ServeTLS(dataLn, certFile, keyFile) }()

	// Peer data plane: the runtime's own stream listener serves the same handler
	// over a fresh TLS config (never shared with the lazy http2 data server).
	// ConnContext installs the real source peer id for ticket verification.
	// peerCertSelfSigned presents a cert not signed by the CA so the dialing
	// side's handshake (which trusts the CA) must reject it.
	peerCertFile, peerKeyFile := certFile, keyFile
	if o.peerCertSelfSigned {
		peerCertFile, peerKeyFile = m.pki.selfSignedCert(m.t)
	}
	peerLn, err := rt.Listener()
	if err != nil {
		m.t.Fatalf("peer listener: %v", err)
	}
	pn.peerHTTP = &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, ConnContext: rt.ConnContext}
	go func() { _ = pn.peerHTTP.ServeTLS(peerLn, peerCertFile, peerKeyFile) }()

	m.t.Cleanup(func() { m.closeNode(pn) })
	return pn
}

// selfSignedCert 生成一个不由测试 CA 签发的自签证书（bad-cert 负向用）。
func (p *testPKI) selfSignedCert(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("self key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "self-signed-peer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create self-signed: %v", err)
	}
	certFile := filepath.Join(t.TempDir(), "badcert.pem")
	keyFile := filepath.Join(t.TempDir(), "badkey.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func (m *peerMaster) nodeInvite() string {
	m.t.Helper()
	code, err := m.store.CreateDeviceInvite(time.Now().Add(time.Hour), time.Now())
	if err != nil {
		m.t.Fatalf("CreateDeviceInvite: %v", err)
	}
	return code
}
