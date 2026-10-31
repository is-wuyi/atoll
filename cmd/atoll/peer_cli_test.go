package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"atoll/client"
	"atoll/master/meta"
	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
	"atoll/pkg/peertransport"
)

// stubNode records StartP2P call count; it deliberately lacks EnableP2P so the
// nodePeerStarter interface makes a double-EnableP2P impossible to compile.
type stubNode struct {
	started int
}

func (s *stubNode) StartP2P(context.Context) error { s.started++; return nil }
func (s *stubNode) Handler() http.Handler          { return http.NotFoundHandler() }

// testPeerCert writes a self-signed cert/key pair to a temp dir and returns paths.
func testPeerCert(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "cli-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// TestNodeStartP2PSequence verifies the node P2P assembly contract: the caller
// owns EnableP2P before Register, and nodeStartP2P must call StartP2P exactly
// once (never EnableP2P again). A re-added EnableP2P in the helper would not
// compile against nodePeerStarter, and the sequence stub catches it at runtime.
func TestNodeStartP2PSequence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rt, err := peertransport.New(ctx, peertransport.Config{
		IdentityPath:    filepath.Join(t.TempDir(), "peer.key"),
		ListenAddresses: []string{"/ip4/0.0.0.0/tcp/0"},
		DirectTimeout:   5 * time.Second,
		RelayTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("runtime: %v", err)
	}
	defer rt.Close()

	stub := &stubNode{}
	certFile, keyFile := testPeerCert(t)
	ps, err := nodeStartP2P(ctx, rt, stub, certFile, keyFile)
	if err != nil {
		t.Fatalf("nodeStartP2P: %v", err)
	}
	if stub.started != 1 {
		t.Fatalf("StartP2P calls = %d, want 1", stub.started)
	}
	if ps == nil {
		t.Fatalf("nodeStartP2P returned nil peerServe")
	}
	if err := ps.Close(); err != nil {
		t.Fatalf("peerServe close: %v", err)
	}
}

// pairRuntimes builds two interconnected runtimes on loopback with mutual
// authorization so a direct dial succeeds in both directions.
func pairRuntimes(t *testing.T, ctx context.Context) (srv, cli *peertransport.Runtime) {
	t.Helper()
	mk := func(name string) *peertransport.Runtime {
		t.Helper()
		rt, err := peertransport.New(ctx, peertransport.Config{
			IdentityPath:    filepath.Join(t.TempDir(), name+".key"),
			ListenAddresses: []string{"/ip4/127.0.0.1/tcp/0"},
			DirectTimeout:   5 * time.Second,
			RelayTimeout:    5 * time.Second,
		})
		if err != nil {
			t.Fatalf("runtime %s: %v", name, err)
		}
		t.Cleanup(func() { _ = rt.Close() })
		return rt
	}
	srv, cli = mk("srv"), mk("cli")
	srv.SetAuthorizer(func(_ context.Context, id string) bool { return id == cli.PeerID() })
	cli.SetAuthorizer(func(_ context.Context, id string) bool { return id == srv.PeerID() })
	return srv, cli
}

// TestStartPeerListenerServesRealTLS 真实 peer 流 + 真实外层 TLS：处理器断言
// 源身份来自流（ConnContext）；Close 后 Serve goroutine 有界退出且幂等。
func TestStartPeerListenerServesRealTLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srvRT, cliRT := pairRuntimes(t, ctx)

	certFile, keyFile := testPeerCert(t)
	leaf, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load test cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf.Leaf)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, peerauth.SourcePeerID(r.Context()))
	})
	ps, err := startPeerListener(srvRT, handler, certFile, keyFile)
	if err != nil {
		t.Fatalf("startPeerListener: %v", err)
	}

	ep := peerauth.Endpoint{
		PeerID:     srvRT.PeerID(),
		PublicKey:  srvRT.PublicKey(),
		Addresses:  srvRT.Addresses(),
		ValidUntil: time.Now().Add(time.Minute),
	}
	dres := cliRT.Dial(ctx, ep, peerauth.Infrastructure{}, peerhttp.PathDirect)
	if dres.Err != nil || dres.Conn == nil {
		t.Fatalf("peer dial: err=%v conn=%v", dres.Err, dres.Conn)
	}
	defer dres.Conn.Close()

	tc := tls.Client(dres.Conn, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
	if err := tc.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := io.WriteString(tc, "GET /who HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != cliRT.PeerID() {
		t.Fatalf("source peer id over the stream = %q, want %q", body, cliRT.PeerID())
	}

	done := ps.serveDone
	if err := ps.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("serve goroutine did not exit after bounded close")
	}
	// Close 必须幂等：二次关闭不得 panic 或报错。
	if err := ps.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

// TestStartPeerListenerBadCertFailsSynchronously 坏证书必须在 startPeerListener
// 返回前报错——绝不允许异步只 log、CLI 却已报告成功继续运行。
func TestStartPeerListenerBadCertFailsSynchronously(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srvRT, _ := pairRuntimes(t, ctx)

	t.Run("garbage cert", func(t *testing.T) {
		dir := t.TempDir()
		certFile := filepath.Join(dir, "cert.pem")
		keyFile := filepath.Join(dir, "key.pem")
		if err := os.WriteFile(certFile, []byte("not a pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, []byte("not a pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		ps, err := startPeerListener(srvRT, http.NotFoundHandler(), certFile, keyFile)
		if err == nil {
			if ps != nil {
				_ = ps.Close()
			}
			t.Fatal("garbage cert must fail synchronously")
		}
		if !strings.Contains(err.Error(), "peer listener certificate") {
			t.Fatalf("error should name the peer listener certificate: %v", err)
		}
	})

	t.Run("cert key mismatch", func(t *testing.T) {
		c1, k1 := testPeerCert(t)
		c2, k2 := testPeerCert(t)
		ps, err := startPeerListener(srvRT, http.NotFoundHandler(), c1, k2)
		if err == nil {
			if ps != nil {
				_ = ps.Close()
			}
			_ = c1
			_ = k1
			_ = c2
			t.Fatal("cert/key mismatch must fail synchronously")
		}
		_ = k1
		_ = c2
	})
}

// TestRunNodeP2PFailureClosesRuntime 原泄漏窗口：runtime 已创建（身份文件已
// 落盘）后 Register 失败，全路径 defer 必须关闭 runtime 并以 1 退出。
func TestRunNodeP2PFailureClosesRuntime(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := testPeerCert(t)
	t.Setenv("ATOLL_NODE_INVITE", "") // 首次入网无邀请码 → EnableSecurity 失败
	dataDir := filepath.Join(dir, "data")
	args := []string{"node",
		"-master", "https://127.0.0.1:1",
		"-listen", "127.0.0.1:0",
		"-data-dir", dataDir,
		"-secure",
		"-tls-cert", certFile, "-tls-key", keyFile,
		"-p2p", "-p2p-listen", "/ip4/127.0.0.1/tcp/0",
	}
	var stderr bytes.Buffer
	code := run(args, io.Discard, &stderr)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, stderr.String())
	}
	// 无邀请码的新身份允许静默创建；失败落在 Register（不可达 master）——
	// 这正是原泄漏窗口：runtime 已创建、旧 defer 尚未注册。
	if !strings.Contains(stderr.String(), "注册 master 失败") {
		t.Fatalf("expected the register failure, got: %s", stderr.String())
	}
	// 身份文件存在证明失败发生在 runtime.New 之后（正是原泄漏窗口）。
	if _, err := os.Stat(filepath.Join(dataDir, "peer.key")); err != nil {
		t.Fatalf("peer identity file should exist (runtime was created before the failure): %v", err)
	}
}

// TestRunMountP2PFailureClosesBeforeFUSE mount 的 peer 装配在 FUSE 之前：登记
// 失败必须快速退出 1，不触碰 FUSE 路径。
func TestRunMountP2PFailureClosesBeforeFUSE(t *testing.T) {
	t.Setenv("ATOLL_SESSION", "sess")
	dir := t.TempDir()
	mountPoint := filepath.Join(dir, "mnt")
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		t.Fatal(err)
	}
	args := []string{"mount",
		"-master", "https://127.0.0.1:1",
		"-session-env", "ATOLL_SESSION", "-space", "7",
		"-cache", filepath.Join(dir, "cache"),
		"-p2p", "-p2p-listen", "/ip4/127.0.0.1/tcp/0",
		mountPoint,
	}
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- run(args, io.Discard, &stderr) }()
	select {
	case code := <-done:
		if code != 1 {
			t.Fatalf("exit = %d, want 1 (stderr: %s)", code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "atoll mount") {
			t.Fatalf("expected mount-scope error, got: %s", stderr.String())
		}
		// 失败发生在 peer 登记层：错误必须与 peer 相关，证明 FUSE 未被触及。
		if !strings.Contains(stderr.String(), "peer") {
			t.Fatalf("expected a peer-plane failure before FUSE, got: %s", stderr.String())
		}
	case <-time.After(45 * time.Second):
		t.Fatal("run mount did not return; peer failure path must stay bounded")
	}
}

// TestRunP2PPreflightDispatchSmoke 经真实 run() 入口验证 -p2p 预检拒绝路径与
// 退出码，而不是只测 flag 解析函数。
func TestRunP2PPreflightDispatchSmoke(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"master p2p without secure", []string{"master", "-p2p", "-p2p-origin", "https://127.0.0.1:9420"}, 1},
		{"node p2p without secure", []string{"node", "-p2p"}, 1},
		{"node p2p without certs", []string{"node", "-p2p", "-secure"}, 1},
		{"put p2p without session", []string{"put", "-p2p", "a", "b"}, 1},
		{"get p2p without session", []string{"get", "-p2p", "a", "b"}, 1},
		{"mount p2p without session", []string{"mount", "-p2p", "nowhere"}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			code := run(tc.args, io.Discard, &stderr)
			if code != tc.want {
				t.Fatalf("exit = %d, want %d (stderr: %s)", code, tc.want, stderr.String())
			}
		})
	}
}

// TestClientEnableP2PFailureKeepsIdentityWire 显式 -p2p-identity 必须真正传入
// runtime 配置（身份文件被创建即为证据）；失败路径不得返回 runtime。
func TestClientEnableP2PFailureKeepsIdentityWire(t *testing.T) {
	dir := t.TempDir()
	idFile := filepath.Join(dir, "client-identity.key")
	fs := flag.NewFlagSet("p2p-cli-test", flag.ContinueOnError)
	p := addP2PFlags(fs)
	if err := fs.Parse([]string{"-p2p", "-p2p-identity", idFile}); err != nil {
		t.Fatal(err)
	}
	if p.identityPath("") != idFile {
		t.Fatalf("identityPath = %q, want %q", p.identityPath(""), idFile)
	}
	// 未设 -p2p-identity 时用户客户端身份为空（临时身份），这是 CLI 契约。
	q := addP2PFlags(flag.NewFlagSet("p2p-cli-test2", flag.ContinueOnError))
	if err := q.listen.Set("/ip4/127.0.0.1/tcp/0"); err != nil {
		t.Fatal(err)
	}
	if q.identityPath("") != "" {
		t.Fatalf("ephemeral identity path = %q, want empty", q.identityPath(""))
	}

	cl, err := client.NewSecure("https://127.0.0.1:1", nil, false)
	if err != nil {
		t.Fatalf("NewSecure: %v", err)
	}
	rt, err := clientEnableP2P(context.Background(), p, cl)
	if err == nil {
		if rt != nil {
			_ = rt.Close()
		}
		t.Fatal("enable against an unreachable master must fail (no session)")
	}
	if rt != nil {
		t.Fatal("failed enable must not return a runtime")
	}
	if _, statErr := os.Stat(idFile); statErr != nil {
		t.Fatalf("explicit identity file should have been created by the runtime: %v", statErr)
	}
	// closeClientP2P 必须容忍 nil 组合，绝不 panic。
	closeClientP2P(nil, nil)
	closeClientP2P(cl, nil)
}

// 编译面守卫：clientEnableP2P/closeClientP2P 只允许依赖这里声明的最小 client
// 表面（EnableP2P/CloseP2P），防止 helper 意外扩大耦合。
var (
	_ clientP2P = (interface {
		EnableP2P(context.Context, peertransport.RuntimeAPI) error
		CloseP2P() error
	})(nil)
	_ = peerhttp.PathDirect
)

// TestRunMasterP2PIdentityFlagWiring 经真实 run() 验证 master 的 -p2p-identity
// 真正传入 runtime：identity 父路径是普通文件 → 显式 flag 必然在 peer runtime
// 创建时报错退出 1；若 flag 被忽略（退回 dbPath+".peer.key"，可创建），master
// 会继续装配并阻塞在 serve，测试超时失败。
func TestRunMasterP2PIdentityFlagWiring(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "atoll.db")
	store, err := meta.Open(dbPath)
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	if _, _, err := store.BootstrapSecurity("admin", "bootstrap-password-123", time.Now()); err != nil {
		t.Fatalf("BootstrapSecurity: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("store close: %v", err)
	}

	certFile, keyFile := testPeerCert(t)
	t.Setenv("ATOLL_CONTROL_TOKEN", "control-token-atoll-0123456789abcdef")
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(blocker, "m.peer.key")

	args := []string{"master",
		"-listen", "127.0.0.1:0",
		"-db", dbPath,
		"-secure",
		"-tls-cert", certFile, "-tls-key", keyFile,
		"-write-planning",
		"-p2p", "-p2p-origin", "https://127.0.0.1:9420",
		"-p2p-identity", identity,
	}
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- run(args, io.Discard, &stderr) }()
	select {
	case code := <-done:
		if code != 1 {
			t.Fatalf("exit = %d, want 1 (stderr: %s)", code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "peer runtime") {
			t.Fatalf("expected the peer runtime identity failure, got: %s", stderr.String())
		}
	case <-time.After(45 * time.Second):
		t.Fatal("master ignored -p2p-identity and kept assembling/serving")
	}
}
