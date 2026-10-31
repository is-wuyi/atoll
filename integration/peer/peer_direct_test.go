package peer

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"atoll/client"
	"atoll/pkg/peerhttp"
	"atoll/pkg/peertransport"
)

// startClientPeer builds a runtime and enables the client's peer data plane.
// EnableP2P registers the client peer with the Master and fetches the directory,
// so it must be called after the node has published its endpoint.
func (m *peerMaster) startClientPeer(cl *clientSecure) *peertransport.Runtime {
	m.t.Helper()
	rt, err := peertransport.New(context.Background(), peertransport.Config{
		IdentityPath:    filepath.Join(m.t.TempDir(), "client.peer.key"),
		ListenAddresses: []string{"/ip4/0.0.0.0/tcp/0"},
		DirectTimeout:   10 * time.Second,
		RelayTimeout:    20 * time.Second,
	})
	if err != nil {
		m.t.Fatalf("client runtime: %v", err)
	}
	m.t.Cleanup(func() { _ = rt.Close() })
	if err := cl.c.EnableP2P(m.ctx, rt); err != nil {
		m.t.Fatalf("client EnableP2P: %v", err)
	}
	m.t.Cleanup(func() { _ = cl.c.CloseP2P() })
	return rt
}

// clientSecure 持有一个登录后的安全客户端及它的登录结果。
type clientSecure struct {
	c    *client.Client
	res  client.LoginResult
	rt   *peertransport.Runtime
	path string
}

// TestPeerDirectRoundTrip 走完整闭环：真实 Master + TLS + 节点经设备邀请注册
// + 用户经邀请注册 + 客户端 EnableP2P + 直连 Put/Get。节点先于客户端发布，
// 客户端新注册后立即 Put（不依赖任何缓存/等待）。
func TestPeerDirectRoundTrip(t *testing.T) {
	pki := newTestPKI(t)
	m := newPeerMaster(t, pki)

	spaceID := m.createUser("alice")
	if spaceID == 0 {
		t.Fatalf("alice space ID must be non-zero")
	}

	// 节点先注册并启动 peer 数据面（发布真实端点 + relay + 目录）。
	node := m.startNode(filepath.Join(t.TempDir(), "node"), m.nodeInvite())
	if node == nil || node.node == nil {
		t.Fatalf("node not started")
	}

	// 客户端登录并立即 EnableP2P（此时目录已含节点端点）。
	cl, res := m.login("alice")
	if res.User.ID == 0 {
		t.Fatalf("alice user ID must be non-zero")
	}
	cs := &clientSecure{c: cl, res: res}
	cs.rt = m.startClientPeer(cs)
	var observations []peerhttp.Observation
	var mu sync.Mutex
	base := cl.HTTP.Transport
	cl.HTTP.Transport = recoveryRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme+"://"+r.URL.Host == m.url {
			return base.RoundTrip(r)
		}
		ctx := peerhttp.WithPath(r.Context(), peerhttp.PathDirect)
		ctx = peerhttp.WithReporter(ctx, &peerhttp.Reporter{Observe: func(o peerhttp.Observation) {
			mu.Lock()
			observations = append(observations, o)
			mu.Unlock()
		}})
		return base.RoundTrip(r.Clone(ctx))
	})

	payload := []byte("peer-direct-roundtrip-payload-0123456789")
	cs.path = "/peer-data.bin"
	if _, err := cl.PutSmall(cs.path, payload, 1, false); err != nil {
		t.Fatalf("PutSmall via peer data plane: %v", err)
	}

	// 直连下载并校验内容。
	out := filepath.Join(t.TempDir(), "out.bin")
	if err := cl.Get(cs.path, out); err != nil {
		t.Fatalf("Get via peer data plane: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read download: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, payload)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(observations) < 2 {
		t.Fatalf("missing actual upload/read path observations: %v", observations)
	}
	for _, observed := range observations {
		if observed.Master || observed.Path != peerhttp.PathDirect || observed.Target != node.nodeDataAddr() {
			t.Fatalf("data did not use the required direct peer path: %+v", observed)
		}
	}
}
