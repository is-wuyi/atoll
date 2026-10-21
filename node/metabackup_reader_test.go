package node

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/contentcrypto"
	"atoll/pkg/metacrypto"
)

// newPinnedTestNode 起 advertise=真实监听地址的 secure 节点（wrapHandler 的
// audience 是 advertise，必须与客户端实际访问的 host 一致）。
func newPinnedTestNode(t *testing.T, fm *fakeSecMaster, invite string) (*Node, *httptest.Server, string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host := l.Addr().String()
	n := New(t.TempDir(), fm.srv.URL, host, 1<<30)
	if err := n.EnableSecurity(t.TempDir()+"/identity.key", invite, true); err != nil {
		t.Fatal(err)
	}
	mustRegister(t, n)
	ts := httptest.NewUnstartedServer(n.Handler())
	ts.Listener = l
	ts.Start()
	t.Cleanup(ts.Close)
	return n, ts, host
}

func accessTicketRequestFor(method, path, host string) access.TicketRequest {
	return access.TicketRequest{NodeAddr: host, Method: method, Path: path}
}

// 中心全损只读恢复 E2E（节点级）：pin 恢复公钥后，仅持恢复签名（无任何在线
// 票据、master 不可达）的读取方可 GET /meta-backup；错误签名/跨主机/带其它
// 凭据一律拒绝；写方法不可签。
func TestMetadataReaderOfflineRecovery(t *testing.T) {
	fm := newFakeSecMaster(t)
	n, _, host := newPinnedTestNode(t, fm, "invite-1")

	kek, err := contentcrypto.NewKEK("reader-node-test")
	if err != nil {
		t.Fatal(err)
	}
	c, err := metacrypto.New(kek)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.sec.SetMetadataReader(c.ReaderInfo()); err != nil {
		t.Fatal(err)
	}

	now := time.Now()

	// 1) 无签名：401。
	resp, err := http.Get("http://" + host + "/meta-backup/manifest")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned read = %d, want 401", resp.StatusCode)
	}

	// 2) 正确签名：200（manifest 不存在也应是 404 而非 401——验签已过）。
	req, _ := http.NewRequest(http.MethodGet, "http://"+host+"/meta-backup/manifest", nil)
	req.Host = host
	if err := c.SignRead(req, host, now); err != nil {
		t.Fatal(err)
	}
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("signed read = %d, want 404 (authorized, blob absent)", resp2.StatusCode)
	}

	// 3) 写方法不可签（恢复通道只读）。
	put, _ := http.NewRequest(http.MethodPut, "http://"+host+"/meta-backup/manifest", nil)
	if err := c.SignRead(put, host, now); err == nil {
		t.Fatal("write method was signable")
	}

	// 4) 跨主机重放：拒绝。
	other := httptest.NewRequest(http.MethodGet, "http://other-host:9421/meta-backup/manifest", nil)
	other.Header.Set(metacrypto.ReaderHeader, req.Header.Get(metacrypto.ReaderHeader))
	if err := metacrypto.VerifyRead(c.ReaderInfo(), other, "other-host:9421", now); err == nil {
		t.Fatal("cross-host proof verified")
	}

	// 5) 混入 Authorization：拒绝。
	req4, _ := http.NewRequest(http.MethodGet, "http://"+host+"/meta-backup/manifest", nil)
	if err := c.SignRead(req4, host, now); err != nil {
		t.Fatal(err)
	}
	req4.Header.Set("Authorization", "Bearer anything")
	resp4, err := http.DefaultClient.Do(req4)
	if err != nil {
		t.Fatal(err)
	}
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusUnauthorized {
		t.Fatalf("proof with injected credentials = %d, want 401", resp4.StatusCode)
	}

	// 6) 未 pin 的节点：恢复签名也拒绝（公钥不在，无法验签）。
	fm2 := newFakeSecMaster(t)
	_, _, host2 := newPinnedTestNode(t, fm2, "invite-2")
	req5, _ := http.NewRequest(http.MethodGet, "http://"+host2+"/meta-backup/manifest", nil)
	req5.Host = host2
	if err := c.SignRead(req5, host2, now); err != nil {
		t.Fatal(err)
	}
	resp5, err := http.DefaultClient.Do(req5)
	if err != nil {
		t.Fatal(err)
	}
	resp5.Body.Close()
	if resp5.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unpinned node accepted recovery proof: %d", resp5.StatusCode)
	}
}

// reader.pin PUT 拦截：写 pin 即时生效 + 落盘；启动读回 pin 生效（重启后仍可恢复）。
func TestMetadataReaderPinPersists(t *testing.T) {
	fm := newFakeSecMaster(t)
	dataDir := t.TempDir()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host := l.Addr().String()
	n := New(dataDir, fm.srv.URL, host, 1<<30)
	if err := n.EnableSecurity(dataDir+"/identity.key", "invite-3", true); err != nil {
		t.Fatal(err)
	}
	mustRegister(t, n)
	ts := httptest.NewUnstartedServer(n.Handler())
	ts.Listener = l
	ts.Start()
	t.Cleanup(ts.Close)

	kek, _ := contentcrypto.NewKEK("pin-persist-test")
	c, err := metacrypto.New(kek)
	if err != nil {
		t.Fatal(err)
	}
	// 经控制票据（fake master mint）写 reader.pin——节点 PUT 拦截应即时 pin。
	tok := fm.mintTicket(accessTicketRequestFor("PUT", "/meta-backup/reader.pin", host), time.Time{})
	info := c.ReaderInfo()
	raw, _ := json.Marshal(info)
	put, _ := http.NewRequest(http.MethodPut, "http://"+host+"/meta-backup/reader.pin", bytes.NewReader(raw))
	put.Header.Set("Authorization", "Bearer "+tok)
	put.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(put)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("pin put = %d: %v", resp.StatusCode, err)
	}

	// 模拟重启：先关旧 server 释放端口，新 Node 从同一 dataDir 读回 pin
	//（同 advertise 地址重新监听）。
	ts.Close()
	l2, err := net.Listen("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	n2 := New(dataDir, fm.srv.URL, host, 1<<30)
	if err := n2.EnableSecurity(dataDir+"/identity.key", "invite-3", true); err != nil {
		t.Fatal(err)
	}
	mustRegister(t, n2)
	n2.loadMetadataReaderPin()
	ts2 := httptest.NewUnstartedServer(n2.Handler())
	ts2.Listener = l2
	ts2.Start()
	t.Cleanup(ts2.Close)
	host2 := host
	req, _ := http.NewRequest(http.MethodGet, "http://"+host2+"/meta-backup/manifest", nil)
	req.Host = host2
	if err := c.SignRead(req, host2, time.Now()); err != nil {
		t.Fatal(err)
	}
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("restarted node rejected persisted recovery proof: %d", resp2.StatusCode)
	}
}
