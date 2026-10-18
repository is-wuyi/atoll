package master

// security_e2e_test.go：安全链路端到端验证（真实 bbolt + httptest master/node +
// client.NewSecure）。只测行为，不改实现；发现实现问题交主 agent 修复。
//
// 装配：meta.BootstrapSecurity → NewServer + SetAdminToken + EnableSecurity
// （ControlToken≥24、AllowInsecure 放行 loopback 明文）→ AttachSecureTransports
// → Handler。节点先 Listen 占位（advertise=真实监听地址）再 EnableSecurity
// （identity 文件 + 设备邀请）+ Register（设备挑战换会话，含心跳 goroutine——
// master 关闭后心跳仅记日志，不影响断言）。设备邀请直接经 store 创建；
// 用户邀请/注册/登录一律走 HTTP。

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"atoll/client"
	"atoll/master/meta"
	atollnode "atoll/node"
	"atoll/pkg/access"
	"atoll/pkg/edgeidentity"
	"atoll/pkg/types"
)

const (
	secAdminPassword = "admin-password-e2e-123"
	secControlToken  = "control-token-e2e-0123456789abcdef" // ≥24 字符
	secAdminToken    = "admin-token-e2e-0123456789abcd"
	secUserPassword  = "user-password-e2e-456"
)

// ---- 装配 ----

type secNode struct {
	node   *atollnode.Node
	server *httptest.Server
}

// addr 是节点对 master 注册的 advertise 地址（先 Listen 占位，与监听地址一致）。
func (sn *secNode) addr() string { return sn.server.Listener.Addr().String() }

type secCluster struct {
	t      *testing.T
	store  *meta.Store
	srv    *Server
	master *httptest.Server
	nodes  []*secNode
}

func newSecureCluster(t *testing.T, numNodes int) *secCluster {
	t.Helper()
	dir := t.TempDir()
	store, err := meta.Open(filepath.Join(dir, "meta.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	if _, _, err := store.BootstrapSecurity("admin", secAdminPassword, time.Now()); err != nil {
		t.Fatalf("BootstrapSecurity: %v", err)
	}
	srv := NewServer(store, time.Hour)
	srv.SetAdminToken(secAdminToken)
	if err := srv.EnableSecurity(SecurityConfig{ControlToken: secControlToken, AllowInsecure: true}); err != nil {
		t.Fatalf("EnableSecurity: %v", err)
	}
	srv.AttachSecureTransports() // 必须在 Handler 之前
	ms := httptest.NewServer(srv.Handler())
	t.Cleanup(ms.Close)

	c := &secCluster{t: t, store: store, srv: srv, master: ms}
	invites := make([]string, numNodes)
	for i := range invites {
		code, err := store.CreateDeviceInvite(time.Now().Add(time.Hour), time.Now())
		if err != nil {
			t.Fatalf("CreateDeviceInvite: %v", err)
		}
		invites[i] = code
	}
	for i := 0; i < numNodes; i++ {
		c.nodes = append(c.nodes, c.startNode(filepath.Join(dir, fmt.Sprintf("node%d", i)), invites[i]))
	}
	return c
}

func (c *secCluster) startNode(dir, invite string) *secNode {
	c.t.Helper()
	// 先 Listen 占位：设备挑战绑定的 advertise 必须是节点真实监听地址。
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		c.t.Fatalf("listen: %v", err)
	}
	n := atollnode.New(filepath.Join(dir, "data"), c.master.URL, l.Addr().String(), 1<<30)
	if err := n.EnableSecurity(filepath.Join(dir, "identity.key"), invite, true); err != nil {
		c.t.Fatalf("node EnableSecurity: %v", err)
	}
	hs := httptest.NewUnstartedServer(n.Handler())
	hs.Listener = l
	hs.Start()
	c.t.Cleanup(hs.Close)
	// Register 启动心跳 goroutine：master 关闭后心跳只记日志（cleanup 可接受）。
	if err := n.Register(); err != nil {
		c.t.Fatalf("node Register: %v", err)
	}
	return &secNode{node: n, server: hs}
}

// ---- 账号（邀请/注册/登录走 HTTP）----

// secRawJSON 用显式 Bearer + space 头发 JSON 请求，返回原始响应（断言状态码用）。
func secRawJSON(t *testing.T, method, url, token string, spaceID uint64, body any) *http.Response {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if spaceID != 0 {
		req.Header.Set(access.SpaceHeader, strconv.FormatUint(spaceID, 10))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

func secDecode(t *testing.T, resp *http.Response, out any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

// secCreateUser 走 HTTP：admin 发邀请 → /auth/register 注册 → 返回注册响应。
func (c *secCluster) secCreateUser(adminToken, username string) (client.UserInfo, uint64) {
	c.t.Helper()
	resp := secRawJSON(c.t, http.MethodPost, c.master.URL+"/auth/invites", adminToken, 0,
		map[string]any{"expires_at": time.Now().Add(time.Hour)})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		c.t.Fatalf("create invite: status %d body %s", resp.StatusCode, body)
	}
	var inv struct {
		Invite string `json:"invite"`
	}
	secDecode(c.t, resp, &inv)

	resp = secRawJSON(c.t, http.MethodPost, c.master.URL+"/auth/register", "", 0, map[string]string{
		"invite": inv.Invite, "username": username, "password": secUserPassword,
	})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		c.t.Fatalf("register %s: status %d body %s", username, resp.StatusCode, body)
	}
	var reg struct {
		User  client.UserInfo  `json:"user"`
		Space client.SpaceInfo `json:"space"`
	}
	secDecode(c.t, resp, &reg)
	return reg.User, reg.Space.ID
}

// secLogin 登录并返回已选个人 space 的客户端。
func (c *secCluster) secLogin(username, password string) (*client.Client, client.LoginResult) {
	c.t.Helper()
	cl, err := client.NewSecure(c.master.URL, nil, true)
	if err != nil {
		c.t.Fatalf("NewSecure: %v", err)
	}
	res, err := cl.Login(context.Background(), username, password)
	if err != nil {
		c.t.Fatalf("login %s: %v", username, err)
	}
	return cl, res
}

func (c *secCluster) adminLogin() (*client.Client, string) {
	c.t.Helper()
	cl, res := c.secLogin("admin", secAdminPassword)
	return cl, res.Token
}

// mustAdminUser 返回管理员的公开用户信息（ID 等）。
func (c *secCluster) mustAdminUser() client.UserInfo {
	c.t.Helper()
	_, res := c.secLogin("admin", secAdminPassword)
	return res.User
}

// secPutSmall 以 replicas=1 上传小文件（≤SmallFileMax）。
func secPutSmall(t *testing.T, cl *client.Client, path string, data []byte) error {
	t.Helper()
	_, err := cl.PutSmall(path, data, 1, false)
	return err
}

// secHTTPError 提取 client 错误里的状态码（0 = 非状态错误）。
func secHTTPError(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var he *client.HTTPError
	if ok := asSecHTTPError(err, &he); ok {
		return he.StatusCode
	}
	return 0
}

func asSecHTTPError(err error, target **client.HTTPError) bool {
	for err != nil {
		if he, ok := err.(*client.HTTPError); ok {
			*target = he
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func secRequireStatus(t *testing.T, err error, want int, what string) {
	t.Helper()
	if got := secHTTPError(t, err); got != want {
		t.Fatalf("%s: status = %d, want %d (err=%v)", what, got, want, err)
	}
}

func secRequireOK(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", what, err)
	}
}

// secMD5 计算字节串 MD5（用例内对比上传/下载内容一致）。
func secMD5(b []byte) string { return fmt.Sprintf("%x", md5.Sum(b)) }

// secRandomBytes 确定性伪随机内容（可复现，避免每次跑结果漂移）。
func secRandomBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*7 + i/251)
	}
	return out
}

// ---- 用例 1：chunked 上传/下载 MD5 + 小文件 + 0B ----

func TestSecureUploadDownloadRoundTrip(t *testing.T) {
	c := newSecureCluster(t, 2)
	_, adminToken := c.adminLogin()
	c.secCreateUser(adminToken, "alice")
	alice, _ := c.secLogin("alice", secUserPassword)

	// 多块：临时缩小块大小，让 1.5MB 拆成 2 块走完整分块链路。
	oldChunk := types.ChunkSize
	types.ChunkSize = 1 << 20
	t.Cleanup(func() { types.ChunkSize = oldChunk })

	payload := secRandomBytes(3 << 20 / 2)
	local := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(local, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	secRequireOK(t, func() error { _, err := alice.Mkdir("/docs"); return err }(), "mkdir")
	secRequireOK(t, alice.PutChunked(local, "/docs/big.bin", 2), "chunked upload")

	out := filepath.Join(t.TempDir(), "out.bin")
	secRequireOK(t, alice.Get("/docs/big.bin", out), "chunked download")
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if secMD5(got) != secMD5(payload) {
		t.Fatalf("chunked roundtrip MD5 mismatch: got %s want %s", secMD5(got), secMD5(payload))
	}

	// 小文件通道（≤256KB）。
	small := secRandomBytes(64 << 10)
	if _, err := alice.PutSmall("/docs/small.bin", small, 1, false); err != nil {
		t.Fatalf("PutSmall: %v", err)
	}
	out2 := filepath.Join(t.TempDir(), "small.bin")
	secRequireOK(t, alice.Get("/docs/small.bin", out2), "small download")
	got2, _ := os.ReadFile(out2)
	if secMD5(got2) != secMD5(small) {
		t.Fatalf("small roundtrip MD5 mismatch")
	}

	// 0 字节文件：secure 会话走 /auth/files/empty，Get 落 0 字节本地文件。
	secRequireOK(t, alice.PutReaderOverwrite("/docs/empty.bin", 0, bytes.NewReader(nil), 1, false), "empty upload")
	out3 := filepath.Join(t.TempDir(), "empty.bin")
	secRequireOK(t, alice.Get("/docs/empty.bin", out3), "empty download")
	st, err := os.Stat(out3)
	if err != nil || st.Size() != 0 {
		t.Fatalf("empty file size = %v, %v", st, err)
	}
}

// ---- 用例 2：跨空间隔离与枚举防护 ----

func TestSecureCrossSpaceIsolation(t *testing.T) {
	c := newSecureCluster(t, 1)
	_, adminToken := c.adminLogin()
	_, aliceSpace := c.secCreateUser(adminToken, "alice")
	_, bobSpace := c.secCreateUser(adminToken, "bob")
	alice, _ := c.secLogin("alice", secUserPassword)
	bob, _ := c.secLogin("bob", secUserPassword)

	// alice 个人空间放一个文件。
	data := secRandomBytes(32 << 10)
	if _, err := alice.PutSmall("/private.txt", data, 1, false); err != nil {
		t.Fatalf("alice PutSmall: %v", err)
	}

	// bob 借 space 头指名 alice 空间：读写全拒。
	secRequireOK(t, bob.UseSpace(aliceSpace), "bob switch space")
	_, _, err := bob.Lookup("/private.txt")
	secRequireStatus(t, err, http.StatusForbidden, "bob cross-space read")
	err = bob.PutReaderOverwrite("/steal.txt", int64(len(data)), bytes.NewReader(data), 1, false)
	secRequireStatus(t, err, http.StatusForbidden, "bob cross-space write")
	_, err = bob.Mkdir("/intrude")
	secRequireStatus(t, err, http.StatusForbidden, "bob cross-space mkdir")

	// 枚举他人 inode：bob 留一个未提交 staging，alice 对它 assign/commit/abort 全拒。
	bob.UseSpace(bobSpace)
	bobTok := secSessionToken(t, c, "bob")
	resp := secRawJSON(t, http.MethodPost, c.master.URL+"/files", bobTok, bobSpace,
		map[string]any{"path": "/staging-target.bin", "chunked": true, "overwrite": false})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("bob staging create: status %d body %s", resp.StatusCode, body)
	}
	var created struct {
		Inode types.Inode `json:"inode"`
	}
	secDecode(t, resp, &created)
	stagingID := created.Inode.ID

	aliceTok := secSessionToken(t, c, "alice")
	aliceUse := func(method, path string, body any) *http.Response {
		return secRawJSON(t, method, c.master.URL+path, aliceTok, aliceSpace, body)
	}
	r := aliceUse(http.MethodPost, "/files/chunks",
		map[string]any{"inode_id": stagingID, "index": 0, "size": 10, "checksum": 1, "replicas": 1})
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign assign: status %d, want 403", r.StatusCode)
	}
	r.Body.Close()
	r = aliceUse(http.MethodPost, "/files/commit",
		map[string]any{"inode_id": stagingID, "name": "staging-target.bin", "size": 10, "chunk_count": 1})
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign commit: status %d, want 403", r.StatusCode)
	}
	r.Body.Close()
	r = aliceUse(http.MethodDelete, fmt.Sprintf("/files/staging/%d", stagingID), nil)
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign abort: status %d, want 403", r.StatusCode)
	}
	r.Body.Close()

	// op_id 按用户+空间隔离：同 op_id 在不同用户/空间不串结果。
	sharedOp := "shared-op-0001"
	u1 := fmt.Sprintf("%s/files/small?path=%s&replicas=1&overwrite=false&op_id=%s",
		c.master.URL, "/op-a.txt", sharedOp)
	req, _ := http.NewRequest(http.MethodPost, u1, bytes.NewReader([]byte("alice-payload")))
	req.Header.Set("Authorization", "Bearer "+aliceTok)
	req.Header.Set(access.SpaceHeader, strconv.FormatUint(aliceSpace, 10))
	req.Header.Set("X-Atoll-Features", "object-id-v1")
	r, err = http.DefaultClient.Do(req)
	if err != nil || r.StatusCode != http.StatusCreated {
		t.Fatalf("alice small upload: %v status %d", err, r.StatusCode)
	}
	var first struct {
		Inode types.Inode `json:"inode"`
	}
	secDecode(t, r, &first)

	// alice 同 op_id 重试 → 幂等回放同一 inode。
	req, _ = http.NewRequest(http.MethodPost, u1, bytes.NewReader([]byte("alice-payload")))
	req.Header.Set("Authorization", "Bearer "+aliceTok)
	req.Header.Set(access.SpaceHeader, strconv.FormatUint(aliceSpace, 10))
	req.Header.Set("X-Atoll-Features", "object-id-v1")
	r, err = http.DefaultClient.Do(req)
	if err != nil || (r.StatusCode != http.StatusOK && r.StatusCode != http.StatusCreated) {
		t.Fatalf("alice small retry: %v status %d", err, r.StatusCode)
	}
	var replay struct {
		Inode types.Inode `json:"inode"`
	}
	secDecode(t, r, &replay)
	if replay.Inode.ID != first.Inode.ID {
		t.Fatalf("幂等回放 inode 不一致: %d vs %d", replay.Inode.ID, first.Inode.ID)
	}

	// bob 同 op_id 在自己空间 → 独立执行，不得回放 alice 的结果。
	u2 := fmt.Sprintf("%s/files/small?path=%s&replicas=1&overwrite=false&op_id=%s",
		c.master.URL, "/op-a.txt", sharedOp)
	req, _ = http.NewRequest(http.MethodPost, u2, bytes.NewReader([]byte("bob-payload")))
	req.Header.Set("Authorization", "Bearer "+bobTok)
	req.Header.Set(access.SpaceHeader, strconv.FormatUint(bobSpace, 10))
	req.Header.Set("X-Atoll-Features", "object-id-v1")
	r, err = http.DefaultClient.Do(req)
	if err != nil || r.StatusCode != http.StatusCreated {
		t.Fatalf("bob small same op: %v status %d", err, r.StatusCode)
	}
	var second struct {
		Inode types.Inode `json:"inode"`
	}
	secDecode(t, r, &second)
	if second.Inode.ID == first.Inode.ID {
		t.Fatalf("op_id 跨用户串结果: bob 拿到 alice 的 inode %d", first.Inode.ID)
	}
}

// secSessionToken 重新登录取一个裸会话 token（raw 请求用；不落日志）。
func secSessionToken(t *testing.T, c *secCluster, username string) string {
	t.Helper()
	_, res := c.secLogin(username, secUserPassword)
	return res.Token
}

// secDenied 报告节点侧拒绝（节点对无效票据/凭据统一映射 401/403；503 仅表示 master 不可达）。
func secDenied(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

// secLookupInode 查询空间内文件的元数据（取对象 ID 供节点级断言用）。
func secLookupInode(t *testing.T, c *secCluster, token string, spaceID uint64, path string) types.Inode {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, c.master.URL+"/meta?path="+urlQueryEscape(path), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(access.SpaceHeader, strconv.FormatUint(spaceID, 10))
	req.Header.Set("X-Atoll-Features", "object-id-v1") // GET /meta 特性协商（高位 ObjID）
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("lookup %s: %v", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("lookup %s: status %d body %s", path, resp.StatusCode, body)
	}
	// GET /meta 响应为 {"inode": …, "nodes": …} 包装形。
	var out struct {
		Inode types.Inode `json:"inode"`
	}
	secDecode(t, resp, &out)
	return out.Inode
}

func urlQueryEscape(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~' || ch == '/' {
			b.WriteByte(ch)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[ch>>4])
		b.WriteByte(hexDigits[ch&0xf])
	}
	return b.String()
}

// secIssueUserTicket 用用户会话换节点票据；返回票据 token 与 HTTP 状态码。
func secIssueUserTicket(t *testing.T, c *secCluster, token string, spaceID uint64, nodeAddr, method, path string) (string, int) {
	t.Helper()
	body := map[string]any{"node_addr": nodeAddr, "method": method, "path": path}
	resp := secRawJSON(t, http.MethodPost, c.master.URL+"/security/tickets", token, spaceID, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode
	}
	var tk access.Ticket
	if err := json.NewDecoder(resp.Body).Decode(&tk); err != nil {
		t.Fatalf("decode ticket: %v", err)
	}
	return tk.Token, resp.StatusCode
}

// secNodeGet 携带给定 Bearer 直连节点发 GET/PUT，返回状态码。
func secNodeStatus(t *testing.T, method, nodeURL, bearer string, body []byte) int {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, nodeURL, rd)
	if err != nil {
		t.Fatalf("node request: %v", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, nodeURL, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// ---- 用例 3：团队 owner/read/write 矩阵与同名团队隔离 ----

func TestSecureTeamRoleMatrix(t *testing.T) {
	c := newSecureCluster(t, 1)
	_, adminToken := c.adminLogin()
	aliceUI, _ := c.secCreateUser(adminToken, "alice")
	bobUI, _ := c.secCreateUser(adminToken, "bob")
	adminUI := c.mustAdminUser()
	alice, _ := c.secLogin("alice", secUserPassword)
	bob, _ := c.secLogin("bob", secUserPassword)
	ctx := context.Background()

	team, err := alice.CreateTeam(ctx, "devs")
	secRequireOK(t, err, "alice CreateTeam")
	secRequireOK(t, alice.UseSpace(team.ID), "owner use team space")
	secRequireOK(t, secPutSmall(t, alice, "/owner-file.txt", []byte("owner-data")), "owner put")

	// read 成员：可读不可写、不可管理成员。
	secRequireOK(t, bob.UseSpace(team.ID), "bob use team space")
	secRequireOK(t, alice.AddMember(ctx, team.ID, bobUI.ID, "read"), "add read member")
	if _, err := bob.Ls("/"); err != nil {
		t.Fatalf("read member ls: %v", err)
	}
	secRequireStatus(t, secPutSmall(t, bob, "/bob-file.txt", []byte("x")), http.StatusForbidden, "read member put")
	secRequireStatus(t, bob.Rm("/owner-file.txt"), http.StatusForbidden, "read member rm")
	secRequireStatus(t, bob.AddMember(ctx, team.ID, adminUI.ID, "read"), http.StatusForbidden, "read member add-member")
	secRequireStatus(t, bob.RemoveMember(ctx, team.ID, aliceUI.ID), http.StatusForbidden, "read member remove-member")

	// write 成员：可写可删；降级 read 后立即只读。
	secRequireOK(t, alice.AddMember(ctx, team.ID, bobUI.ID, "write"), "upgrade write")
	secRequireOK(t, secPutSmall(t, bob, "/bob-file.txt", []byte("bob-data")), "write member put")
	secRequireOK(t, bob.Rm("/owner-file.txt"), "write member rm")
	secRequireOK(t, alice.AddMember(ctx, team.ID, bobUI.ID, "read"), "downgrade read")
	secRequireStatus(t, secPutSmall(t, bob, "/bob-file2.txt", []byte("y")), http.StatusForbidden, "downgraded put")
	if _, err := bob.Ls("/"); err != nil {
		t.Fatalf("downgraded read ls: %v", err)
	}

	// 个人空间成员不可改（走 HTTP 层同样拒绝）。
	secRequireStatus(t, alice.AddMember(ctx, aliceUI.PersonalSpaceID, bobUI.ID, "read"),
		http.StatusForbidden, "add member to personal space")

	// 同名团队：完全独立，互不可见不可串。
	teamB, err := bob.CreateTeam(ctx, "devs")
	secRequireOK(t, err, "bob CreateTeam same name")
	if teamB.ID == team.ID {
		t.Fatal("同名团队应持有独立 ID")
	}
	secRequireOK(t, bob.UseSpace(teamB.ID), "bob use own team")
	secRequireOK(t, secPutSmall(t, bob, "/cross.txt", []byte("bob-team-data")), "bob own team put")
	secRequireOK(t, alice.UseSpace(team.ID), "alice back to own team")
	entries, err := alice.Ls("/")
	secRequireOK(t, err, "alice ls own team")
	for _, e := range entries {
		if e.Name == "cross.txt" {
			t.Fatal("同名团队内容不应跨队可见")
		}
	}
	secRequireOK(t, alice.UseSpace(teamB.ID), "alice switch to foreign team")
	_, err = alice.Ls("/")
	secRequireStatus(t, err, http.StatusForbidden, "alice read foreign same-name team")
}

// ---- 用例 4：成员移除/登出后旧票据被节点在线拒绝 ----

func TestSecureTicketRevocation(t *testing.T) {
	c := newSecureCluster(t, 1)
	_, adminToken := c.adminLogin()
	aliceUI, _ := c.secCreateUser(adminToken, "alice")
	bobUI, _ := c.secCreateUser(adminToken, "bob")
	alice, _ := c.secLogin("alice", secUserPassword)
	bob, _ := c.secLogin("bob", secUserPassword)
	ctx := context.Background()

	team, err := alice.CreateTeam(ctx, "proj")
	secRequireOK(t, err, "create team")
	secRequireOK(t, alice.AddMember(ctx, team.ID, bobUI.ID, "write"), "add bob write")
	secRequireOK(t, bob.UseSpace(team.ID), "bob use team")
	payload := []byte("team-object-data")
	secRequireOK(t, secPutSmall(t, bob, "/shared.txt", payload), "bob put small")
	objID := secLookupInode(t, c, secSessionToken(t, c, "bob"), team.ID, "/shared.txt").ObjID
	if objID == 0 {
		t.Fatal("small 文件应有独立 ObjID")
	}

	// 成员持有效票据读节点对象。
	nodeAddr := c.nodes[0].addr()
	ticket, st := secIssueUserTicket(t, c, secSessionToken(t, c, "bob"), team.ID, nodeAddr,
		http.MethodGet, "/objects/"+strconv.FormatUint(objID, 10))
	if st != http.StatusOK || ticket == "" {
		t.Fatalf("issue member ticket: status %d", st)
	}
	if got := secNodeStatus(t, http.MethodGet, c.nodes[0].server.URL+"/objects/"+strconv.FormatUint(objID, 10), ticket, nil); got != http.StatusOK {
		t.Fatalf("member ticket GET /objects: status %d, want 200", got)
	}

	// 降级 read：读票据仍有效。
	secRequireOK(t, alice.AddMember(ctx, team.ID, bobUI.ID, "read"), "downgrade to read")
	if got := secNodeStatus(t, http.MethodGet, c.nodes[0].server.URL+"/objects/"+strconv.FormatUint(objID, 10), ticket, nil); got != http.StatusOK {
		t.Fatalf("read member ticket should survive downgrade: status %d", got)
	}

	// 移除成员：同一张票据下一个请求即被节点在线拒绝。
	secRequireOK(t, alice.RemoveMember(ctx, team.ID, bobUI.ID), "remove member")
	if got := secNodeStatus(t, http.MethodGet, c.nodes[0].server.URL+"/objects/"+strconv.FormatUint(objID, 10), ticket, nil); !secDenied(got) {
		t.Fatalf("removed member old ticket: status %d, want 401/403", got)
	}
	secRequireOK(t, bob.UseSpace(team.ID), "use space")
	_, err = bob.Ls("/")
	secRequireStatus(t, err, http.StatusForbidden, "removed member master access")

	// 登出：个人空间票据同样即时失效（登出的必须就是持票会话）。
	alice2, aliceRes := c.secLogin("alice", secUserPassword)
	secRequireOK(t, secPutSmall(t, alice2, "/mine.txt", []byte("personal-data")), "alice put personal")
	personalObj := secLookupInode(t, c, aliceRes.Token, aliceUI.PersonalSpaceID, "/mine.txt").ObjID
	aTicket, st := secIssueUserTicket(t, c, aliceRes.Token, aliceUI.PersonalSpaceID, nodeAddr,
		http.MethodGet, "/objects/"+strconv.FormatUint(personalObj, 10))
	if st != http.StatusOK {
		t.Fatalf("issue alice ticket: status %d", st)
	}
	objURL := c.nodes[0].server.URL + "/objects/" + strconv.FormatUint(personalObj, 10)
	if got := secNodeStatus(t, http.MethodGet, objURL, aTicket, nil); got != http.StatusOK {
		t.Fatalf("alice ticket GET: status %d, want 200", got)
	}
	secRequireOK(t, alice2.Logout(ctx), "logout")
	if got := secNodeStatus(t, http.MethodGet, objURL, aTicket, nil); !secDenied(got) {
		t.Fatalf("logged-out ticket: status %d, want 401/403", got)
	}
}

// ---- 用例 5：节点拒绝用户会话/legacy token，ID 端点与越权 admin 不可达 ----

func TestSecureNodeRejectsForeignCredentials(t *testing.T) {
	c := newSecureCluster(t, 1)
	_, adminToken := c.adminLogin()
	aliceUI, _ := c.secCreateUser(adminToken, "alice")
	alice, _ := c.secLogin("alice", secUserPassword)
	aliceTok := secSessionToken(t, c, "alice")

	secRequireOK(t, secPutSmall(t, alice, "/obj.txt", []byte("node-object")), "alice put")
	objID := secLookupInode(t, c, aliceTok, aliceUI.PersonalSpaceID, "/obj.txt").ObjID
	objURL := c.nodes[0].server.URL + "/objects/" + strconv.FormatUint(objID, 10)

	// 用户会话直打节点：不接受（节点只认在线核验的短期票据）。
	if got := secNodeStatus(t, http.MethodGet, objURL, aliceTok, nil); !secDenied(got) {
		t.Fatalf("user session at node: status %d, want 401/403", got)
	}
	if got := secNodeStatus(t, http.MethodPut, objURL, aliceTok, []byte("forged")); !secDenied(got) {
		t.Fatalf("user session PUT at node: status %d, want 401/403", got)
	}
	// legacy 集群 token 直打节点：同样不接受。
	if got := secNodeStatus(t, http.MethodGet, objURL, "legacy-cluster-token-e2e-0123456789", nil); !secDenied(got) {
		t.Fatalf("legacy cluster token at node: status %d, want 401/403", got)
	}
	// 节点侧非对象端点（meta-backup/admin）一律 401。
	if got := secNodeStatus(t, http.MethodGet, c.nodes[0].server.URL+"/meta-backup", aliceTok, nil); !secDenied(got) {
		t.Fatalf("node meta-backup with user session: status %d, want 401/403", got)
	}
	if got := secNodeStatus(t, http.MethodGet, c.nodes[0].server.URL+"/admin/metabackup", aliceTok, nil); !secDenied(got) {
		t.Fatalf("node admin path with user session: status %d, want 401/403", got)
	}

	// master 侧：非管理员不得入 /admin；控制凭据不是用户会话。
	r := secRawJSON(t, http.MethodGet, c.master.URL+"/admin/nodes", aliceTok, 0, nil)
	r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("alice /admin/nodes: status %d, want 403", r.StatusCode)
	}
	// /admin/metabackup 在 secure 模式下整体禁用（网关对任何凭据恒 409，要求离线备份）。
	r = secRawJSON(t, http.MethodGet, c.master.URL+"/admin/metabackup", aliceTok, 0, nil)
	r.Body.Close()
	if r.StatusCode != http.StatusConflict {
		t.Fatalf("secure /admin/metabackup: status %d, want 409", r.StatusCode)
	}
	r = secRawJSON(t, http.MethodGet, c.master.URL+"/admin/metabackup", secAdminToken, 0, nil)
	r.Body.Close()
	if r.StatusCode != http.StatusConflict {
		t.Fatalf("secure /admin/metabackup with admin token: status %d, want 409", r.StatusCode)
	}
	r = secRawJSON(t, http.MethodGet, c.master.URL+"/meta", secControlToken, 0, nil)
	r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("control token on user path: status %d, want 403", r.StatusCode)
	}
}

// ---- 用例 6：设备挑战注册、伪造拒绝与撤销即时生效 ----

func TestSecureDeviceLifecycle(t *testing.T) {
	c := newSecureCluster(t, 1)
	_, adminToken := c.adminLogin()

	// 管理员经 HTTP 发设备邀请；测试内生成 Ed25519 身份走完整挑战注册。
	resp := secRawJSON(t, http.MethodPost, c.master.URL+"/auth/devices/invites", adminToken, 0,
		map[string]any{"expires_at": time.Now().Add(time.Hour)})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("device invite: status %d", resp.StatusCode)
	}
	var inv struct {
		Invite string `json:"invite"`
	}
	secDecode(t, resp, &inv)
	// 未认证用户拿不到设备邀请（公开登录端点对未知用户也统一 401，不枚举）。
	resp = secRawJSON(t, http.MethodPost, c.master.URL+"/auth/login", "", 0,
		map[string]string{"username": "no-such-user", "password": "whatever-password"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown user login: status %d, want 401", resp.StatusCode)
	}

	// 占一个空闲端口作为设备 advertise。
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	devAddr := l.Addr().String()
	l.Close()

	identity, err := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), "device.identity"))
	if err != nil {
		t.Fatal(err)
	}
	challenge := func(invite string) (access.DeviceChallenge, int) {
		var ch access.DeviceChallenge
		resp := secRawJSON(t, http.MethodPost, c.master.URL+"/security/devices/challenge", "", 0,
			access.DeviceChallengeRequest{
				PublicKey: identity.PublicKey(), Addr: devAddr, TotalBytes: 1 << 30, Invite: invite,
			})
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			if err := json.NewDecoder(resp.Body).Decode(&ch); err != nil {
				t.Fatalf("decode challenge: %v", err)
			}
		}
		return ch, resp.StatusCode
	}

	ch, st := challenge(inv.Invite)
	if st != http.StatusOK {
		t.Fatalf("device challenge: status %d", st)
	}
	sig, err := identity.Sign(ch.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	var sess access.DeviceSession
	resp = secRawJSON(t, http.MethodPost, c.master.URL+"/security/devices/session", "", 0,
		access.DeviceLoginRequest{ChallengeID: ch.ID, Signature: sig})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("device session: status %d body %s", resp.StatusCode, body)
	}
	secDecode(t, resp, &sess)
	if sess.Token == "" || sess.NodeID == 0 {
		t.Fatalf("device session incomplete: node_id=%d", sess.NodeID)
	}

	// 合法心跳。
	hb := func(nodeID uint64, token string) int {
		return secNodeStatus(t, http.MethodPost, c.master.URL+"/nodes/heartbeat", token,
			[]byte(fmt.Sprintf(`{"node_id": %d, "used_bytes": 0}`, nodeID)))
	}
	if got := hb(sess.NodeID, sess.Token); got != http.StatusOK {
		t.Fatalf("device heartbeat: status %d, want 200", got)
	}
	// 伪造：claim 别的 node_id、无凭据注册、坏签名会话、legacy /nodes/register。
	if got := hb(999999, sess.Token); got != http.StatusForbidden {
		t.Fatalf("spoofed node_id heartbeat: status %d, want 403", got)
	}
	if got := hb(sess.NodeID, ""); !secDenied(got) {
		t.Fatalf("anonymous heartbeat: status %d, want 401/403", got)
	}
	if got := secNodeStatus(t, http.MethodPost, c.master.URL+"/nodes/register", "",
		[]byte(`{"addr": "127.0.0.1:1", "total_bytes": 1}`)); !secDenied(got) {
		t.Fatalf("legacy register in secure mode: status %d, want 401/403", got)
	}
	ch2, st := challenge("") // 续期式挑战（无 invite）
	if st != http.StatusOK {
		t.Fatalf("second challenge: status %d", st)
	}
	resp = secRawJSON(t, http.MethodPost, c.master.URL+"/security/devices/session", "", 0,
		access.DeviceLoginRequest{ChallengeID: ch2.ID, Signature: []byte("forged-signature")})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged device signature: status %d, want 401", resp.StatusCode)
	}

	// 撤销：心跳与票据立即拒绝，重注册（续期）也被拒。
	resp = secRawJSON(t, http.MethodPost, c.master.URL+"/auth/devices/revoke", adminToken, 0,
		map[string]any{"node_id": sess.NodeID})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device revoke: status %d", resp.StatusCode)
	}
	if got := hb(sess.NodeID, sess.Token); !secDenied(got) {
		t.Fatalf("revoked device heartbeat: status %d, want 401/403", got)
	}
	_, st = secIssueUserTicketForDevice(t, c, sess.Token)
	if st != http.StatusUnauthorized {
		t.Fatalf("revoked device ticket: status %d, want 401", st)
	}
	ch3, st := challenge("")
	if st == http.StatusOK {
		resp = secRawJSON(t, http.MethodPost, c.master.URL+"/security/devices/session", "", 0,
			access.DeviceLoginRequest{ChallengeID: ch3.ID, Signature: mustSign(t, identity, ch3.Challenge)})
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("revoked device re-register: status %d, want 401", resp.StatusCode)
		}
	}
}

// secIssueUserTicketForDevice 用设备会话尝试换票（撤销后应 403）。
func secIssueUserTicketForDevice(t *testing.T, c *secCluster, deviceToken string) (string, int) {
	t.Helper()
	body := map[string]any{"node_addr": "127.0.0.1:1", "method": "GET", "path": "/objects/1"}
	resp := secRawJSON(t, http.MethodPost, c.master.URL+"/security/tickets", deviceToken, 0, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode
	}
	var tk access.Ticket
	secDecode(t, resp, &tk)
	return tk.Token, resp.StatusCode
}

func mustSign(t *testing.T, identity *edgeidentity.Identity, ch edgeidentity.Challenge) []byte {
	t.Helper()
	sig, err := identity.Sign(ch)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// ---- 用例 7：安全库已初始化但未 Enable → fallback 503 ----

func TestSecureMasterFallback503(t *testing.T) {
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta503.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if _, _, err := store.BootstrapSecurity("admin", secAdminPassword, time.Now()); err != nil {
		t.Fatal(err)
	}
	h := NewServer(store, time.Hour).Handler() // 刻意不 EnableSecurity
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)

	r := secRawJSON(t, http.MethodGet, ts.URL+"/healthz", "", 0, nil)
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("healthz: status %d, want 200", r.StatusCode)
	}
	for _, path := range []string{"/meta", "/auth/login", "/files"} {
		r = secRawJSON(t, http.MethodPost, ts.URL+path, "", 0, nil)
		r.Body.Close()
		if r.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("%s unenabled: status %d, want 503", path, r.StatusCode)
		}
	}
}
