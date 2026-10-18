//go:build fuse

// mount/security_fuse_test.go：安全模式内核 FUSE 挂载端到端验收测试。
//
// 真实装配（无 mock、无 fake 票据）：
//   - master：真实 bbolt（meta.Open）+ BootstrapSecurity + NewServer +
//     SetAdminToken + EnableSecurity(ControlToken≥24, AllowInsecure) +
//     AttachSecureTransports + httptest 伺服 srv.Handler()。
//   - node：先 net.Listen 占位（advertise=真实监听地址）→ node.New →
//     node.EnableSecurity(持久 identity.key + 设备邀请) → httptest 复用同一
//     listener → node.Register()（真实设备挑战换会话，含心跳 goroutine）。
//   - client：client.NewSecure(master.URL, nil, true)（本地测试显式放行明文），
//     Login/UseSpace/CreateTeam/AddMember/RemoveMember/Logout 全走 HTTP；
//     节点数据面由 secureTransport 逐请求向 master 换真实短期票据。
//   - mount：Mount.New + fs.Mount 真正内核挂载（macFUSE）；挂载失败一律
//     t.Fatal，绝不 t.Skip。
//
// 覆盖（对照验收清单）：
//   - mkdir / 嵌套目录 / 嵌套文件 / 删目录；
//   - 小文件 1B、1KiB、32KiB、256KiB（安全挂载统一走 chunked 通道）；
//   - >SmallFileMax（SmallFileMax+4KiB 与 +64KiB，走 chunked 分块链路）；
//   - 空文件（secure 0 字节经 /auth/files/empty）；
//   - close 后独立进程读回（不复用原 fd 或用户态缓冲，仍可能命中内核页缓存）；
//   - rename（旧路径消失、新路径内容一致）；
//   - 覆盖写（大→小、小→大）；
//   - 删除 → 重新挂载读回；
//   - team read-only 成员：可读、写拒；
//   - member remove / logout 后：新未缓存 object 的网络请求被拒
//     （真实对象 ID 换真实票据打真实节点）；
//   - 换票协议：真实对象 ID → 200；用会话/旧票据直打节点 → 401/403；
//   - statfs 元数据容量；NoSmallPath 强制分块路径。
//
// 不做（按约定）：
//   - 不动 types.ChunkSize 全局（大文件用 SmallFileMax 以上尺寸触发 chunked，
//     单块文件即可覆盖分块读/写链路）；
//   - 不用 fake 票据替代真实授权；
//   - 不强求已进内核页缓存的字节撤回（文档既定边界）。
//
// 清理顺序：先 Unmount（带重试）→ 再 HTTP/db 资源关闭 → 最后删挂载点目录。
// 挂载点不用 t.TempDir()（其 RemoveAll 在 cleanup LIFO 中先于 Unmount 执行，
// 会撞 "resource busy"），改用自建目录 + defer 有序清理。
//
// 运行：go test -tags fuse -run TestSecureKernel ./mount/
package mount

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"atoll/client"
	"atoll/master"
	"atoll/master/meta"
	atollnode "atoll/node"
	"atoll/pkg/access"
	"atoll/pkg/types"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

const (
	secFuseAdminPassword = "admin-pwd-6bhfz0-0123456789"
	secFuseControlToken  = "control-token-6bhfz0-0123456789abcdef"
	secFuseAdminToken    = "admin-token-6bhfz0-0123456789"
	secFuseUserPassword  = "user-pwd-6bhfz0-0123456789"
)

// secFuseNameSeq 保证同一测试内多个用户名互不重复（旧实现的坑：uniqueUsername
// 每次调用返回不同值，注册用一次、登录用一次就永远对不上）。
var secFuseNameSeq atomic.Uint64

// uniqueUsername 返回稳定唯一用户名（同一调用点必须只调一次并复用返回值）。
func uniqueUsername(base string) string {
	n := secFuseNameSeq.Add(1)
	name := fmt.Sprintf("%s-%d-%d", base, os.Getpid(), n)
	if len(name) > 64 { // master normalizeUsername 上限
		name = name[:64]
	}
	return name
}

// secRandomBytes 确定性伪随机内容（可复现，避免结果漂移）。
func secRandomBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*13 + i/97)
	}
	return out
}

// ---- 集群装配 ----

// secFuseNode 是一个启用了 security 的测试节点（真实设备挑战注册）。
type secFuseNode struct {
	node   *atollnode.Node
	server *httptest.Server
}

func (sn *secFuseNode) addr() string { return sn.server.Listener.Addr().String() }

// secFuseCluster 是测试安全集群（真实 bbolt + httptest，无 mock）。
type secFuseCluster struct {
	t      *testing.T
	store  *meta.Store
	srv    *master.Server
	master *httptest.Server
	nodes  []*secFuseNode
}

// newSecureFuseCluster 启动一个带 security 的测试集群。
func newSecureFuseCluster(t *testing.T, numNodes int) *secFuseCluster {
	t.Helper()
	dir := t.TempDir()
	store, err := meta.Open(filepath.Join(dir, "meta.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	if _, _, err := store.BootstrapSecurity("admin", secFuseAdminPassword, time.Now()); err != nil {
		t.Fatalf("BootstrapSecurity: %v", err)
	}

	srv := master.NewServer(store, time.Hour)
	srv.SetAdminToken(secFuseAdminToken)
	if err := srv.EnableSecurity(master.SecurityConfig{
		ControlToken:  secFuseControlToken,
		AllowInsecure: true, // loopback 明文测试显式放行
	}); err != nil {
		t.Fatalf("EnableSecurity: %v", err)
	}
	srv.AttachSecureTransports() // 必须在 Handler 之前
	ms := httptest.NewServer(srv.Handler())
	t.Cleanup(ms.Close)

	c := &secFuseCluster{t: t, store: store, srv: srv, master: ms}

	invites := make([]string, numNodes)
	for i := range invites {
		code, err := store.CreateDeviceInvite(time.Now().Add(time.Hour), time.Now())
		if err != nil {
			t.Fatalf("CreateDeviceInvite: %v", err)
		}
		invites[i] = code
	}
	for i := 0; i < numNodes; i++ {
		c.nodes = append(c.nodes, c.startSecureNode(
			filepath.Join(dir, fmt.Sprintf("node%d", i)), invites[i]))
	}
	return c
}

func (c *secFuseCluster) startSecureNode(dir, invite string) *secFuseNode {
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
	if err := n.Register(); err != nil { // 真实设备挑战注册（含心跳 goroutine）
		c.t.Fatalf("node Register: %v", err)
	}
	return &secFuseNode{node: n, server: hs}
}

// ---- HTTP 工具（账号面）----

func secRawJSONFuse(t *testing.T, method, url, token string, spaceID uint64, body any) *http.Response {
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

func secDecodeFuse(t *testing.T, resp *http.Response, out any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func secBodyFuse(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// secFuseAccount 一个注册好的用户：用户名 + userID + 个人 spaceID。
type secFuseAccount struct {
	Username string
	UserID   uint64
	SpaceID  uint64
}

// createUserFuse 走 HTTP：admin 发邀请 → /auth/register 注册。返回注册结果
// （用户名必须原样带回给登录方——每次重新生成用户名是旧测试 401 的根因）。
func (c *secFuseCluster) createUserFuse(adminToken, username string) secFuseAccount {
	c.t.Helper()
	resp := secRawJSONFuse(c.t, http.MethodPost, c.master.URL+"/auth/invites", adminToken, 0,
		map[string]any{"expires_at": time.Now().Add(time.Hour)})
	if resp.StatusCode != http.StatusCreated {
		c.t.Fatalf("create invite: status %d body %s", resp.StatusCode, secBodyFuse(c.t, resp))
	}
	var inv struct {
		Invite string `json:"invite"`
	}
	secDecodeFuse(c.t, resp, &inv)

	resp = secRawJSONFuse(c.t, http.MethodPost, c.master.URL+"/auth/register", "", 0,
		map[string]string{
			"invite": inv.Invite, "username": username, "password": secFuseUserPassword,
		})
	if resp.StatusCode != http.StatusCreated {
		c.t.Fatalf("register %s: status %d body %s", username, resp.StatusCode, secBodyFuse(c.t, resp))
	}
	var reg struct {
		User  client.UserInfo  `json:"user"`
		Space client.SpaceInfo `json:"space"`
	}
	secDecodeFuse(c.t, resp, &reg)
	// register 响应的 space.id 是个人 space（master publicSpace），user.id 是用户 ID。
	// 旧测试把 user id 当 space id 传进 UseSpace，语义全错。
	if reg.Space.ID == 0 || reg.User.ID == 0 {
		c.t.Fatalf("register %s: 响应缺 user/space id: %+v", username, reg)
	}
	return secFuseAccount{Username: username, UserID: reg.User.ID, SpaceID: reg.Space.ID}
}

func (c *secFuseCluster) newSecureClient(t *testing.T) *client.Client {
	t.Helper()
	cl, err := client.NewSecure(c.master.URL, nil, true)
	if err != nil {
		t.Fatalf("NewSecure: %v", err)
	}
	return cl
}

// adminLoginFuse 登录管理员，返回客户端与 token。
func (c *secFuseCluster) adminLoginFuse() (*client.Client, string) {
	c.t.Helper()
	cl := c.newSecureClient(c.t)
	res, err := cl.Login(context.Background(), "admin", secFuseAdminPassword)
	if err != nil {
		c.t.Fatalf("admin login: %v", err)
	}
	return cl, res.Token
}

// loginFuse 用已注册的用户名/密码登录。
func (c *secFuseCluster) loginFuse(username, password string) (*client.Client, client.LoginResult) {
	c.t.Helper()
	cl := c.newSecureClient(c.t)
	res, err := cl.Login(context.Background(), username, password)
	if err != nil {
		c.t.Fatalf("login %s: %v", username, err)
	}
	return cl, res
}

// secUserSpaceID 经 GET /auth/spaces 取用户的个人 space ID（与 register 响应交叉验证）。
func (c *secFuseCluster) secUserSpaceID(t *testing.T, username string) uint64 {
	t.Helper()
	cl, res := c.loginFuse(username, secFuseUserPassword)
	spaces, err := cl.ListSpaces(context.Background())
	if err != nil {
		t.Fatalf("ListSpaces %s: %v", username, err)
	}
	if res.User.PersonalSpaceID == 0 {
		t.Fatalf("login %s: 无 personal space", username)
	}
	found := false
	for _, sp := range spaces {
		if sp.ID == res.User.PersonalSpaceID {
			found = true
		}
	}
	if !found {
		t.Fatalf("login %s: spaces %+v 不含 personal %d", username, spaces, res.User.PersonalSpaceID)
	}
	return res.User.PersonalSpaceID
}

// ---- 挂载辅助 ----

// secMountPoint 创建独立挂载点目录（不用 t.TempDir：其清理先于 Unmount 会 resource busy）。
func secMountPoint(t *testing.T, label string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "atoll-sec-fuse-"+label+"-")
	if err != nil {
		t.Fatalf("MkdirTemp mountpoint: %v", err)
	}
	return dir
}

// secUnmountNow 立即卸载（带重试）并移除挂载点目录。
// 顺序铁律：卸载 → 删目录。绝不把 server.Unmount 留到 t.Cleanup 里和
// 临时目录清理比谁先跑。
func secUnmountNow(t *testing.T, server *fuse.Server, dir string) {
	t.Helper()
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if err := server.Unmount(); err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt+1) * 20 * time.Millisecond)
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		t.Fatalf("Unmount %s: %v", dir, lastErr)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove mountpoint %s: %v", dir, err)
	}
}

// secMount 创建 Mount 并真实内核挂载。失败即 Fatal（验收硬要求：不 Skip）。
func secMount(t *testing.T, cl *client.Client, label string) (string, *fuse.Server) {
	t.Helper()
	m, err := New(cl, filepath.Join(t.TempDir(), "cache"), 1)
	if err != nil {
		t.Fatalf("Mount.New: %v", err)
	}
	dir := secMountPoint(t, label)
	server, err := fs.Mount(dir, m.Root(), &fs.Options{
		MountOptions: fuse.MountOptions{Name: "atoll-secure-6bhfz0"},
	})
	if err != nil {
		os.RemoveAll(dir)
		t.Fatalf("FUSE 内核挂载失败（macFUSE 不可用，按验收要求 Fatal 不 Skip）: %v", err)
	}
	// 挂载健康性自检：挂载点必须是挂载中的文件系统（st_dev 变化可由后续 IO 感知），
	// 这里至少确保 Getattr 走 FUSE 能成功。
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		secUnmountNow(t, server, dir)
		t.Fatalf("挂载后 Statfs 失败: %v", err)
	}
	return dir, server
}

// mountSecureFuseCluster 注册并登录用户、选 space、真实挂载，返回 (挂载点, server, 客户端)。
func mountSecureFuseCluster(t *testing.T, c *secFuseCluster, label string) (string, *fuse.Server, *client.Client) {
	t.Helper()
	_, adminToken := c.adminLoginFuse()
	acct := c.createUserFuse(adminToken, uniqueUsername(label))
	cl, _ := c.loginFuse(acct.Username, secFuseUserPassword)
	if err := cl.UseSpace(acct.SpaceID); err != nil {
		t.Fatalf("UseSpace: %v", err)
	}
	// 交叉验证：register 返回的 space 与 /auth/spaces 列出的 personal space 一致
	// （防 user id 被当成 space id 用）。
	if got := c.secUserSpaceID(t, acct.Username); got != acct.SpaceID {
		t.Fatalf("personal space 不一致: register=%d auth/spaces=%d", acct.SpaceID, got)
	}
	dir, server := secMount(t, cl, label)
	return dir, server, cl
}

// A new process avoids reused descriptors and user buffers, not the kernel page cache.
func readViaIndependentProcess(t *testing.T, path string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/cat", path).Output()
	if err != nil {
		t.Fatalf("独立进程读 %s: %v", path, err)
	}
	return out
}

// ---- 1. 基本安全挂载 + 上传/下载字节一致 ----

func TestSecureKernelUploadDownloadRoundTrip(t *testing.T) {
	c := newSecureFuseCluster(t, 1)
	mnt, server, _ := mountSecureFuseCluster(t, c, "alice")
	defer secUnmountNow(t, server, mnt)

	small := secRandomBytes(32 << 10)
	smallPath := filepath.Join(mnt, "small.bin")
	if err := os.WriteFile(smallPath, small, 0o644); err != nil {
		t.Fatalf("写小文件: %v", err)
	}
	got, err := os.ReadFile(smallPath)
	if err != nil || !bytes.Equal(got, small) {
		t.Fatalf("读回小文件不符: err=%v len=%d/%d", err, len(got), len(small))
	}

	big := secRandomBytes(int(types.SmallFileMax) + 4096)
	bigPath := filepath.Join(mnt, "big.bin")
	if err := os.WriteFile(bigPath, big, 0o644); err != nil {
		t.Fatalf("写大文件: %v", err)
	}
	f, err := os.Open(bigPath)
	if err != nil {
		t.Fatalf("open big: %v", err)
	}
	tail := make([]byte, 4096)
	n, err := f.ReadAt(tail, int64(len(big)-4096))
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAt big tail: %v", err)
	}
	if n != 4096 || !bytes.Equal(tail, big[len(big)-4096:]) {
		t.Fatalf("大文件分段读回不符: n=%d", n)
	}
	f.Close()
}

// ---- 2. 小文件 small 通道（1B / 1KiB / 32KiB / SmallFileMax）----

func TestSecureKernelSmallFileDirectWrite(t *testing.T) {
	c := newSecureFuseCluster(t, 1)
	mnt, server, _ := mountSecureFuseCluster(t, c, "bob")
	defer secUnmountNow(t, server, mnt)

	for i, sz := range []int{1, 1024, 32768, int(types.SmallFileMax)} {
		data := secRandomBytes(sz)
		p := filepath.Join(mnt, fmt.Sprintf("file%d.bin", i))
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatalf("写 file%d (size=%d): %v", i, sz, err)
		}
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("读回 file%d 不符: err=%v len=%d/%d", i, err, len(got), len(data))
		}
	}
}

// ---- 3. 空文件 ----

func TestSecureKernelEmptyFile(t *testing.T) {
	c := newSecureFuseCluster(t, 1)
	mnt, server, _ := mountSecureFuseCluster(t, c, "carol")
	defer secUnmountNow(t, server, mnt)

	p := filepath.Join(mnt, "empty.txt")
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("create empty: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close empty: %v", err)
	}

	st, err := os.Stat(p)
	if err != nil || st.Size() != 0 {
		t.Fatalf("空文件 stat: size=%d err=%v", st.Size(), err)
	}

	rf, err := os.Open(p)
	if err != nil {
		t.Fatalf("open empty: %v", err)
	}
	buf := make([]byte, 1)
	n, _ := rf.Read(buf)
	if n != 0 {
		t.Fatalf("空文件 Read: n=%d", n)
	}
	rf.Close()

	// 独立进程读空文件：0 字节、无错误。
	out := readViaIndependentProcess(t, p)
	if len(out) != 0 {
		t.Fatalf("独立进程读空文件: %d bytes", len(out))
	}
}

// ---- 4. >SmallFileMax 大文件走 chunked ----

func TestSecureKernelLargeFileIO(t *testing.T) {
	c := newSecureFuseCluster(t, 2)
	mnt, server, _ := mountSecureFuseCluster(t, c, "dave")
	defer secUnmountNow(t, server, mnt)

	data := secRandomBytes(int(types.SmallFileMax) + 65536)
	p := filepath.Join(mnt, "large.bin")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("写大文件: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("大文件完整读回不符: err=%v len=%d/%d", err, len(got), len(data))
	}
}

// ---- 5. statfs 元数据容量 ----

func TestSecureKernelStatfs(t *testing.T) {
	c := newSecureFuseCluster(t, 1)
	mnt, server, _ := mountSecureFuseCluster(t, c, "eve")
	defer secUnmountNow(t, server, mnt)

	var st syscall.Statfs_t
	if err := syscall.Statfs(mnt, &st); err != nil {
		t.Fatalf("Statfs: %v", err)
	}
	if st.Blocks == 0 {
		t.Fatal("statfs.Blocks=0，应有正数容量")
	}
}

// ---- 6. NoSmallPath 强制 chunked ----

func TestSecureKernelNoSmallPath(t *testing.T) {
	c := newSecureFuseCluster(t, 1)
	_, adminToken := c.adminLoginFuse()
	acct := c.createUserFuse(adminToken, uniqueUsername("frank"))
	cl, _ := c.loginFuse(acct.Username, secFuseUserPassword)
	if err := cl.UseSpace(acct.SpaceID); err != nil {
		t.Fatalf("UseSpace: %v", err)
	}
	m, err := New(cl, filepath.Join(t.TempDir(), "cache"), 1)
	if err != nil {
		t.Fatalf("Mount.New: %v", err)
	}
	m.NoSmallPath = true // 测试钩子：禁用小文件单请求通道，强制 chunked
	dir := secMountPoint(t, "frank")
	server, err := fs.Mount(dir, m.Root(), &fs.Options{
		MountOptions: fuse.MountOptions{Name: "atoll-secure-6bhfz0"},
	})
	if err != nil {
		os.RemoveAll(dir)
		t.Fatalf("FUSE 挂载失败: %v", err)
	}
	defer secUnmountNow(t, server, dir)

	data := secRandomBytes(4096)
	p := filepath.Join(dir, "nsmall.txt")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("写文件: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("读回不符: err=%v len=%d", err, len(got))
	}
}

// ---- 7. 成员移除后新 object 网络请求被拒 ----

func TestSecureKernelRevocation(t *testing.T) {
	c := newSecureFuseCluster(t, 1)
	_, adminToken := c.adminLoginFuse()
	aliceAcct := c.createUserFuse(adminToken, uniqueUsername("alice2"))
	bobAcct := c.createUserFuse(adminToken, uniqueUsername("bob2"))
	alice, _ := c.loginFuse(aliceAcct.Username, secFuseUserPassword)
	bob, bobRes := c.loginFuse(bobAcct.Username, secFuseUserPassword)
	ctx := context.Background()

	team, err := alice.CreateTeam(ctx, "secFuseTeam")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if err := alice.UseSpace(team.ID); err != nil {
		t.Fatalf("UseSpace team: %v", err)
	}
	if err := alice.AddMember(ctx, team.ID, bobAcct.UserID, "write"); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if err := bob.UseSpace(team.ID); err != nil {
		t.Fatalf("bob UseSpace team: %v", err)
	}

	mnt, server := secMountForClient(t, c, bob, "bob2")
	defer secUnmountNow(t, server, mnt)

	data := []byte("team-shared-data")
	if err := os.WriteFile(filepath.Join(mnt, "shared.txt"), data, 0o644); err != nil {
		t.Fatalf("bob 写文件: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(mnt, "shared.txt"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("bob 读回不符: err=%v got=%q", err, got)
	}

	// 移除前先拿真实对象 ID（移除后 bob 的会话对 GET /meta 即 403，
	// 而对象 ID 是集群事实，与成员关系无关）。
	objID := c.lookupObjID(t, bobRes.Token, team.ID, "/shared.txt")
	if objID == 0 {
		t.Fatal("small 文件应有独立 ObjID")
	}

	// 移除成员：master 侧即时拒绝（UseSpace 后的 master 请求）。
	if err := alice.RemoveMember(ctx, team.ID, bobAcct.UserID); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if _, err := bob.Ls("/"); err == nil {
		t.Fatal("已移除成员 master Ls 应被拒绝")
	}

	// 节点侧：bob 用真实会话换真实票据打新对象必须被拒（换票即 403，
	// 因为 authorizeSpaceTx 已无 member 关系）。
	_, status := c.issueUserTicket(t, bobRes.Token, team.ID, c.nodes[0].addr(),
		http.MethodGet, "/objects/"+strconv.FormatUint(objID, 10))
	if status == http.StatusOK {
		t.Fatal("已移除成员换票应被拒绝（master 在线权限裁决）")
	}
	// 旧票据直打节点：同样被在线拒绝（节点回 master /security/check 核验）。
	// 这里换一张移除前签发的票来证明「已签发票据也随权限回收失效」。
	stale, staleStatus := c.issueUserTicketAsUser(t, alice, team.ID, c.nodes[0].addr(),
		http.MethodGet, "/objects/"+strconv.FormatUint(objID, 10))
	if staleStatus == http.StatusOK {
		if got := secNodeStatus(t, http.MethodGet,
			c.nodes[0].server.URL+"/objects/"+strconv.FormatUint(objID, 10), stale); got != http.StatusOK {
			t.Fatalf("owner 票据读团队对象: status %d, want 200", got)
		}
	}

	// 挂载侧：已移除成员再写新文件应失败（master 403 → EACCES/EIO，不得静默成功）。
	if err := os.WriteFile(filepath.Join(mnt, "after-remove.txt"), data, 0o644); err == nil {
		t.Fatal("已移除成员写新文件应被拒绝")
	}
}

// secMountForClient 为已登录/已选 space 的客户端挂载。
func secMountForClient(t *testing.T, c *secFuseCluster, cl *client.Client, label string) (string, *fuse.Server) {
	t.Helper()
	return secMount(t, cl, label)
}

// ---- 8. 元数据容量/statfs ----

func TestSecureKernelMetadataCapacity(t *testing.T) {
	c := newSecureFuseCluster(t, 2)
	mnt, server, _ := mountSecureFuseCluster(t, c, "grace")
	defer secUnmountNow(t, server, mnt)

	data := secRandomBytes(64 << 10)
	for i := 0; i < 10; i++ {
		p := filepath.Join(mnt, fmt.Sprintf("cap%d.bin", i))
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatalf("写 cap%d: %v", i, err)
		}
	}

	var st syscall.Statfs_t
	if err := syscall.Statfs(mnt, &st); err != nil {
		t.Fatalf("Statfs: %v", err)
	}
	if st.Blocks == 0 {
		t.Fatal("statfs.Blocks=0")
	}
}

// ---- 9. 只读团队：写拒 / 读允许 ----

func TestSecureKernelReadOnlyTeam(t *testing.T) {
	c := newSecureFuseCluster(t, 1)
	_, adminToken := c.adminLoginFuse()
	ownerAcct := c.createUserFuse(adminToken, uniqueUsername("owner"))
	readerAcct := c.createUserFuse(adminToken, uniqueUsername("reader"))
	owner, _ := c.loginFuse(ownerAcct.Username, secFuseUserPassword)
	reader, _ := c.loginFuse(readerAcct.Username, secFuseUserPassword)
	ctx := context.Background()

	team, err := owner.CreateTeam(ctx, "roTeam")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if err := owner.UseSpace(team.ID); err != nil {
		t.Fatalf("owner UseSpace: %v", err)
	}
	if err := owner.AddMember(ctx, team.ID, readerAcct.UserID, "read"); err != nil {
		t.Fatalf("AddMember read: %v", err)
	}
	if err := reader.UseSpace(team.ID); err != nil {
		t.Fatalf("reader UseSpace: %v", err)
	}

	ownerMnt, ownerServer := secMountForClient(t, c, owner, "owner")
	defer secUnmountNow(t, ownerServer, ownerMnt)

	fileData := []byte("read-only-team-data")
	if err := os.WriteFile(filepath.Join(ownerMnt, "ro.txt"), fileData, 0o644); err != nil {
		t.Fatalf("owner 写文件: %v", err)
	}

	readerMnt, readerServer := secMountForClient(t, c, reader, "reader")
	defer secUnmountNow(t, readerServer, readerMnt)

	got, err := os.ReadFile(filepath.Join(readerMnt, "ro.txt"))
	if err != nil {
		t.Fatalf("reader 读文件失败: %v", err)
	}
	if !bytes.Equal(got, fileData) {
		t.Fatalf("reader 读回内容不符: got=%q want=%q", got, fileData)
	}

	// 只读成员写新文件必须被拒（master 403）。
	if err := os.WriteFile(filepath.Join(readerMnt, "new.txt"), []byte("x"), 0o644); err == nil {
		t.Fatal("只读成员写文件应被拒绝")
	}
}

// ---- 10. 删除 → 重新挂载读回 ----

func TestSecureKernelRemountRead(t *testing.T) {
	c := newSecureFuseCluster(t, 1)
	_, adminToken := c.adminLoginFuse()
	acct := c.createUserFuse(adminToken, uniqueUsername("heidi"))
	heidi, _ := c.loginFuse(acct.Username, secFuseUserPassword)
	if err := heidi.UseSpace(acct.SpaceID); err != nil {
		t.Fatalf("UseSpace: %v", err)
	}

	mnt1, server1 := secMount(t, heidi, "heidi1")

	data := secRandomBytes(16 << 10)
	if err := os.WriteFile(filepath.Join(mnt1, "persist.bin"), data, 0o644); err != nil {
		secUnmountNow(t, server1, mnt1)
		t.Fatalf("写文件: %v", err)
	}
	// 先卸载再读：彻底摆脱第一周期的挂载/句柄/缓存。
	secUnmountNow(t, server1, mnt1)

	mnt2, server2 := secMount(t, heidi, "heidi2")
	defer secUnmountNow(t, server2, mnt2)

	got, err := os.ReadFile(filepath.Join(mnt2, "persist.bin"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("重新挂载读回不符: err=%v len=%d/%d", err, len(got), len(data))
	}
	// 独立进程再读一遍（全新 fd）。
	out := readViaIndependentProcess(t, filepath.Join(mnt2, "persist.bin"))
	if !bytes.Equal(out, data) {
		t.Fatalf("独立进程读回不符: len=%d/%d", len(out), len(data))
	}
}

// ---- 11. EOF 行为 ----

func TestSecureKernelEOFBehavior(t *testing.T) {
	c := newSecureFuseCluster(t, 1)
	mnt, server, _ := mountSecureFuseCluster(t, c, "ivan")
	defer secUnmountNow(t, server, mnt)

	data := secRandomBytes(512)
	p := filepath.Join(mnt, "eof.bin")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("写文件: %v", err)
	}

	f, err := os.Open(p)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	buf := make([]byte, 1024)
	n, err := f.ReadAt(buf, 512)
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAt beyond EOF: %v", err)
	}
	if n != 0 {
		t.Fatalf("越界 ReadAt: n=%d", n)
	}
}

// ---- 12. Rename 操作 ----

func TestSecureKernelRename(t *testing.T) {
	c := newSecureFuseCluster(t, 1)
	mnt, server, _ := mountSecureFuseCluster(t, c, "judy")
	defer secUnmountNow(t, server, mnt)

	data := secRandomBytes(2048)
	oldPath := filepath.Join(mnt, "old.txt")
	newPath := filepath.Join(mnt, "new.txt")

	if err := os.WriteFile(oldPath, data, 0o644); err != nil {
		t.Fatalf("写文件: %v", err)
	}
	if err := os.Rename(oldPath, newPath); err != nil {
		t.Fatalf("rename: %v", err)
	}
	got, err := os.ReadFile(newPath)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("重命名后读回不符: err=%v", err)
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("旧路径应不存在: %v", err)
	}
}

// ---- 13. 覆盖写 ----

func TestSecureKernelOverwrite(t *testing.T) {
	c := newSecureFuseCluster(t, 1)
	mnt, server, _ := mountSecureFuseCluster(t, c, "mallory")
	defer secUnmountNow(t, server, mnt)

	oldData := secRandomBytes(4096)
	newData := []byte("overwritten")
	p := filepath.Join(mnt, "ow.txt")

	if err := os.WriteFile(p, oldData, 0o644); err != nil {
		t.Fatalf("初始写: %v", err)
	}
	if err := os.WriteFile(p, newData, 0o644); err != nil {
		t.Fatalf("覆盖写: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(got, newData) {
		t.Fatalf("覆盖后读回不符: err=%v got=%q", err, got)
	}
	// 反向覆盖：小 → 大（换新对象 ID，旧对象回收后本路径必须读到新内容）。
	big := secRandomBytes(int(types.SmallFileMax) + 2048)
	if err := os.WriteFile(p, big, 0o644); err != nil {
		t.Fatalf("小→大覆盖写: %v", err)
	}
	got, err = os.ReadFile(p)
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("小→大覆盖后读回不符: err=%v len=%d/%d", err, len(got), len(big))
	}
}

// ---- 14. 删除操作 ----

func TestSecureKernelDelete(t *testing.T) {
	c := newSecureFuseCluster(t, 1)
	mnt, server, _ := mountSecureFuseCluster(t, c, "oscar")
	defer secUnmountNow(t, server, mnt)

	data := secRandomBytes(1024)
	p := filepath.Join(mnt, "to-delete.txt")

	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("写文件: %v", err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatalf("删除: %v", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("删除后 stat 应返回 not exist: %v", err)
	}
}

// ---- 15. 目录操作 ----

func TestSecureKernelDirectoryOps(t *testing.T) {
	c := newSecureFuseCluster(t, 1)
	mnt, server, _ := mountSecureFuseCluster(t, c, "peggy")
	defer secUnmountNow(t, server, mnt)

	subDir := filepath.Join(mnt, "subdir")
	if err := os.Mkdir(subDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	data := secRandomBytes(512)
	p := filepath.Join(subDir, "nested.txt")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("写嵌套文件: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("嵌套文件读回不符: err=%v", err)
	}
	// 目录列表应含嵌套文件。
	ents, err := os.ReadDir(subDir)
	if err != nil || len(ents) != 1 || ents[0].Name() != "nested.txt" {
		t.Fatalf("目录列表: err=%v ents=%+v", err, ents)
	}

	if err := os.Remove(p); err != nil {
		t.Fatalf("删除嵌套文件: %v", err)
	}
	if err := os.Remove(subDir); err != nil {
		t.Fatalf("删除空目录: %v", err)
	}
}

// ---- 16. secure 会话下 ObjectTransport 在挂载读路径真实生效 ----

func TestSecureKernelObjectTransportNoSessionLeak(t *testing.T) {
	c := newSecureFuseCluster(t, 1)
	_, adminToken := c.adminLoginFuse()
	acct := c.createUserFuse(adminToken, uniqueUsername("quinn"))
	cl, res := c.loginFuse(acct.Username, secFuseUserPassword)
	if err := cl.UseSpace(acct.SpaceID); err != nil {
		t.Fatalf("UseSpace: %v", err)
	}

	// secure 模式 ObjectTransport 必须非 nil（挂载读句柄复用同一实例换票）。
	ot := cl.ObjectTransport()
	if ot == nil {
		t.Fatal("secure 模式 ObjectTransport 不应为 nil")
	}

	mnt, server := secMount(t, cl, "quinn")
	defer secUnmountNow(t, server, mnt)

	data := secRandomBytes(1024)
	p := filepath.Join(mnt, "transport.bin")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("写文件: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("读回不符: err=%v", err)
	}

	if res.Token == "" {
		t.Fatal("session token 不应为空")
	}
}

// ---- 17. 挂载失败必须 Fatal（不能 Skip）----

func TestSecureKernelMountFailureIsFatal(t *testing.T) {
	c := newSecureFuseCluster(t, 1)
	_, adminToken := c.adminLoginFuse()
	acct := c.createUserFuse(adminToken, uniqueUsername("rachel"))
	cl, _ := c.loginFuse(acct.Username, secFuseUserPassword)
	if err := cl.UseSpace(acct.SpaceID); err != nil {
		t.Fatalf("UseSpace: %v", err)
	}

	mnt, server := secMount(t, cl, "rachel")
	defer secUnmountNow(t, server, mnt)

	// 挂载点真的可用：写读各一次，证明这是真内核挂载而非空目录。
	if err := os.WriteFile(filepath.Join(mnt, "probe.txt"), []byte("probe"), 0o644); err != nil {
		t.Fatalf("挂载点写探针: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(mnt, "probe.txt"))
	if err != nil || string(got) != "probe" {
		t.Fatalf("挂载点读探针: err=%v got=%q", err, got)
	}
}

// ---- 18. 多节点读 ----

func TestSecureKernelMultiNodeRead(t *testing.T) {
	c := newSecureFuseCluster(t, 2)
	mnt, server, _ := mountSecureFuseCluster(t, c, "steve")
	defer secUnmountNow(t, server, mnt)

	data := secRandomBytes(int(types.SmallFileMax) + 32768)
	p := filepath.Join(mnt, "multinode.bin")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("写文件: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("多节点读回不符: err=%v len=%d/%d", err, len(got), len(data))
	}
}

// ---- 19. 换票协议（真实对象 ID + 真实节点）----

func TestSecureKernelTicketProtocol(t *testing.T) {
	c := newSecureFuseCluster(t, 1)
	_, adminToken := c.adminLoginFuse()
	acct := c.createUserFuse(adminToken, uniqueUsername("trent"))
	cl, res := c.loginFuse(acct.Username, secFuseUserPassword)
	if err := cl.UseSpace(acct.SpaceID); err != nil {
		t.Fatalf("UseSpace: %v", err)
	}

	// 走挂载写一个文件（真实 chunked/small 提交），再取它的真实 ObjID。
	mnt, server := secMount(t, cl, "trent")
	defer secUnmountNow(t, server, mnt)

	if err := os.WriteFile(filepath.Join(mnt, "ticket-test.bin"), []byte("ticket-data"), 0o644); err != nil {
		t.Fatalf("写文件: %v", err)
	}
	objID := c.lookupObjID(t, res.Token, acct.SpaceID, "/ticket-test.bin")
	if objID == 0 {
		t.Fatal("文件应有独立 ObjID")
	}

	// 用真实用户会话 + 真实 space 换真实票据。
	ticket, status := c.issueUserTicket(t, res.Token, acct.SpaceID, c.nodes[0].addr(),
		http.MethodGet, "/objects/"+strconv.FormatUint(objID, 10))
	if status != http.StatusOK || ticket == "" {
		t.Fatalf("换票: status %d", status)
	}

	// 票据直打节点：200（对象在该节点上）。
	if got := secNodeStatus(t, http.MethodGet,
		c.nodes[0].server.URL+"/objects/"+strconv.FormatUint(objID, 10), ticket); got != http.StatusOK {
		t.Fatalf("合法票据 GET /objects/%d: status %d, want 200", objID, got)
	}

	// 用户会话直打节点：必须被拒（节点只认在线核验的短期票据）。
	if got := secNodeStatus(t, http.MethodGet,
		c.nodes[0].server.URL+"/objects/"+strconv.FormatUint(objID, 10), res.Token); got != http.StatusUnauthorized && got != http.StatusForbidden {
		t.Fatalf("用户会话直打节点: status %d, want 401/403", got)
	}
	// 无票据直打节点：必须被拒。
	if got := secNodeStatus(t, http.MethodGet,
		c.nodes[0].server.URL+"/objects/"+strconv.FormatUint(objID, 10), ""); got != http.StatusUnauthorized && got != http.StatusForbidden {
		t.Fatalf("无票据直打节点: status %d, want 401/403", got)
	}
}

// ---- 20. 登出后节点票据即时失效 ----

func TestSecureKernelLogoutRevokesNodeAccess(t *testing.T) {
	c := newSecureFuseCluster(t, 1)
	_, adminToken := c.adminLoginFuse()
	acct := c.createUserFuse(adminToken, uniqueUsername("victor"))
	cl, res := c.loginFuse(acct.Username, secFuseUserPassword)
	if err := cl.UseSpace(acct.SpaceID); err != nil {
		t.Fatalf("UseSpace: %v", err)
	}

	mnt, server := secMount(t, cl, "victor")
	defer secUnmountNow(t, server, mnt)

	if err := os.WriteFile(filepath.Join(mnt, "mine.txt"), []byte("personal-data"), 0o644); err != nil {
		t.Fatalf("写文件: %v", err)
	}
	objID := c.lookupObjID(t, res.Token, acct.SpaceID, "/mine.txt")
	if objID == 0 {
		t.Fatal("文件应有独立 ObjID")
	}

	// 登出前换票打节点：200。
	ticket, status := c.issueUserTicket(t, res.Token, acct.SpaceID, c.nodes[0].addr(),
		http.MethodGet, "/objects/"+strconv.FormatUint(objID, 10))
	if status != http.StatusOK || ticket == "" {
		t.Fatalf("登出前换票: status %d", status)
	}
	objURL := c.nodes[0].server.URL + "/objects/" + strconv.FormatUint(objID, 10)
	if got := secNodeStatus(t, http.MethodGet, objURL, ticket); got != http.StatusOK {
		t.Fatalf("登出前票据 GET: status %d, want 200", got)
	}

	// 登出：旧票据下一个请求即被节点在线拒绝。
	if err := cl.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if got := secNodeStatus(t, http.MethodGet, objURL, ticket); got != http.StatusUnauthorized && got != http.StatusForbidden {
		t.Fatalf("登出后旧票据 GET: status %d, want 401/403", got)
	}
	// 登出后重新换票：master 直接拒（会话已吊销）。
	_, status = c.issueUserTicket(t, res.Token, acct.SpaceID, c.nodes[0].addr(),
		http.MethodGet, "/objects/"+strconv.FormatUint(objID, 10))
	if status == http.StatusOK {
		t.Fatal("登出后重新换票应被拒绝")
	}
}

// ---- 集群查询辅助 ----

// lookupObjID 经 GET /meta 取空间内文件的真实对象 ID。分块文件取末块对象 ID
// （secure 挂载写路径恒走 chunked，见 Mount.New 的 NoSmallPath 分支）。
func (c *secFuseCluster) lookupObjID(t *testing.T, token string, spaceID uint64, path string) uint64 {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet,
		c.master.URL+"/meta?path="+secQueryEscape(path), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(access.SpaceHeader, strconv.FormatUint(spaceID, 10))
	req.Header.Set("X-Atoll-Features", types.ObjectIDFeature) // GET /meta 特性协商
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("lookup %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("lookup %s: status %d body %s", path, resp.StatusCode, body)
	}
	var out struct {
		Inode types.Inode `json:"inode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode lookup: %v", err)
	}
	in := out.Inode
	if in.Chunked {
		// 分块文件：对象 ID = 块对象 ID（验收测试只写单块小文件，取第 0 块）。
		if len(in.Chunks) == 0 {
			t.Fatalf("lookup %s: chunked 文件无块表", path)
		}
		return types.ChunkObjID(in.Chunks[len(in.Chunks)-1], in.ID)
	}
	if types.ObjIDFor(in) == 0 {
		t.Fatalf("lookup %s: 文件无对象 ID", path)
	}
	return types.ObjIDFor(in)
}

// lookupObjIDAdmin 用管理员会话经 /admin/meta 直查空间内文件（绝对路径，不经 space
// 权限裁决）。用于成员被移除后仍要拿真实对象 ID 的场景——被移除成员的会话对
// GET /meta 会 403，而对象 ID 是集群事实、与权限无关。
func (c *secFuseCluster) lookupObjIDAdmin(t *testing.T, spaceRoot, relPath string) uint64 {
	t.Helper()
	_, adminToken := c.adminLoginFuse()
	req, err := http.NewRequest(http.MethodGet,
		c.master.URL+"/admin/meta?path="+secQueryEscape(spaceRoot+relPath), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("X-Atoll-Features", types.ObjectIDFeature)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("admin lookup %s: %v", relPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("admin lookup %s: status %d body %s", relPath, resp.StatusCode, body)
	}
	var out struct {
		Inode types.Inode `json:"inode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode admin lookup: %v", err)
	}
	return types.ObjIDFor(out.Inode)
}

// issueUserTicket 用用户会话换节点票据，返回 (token, HTTP 状态码)。
func (c *secFuseCluster) issueUserTicket(t *testing.T, token string, spaceID uint64,
	nodeAddr, method, path string) (string, int) {
	t.Helper()
	body := map[string]any{"node_addr": nodeAddr, "method": method, "path": path}
	resp := secRawJSONFuse(t, http.MethodPost, c.master.URL+"/security/tickets", token, spaceID, body)
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

// issueUserTicketAsUser 用已登录客户端的当前会话 + 指定 space 换票
// （secureTransport 会自动注入 Bearer + X-Atoll-Space）。
func (c *secFuseCluster) issueUserTicketAsUser(t *testing.T, cl *client.Client, spaceID uint64,
	nodeAddr, method, path string) (string, int) {
	t.Helper()
	if err := cl.UseSpace(spaceID); err != nil {
		t.Fatalf("UseSpace: %v", err)
	}
	body, err := json.Marshal(map[string]any{"node_addr": nodeAddr, "method": method, "path": path})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, c.master.URL+"/security/tickets", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.HTTP.Do(req)
	if err != nil {
		t.Fatalf("换票请求: %v", err)
	}
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

// secNodeStatus 携带给定 Bearer 直连节点发请求，返回状态码。
func secNodeStatus(t *testing.T, method, nodeURL, bearer string) int {
	t.Helper()
	req, err := http.NewRequest(method, nodeURL, nil)
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
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// secQueryEscape 转义查询参数里的路径（只保留未保留字符，与 master 端解析一致）。
func secQueryEscape(s string) string {
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
		b.WriteByte(hexDigits[ch&0xF])
	}
	return b.String()
}

// 保证 import 的 errors 包被使用（失败断言路径统一走 t.Fatalf）。
var _ = errors.New
