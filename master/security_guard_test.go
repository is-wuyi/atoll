// security_guard_test.go：安全网关独立边界审计（主 agent 之外的第二双眼睛）。
//
// 只测行为，不改实现/原测试；发现可复现漏洞先报主 agent，再用本文件记录 RED。
// 与 security_e2e_test.go 分工：e2e 走真组件全链路（登录 happy path、真节点、设备
// 全流程）；本文件用最小 fixture——真 bbolt + NewServer security 模式，节点只在
// store 层种子（fakenode），聚焦网关判定边界本身：
//
//  1. 命名空间路径/ID 绕过：空间根 DELETE/rename/mkdir、../ 与编码变体、重复 query 参数
//  2. 他人 staging 的 assign/commit/abort（跨用户/跨空间/非 staging）
//  3. 只读成员 suspect 上报（读损坏上报应允许）与删除/写入仍拒绝
//  4. op_id 作用域：跨用户/跨空间不串号，同 op 不同 body 拒绝
//  5. 旧集群 token 不得注册节点/不得当用户会话；设备会话边界（claim 他人 node_id）
//  6. 会话即时吊销：logout/禁用/改密后旧 token 立即失效、无法再换票
package master

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/access"
	"atoll/pkg/edgeidentity"
	"atoll/pkg/types"
)

const (
	guardControlToken = "guard-control-token-0123456789abcdef" // ≥24 字符
	guardAdminToken   = "guard-admin-token-0123456789abcdef"
	guardLegacyToken  = "legacy-cluster-shared-secret-0123456789" // 旧静态集群 token（安全模式下未注册）
	guardPassword     = "guard-user-password-123"
)

// ---- 最小 fixture：真 bbolt + security 模式 master，无真节点 ----

type guardCluster struct {
	t      *testing.T
	store  *meta.Store
	srv    *Server
	master *httptest.Server
	admin  meta.PublicUser
}

func newGuardCluster(t *testing.T) *guardCluster {
	t.Helper()
	store, err := meta.Open(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	admin, _, err := store.BootstrapSecurity("guardadmin", "guard-admin-password-123", time.Now())
	if err != nil {
		t.Fatalf("BootstrapSecurity: %v", err)
	}
	srv := NewServer(store, time.Hour)
	srv.SetAdminToken(guardAdminToken)
	if err := srv.EnableSecurity(SecurityConfig{ControlToken: guardControlToken, AllowInsecure: true}); err != nil {
		t.Fatalf("EnableSecurity: %v", err)
	}
	ms := httptest.NewServer(srv.Handler())
	t.Cleanup(ms.Close)
	return &guardCluster{t: t, store: store, srv: srv, master: ms, admin: admin}
}

// guardUser 在 store 层直接建用户并签发会话（不经 HTTP，避免重复账号 e2e 的登录
// happy path fixture），返回 token / 用户记录 / 个人 space。
func (c *guardCluster) guardUser(name string) (string, meta.PublicUser, meta.Space) {
	c.t.Helper()
	invite, err := c.store.CreateUserInvite(c.admin.ID, time.Now().Add(time.Hour), time.Now())
	if err != nil {
		c.t.Fatalf("CreateUserInvite: %v", err)
	}
	user, space, err := c.store.RegisterInvitedUser(invite, name, guardPassword, time.Now())
	if err != nil {
		c.t.Fatalf("RegisterInvitedUser %s: %v", name, err)
	}
	sess, err := c.store.AuthenticateUser(name, guardPassword, time.Now())
	if err != nil {
		c.t.Fatalf("AuthenticateUser %s: %v", name, err)
	}
	return sess.Token, user, space
}

// guardDevice 在 store 层完成设备挑战（fakenode：只注册身份与容量，无 HTTP 服务）。
func (c *guardCluster) guardDevice(addr string) (token string, nodeID uint64) {
	c.t.Helper()
	identity, err := edgeidentity.LoadOrCreate(filepath.Join(c.t.TempDir(), "device-"+strings.ReplaceAll(addr, ":", "_")+".key"))
	if err != nil {
		c.t.Fatalf("LoadOrCreate identity: %v", err)
	}
	invite, err := c.store.CreateDeviceInvite(time.Now().Add(time.Hour), time.Now())
	if err != nil {
		c.t.Fatalf("CreateDeviceInvite: %v", err)
	}
	ch, err := c.store.NewDeviceChallenge(access.DeviceChallengeRequest{
		PublicKey: identity.PublicKey(), Addr: addr, TotalBytes: 1 << 20, Invite: invite,
	}, time.Now())
	if err != nil {
		c.t.Fatalf("NewDeviceChallenge: %v", err)
	}
	sig, err := identity.Sign(ch.Challenge)
	if err != nil {
		c.t.Fatalf("Sign challenge: %v", err)
	}
	sess, err := c.store.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch.ID, Signature: sig}, time.Now())
	if err != nil {
		c.t.Fatalf("CompleteDeviceChallenge: %v", err)
	}
	return sess.Token, sess.NodeID
}

// guardDo 发显式 Bearer+space 请求，返回状态码/响应头/响应体。
func (c *guardCluster) guardDo(method, target, token string, spaceID uint64, extra map[string]string, body any) (int, http.Header, []byte) {
	c.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case string:
		rd = strings.NewReader(b)
	default:
		raw, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("marshal body: %v", err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.master.URL+target, rd)
	if err != nil {
		c.t.Fatalf("new request %s %s: %v", method, target, err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if spaceID != 0 {
		req.Header.Set(access.SpaceHeader, strconv.FormatUint(spaceID, 10))
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, data
}

func guardExpect(t *testing.T, what string, got, want int, body []byte) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: status = %d, want %d (body %s)", what, got, want, body)
	}
}

// ---- 1. 命名空间路径/ID 绕过 ----

func TestGuardNamespacePathBoundaries(t *testing.T) {
	c := newGuardCluster(t)
	token, _, space := c.guardUser("alice")

	if _, err := c.store.CreateFile(space.RootID, "f.txt", nil); err != nil {
		t.Fatalf("seed f.txt: %v", err)
	}
	if _, err := c.store.CreateFile(space.RootID, "f2.txt", nil); err != nil {
		t.Fatalf("seed f2.txt: %v", err)
	}

	// 正控制：合法删除/查询不受影响。
	code, _, body := c.guardDo(http.MethodDelete, "/entry?"+url.Values{"path": {"/f2.txt"}}.Encode(), token, space.ID, nil, nil)
	guardExpect(t, "delete own file", code, http.StatusOK, body)
	code, _, body = c.guardDo(http.MethodGet, "/meta?"+url.Values{"path": {"/f.txt"}}.Encode(), token, space.ID, nil, nil)
	guardExpect(t, "meta own file", code, http.StatusOK, body)

	// 空间根本体：DELETE / rename / mkdir 全拒。
	for _, p := range []string{"", "/", "/.", "/./"} {
		code, _, body = c.guardDo(http.MethodDelete, "/entry?"+url.Values{"path": {p}}.Encode(), token, space.ID, nil, nil)
		guardExpect(t, fmt.Sprintf("delete root path=%q", p), code, http.StatusForbidden, body)
		code, _, body = c.guardDo(http.MethodPost, "/entry/rename", token, space.ID, nil,
			map[string]string{"path": p, "new_name": "x"})
		guardExpect(t, fmt.Sprintf("rename root path=%q", p), code, http.StatusForbidden, body)
		code, _, body = c.guardDo(http.MethodPost, "/dirs", token, space.ID, nil, map[string]string{"path": p})
		guardExpect(t, fmt.Sprintf("mkdir root path=%q", p), code, http.StatusForbidden, body)
	}

	// ../ 与编码变体（raw query 原样发送，避免测试侧二次编码）：
	// 明文、百分号编码点、编码斜杠拼接、反斜杠、NUL，全部拒绝。
	for _, rawq := range []string{
		"path=/..", "path=/../x", "path=/x/..", "path=/x/../..", "path=//..//x",
		"path=%2e%2e", "path=%2e%2e/x", "path=%2f..%2fx", "path=/x/%2e%2e",
		"path=..%2fx", "path=%2f..%2f..%2fx", "path=/..%5c..", "path=%2f%2e%2e%2fx",
	} {
		code, _, body = c.guardDo(http.MethodDelete, "/entry?"+rawq, token, space.ID, nil, nil)
		guardExpect(t, fmt.Sprintf("delete escape %s", rawq), code, http.StatusForbidden, body)
		code, _, body = c.guardDo(http.MethodGet, "/meta?"+rawq, token, space.ID, nil, nil)
		guardExpect(t, fmt.Sprintf("meta escape %s", rawq), code, http.StatusForbidden, body)
	}
	// 双重编码解到字面 "%2e%2e" 文件名：不构成穿越，按普通名字解析（此处 404）。
	code, _, body = c.guardDo(http.MethodDelete, "/entry?path=%252e%252e", token, space.ID, nil, nil)
	if code < 400 {
		t.Fatalf("double-encoded dot-dot 不应命中任何条目: status %d", code)
	}

	// 重复 query 参数：取第一个值判定——逃逸值在首位必须被拒，不得被第二个合法值"漂白"。
	code, _, body = c.guardDo(http.MethodDelete, "/entry?path=%2F..%2Fx&path=%2Ff.txt", token, space.ID, nil, nil)
	guardExpect(t, "dup query escape first", code, http.StatusForbidden, body)
	if _, err := c.store.ResolvePath(space.InternalPath + "/f.txt"); err != nil {
		t.Fatalf("dup query 不应删除 f.txt: %v", err)
	}
	// 反序重复：合法值在首位 → 只删自己的文件（网关重写为单值，不放大）。
	code, _, body = c.guardDo(http.MethodDelete, "/entry?path=%2Ff.txt&path=%2F..%2Fx", token, space.ID, nil, nil)
	guardExpect(t, "dup query legal first", code, http.StatusOK, body)
	if _, err := c.store.ResolvePath(space.InternalPath + "/f.txt"); err == nil {
		t.Fatal("合法首位值的删除应生效")
	}

	// rename new_name 边界（父引用/含斜杠/点名字）——拒绝而非落入 children 索引。
	for _, nn := range []string{"../y", "sub/x", "..", "."} {
		code, _, body = c.guardDo(http.MethodPost, "/entry/rename", token, space.ID, nil,
			map[string]string{"path": "/f.txt", "new_name": nn})
		guardExpect(t, fmt.Sprintf("rename new_name=%q", nn), code, http.StatusBadRequest, body)
	}

	// symlink target：绝对路径与越出空间根的相对逃逸（主 agent 已修 base 相对化——
	// base 以空间根为相对原点，Clean 钳位在空间根内；锁定修后语义）。
	if _, err := c.store.CreateDir(space.RootID, "docs"); err != nil {
		t.Fatalf("seed docs dir: %v", err)
	}
	for _, target := range []string{"../../x", "/abs", "a/../../..", "a\\b", "x/../../../y", "../.."} {
		code, _, body = c.guardDo(http.MethodPost, "/files/symlink", token, space.ID, nil,
			map[string]string{"path": "/docs/link", "target": target})
		guardExpect(t, fmt.Sprintf("symlink target=%q", target), code, http.StatusForbidden, body)
	}
	// 正控制：相对合法 target 与"钳位后仍在空间内"的 target 允许。
	code, _, body = c.guardDo(http.MethodPost, "/files/symlink", token, space.ID, nil,
		map[string]string{"path": "/docs/link", "target": "f.txt"})
	guardExpect(t, "symlink relative target", code, http.StatusCreated, body)
	code, _, body = c.guardDo(http.MethodPost, "/files/symlink", token, space.ID, nil,
		map[string]string{"path": "/docs/link2", "target": "x/../../y"})
	guardExpect(t, "symlink clamped-in-space target", code, http.StatusCreated, body)
}

// ---- 2. 他人 staging 的 assign/commit/abort ----

func TestGuardStagingOwnershipBoundary(t *testing.T) {
	c := newGuardCluster(t)
	tokenA, userA, spaceA := c.guardUser("alice")
	tokenB, _, spaceB := c.guardUser("bob")

	// alice 的 staging：个人空间 + 团队空间各一个。
	stagingA, err := c.store.CreateSecureUpload(userA.ID, spaceA.ID, spaceA.RootID, "a.bin", false, time.Now())
	if err != nil {
		t.Fatalf("CreateSecureUpload: %v", err)
	}
	team, err := c.store.CreateTeam(userA.ID, "guard-staging-team")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	stagingT, err := c.store.CreateSecureUpload(userA.ID, team.ID, team.RootID, "t.bin", false, time.Now())
	if err != nil {
		t.Fatalf("CreateSecureUpload team: %v", err)
	}

	assignBody := func(id uint64) map[string]any {
		return map[string]any{"inode_id": id, "index": 0, "size": 10, "replicas": 1, "checksum": 12345}
	}
	commitBody := func(id uint64) map[string]any {
		return map[string]any{"inode_id": id, "chunk_count": 1, "name": "a.bin", "size": 10}
	}

	// bob（非成员）对 alice staging 的三类操作全拒。
	code, _, body := c.guardDo(http.MethodPost, "/files/chunks", tokenB, spaceB.ID, nil, assignBody(stagingA.ID))
	guardExpect(t, "bob assign alice staging", code, http.StatusForbidden, body)
	code, _, body = c.guardDo(http.MethodPost, "/files/commit", tokenB, spaceB.ID, nil, commitBody(stagingA.ID))
	guardExpect(t, "bob commit alice staging", code, http.StatusForbidden, body)
	code, _, body = c.guardDo(http.MethodDelete, "/files/staging/"+strconv.FormatUint(stagingA.ID, 10), tokenB, spaceB.ID, nil, nil)
	guardExpect(t, "bob abort alice staging", code, http.StatusForbidden, body)

	// 所有者本人但换用另一空间的 space 头：跨空间引用同样拒绝。
	code, _, body = c.guardDo(http.MethodPost, "/files/chunks", tokenA, spaceA.ID, nil, assignBody(stagingT.ID))
	guardExpect(t, "assign team staging with personal space header", code, http.StatusForbidden, body)

	// 对已提交（非 staging）inode 的 assign 拒绝。
	if _, err := c.store.CreateFile(spaceA.RootID, "live.bin", nil); err != nil {
		t.Fatalf("seed live.bin: %v", err)
	}
	live, err := c.store.ResolvePath(spaceA.InternalPath + "/live.bin")
	if err != nil {
		t.Fatalf("resolve live.bin: %v", err)
	}
	code, _, body = c.guardDo(http.MethodPost, "/files/chunks", tokenA, spaceA.ID, nil, assignBody(live.ID))
	guardExpect(t, "assign on committed inode", code, http.StatusForbidden, body)

	// 正控制：所有者本人 abort 自己的 staging。
	code, _, body = c.guardDo(http.MethodDelete, "/files/staging/"+strconv.FormatUint(stagingA.ID, 10), tokenA, spaceA.ID, nil, nil)
	guardExpect(t, "owner abort own staging", code, http.StatusOK, body)
}

// ---- 3. 只读成员：suspect 上报允许，删除/写入拒绝 ----

func TestGuardReadonlySuspectBoundary(t *testing.T) {
	c := newGuardCluster(t)
	_, userA, spaceA := c.guardUser("alice")
	tokenR, userR, _ := c.guardUser("reader")

	team, err := c.store.CreateTeam(userA.ID, "guard-readonly-team")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if err := c.store.SetTeamMember(userA.ID, team.ID, userR.ID, meta.RoleRead); err != nil {
		t.Fatalf("SetTeamMember reader: %v", err)
	}

	// fakenode：store 层注册副本节点 + 带副本的文件（版本三元组供 suspect 上报）。
	node, err := c.store.RegisterNode("127.0.0.1:64001", 1<<20)
	if err != nil {
		t.Fatalf("RegisterNode: %v", err)
	}
	doc, err := c.store.CreateFile(team.RootID, "doc.bin", []uint64{node.ID})
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	payload := "guard-document-payload"
	crc := types.CRC32C([]byte(payload))
	if err := c.store.UpdateFileSize(doc.ID, int64(len(payload)), crc); err != nil {
		t.Fatalf("UpdateFileSize: %v", err)
	}
	docNow, err := c.store.ResolvePath(team.InternalPath + "/doc.bin") // 取 UpdateFileSize 后的 generation
	if err != nil {
		t.Fatalf("resolve doc.bin: %v", err)
	}

	// 只读成员：读损坏上报（不删数据的自愈线索）应允许。
	code, _, body := c.guardDo(http.MethodPost, "/files/suspect", tokenR, team.ID, nil, map[string]any{
		"inode_id": doc.ID, "node_id": node.ID, "generation": docNow.Generation,
		"size": int64(len(payload)), "checksum": crc,
	})
	guardExpect(t, "readonly suspect report", code, http.StatusOK, body)
	code, _, body = c.guardDo(http.MethodPost, "/files/chunks/suspect", tokenR, team.ID, nil, map[string]any{
		"inode_id": doc.ID, "generation": docNow.Generation, "chunk_index": 0,
		"object_id": doc.ID, "node_id": node.ID, "size": 10, "checksum": 777,
	})
	guardExpect(t, "readonly chunk suspect report", code, http.StatusOK, body)

	// 只读成员：删除/写入仍拒绝（上报通道不等于数据面写权限）。
	code, _, body = c.guardDo(http.MethodDelete, "/entry?"+url.Values{"path": {"/doc.bin"}}.Encode(), tokenR, team.ID, nil, nil)
	guardExpect(t, "readonly delete", code, http.StatusForbidden, body)
	code, _, body = c.guardDo(http.MethodPost, "/dirs", tokenR, team.ID, nil, map[string]string{"path": "/sub"})
	guardExpect(t, "readonly mkdir", code, http.StatusForbidden, body)
	code, _, body = c.guardDo(http.MethodPost, "/files/small?path=%2Fx&replicas=1&overwrite=false&op_id=op-ro",
		tokenR, team.ID, map[string]string{"X-Atoll-Features": types.ObjectIDFeature}, []byte("payload"))
	guardExpect(t, "readonly small upload", code, http.StatusForbidden, body)

	// 跨空间 suspect：只读成员用团队 space 头引用 alice 个人空间的 inode → 拒绝。
	other, err := c.store.CreateFile(spaceA.RootID, "other.bin", nil)
	if err != nil {
		t.Fatalf("seed other.bin: %v", err)
	}
	code, _, body = c.guardDo(http.MethodPost, "/files/suspect", tokenR, team.ID, nil, map[string]any{
		"inode_id": other.ID, "node_id": node.ID, "generation": uint64(0), "size": int64(1), "checksum": uint32(1),
	})
	guardExpect(t, "cross-space suspect report", code, http.StatusForbidden, body)
}

// ---- 4. op_id 作用域：跨用户/跨空间不串号，无指纹记录不回放 ----

func TestGuardOpScopeBoundary(t *testing.T) {
	c := newGuardCluster(t)
	tokenA, userA, spaceA := c.guardUser("alice")
	tokenB, _, spaceB := c.guardUser("bob")
	team, err := c.store.CreateTeam(userA.ID, "guard-op-team")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}

	// 说明：指纹绑定的 op 记录只能由真实上传流（PrepareSmallFile/CommitStagingFile+
	// bindings，需真节点）产生——那半边由 e2e 覆盖。本测试用 store 层可种子的
	// 无指纹记录，验证网关自身的两条性质：
	//   (a) commit 回放绝不回放缺 body 指纹的记录（opResultTx 空指纹跳过校验的
	//       脆弱点被网关二次校验拦住）；
	//   (b) op_id 按 (user, space, kind) 作用域化——跨用户/跨空间同裸 op 不串号。

	// ---- commit：无指纹记录 → 即使同 body 也 409，绝不当幂等结果回放。----
	live, err := c.store.CreateFile(spaceA.RootID, "c.bin", nil)
	if err != nil {
		t.Fatalf("seed c.bin: %v", err)
	}
	commitMap := func(size int64) map[string]json.RawMessage {
		return map[string]json.RawMessage{
			"inode_id":    json.RawMessage(strconv.FormatUint(live.ID, 10)),
			"chunk_count": json.RawMessage("1"),
			"name":        json.RawMessage(`"c.bin"`),
			"size":        json.RawMessage(strconv.FormatInt(size, 10)),
			"op_id":       json.RawMessage(`"op-c1"`),
		}
	}
	opCommit := scopedOp(userA.ID, spaceA.ID, "commit", "op-c1")
	if err := c.store.PutOpResultAt(opCommit, "commit", live, time.Now()); err != nil {
		t.Fatalf("PutOpResultAt commit: %v", err)
	}
	code, _, body := c.guardDo(http.MethodPost, "/files/commit", tokenA, spaceA.ID, nil, commitMap(100))
	guardExpect(t, "commit replay refuses fingerprint-less record", code, http.StatusConflict, body)

	// 跨空间（同一用户、团队 space 头）：作用域不同 → 不回放 → 对他空间 inode 无权 → 403。
	code, _, body = c.guardDo(http.MethodPost, "/files/commit", tokenA, team.ID, nil, commitMap(100))
	guardExpect(t, "commit cross-space scope", code, http.StatusForbidden, body)
	// 跨用户（同一裸 op、bob 自己的 space）：不回放、无权 → 403。
	code, _, body = c.guardDo(http.MethodPost, "/files/commit", tokenB, spaceB.ID, nil, commitMap(100))
	guardExpect(t, "commit cross-user scope", code, http.StatusForbidden, body)

	// ---- small：跨用户同裸 op 不回放（无指纹记录即使命中也不该跨域返回他人结果）。----
	data := []byte("guard-small-payload")
	opSmall := scopedOp(userA.ID, spaceA.ID, "small", "op-s1")
	if err := c.store.PutOpResultAt(opSmall, "small", types.Inode{ID: 424242, Name: "f.txt"}, time.Now()); err != nil {
		t.Fatalf("PutOpResultAt small: %v", err)
	}
	q := url.Values{"path": {"/f.txt"}, "replicas": {"1"}, "overwrite": {"true"}, "op_id": {"op-s1"}}
	extra := map[string]string{"X-Atoll-Features": types.ObjectIDFeature, "Content-Type": "application/octet-stream"}
	code, hdrB, body := c.guardDo(http.MethodPost, "/files/small?"+q.Encode(), tokenB, spaceB.ID, extra, data)
	if hdrB.Get("X-Atoll-Replay") == "true" || (code == http.StatusOK && len(body) > 0 && strings.Contains(string(body), "424242")) {
		t.Fatalf("跨用户 op 不得回放他人结果: status %d body %s", code, body)
	}
}

// ---- 5. 旧集群 token / 设备会话边界 ----

func TestGuardLegacyTokenAndDeviceBoundary(t *testing.T) {
	c := newGuardCluster(t)

	// 旧静态集群 token 不是用户会话：注册节点与文件操作全拒（401）。
	reg := map[string]any{"addr": "127.0.0.1:64002", "total_bytes": 1000}
	code, _, body := c.guardDo(http.MethodPost, "/nodes/register", guardLegacyToken, 0, nil, reg)
	guardExpect(t, "legacy token node register", code, http.StatusUnauthorized, body)
	code, _, body = c.guardDo(http.MethodGet, "/meta?"+url.Values{"path": {"/x"}}.Encode(), guardLegacyToken, 0, nil, nil)
	guardExpect(t, "legacy token meta", code, http.StatusUnauthorized, body)
	code, _, body = c.guardDo(http.MethodPost, "/files/commit", guardLegacyToken, 0, nil,
		map[string]any{"inode_id": 1, "chunk_count": 1, "name": "x", "size": 1})
	guardExpect(t, "legacy token commit", code, http.StatusUnauthorized, body)

	// 控制/admin 凭据只限 /admin/*：不得当用户会话注册节点。
	code, _, body = c.guardDo(http.MethodPost, "/nodes/register", guardControlToken, 0, nil, reg)
	guardExpect(t, "control token node register", code, http.StatusForbidden, body)
	code, _, body = c.guardDo(http.MethodPost, "/nodes/register", guardAdminToken, 0, nil, reg)
	guardExpect(t, "admin token node register", code, http.StatusForbidden, body)

	// 设备会话（nd1_）：心跳只能 claim 自己的 node_id，注册节点被拒。
	deviceToken, nodeID := c.guardDevice("127.0.0.1:64002")
	code, _, body = c.guardDo(http.MethodPost, "/nodes/heartbeat", deviceToken, 0, nil,
		map[string]any{"node_id": nodeID, "used_bytes": 0})
	guardExpect(t, "device heartbeat own node", code, http.StatusOK, body)
	code, _, body = c.guardDo(http.MethodPost, "/nodes/heartbeat", deviceToken, 0, nil,
		map[string]any{"node_id": nodeID + 999999, "used_bytes": 0})
	guardExpect(t, "device heartbeat spoofed node", code, http.StatusForbidden, body)
	code, _, body = c.guardDo(http.MethodPost, "/nodes/register", deviceToken, 0, nil, reg)
	guardExpect(t, "device token node register", code, http.StatusForbidden, body)
}

// ---- 6. 会话即时吊销 ----

func guardLogin(c *guardCluster, name string) string {
	c.t.Helper()
	sess, err := c.store.AuthenticateUser(name, guardPassword, time.Now())
	if err != nil {
		c.t.Fatalf("AuthenticateUser %s: %v", name, err)
	}
	return sess.Token
}

func TestGuardSessionImmediateRevocation(t *testing.T) {
	c := newGuardCluster(t)
	_, userB, _ := c.guardUser("bob")
	_, userC, _ := c.guardUser("carol")
	tokenA, _, spaceA := c.guardUser("alice")

	code, _, body := c.guardDo(http.MethodGet, "/auth/me", tokenA, 0, nil, nil)
	guardExpect(t, "me before logout", code, http.StatusOK, body)

	// 登出即时生效：同一 token 的会话与换票通道同时失效。
	code, _, body = c.guardDo(http.MethodPost, "/auth/logout", tokenA, 0, nil, nil)
	guardExpect(t, "logout", code, http.StatusOK, body)
	code, _, body = c.guardDo(http.MethodGet, "/auth/me", tokenA, 0, nil, nil)
	guardExpect(t, "me after logout", code, http.StatusUnauthorized, body)
	code, _, body = c.guardDo(http.MethodPost, "/security/tickets", tokenA, spaceA.ID, nil,
		map[string]any{"node_addr": "127.0.0.1:64003", "method": "GET", "path": "/objects/1"})
	guardExpect(t, "ticket after logout", code, http.StatusForbidden, body)

	// 禁用即时生效：平台管理员停用后旧会话全灭。
	tokenB := guardLogin(c, "bob")
	code, _, _ = c.guardDo(http.MethodGet, "/auth/me", tokenB, 0, nil, nil)
	if code != http.StatusOK {
		t.Fatalf("me before disable: status %d", code)
	}
	if err := c.store.DisableUser(c.admin.ID, userB.ID, true); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	code, _, body = c.guardDo(http.MethodGet, "/auth/me", tokenB, 0, nil, nil)
	guardExpect(t, "me after disable", code, http.StatusUnauthorized, body)
	code, _, body = c.guardDo(http.MethodPost, "/security/tickets", tokenB, 0, nil,
		map[string]any{"node_addr": "127.0.0.1:64004", "method": "GET", "path": "/objects/1"})
	guardExpect(t, "ticket after disable", code, http.StatusForbidden, body)

	// 改密：全部旧会话（含发起者）立即吊销。
	tokenC := guardLogin(c, "carol")
	code, _, _ = c.guardDo(http.MethodGet, "/auth/me", tokenC, 0, nil, nil)
	if code != http.StatusOK {
		t.Fatalf("me before password change: status %d", code)
	}
	if err := c.store.ChangePassword(userC.ID, guardPassword, "guard-carol-new-password-9"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	code, _, body = c.guardDo(http.MethodGet, "/auth/me", tokenC, 0, nil, nil)
	guardExpect(t, "me after password change", code, http.StatusUnauthorized, body)
	code, _, body = c.guardDo(http.MethodPost, "/security/tickets", tokenC, 0, nil,
		map[string]any{"node_addr": "127.0.0.1:64005", "method": "GET", "path": "/objects/1"})
	guardExpect(t, "ticket after password change", code, http.StatusForbidden, body)
}
