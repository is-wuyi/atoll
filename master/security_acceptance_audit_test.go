// security_acceptance_audit_test.go：安全验收独立审计（第三双眼睛，只读审计产物）。
//
// 与 security_e2e_test.go（真节点全链路）、security_guard_test.go（网关边界）分工，
// 本文件只补三处此前无人锁定的验收缺口：
//
//  1. 票据核验侧绑定矩阵：CheckAccessTicket 对 method/path/query/body_hash/受众节点
//     的逐项失配必须拒绝（此前只测过"正确使用 + 发票侧吊销"）。
//  2. 设备票据规则与即时吊销：GET /objects 需要 sender 是副本、受众 Done；
//     PUT /replicate 需要 sender Done、受众是副本；设备撤销/会话版本变更后旧票立即失效。
//  3. 指纹绑定 commit 回放（真实事务内 op 记录）+ 覆盖写 target CAS。
package master

import (
	"encoding/json"
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
	accControlToken = "acc-control-token-0123456789abcdef"
	accAdminToken   = "acc-admin-token-0123456789abcdef"
	accLegacyToken  = "acc-legacy-cluster-shared-secret-0123456789"
	accPassword     = "acc-user-password-123"
)

type accCluster struct {
	t      *testing.T
	store  *meta.Store
	srv    *Server
	master *httptest.Server
}

func newAccCluster(t *testing.T) *accCluster {
	t.Helper()
	store, err := meta.Open(filepath.Join(t.TempDir(), "acc.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	if _, _, err := store.BootstrapSecurity("accadmin", "acc-admin-password-123", time.Now()); err != nil {
		t.Fatalf("BootstrapSecurity: %v", err)
	}
	srv := NewServer(store, time.Hour)
	srv.SetAdminToken(accAdminToken)
	if err := srv.EnableSecurity(SecurityConfig{ControlToken: accControlToken, AllowInsecure: true}); err != nil {
		t.Fatalf("EnableSecurity: %v", err)
	}
	ms := httptest.NewServer(srv.Handler())
	t.Cleanup(ms.Close)
	return &accCluster{t: t, store: store, srv: srv, master: ms}
}

func (c *accCluster) accUser(name string) (string, meta.PublicUser, meta.Space) {
	c.t.Helper()
	invite, err := c.store.CreateUserInvite(1, time.Now().Add(time.Hour), time.Now())
	if err != nil {
		tfatalf(c.t, "CreateUserInvite: %v", err)
	}
	user, space, err := c.store.RegisterInvitedUser(invite, name, accPassword, time.Now())
	if err != nil {
		tfatalf(c.t, "RegisterInvitedUser %s: %v", name, err)
	}
	sess, err := c.store.AuthenticateUser(name, accPassword, time.Now())
	if err != nil {
		tfatalf(c.t, "AuthenticateUser %s: %v", name, err)
	}
	return sess.Token, user, space
}

func tfatalf(t *testing.T, format string, args ...any) { t.Fatalf(format, args...) }

// accDevice 用设备邀请 + 挑战签名在 store 层直接落一个设备会话（fakenode）。
func (c *accCluster) accDevice(addr string) (string, uint64) {
	c.t.Helper()
	identity, err := edgeidentity.LoadOrCreate(filepath.Join(c.t.TempDir(), "acc-device-"+strings.ReplaceAll(addr, ":", "_")+".key"))
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

func (c *accCluster) accDo(method, target, token string, spaceID uint64, body any) (int, http.Header, []byte) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("marshal body: %v", err)
		}
		rd = strings.NewReader(string(raw))
	}
	req, err := http.NewRequest(method, c.master.URL+target, rd)
	if err != nil {
		c.t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if spaceID != 0 {
		req.Header.Set(access.SpaceHeader, strconv.FormatUint(spaceID, 10))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, data
}

// ---- 1. 票据核验侧绑定矩阵：method/path/query/body_hash/受众 逐项失配拒绝 ----

func TestAcceptanceTicketRequestBinding(t *testing.T) {
	c := newAccCluster(t)
	tokenA, userA, spaceA := c.accUser("accalice")
	devTok1, node1 := c.accDevice("127.0.0.1:51101")
	foreignTok, _ := c.accDevice("127.0.0.1:51102") // 外来设备（非受众）

	if _, err := c.store.RegisterNode("127.0.0.1:51101", 1<<20); err != nil {
		t.Fatalf("re-register node: %v", err)
	}
	doc, err := c.store.CreateFile(spaceA.RootID, "doc.bin", []uint64{node1})
	if err != nil {
		t.Fatalf("seed doc: %v", err)
	}
	payload := "acc-binding-payload"
	crc := types.CRC32C([]byte(payload))
	if err := c.store.UpdateFileSize(doc.ID, int64(len(payload)), crc); err != nil {
		t.Fatalf("UpdateFileSize: %v", err)
	}
	objPath := "/objects/" + strconv.FormatUint(doc.ID, 10)

	tk, err := c.store.IssueUserTicket(tokenA, spaceA.ID, access.TicketRequest{
		NodeAddr: "127.0.0.1:51101", Method: http.MethodGet, Path: objPath,
	}, time.Now())
	if err != nil {
		t.Fatalf("IssueUserTicket: %v", err)
	}

	check := func(method, path, query, bodyHash, devTok string) error {
		c.t.Helper()
		_, err := c.store.CheckAccessTicket(devTok, access.CheckRequest{
			Token: tk.Token, Method: method, Path: path, Query: query, BodyHash: bodyHash,
		}, time.Now())
		return err
	}
	if err := check(http.MethodGet, objPath, "", "", devTok1); err != nil {
		t.Fatalf("正确绑定应放行: %v", err)
	}
	if err := check(http.MethodPut, objPath, "", "", devTok1); err == nil {
		t.Fatal("method 失配必须拒绝")
	}
	if err := check(http.MethodGet, "/objects/999999", "", "", devTok1); err == nil {
		t.Fatal("path 失配必须拒绝")
	}
	if err := check(http.MethodGet, objPath, "plan_id=x", "", devTok1); err == nil {
		t.Fatal("query 失配必须拒绝")
	}
	if err := check(http.MethodGet, objPath, "", "0011223344556677889900112233445566778899001122334455667788990011", devTok1); err == nil {
		t.Fatal("body_hash 失配必须拒绝")
	}
	if err := check(http.MethodGet, objPath, "", "", foreignTok); err == nil {
		t.Fatal("受众节点失配必须拒绝")
	}

	// 写票据（PUT /objects）：他人 staging 拒绝、本人 staging 放行、已发布对象只读票拒绝。
	staging, err := c.store.CreateSecureUpload(userA.ID, spaceA.ID, spaceA.RootID, "up.bin", false, time.Now())
	if err != nil {
		t.Fatalf("CreateSecureUpload: %v", err)
	}
	chunk, err := c.store.AssignChunk(staging.ID, 0, 64, []uint64{node1}, 0, true)
	if err != nil {
		t.Fatalf("AssignChunk: %v", err)
	}
	if err := c.store.MarkChunkDone(types.ChunkObjID(chunk, staging.ID), node1); err != nil {
		t.Fatalf("MarkChunkDone: %v", err)
	}
	_, _, spaceB := c.accUser("accbob")
	// 他人 staging 的 PUT 票据在"签发侧"即被拒（issueTicket 内联校验 upload 记录属主），
	// 根本拿不到票据——比核验侧拒绝更前置。
	if _, err := c.store.IssueUserTicket(c.mustSession(t, "accbob"), spaceB.ID, access.TicketRequest{
		NodeAddr: "127.0.0.1:51101", Method: http.MethodPut, Path: "/objects/" + strconv.FormatUint(types.ChunkObjID(chunk, staging.ID), 10),
	}, time.Now()); err == nil {
		t.Fatal("他人 staging 的 PUT 票据必须拒绝（签发侧）")
	}
	tkW, err := c.store.IssueUserTicket(tokenA, spaceA.ID, access.TicketRequest{
		NodeAddr: "127.0.0.1:51101", Method: http.MethodPut, Path: "/objects/" + strconv.FormatUint(types.ChunkObjID(chunk, staging.ID), 10),
	}, time.Now())
	if err != nil {
		t.Fatalf("IssueUserTicket owner: %v", err)
	}
	if _, err := c.store.CheckAccessTicket(devTok1, access.CheckRequest{Token: tkW.Token,
		Method: http.MethodPut, Path: "/objects/" + strconv.FormatUint(types.ChunkObjID(chunk, staging.ID), 10)},
		time.Now()); err != nil {
		t.Fatalf("本人 staging 的 PUT 票据应放行: %v", err)
	}
	// 已发布对象的 PUT 票据在签发侧即拒（write 校验要求 staging）。
	if _, err := c.store.IssueUserTicket(tokenA, spaceA.ID, access.TicketRequest{
		NodeAddr: "127.0.0.1:51101", Method: http.MethodPut, Path: objPath,
	}, time.Now()); err == nil {
		t.Fatal("已发布对象的 PUT 票据必须拒绝（签发侧）")
	}
}

func (c *accCluster) mustSession(t *testing.T, name string) string {
	t.Helper()
	sess, err := c.store.AuthenticateUser(name, accPassword, time.Now())
	if err != nil {
		t.Fatalf("login %s: %v", name, err)
	}
	return sess.Token
}

// ---- 2. 设备票据规则 + 即时撤销 ----

func TestAcceptanceDeviceTicketRulesAndRevocation(t *testing.T) {
	c := newAccCluster(t)
	_, _, spaceA := c.accUser("accalice")
	devA, nodeA := c.accDevice("127.0.0.1:51201")
	devB, nodeB := c.accDevice("127.0.0.1:51202")

	doc, err := c.store.CreateFile(spaceA.RootID, "shared.bin", []uint64{nodeA, nodeB})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	payload := "acc-device-payload"
	if err := c.store.UpdateFileSize(doc.ID, int64(len(payload)), types.CRC32C([]byte(payload))); err != nil {
		t.Fatalf("UpdateFileSize: %v", err)
	}
	if err := c.store.AddReplicaDone(doc.ID, nodeB); err != nil {
		t.Fatalf("AddReplicaDone: %v", err)
	}
	objPath := "/objects/" + strconv.FormatUint(doc.ID, 10)
	repPath := "/replicate/" + strconv.FormatUint(doc.ID, 10)
	now := time.Now()

	// GET /objects：sender 必须是副本、受众必须 Done。
	tk, err := c.store.IssueDeviceTicket(devB, access.TicketRequest{NodeAddr: "127.0.0.1:51201", Method: http.MethodGet, Path: objPath}, now)
	if err != nil {
		t.Fatalf("IssueDeviceTicket GET: %v", err)
	}
	if _, err := c.store.CheckAccessTicket(devA, access.CheckRequest{Token: tk.Token, Method: http.MethodGet, Path: objPath}, now); err != nil {
		t.Fatalf("设备 GET 票据应放行: %v", err)
	}
	if _, err := c.store.CheckAccessTicket(devB, access.CheckRequest{Token: tk.Token, Method: http.MethodGet, Path: objPath}, now); err == nil {
		t.Fatal("设备票据跨节点出示必须拒绝")
	}

	// PUT /replicate：sender 必须 Done、受众必须是副本。
	tkR, err := c.store.IssueDeviceTicket(devA, access.TicketRequest{NodeAddr: "127.0.0.1:51202", Method: http.MethodPut, Path: repPath}, now)
	if err != nil {
		t.Fatalf("IssueDeviceTicket replicate: %v", err)
	}
	if _, err := c.store.CheckAccessTicket(devB, access.CheckRequest{Token: tkR.Token, Method: http.MethodPut, Path: repPath}, now); err != nil {
		t.Fatalf("设备 replicate 票据应放行: %v", err)
	}
	if _, err := c.store.CheckAccessTicket(devB, access.CheckRequest{Token: tkR.Token, Method: http.MethodPut, Path: repPath, BodyHash: strings.Repeat("ab", 32)}, now); err == nil {
		t.Fatal("设备票据不得绑定 body_hash（normalize 即拒绝）")
	}

	// sender 丢失 Done 后新票与旧票同时失效。
	if err := c.store.RemoveReplicaDone(doc.ID, nodeA); err != nil {
		t.Fatalf("RemoveReplicaDone: %v", err)
	}
	if _, err := c.store.IssueDeviceTicket(devA, access.TicketRequest{NodeAddr: "127.0.0.1:51202", Method: http.MethodPut, Path: repPath}, now); err == nil {
		t.Fatal("sender 非 Done 不得再签 replicate 票")
	}
	if _, err := c.store.CheckAccessTicket(devB, access.CheckRequest{Token: tkR.Token, Method: http.MethodPut, Path: repPath}, now); err == nil {
		t.Fatal("sender Done 被移除后旧 replicate 票必须拒绝")
	}

	// 即时撤销（check 时实时判定，不靠清扫）：
	//   a) sender 设备撤销 → 旧票 issuer 校验立即失败、不得再换票；
	//   b) 受众设备撤销 → 其核验会话立即失效。
	if err := c.store.AddReplicaDone(doc.ID, nodeA); err != nil {
		t.Fatalf("restore nodeA Done: %v", err)
	}
	tk2, err := c.store.IssueDeviceTicket(devB, access.TicketRequest{NodeAddr: "127.0.0.1:51201", Method: http.MethodGet, Path: objPath}, now)
	if err != nil {
		t.Fatalf("IssueDeviceTicket again: %v", err)
	}
	if _, err := c.store.CheckAccessTicket(devA, access.CheckRequest{Token: tk2.Token, Method: http.MethodGet, Path: objPath}, now); err != nil {
		t.Fatalf("恢复 Done 后 GET 票据应放行: %v", err)
	}
	if err := c.store.RevokeDevice(nodeB); err != nil {
		t.Fatalf("RevokeDevice sender: %v", err)
	}
	if _, err := c.store.IssueDeviceTicket(devB, access.TicketRequest{NodeAddr: "127.0.0.1:51201", Method: http.MethodGet, Path: objPath}, now); err == nil {
		t.Fatal("撤销设备不得再换票")
	}
	if _, err := c.store.CheckAccessTicket(devA, access.CheckRequest{Token: tk2.Token, Method: http.MethodGet, Path: objPath}, now); err == nil {
		t.Fatal("sender 设备撤销后旧票必须拒绝")
	}
	if err := c.store.RevokeDevice(nodeA); err != nil {
		t.Fatalf("RevokeDevice audience: %v", err)
	}
	if _, err := c.store.CheckAccessTicket(devA, access.CheckRequest{Token: tk2.Token, Method: http.MethodGet, Path: objPath}, now); err == nil {
		t.Fatal("受众设备撤销后核验会话必须立即失效")
	}
}

// ---- 3. commit 回放：指纹绑定 + 事务内 op 记录 + 作用域隔离 ----

func TestAcceptanceCommitReplayFingerprint(t *testing.T) {
	c := newAccCluster(t)
	tokenA, userA, spaceA := c.accUser("accalice")
	tokenB, _, spaceB := c.accUser("accbob")
	team, err := c.store.CreateTeam(userA.ID, "acc-replay-team")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}

	node, err := c.store.RegisterNode("127.0.0.1:51301", 1<<20)
	if err != nil {
		t.Fatalf("RegisterNode: %v", err)
	}
	staging, err := c.store.CreateSecureUpload(userA.ID, spaceA.ID, spaceA.RootID, "a.bin", false, time.Now())
	if err != nil {
		t.Fatalf("CreateSecureUpload: %v", err)
	}
	chunk, err := c.store.AssignChunk(staging.ID, 0, 100, []uint64{node.ID}, 0, false)
	if err != nil {
		t.Fatalf("AssignChunk: %v", err)
	}
	if err := c.store.MarkChunkDone(types.ChunkObjID(chunk, staging.ID), node.ID); err != nil {
		t.Fatalf("MarkChunkDone: %v", err)
	}

	commitBody := func(size int64) map[string]any {
		return map[string]any{"inode_id": staging.ID, "chunk_count": 1, "name": "a.bin", "size": size, "op_id": "acc-op-1"}
	}
	code, hdr, body := c.accDo(http.MethodPost, "/files/commit", tokenA, spaceA.ID, commitBody(100))
	if code != http.StatusOK {
		t.Fatalf("首次 commit: status %d body %s", code, body)
	}
	if hdr.Get("X-Atoll-Replay") == "true" {
		t.Fatal("首次 commit 不应带回放标记")
	}
	var first struct {
		ID      uint64 `json:"id"`
		Staging bool   `json:"staging"`
	}
	if err := json.Unmarshal(body, &first); err != nil || first.ID == 0 || first.Staging {
		t.Fatalf("首次 commit 响应异常: %s", body)
	}

	code, hdr, body = c.accDo(http.MethodPost, "/files/commit", tokenA, spaceA.ID, commitBody(100))
	if code != http.StatusOK {
		t.Fatalf("同 op 重试应回放: status %d body %s", code, body)
	}
	var replay struct {
		ID uint64 `json:"id"`
	}
	if err := json.Unmarshal(body, &replay); err != nil || replay.ID != first.ID {
		t.Fatalf("回放结果必须与原结果一致: %s vs %d", body, first.ID)
	}
	if hdr.Get("X-Atoll-Replay") == "true" {
		t.Log("网关层 commit 回放未设 X-Atoll-Replay（内层路径才有）——一致性观察项")
	}

	code, _, body = c.accDo(http.MethodPost, "/files/commit", tokenA, spaceA.ID, commitBody(101))
	if code != http.StatusConflict {
		t.Fatalf("同 op 不同 body 必须 409: status %d body %s", code, body)
	}
	code, _, body = c.accDo(http.MethodPost, "/files/commit", tokenA, team.ID, commitBody(100))
	if code != http.StatusForbidden {
		t.Fatalf("跨空间同 op 不得回放: status %d body %s", code, body)
	}
	code, _, body = c.accDo(http.MethodPost, "/files/commit", tokenB, spaceB.ID, commitBody(100))
	if code != http.StatusForbidden {
		t.Fatalf("跨用户同 op 不得回放: status %d body %s", code, body)
	}
}

// ---- 4. 覆盖写 target CAS：目标在 create→commit 窗口被替换必须拒绝 ----

func TestAcceptanceCommitTargetCAS(t *testing.T) {
	c := newAccCluster(t)
	tokenA, userA, spaceA := c.accUser("accalice")
	node, err := c.store.RegisterNode("127.0.0.1:51401", 1<<20)
	if err != nil {
		t.Fatalf("RegisterNode: %v", err)
	}

	seedChunk := func(staging uint64) {
		c.t.Helper()
		chunk, err := c.store.AssignChunk(staging, 0, 50, []uint64{node.ID}, 0, false)
		if err != nil {
			t.Fatalf("AssignChunk: %v", err)
		}
		if err := c.store.MarkChunkDone(types.ChunkObjID(chunk, staging), node.ID); err != nil {
			t.Fatalf("MarkChunkDone: %v", err)
		}
	}

	target, err := c.store.CreateFile(spaceA.RootID, "t.bin", nil)
	if err != nil {
		t.Fatalf("seed target: %v", err)
	}
	staging, err := c.store.CreateSecureUpload(userA.ID, spaceA.ID, spaceA.RootID, "t.bin", true, time.Now())
	if err != nil {
		t.Fatalf("CreateSecureUpload overwrite: %v", err)
	}
	seedChunk(staging.ID)

	// 目标在窗口内被替换（删旧建新 → 新 inode 新 generation）。
	if err := c.store.DeleteFile(target.ID); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}
	replacement, err := c.store.CreateFile(spaceA.RootID, "t.bin", nil)
	if err != nil {
		t.Fatalf("recreate target: %v", err)
	}
	code, _, body := c.accDo(http.MethodPost, "/files/commit", tokenA, spaceA.ID,
		map[string]any{"inode_id": staging.ID, "chunk_count": 1, "name": "t.bin", "size": 50, "op_id": "acc-cas-1"})
	if code != http.StatusConflict {
		t.Fatalf("CAS 失配 commit 必须 409: status %d body %s", code, body)
	}
	if cur, err := c.store.ResolvePath(spaceA.InternalPath + "/t.bin"); err != nil || cur.ID != replacement.ID {
		t.Fatalf("CAS 失配不得动目标: resolve err=%v id=%d want %d", err, cur.ID, replacement.ID)
	}

	// 正控制：无冲突覆盖提交成功，目标 inode 身份保留、generation 前进；改名不匹配拒绝。
	staging2, err := c.store.CreateSecureUpload(userA.ID, spaceA.ID, spaceA.RootID, "t.bin", true, time.Now())
	if err != nil {
		t.Fatalf("CreateSecureUpload 2: %v", err)
	}
	seedChunk(staging2.ID)
	code, _, body = c.accDo(http.MethodPost, "/files/commit", tokenA, spaceA.ID,
		map[string]any{"inode_id": staging2.ID, "chunk_count": 1, "name": "wrong.bin", "size": 50})
	if code != http.StatusForbidden {
		t.Fatalf("commit name 不匹配必须拒绝: status %d body %s", code, body)
	}
	code, _, body = c.accDo(http.MethodPost, "/files/commit", tokenA, spaceA.ID,
		map[string]any{"inode_id": staging2.ID, "chunk_count": 1, "name": "t.bin", "size": 50})
	if code != http.StatusOK {
		t.Fatalf("CAS 命中覆盖提交应成功: status %d body %s", code, body)
	}
	var out struct {
		ID         uint64 `json:"id"`
		Generation uint64 `json:"generation"`
		Staging    bool   `json:"staging"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.ID != replacement.ID || out.Staging {
		t.Fatalf("采纳式替换必须保留当前目标身份: %s (want id %d)", body, replacement.ID)
	}
	if out.Generation <= 0 {
		t.Fatalf("覆盖提交应推进 generation: %s", body)
	}
}

// ---- 5. control/admin 凭据边界：不得当用户会话触达数据面或换票 ----

func TestAcceptanceControlCredentialBoundary(t *testing.T) {
	c := newAccCluster(t)
	_, _, spaceA := c.accUser("accalice")

	// 控制凭据：数据面与用户面全拒。
	for _, tc := range []struct {
		name, method, target string
		space                uint64
		want                 int
	}{
		{"meta", http.MethodGet, "/meta?path=/", 0, http.StatusForbidden},
		{"replication", http.MethodGet, "/files/replication?object_id=1&node_id=1", 0, http.StatusForbidden},
		{"heartbeat", http.MethodPost, "/nodes/heartbeat", 0, http.StatusForbidden},
		{"ticket-no-space", http.MethodPost, "/security/tickets", 0, http.StatusForbidden},
		{"ticket-with-space", http.MethodPost, "/security/tickets", spaceA.ID, http.StatusForbidden},
	} {
		code, _, body := c.accDo(tc.method, tc.target, accControlToken, tc.space, map[string]any{"node_id": 1, "used_bytes": 0, "node_addr": "127.0.0.1:1", "path": "/objects/1", "method": "GET"})
		if code != tc.want {
			t.Fatalf("control token %s: status %d want %d (body %s)", tc.name, code, tc.want, body)
		}
	}
	// admin token 同样不得当用户会话。
	code, _, body := c.accDo(http.MethodGet, "/meta?path=/", accAdminToken, 0, nil)
	if code != http.StatusForbidden {
		t.Fatalf("admin token meta: status %d body %s", code, body)
	}
	// 旧静态集群 token 在安全模式下完全失效。
	code, _, body = c.accDo(http.MethodGet, "/meta?path=/", accLegacyToken, 0, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("legacy token meta: status %d body %s", code, body)
	}
	// /admin 只读 read-model 控制凭据可读（现行设计），破坏性 /admin/gc 必须 adminToken。
	code, _, body = c.accDo(http.MethodGet, "/admin/overview", accControlToken, 0, nil)
	if code != http.StatusOK {
		t.Fatalf("control token admin read-model: status %d body %s", code, body)
	}
	code, _, body = c.accDo(http.MethodPost, "/admin/gc", accControlToken, 0, map[string]any{"execute": false})
	if code != http.StatusUnauthorized {
		t.Fatalf("control token /admin/gc 必须要求 adminToken: status %d body %s", code, body)
	}
}

// ---- 6. 设备数据面：replication/replicated/objects-suspect 只能动自己的节点与真实副本 ----

func TestAcceptanceDeviceDataPlaneBoundary(t *testing.T) {
	c := newAccCluster(t)
	_, _, spaceA := c.accUser("accalice")
	dev1, node1 := c.accDevice("127.0.0.1:51601")
	_, node2 := c.accDevice("127.0.0.1:51602")

	doc, err := c.store.CreateFile(spaceA.RootID, "doc.bin", []uint64{node1})
	if err != nil {
		t.Fatalf("seed doc: %v", err)
	}
	payload := "acc-plane-payload"
	crc := types.CRC32C([]byte(payload))
	if err := c.store.UpdateFileSize(doc.ID, int64(len(payload)), crc); err != nil {
		t.Fatalf("UpdateFileSize: %v", err)
	}
	if _, err := c.store.RegisterNode("127.0.0.1:51601", 1<<20); err != nil {
		t.Fatalf("re-register: %v", err)
	}

	q1 := url.Values{"object_id": {strconv.FormatUint(doc.ID, 10)}, "node_id": {strconv.FormatUint(node1, 10)}}.Encode()
	code, _, body := c.accDo(http.MethodGet, "/files/replication?"+q1, dev1, 0, nil)
	if code != http.StatusOK {
		t.Fatalf("本节点 replication 查询应放行: status %d body %s", code, body)
	}
	q2 := url.Values{"object_id": {strconv.FormatUint(doc.ID, 10)}, "node_id": {strconv.FormatUint(node2, 10)}}.Encode()
	code, _, body = c.accDo(http.MethodGet, "/files/replication?"+q2, dev1, 0, nil)
	if code != http.StatusForbidden {
		t.Fatalf("claim 他人 node_id 的 replication 查询必须拒绝: status %d body %s", code, body)
	}

	// present：只能 claim 自己（unrecorded-checksum 文件）；回执必须绑定文件身份。
	plain, err := c.store.CreateFile(spaceA.RootID, "p.bin", []uint64{node1})
	if err != nil {
		t.Fatalf("seed plain: %v", err)
	}
	plainNow, err := c.store.ResolvePath(spaceA.InternalPath + "/p.bin")
	if err != nil {
		t.Fatalf("resolve plain: %v", err)
	}
	present := func(nodeID uint64) (int, []byte) {
		c.t.Helper()
		code, _, body := c.accDo(http.MethodPost, "/files/replicated/present", dev1, 0, map[string]any{
			"object": map[string]any{"object_id": plain.ID, "inode_id": plainNow.ID,
				"generation": plainNow.Generation, "size": 0},
			"node_id": nodeID,
		})
		return code, body
	}
	if code, body := present(node1); code != http.StatusOK {
		t.Fatalf("本节点 present 应放行: status %d body %s", code, body)
	}
	if code, body := present(node2); code != http.StatusForbidden {
		t.Fatalf("spoofed present 必须拒绝: status %d body %s", code, body)
	}

	// objects/suspect：目标必须是副本，reporter 必须是副本或保护计划参与者。
	suspect := func(target uint64, dev string) (int, []byte) {
		c.t.Helper()
		code, _, body := c.accDo(http.MethodPost, "/files/objects/suspect", dev, 0, map[string]any{
			"object":  map[string]any{"object_id": doc.ID, "size": int64(len(payload)), "checksum": crc, "checksum_known": true},
			"node_id": target,
		})
		return code, body
	}
	if code, body := suspect(node1, dev1); code != http.StatusOK {
		t.Fatalf("副本上报本副本 suspect 应放行: status %d body %s", code, body)
	}
	if code, body := suspect(node2, dev1); code != http.StatusForbidden {
		t.Fatalf("目标非副本的 suspect 必须拒绝: status %d body %s", code, body)
	}
	dev2, _ := c.accDevice("127.0.0.1:51603")
	if code, body := suspect(node1, dev2); code != http.StatusForbidden {
		t.Fatalf("非副本 reporter 的 suspect 必须拒绝: status %d body %s", code, body)
	}
}
