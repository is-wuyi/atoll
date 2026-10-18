package meta

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/edgeidentity"
	"atoll/pkg/types"

	bolt "go.etcd.io/bbolt"
)

// auditDevice 在 store 层完成一次设备登录，返回设备会话与登录上下文。
type auditDevice struct {
	Token    string
	NodeID   uint64
	Identity *edgeidentity.Identity
}

func auditLoginDevice(t *testing.T, s *Store, addr string, invite string) auditDevice {
	t.Helper()
	id, err := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), "audit-"+strings.ReplaceAll(addr, ":", "_")+".key"))
	if err != nil {
		t.Fatalf("LoadOrCreate identity: %v", err)
	}
	if invite == "" {
		invite, err = s.CreateDeviceInvite(time.Now().Add(time.Hour), time.Now())
		if err != nil {
			t.Fatalf("CreateDeviceInvite: %v", err)
		}
	}
	ch, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{
		PublicKey: id.PublicKey(), Addr: addr, TotalBytes: 1 << 20, Invite: invite,
	}, time.Now())
	if err != nil {
		t.Fatalf("NewDeviceChallenge(%s): %v", addr, err)
	}
	sig, err := id.Sign(ch.Challenge)
	if err != nil {
		t.Fatalf("Sign challenge: %v", err)
	}
	sess, err := s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch.ID, Signature: sig}, time.Now())
	if err != nil {
		t.Fatalf("CompleteDeviceChallenge: %v", err)
	}
	return auditDevice{Token: sess.Token, NodeID: sess.NodeID, Identity: id}
}

// ---- Test 1: securityEnabled 配置损坏必须 fail-closed ----

func TestAuditSecurityConfigCorruptionFailsClosed(t *testing.T) {
	s := newTestStore(t)
	admin, space := bootstrapAdmin(t, s)
	if admin.ID == 0 || space.ID == 0 {
		t.Fatal("bootstrap 未产生管理员/空间")
	}
	// 基线：启用状态下，无设备记录的 legacy 节点不允许心跳（安全门生效）。
	legacy, err := s.RegisterNode("127.0.0.1:59901", 1<<20)
	if err != nil {
		t.Fatalf("RegisterNode legacy: %v", err)
	}
	if err := s.Heartbeat(legacy.ID, 1); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("启用安全时 legacy 节点心跳应被拒（ErrDeviceAuth），got %v", err)
	}
	if enabled, err := s.SecurityEnabled(); err != nil || !enabled {
		t.Fatalf("基线 SecurityEnabled 应为 (true,nil)，got (%v,%v)", enabled, err)
	}
	// 损坏 cfg/security（模拟位翻转/撕裂写：bbolt 记录无内建校验）。
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSecurity).Put(keySecConfig, []byte("{corrupted-not-json"))
	}); err != nil {
		t.Fatalf("corrupt cfg: %v", err)
	}
	// 验收语义：损坏必须 fail-closed。
	if _, err := s.SecurityEnabled(); err == nil {
		t.Errorf("AUDIT DEFECT (fail-open): cfg/security 损坏时 SecurityEnabled() 返回 nil error，" +
			"把『损坏』与『未启用』混为一谈；调用方（如 EnableSecurity 之外的心跳门）会静默退回无安全模式")
	}
	if err := s.Heartbeat(legacy.ID, 1); err == nil {
		t.Errorf("AUDIT DEFECT (fail-open): cfg/security 损坏后无设备节点的 Heartbeat 被放行——" +
			"任意未认证方可在安全门失效期间伪造任意节点心跳/用量")
	}
	for _, n := range func() []types.NodeInfo { out, _ := s.ListAliveNodes(time.Hour); return out }() {
		if n.ID == legacy.ID {
			t.Errorf("AUDIT DEFECT (fail-open): cfg/security 损坏后 ListAliveNodes 重新纳入无设备记录节点 %d", n.ID)
		}
	}
}

// ---- Test 2: deviceChallenge 一次性/过期/重放/Endpoint + RevokeDevice 幂等 ----

func TestAuditDeviceChallengeReplayRevokeAndEndpoint(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()

	invite, err := s.CreateDeviceInvite(now.Add(time.Hour), now)
	if err != nil {
		t.Fatalf("CreateDeviceInvite: %v", err)
	}
	// 一次邀请可催生多个未完成挑战（创建不烧邀请），但只有一次完成能建立设备。
	id, err := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), "audit-dev.key"))
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	const addrA = "127.0.0.1:59001"
	const addrB = "127.0.0.1:59002"
	ch1, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: id.PublicKey(), Addr: addrA, TotalBytes: 1 << 20, Invite: invite}, now)
	if err != nil {
		t.Fatalf("NewDeviceChallenge c1: %v", err)
	}
	ch2, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: id.PublicKey(), Addr: addrB, TotalBytes: 1 << 20, Invite: invite}, now)
	if err != nil {
		t.Fatalf("NewDeviceChallenge c2: %v", err)
	}
	sig1, err := id.Sign(ch1.Challenge)
	if err != nil {
		t.Fatalf("Sign c1: %v", err)
	}
	sig2, err := id.Sign(ch2.Challenge)
	if err != nil {
		t.Fatalf("Sign c2: %v", err)
	}
	// 未知挑战 / 错误签名（伪证）必须拒绝。
	if _, err := s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: "dc1_nope", Signature: sig1}, now); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("未知挑战应 ErrDeviceAuth，got %v", err)
	}
	if _, err := s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch1.ID, Signature: sig2}, now); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("用另一挑战的签名完成 c1 应 ErrDeviceAuth，got %v", err)
	}
	sessA, err := s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch1.ID, Signature: sig1}, now)
	if err != nil {
		t.Fatalf("CompleteDeviceChallenge c1: %v", err)
	}
	// 一次性：同一 (挑战, 签名) 重放拒绝（两 nonce 之一已烧毁）。
	if _, err := s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch1.ID, Signature: sig1}, now); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("已用挑战重放应 ErrDeviceAuth，got %v", err)
	}
	// 过期：挑战 2 分钟窗口外完成拒绝（VerifyAt 严格 skew=0）。
	if _, err := s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch2.ID, Signature: sig2}, now.Add(3*time.Minute)); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("过期挑战完成应 ErrDeviceAuth，got %v", err)
	}
	// 邀请已烧毁：再用同一邀请为**新**公钥开挑战必须拒绝。
	id2, err := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), "audit-dev2.key"))
	if err != nil {
		t.Fatalf("LoadOrCreate 2: %v", err)
	}
	if _, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: id2.PublicKey(), Addr: "127.0.0.1:59003", TotalBytes: 1, Invite: invite}, now); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("已用邀请再开新设备挑战应 ErrDeviceAuth，got %v", err)
	}
	// 换 Endpoint：新挑战 c3 完成后设备迁到 addrB，SessionVersion++ 使旧会话失效。
	ch3, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: id.PublicKey(), Addr: addrB, TotalBytes: 1 << 20}, now)
	if err != nil {
		t.Fatalf("NewDeviceChallenge c3: %v", err)
	}
	sig3, err := id.Sign(ch3.Challenge)
	if err != nil {
		t.Fatalf("Sign c3: %v", err)
	}
	sessB, err := s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch3.ID, Signature: sig3}, now)
	if err != nil {
		t.Fatalf("CompleteDeviceChallenge c3: %v", err)
	}
	if sessB.NodeID != sessA.NodeID {
		t.Fatalf("同一设备再登录应复用 NodeID：%d vs %d", sessA.NodeID, sessB.NodeID)
	}
	// 旧 Endpoint 挑战 (c1) 已烧毁：无法借重放把设备切回 addrA。
	if _, err := s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch1.ID, Signature: sig1}, now); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("重放旧 Endpoint 挑战应 ErrDeviceAuth，got %v", err)
	}
	if d, err := s.DeviceByNode(sessB.NodeID); err != nil || d.Addr != addrB {
		t.Fatalf("设备 Endpoint 应停留在最新挑战地址 %s，got %s err=%v", addrB, d.Addr, err)
	}
	if _, err := s.DeviceForSession(sessA.Token, now.Add(time.Minute)); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("SessionVersion++ 后旧设备会话应失效，got %v", err)
	}
	if _, err := s.DeviceForSession(sessB.Token, now.Add(time.Minute)); err != nil {
		t.Fatalf("最新设备会话应有效，got %v", err)
	}
	// RevokeDevice：即时失效在线会话。
	if err := s.RevokeDevice(sessB.NodeID); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	if _, err := s.DeviceForSession(sessB.Token, now.Add(time.Minute)); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("吊销后设备会话应失效，got %v", err)
	}
	// 验收语义：重复吊销幂等成功（误报失败会让运维误以为吊销未生效，且
	// postCommit 同步失败后的重试会把『已生效』当『失败』）。
	if err := s.RevokeDevice(sessB.NodeID); err != nil {
		t.Errorf("AUDIT DEFECT (non-idempotent): RevokeDevice 重复吊销已吊销设备返回 %v；"+
			"应为 nil（对照 DisableUser/RemoveTeamMember 的幂等语义），否则吊销重试不可区分『未生效』与『已生效』", err)
	}
	// 未知节点吊销仍应报错（非 ErrDeviceAuth 之外不放宽）。
	if err := s.RevokeDevice(^uint64(0) - 1); err == nil {
		t.Fatalf("吊销不存在节点应报错，got nil")
	}
}

// ---- Test 3: 用户票据在线核验：登出/停用/改密即时失效 ----

func TestAuditUserTicketOnlineInvalidation(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	now := time.Now()
	admin, _ := bootstrapAdmin(t, s)
	dev := auditLoginDevice(t, s, "127.0.0.1:59101", "")

	inviteCode, err := s.CreateUserInvite(admin.ID, now.Add(time.Hour), now)
	if err != nil {
		t.Fatalf("CreateUserInvite: %v", err)
	}
	bob, bobSpace, err := s.RegisterInvitedUser(inviteCode, "bob", "bob-password-123", now)
	if err != nil {
		t.Fatalf("RegisterInvitedUser: %v", err)
	}
	bobFile, err := s.CreateFile(bobSpace.RootID, "bf.bin", []uint64{dev.NodeID})
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	objPath := fmt.Sprintf("/objects/%d", bobFile.ID)
	mkTicket := func(sessToken string) access.Ticket {
		t.Helper()
		tk, err := s.IssueUserTicket(sessToken, bobSpace.ID, access.TicketRequest{
			NodeAddr: "127.0.0.1:59101", Method: "GET", Path: objPath,
		}, time.Now())
		if err != nil {
			t.Fatalf("IssueUserTicket: %v", err)
		}
		return tk
	}
	check := func(tk access.Ticket) error {
		_, err := s.CheckAccessTicket(dev.Token, access.CheckRequest{Token: tk.Token, Method: "GET", Path: objPath}, time.Now())
		return err
	}

	// 登出：会话吊销 → 在线核验立即拒绝（票据仍在其 2 分钟 TTL 内）。
	sess1, err := s.AuthenticateUser("bob", "bob-password-123", now)
	if err != nil {
		t.Fatalf("AuthenticateUser bob: %v", err)
	}
	tk1 := mkTicket(sess1.Token)
	if err := check(tk1); err != nil {
		t.Fatalf("有效票据应通过在线核验: %v", err)
	}
	if err := s.RevokeSession(sess1.Token); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if err := check(tk1); !errors.Is(err, ErrAccessTicket) {
		t.Errorf("登出后票据必须立即失效（在线核验），got %v", err)
	}

	// 停用：全部会话同事务吊销 + 实时 Disabled 判定 → 票据立即失效，且不能再登录。
	sess2, err := s.AuthenticateUser("bob", "bob-password-123", now)
	if err != nil {
		t.Fatalf("re-login: %v", err)
	}
	tk2 := mkTicket(sess2.Token)
	if err := s.DisableUser(admin.ID, bob.ID, true); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	if err := check(tk2); !errors.Is(err, ErrAccessTicket) {
		t.Errorf("停用后票据必须立即失效，got %v", err)
	}
	if _, err := s.AuthenticateUser("bob", "bob-password-123", now); !errors.Is(err, ErrAuthentication) {
		t.Errorf("停用账号登录应 ErrAuthentication，got %v", err)
	}

	// 改密：旧会话（含未过期票据）跨改密不得存活。
	if err := s.DisableUser(admin.ID, bob.ID, false); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	sess3, err := s.AuthenticateUser("bob", "bob-password-123", now)
	if err != nil {
		t.Fatalf("re-login after enable: %v", err)
	}
	tk3 := mkTicket(sess3.Token)
	if err := s.ChangePassword(bob.ID, "bob-password-123", "bob-password-456"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if err := check(tk3); !errors.Is(err, ErrAccessTicket) {
		t.Errorf("改密后旧票据必须立即失效，got %v", err)
	}
	if _, err := s.UserForSession(sess3.Token, now.Add(time.Minute)); !errors.Is(err, ErrAuthentication) {
		t.Errorf("改密后旧会话应失效，got %v", err)
	}
	// 票据 audience 绑定：换个设备会话（不同 NodeID/addr）不可核对他人票据。
	if _, err := s.CheckAccessTicket("nd1_bogus", access.CheckRequest{Token: tk3.Token, Method: "GET", Path: objPath}, time.Now()); !errors.Is(err, ErrAccessTicket) {
		t.Errorf("无效设备会话核验票据应 ErrAccessTicket，got %v", err)
	}
}

// ---- Test 4: staging 目标 CAS + secure commit 指纹绑定与业务变更同帧原子 ----

func TestAuditStagingTargetCASAndCommitBindingAtomic(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	admin, space := bootstrapAdmin(t, s)

	// 目标文件：空文件覆盖语义（CreateSecureEmpty），Generation 从 1 开始。
	target, _, replaced, err := s.CreateSecureEmpty(admin.ID, space.ID, space.RootID, "e.bin", false, now)
	if err != nil || replaced {
		t.Fatalf("CreateSecureEmpty: %v replaced=%v", err, replaced)
	}
	if target.Generation != 1 {
		t.Fatalf("新文件 Generation 应为 1，got %d", target.Generation)
	}

	commit := func(staging uint64, opID, fp string, wantGen uint64) types.Inode {
		t.Helper()
		out, _, hadOld, err := s.CommitStagingFile(staging, "e.bin", 100, SecureCommitBinding{OpID: opID, Fingerprint: fp})
		if err != nil {
			t.Fatalf("CommitStagingFile(%s): %v", opID, err)
		}
		if !hadOld || out.ID != target.ID || out.Generation != wantGen {
			t.Fatalf("adopt 结果不符: out=%+v want id=%d gen=%d", out, target.ID, wantGen)
		}
		return out
	}
	stage := func() uint64 {
		t.Helper()
		st, err := s.CreateSecureUpload(admin.ID, space.ID, space.RootID, "e.bin", true, now)
		if err != nil {
			t.Fatalf("CreateSecureUpload: %v", err)
		}
		if st.ID < types.StagingInodeBase {
			t.Fatalf("staging inode 应取 StagingInodeBase 段，got %d", st.ID)
		}
		if _, err := s.AssignChunk(st.ID, 0, 100, []uint64{7}, 1234); err != nil {
			t.Fatalf("AssignChunk: %v", err)
		}
		if err := s.MarkChunkDone(types.ChunkID(st.ID, 0), 7); err != nil {
			t.Fatalf("MarkChunkDone: %v", err)
		}
		return st.ID
	}

	// 首次覆盖：CAS 命中（TargetGeneration=1 → adopt 后 2），op 指纹随业务变更同帧落库。
	st1 := stage()
	commit(st1, "audit-op-1", "fp-1", 2)
	rec, ok, err := s.GetOpResult("audit-op-1")
	if err != nil || !ok || rec.Kind != "commit" || rec.Fingerprint != "fp-1" || rec.Inode.Generation != 2 {
		t.Fatalf("commit 幂等结果应与变更同事务可查: ok=%v rec=%+v err=%v", ok, rec, err)
	}
	// 同库同帧原子：最后一帧必须同时含 bucketOps 的 op 记录与 bucketInodes 的 inode 变更。
	frames, err := s.FramesSince(0)
	if err != nil || len(frames) == 0 {
		t.Fatalf("FramesSince: %v n=%d", err, len(frames))
	}
	last := frames[len(frames)-1]
	var hasOp, hasInode bool
	for _, m := range last.Muts {
		if m.Bucket == bcOps && string(m.Key) == "audit-op-1" {
			hasOp = true
		}
		if m.Bucket == bcInodes && bytes.Equal(m.Key, u64be(target.ID)) {
			hasInode = true
		}
	}
	if !hasOp || !hasInode {
		t.Fatalf("secure commit 帧应同帧含 op 记录与 inode 变更（原子同库）: hasOp=%v hasInode=%v", hasOp, hasInode)
	}
	// 同 op_id 不同指纹 → 冲突拒绝（绝不能回放无关请求的结果）。
	if err := s.db.View(func(tx *bolt.Tx) error {
		_, _, err := opResultTx(tx, "audit-op-1", "commit", "fp-different")
		return err
	}); !errors.Is(err, ErrOpConflict) {
		t.Fatalf("同 op_id 不同指纹应 ErrOpConflict，got %v", err)
	}

	// CAS 失配：两个 staging 先后指向 gen2；先提交其一升到 gen3，另一个提交必须拒绝。
	st2, st3 := stage(), stage()
	commit(st3, "audit-op-3", "fp-3", 3)
	if _, _, _, err := s.CommitStagingFile(st2, "e.bin", 100); !errors.Is(err, ErrObjectChanged) {
		t.Errorf("过期 Generation 的 staging 提交必须 ErrObjectChanged（防覆盖丢失并发写），got %v", err)
	}

	// CAS 失配：目标在提交前被删除 → TargetID 悬空必须拒绝，不得凭空复活文件。
	st4 := stage()
	if err := s.DeleteFile(target.ID); err != nil {
		t.Fatalf("DeleteFile target: %v", err)
	}
	if _, _, _, err := s.CommitStagingFile(st4, "e.bin", 100); !errors.Is(err, ErrObjectChanged) {
		t.Errorf("目标已删除的 staging 提交必须 ErrObjectChanged，got %v", err)
	}
	if _, err := s.GetInode(target.ID); !errors.Is(err, ErrNotExist) {
		t.Errorf("已删除目标不应被 staging 提交复活，getInode=%v", err)
	}
}

// ---- Test 5: 明文凭据不落库 + WAL（bcSecurity）重放 / 快照恢复的安全状态 ----

func TestAuditRawCredentialsHashedAndSecurityStateRestore(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	now := time.Now()
	admin, _ := bootstrapAdmin(t, s)

	inviteCode, err := s.CreateUserInvite(admin.ID, now.Add(time.Hour), now)
	if err != nil {
		t.Fatalf("CreateUserInvite: %v", err)
	}
	_, bobSpace, err := s.RegisterInvitedUser(inviteCode, "bob", "bob-password-123", now)
	if err != nil {
		t.Fatalf("RegisterInvitedUser: %v", err)
	}
	sessBob, err := s.AuthenticateUser("bob", "bob-password-123", now)
	if err != nil {
		t.Fatalf("AuthenticateUser: %v", err)
	}
	devInvite, err := s.CreateDeviceInvite(now.Add(time.Hour), now)
	if err != nil {
		t.Fatalf("CreateDeviceInvite: %v", err)
	}
	id, err := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), "audit-restore.key"))
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	ch, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: id.PublicKey(), Addr: "127.0.0.1:59201", TotalBytes: 1 << 20, Invite: devInvite}, now)
	if err != nil {
		t.Fatalf("NewDeviceChallenge: %v", err)
	}
	sig, err := id.Sign(ch.Challenge)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sessDev, err := s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch.ID, Signature: sig}, now)
	if err != nil {
		t.Fatalf("CompleteDeviceChallenge: %v", err)
	}
	bobFile, err := s.CreateFile(bobSpace.RootID, "bf.bin", []uint64{sessDev.NodeID})
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	ticket, err := s.IssueUserTicket(sessBob.Token, bobSpace.ID, access.TicketRequest{
		NodeAddr: "127.0.0.1:59201", Method: "GET", Path: fmt.Sprintf("/objects/%d", bobFile.ID),
	}, now)
	if err != nil {
		t.Fatalf("IssueUserTicket: %v", err)
	}

	// 明文凭据（会话/邀请/设备邀请/设备会话/票据）绝不能出现在 bucketSecurity 的 key 或 value 里。
	// 挑战 ID 例外于 value 扫描：它被签进 Challenge.Extras（绑定完成的正是该挑战，
	// VerifyAt 按存储原文核验，结构性要求原文在库），且只是半个凭据——完成登录仍需
	// Ed25519 私钥，库泄漏不因此获得可用凭据；其 key 侧仍必须只存散列。
	secrets := map[string]string{
		"user session":   sessBob.Token,
		"invite code":    inviteCode,
		"device invite":  devInvite,
		"device session": sessDev.Token,
		"ticket token":   ticket.Token,
	}
	valueExempt := map[string]bool{"challenge id": true}
	sessAdmin, err := s.AuthenticateUser("admin", "admin-password-123", now)
	if err != nil {
		t.Fatalf("AuthenticateUser admin: %v", err)
	}
	secrets["admin session"] = sessAdmin.Token
	secrets["challenge id"] = ch.ID
	if err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketSecurity).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			for what, secret := range secrets {
				if bytes.Contains(k, []byte(secret)) {
					t.Errorf("AUDIT: %s 明文泄漏在 bucketSecurity key (%q)——key 侧必须只存散列", what, k)
				}
				if !valueExempt[what] && bytes.Contains(v, []byte(secret)) {
					t.Errorf("AUDIT: %s 明文泄漏在 bucketSecurity value (key %q)", what, k)
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("scan bucketSecurity: %v", err)
	}

	// WAL 重放（含新 bcSecurity=9 桶）：新库从 seq 0 重放全部帧后，账号/会话/设备状态必须存活。
	frames, err := s.FramesSince(0)
	if err != nil || len(frames) == 0 {
		t.Fatalf("FramesSince: %v n=%d", err, len(frames))
	}
	replayed, err := Open(filepath.Join(t.TempDir(), "replay.db"))
	if err != nil {
		t.Fatalf("Open replay target: %v", err)
	}
	defer replayed.Close()
	if err := replayed.ApplyFrames(frames); err != nil {
		t.Fatalf("ApplyFrames(bcSecurity 帧重放): %v", err)
	}
	if enabled, err := replayed.SecurityEnabled(); err != nil || !enabled {
		t.Fatalf("重放后 SecurityEnabled=(%v,%v)", enabled, err)
	}
	if _, err := replayed.UserForSession(sessBob.Token, now.Add(time.Minute)); err != nil {
		t.Errorf("WAL 重放后 bob 会话应存活: %v", err)
	}
	if _, err := replayed.AuthenticateUser("bob", "bob-password-123", now); err != nil {
		t.Errorf("WAL 重放后口令散列应存活: %v", err)
	}
	if _, err := replayed.DeviceForSession(sessDev.Token, now.Add(time.Minute)); err != nil {
		t.Errorf("WAL 重放后设备会话应存活: %v", err)
	}
	// 设计语义（非缺陷）：票据走 db.Update 不进 WAL，重放后丢失；2 分钟 TTL 使其在
	// 恢复窗口内自然过期，在线核验路径 fail-closed。
	if _, err := replayed.CheckAccessTicket(sessDev.Token, access.CheckRequest{Token: ticket.Token, Method: "GET",
		Path: fmt.Sprintf("/objects/%d", bobFile.ID)}, now.Add(time.Minute)); !errors.Is(err, ErrAccessTicket) {
		t.Errorf("WAL 重放后票据应不可用（fail-closed），got %v", err)
	}

	// 快照恢复：整库一致字节流，票据等全部状态存活；挑战一次性状态随之持久。
	snap := &bytes.Buffer{}
	if _, err := s.Snapshot(snap); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := RestoreFromReader(filepath.Join(t.TempDir(), "restore.db"), bytes.NewReader(snap.Bytes()))
	if err != nil {
		t.Fatalf("RestoreFromReader: %v", err)
	}
	defer restored.Close()
	if _, err := restored.UserForSession(sessBob.Token, now.Add(time.Minute)); err != nil {
		t.Errorf("快照恢复后 bob 会话应存活: %v", err)
	}
	if _, err := restored.DeviceForSession(sessDev.Token, now.Add(time.Minute)); err != nil {
		t.Errorf("快照恢复后设备会话应存活: %v", err)
	}
	if _, err := restored.CheckAccessTicket(sessDev.Token, access.CheckRequest{Token: ticket.Token, Method: "GET",
		Path: fmt.Sprintf("/objects/%d", bobFile.ID)}, now.Add(time.Minute)); err != nil {
		t.Errorf("快照恢复后票据应存活: %v", err)
	}
	// 已用挑战不可在恢复库上重放完成。
	if _, err := restored.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch.ID, Signature: sig}, now.Add(time.Minute)); !errors.Is(err, ErrDeviceAuth) {
		t.Errorf("快照恢复后已用挑战重放应 ErrDeviceAuth，got %v", err)
	}
}
