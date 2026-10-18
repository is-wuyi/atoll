package meta

// 安全状态清扫（security_gc.go）的验收测试：过期/TTL 精确边界、used+unexpired、
// 有效会话保留、challenge 有界上限与清扫后再签、WAL 重放不复活、损坏记录保留。
// 命名约定：断言"应该怎样"。全部走 store 层，不依赖 HTTP。

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/edgeidentity"
	bolt "go.etcd.io/bbolt"
)

// gcKeyCount 返回 bucketSecurity 内以 prefix 开头的 key 数（测试断言用）。
func gcKeyCount(t *testing.T, s *Store, prefix string) int {
	t.Helper()
	n := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketSecurity).Cursor()
		p := []byte(prefix)
		for k, _ := c.Seek(p); k != nil && len(k) >= len(p) && string(k[:len(p)]) == prefix; k, _ = c.Next() {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("count %q: %v", prefix, err)
	}
	return n
}

// gcDeviceKey 为指定 addr 建一个一次性设备身份（只用于派生公钥/签名）。
func gcDeviceKey(t *testing.T, name string) *edgeidentity.Identity {
	t.Helper()
	id, err := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), name+".key"))
	if err != nil {
		t.Fatalf("LoadOrCreate %s: %v", name, err)
	}
	return id
}

// ---- 1. 各前缀过期即清；TTL 精确边界（未过期一刻保留） ----

func TestSweepSecurityStateExpiresByTTL(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	now := time.Now()

	// 用户会话：一个已过期、一个恰好未过期（边界：now < ExpiresAt 才算有效）。
	if _, _, err := s.BootstrapSecurity("admin", "admin-password-123", now); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	liveSess, err := s.AuthenticateUser("admin", "admin-password-123", now)
	if err != nil {
		t.Fatalf("AuthenticateUser: %v", err)
	}
	// 直接注入一条过期会话记录（避免等待 TTL）。
	if err := s.write(func(w *txw) error {
		return putSecurityJSON(w, secKeySession(hashOpaqueToken("expired-user-token")), SessionRecord{
			UserID: 1, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Minute),
		})
	}); err != nil {
		t.Fatalf("inject expired session: %v", err)
	}
	if got := gcKeyCount(t, s, "sess/"); got != 2 {
		t.Fatalf("sess/ 初始应为 2，got %d", got)
	}
	if _, err := s.SweepSecurityState(now); err != nil {
		t.Fatalf("SweepSecurityState: %v", err)
	}
	if got := gcKeyCount(t, s, "sess/"); got != 1 {
		t.Fatalf("过期会话应被清、有效会话保留，sess/ = %d，want 1", got)
	}
	if _, err := s.UserForSession(liveSess.Token, now.Add(time.Minute)); err != nil {
		t.Fatalf("清扫不得影响未过期会话: %v", err)
	}

	// 精确边界：ExpiresAt == now 视为已过期（now.Before 为假）；now+1ns 仍有效。
	boundary := now.Add(time.Hour)
	if err := s.write(func(w *txw) error {
		return putSecurityJSON(w, secKeySession(hashOpaqueToken("boundary-token")), SessionRecord{UserID: 1, ExpiresAt: boundary})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SweepSecurityState(boundary.Add(-time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if got := gcKeyCount(t, s, "sess/"); got != 2 {
		t.Fatalf("now=expires-1ns 时边界会话须保留，sess/ = %d，want 2", got)
	}
	if _, err := s.SweepSecurityState(boundary); err != nil {
		t.Fatal(err)
	}
	if got := gcKeyCount(t, s, "sess/"); got != 1 {
		t.Fatalf("now=expires 时边界会话须清除，sess/ = %d，want 1", got)
	}
}

// ---- 2. 设备邀请：used+unexpired 可回收，且回收后记录缺失继续拒 ----

func TestSweepSecurityStateDeviceInviteUsedAndExpired(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	now := time.Now()
	if _, _, err := s.BootstrapSecurity("admin", "admin-password-123", now); err != nil {
		t.Fatal(err)
	}

	// 已用邀请（未过期）：完成一次设备登录会烧掉邀请，但记录仍在 → 应可被清扫。
	invite, err := s.CreateDeviceInvite(now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	id := gcDeviceKey(t, "dev-used")
	ch, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: id.PublicKey(), Addr: "127.0.0.1:57001", TotalBytes: 1 << 20, Invite: invite}, now)
	if err != nil {
		t.Fatalf("NewDeviceChallenge: %v", err)
	}
	sig, err := id.Sign(ch.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch.ID, Signature: sig}, now); err != nil {
		t.Fatalf("CompleteDeviceChallenge: %v", err)
	}
	// 未过期但已用的邀请 + 已完成的挑战都应被回收。
	expInvite, err := s.CreateDeviceInvite(now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SweepSecurityState(now); err != nil {
		t.Fatalf("SweepSecurityState: %v", err)
	}
	if got := gcKeyCount(t, s, "device-invite/"); got != 1 {
		t.Fatalf("已用邀请应被清、未用未过期邀请保留，device-invite/ = %d，want 1", got)
	}
	// 已用邀请记录被删后，用同一邀请为新公钥开挑战仍须拒绝（记录缺失即拒）。
	id2 := gcDeviceKey(t, "dev-new")
	if _, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: id2.PublicKey(), Addr: "127.0.0.1:57002", TotalBytes: 1 << 20, Invite: invite}, now); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("清扫已用邀请后再用应 ErrDeviceAuth，got %v", err)
	}
	// 未过期未用邀请仍可用。
	if _, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: id2.PublicKey(), Addr: "127.0.0.1:57003", TotalBytes: 1 << 20, Invite: expInvite}, now); err != nil {
		t.Fatalf("未用未过期邀请应仍可用: %v", err)
	}
}

// ---- 3. 已用 challenge 清扫后不可 replay；未过期 challenge 保留可完成 ----

func TestSweepSecurityStateUsedChallengeNoReplay(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	now := time.Now()
	if _, _, err := s.BootstrapSecurity("admin", "admin-password-123", now); err != nil {
		t.Fatal(err)
	}
	invite, err := s.CreateDeviceInvite(now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	id := gcDeviceKey(t, "dev-replay")
	ch, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: id.PublicKey(), Addr: "127.0.0.1:57011", TotalBytes: 1 << 20, Invite: invite}, now)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := id.Sign(ch.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch.ID, Signature: sig}, now); err != nil {
		t.Fatalf("CompleteDeviceChallenge: %v", err)
	}
	// 清扫（挑战已 Used 但未过期 → 由"未过期"判定保留；已用不影响，used 记录在过期后清）。
	if _, err := s.SweepSecurityState(now); err != nil {
		t.Fatal(err)
	}
	// 关键：任何时刻都不允许已用 challenge 重放成功（记录存在 → Used；记录被清 → 缺失）。
	if _, err := s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch.ID, Signature: sig}, now); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("清扫后已用 challenge 重放应 ErrDeviceAuth，got %v", err)
	}
	// 过期后清扫删除，再完成仍拒绝。
	if _, err := s.SweepSecurityState(now.Add(3 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := gcKeyCount(t, s, "device-challenge/"); got != 0 {
		t.Fatalf("过期 challenge 应被清空，got %d", got)
	}
	if _, err := s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch.ID, Signature: sig}, now.Add(3*time.Minute)); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("清除后重放应 ErrDeviceAuth，got %v", err)
	}
}

// ---- 4. 清扫不误删用户/空间/成员/设备/device-node ----

func TestSweepSecurityStatePreservesAccountsAndDevices(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	now := time.Now()
	admin, space := bootstrapAdmin(t, s)
	invite, err := s.CreateUserInvite(admin.ID, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	bob, bobSpace, err := s.RegisterInvitedUser(invite, "bob", "bob-password-123", now)
	if err != nil {
		t.Fatal(err)
	}
	devInvite, err := s.CreateDeviceInvite(now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	id := gcDeviceKey(t, "dev-keep")
	ch, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: id.PublicKey(), Addr: "127.0.0.1:57021", TotalBytes: 1 << 20, Invite: devInvite}, now)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := id.Sign(ch.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch.ID, Signature: sig}, now)
	if err != nil {
		t.Fatal(err)
	}
	users := gcKeyCount(t, s, "user/")
	spaces := gcKeyCount(t, s, "spc/")
	members := gcKeyCount(t, s, "mem/")
	devices := gcKeyCount(t, s, "device/")
	deviceNodes := gcKeyCount(t, s, "device-node/")
	if users == 0 || spaces == 0 || members == 0 || devices == 0 || deviceNodes == 0 {
		t.Fatalf("前置状态缺失: users=%d spaces=%d mem=%d device=%d device-node=%d", users, spaces, members, devices, deviceNodes)
	}
	if _, err := s.SweepSecurityState(now.Add(time.Hour)); err != nil {
		t.Fatalf("SweepSecurityState: %v", err)
	}
	if got := gcKeyCount(t, s, "user/"); got != users {
		t.Fatalf("user/ 被误删: %d -> %d", users, got)
	}
	if got := gcKeyCount(t, s, "spc/"); got != spaces {
		t.Fatalf("spc/ 被误删: %d -> %d", spaces, got)
	}
	if got := gcKeyCount(t, s, "mem/"); got != members {
		t.Fatalf("mem/ 被误删: %d -> %d", members, got)
	}
	if got := gcKeyCount(t, s, "device/"); got != devices {
		t.Fatalf("device/ 被误删: %d -> %d", devices, got)
	}
	if got := gcKeyCount(t, s, "device-node/"); got != deviceNodes {
		t.Fatalf("device-node/ 被误删: %d -> %d", deviceNodes, got)
	}
	// 设备记录仍在、可解析；用户空间仍可授权（清扫不破坏授权语义）。
	if _, err := s.DeviceByNode(sess.NodeID); err != nil {
		t.Fatalf("device 记录应存活: %v", err)
	}
	if _, err := s.AuthorizeSpace(bob.ID, bobSpace.ID, false); err != nil {
		t.Fatalf("成员授权应存活: %v", err)
	}
	if _, err := s.AuthorizeSpace(bob.ID, space.ID, false); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("bob 不应能访问 admin 空间（基线）: %v", err)
	}
}

// ---- 5. WAL 重放：清扫删除进 WAL，重放后不复活 ----

func TestSweepSecurityStateWALReplayDoesNotResurrect(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	now := time.Now()
	if _, _, err := s.BootstrapSecurity("admin", "admin-password-123", now); err != nil {
		t.Fatal(err)
	}
	// 一条过期会话 + 一条有效会话。
	if err := s.write(func(w *txw) error {
		return putSecurityJSON(w, secKeySession(hashOpaqueToken("dead")), SessionRecord{UserID: 1, ExpiresAt: now.Add(-time.Minute)})
	}); err != nil {
		t.Fatal(err)
	}
	live, err := s.AuthenticateUser("admin", "admin-password-123", now)
	if err != nil {
		t.Fatal(err)
	}
	// 先记下清扫前帧数（用于确认删除确实进了 WAL）。
	beforeFrames, err := s.FramesSince(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SweepSecurityState(now); err != nil {
		t.Fatalf("SweepSecurityState: %v", err)
	}
	afterFrames, err := s.FramesSince(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterFrames) <= len(beforeFrames) {
		t.Fatalf("清扫删除应产生 WAL 帧: %d -> %d", len(beforeFrames), len(afterFrames))
	}
	// 从 seq 0 全量重放到新库：过期会话不得复活，有效会话存活。
	replayed, err := Open(filepath.Join(t.TempDir(), "gc-replay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer replayed.Close()
	if err := replayed.ApplyFrames(afterFrames); err != nil {
		t.Fatalf("ApplyFrames: %v", err)
	}
	if got := gcKeyCount(t, replayed, "sess/"); got != 1 {
		t.Fatalf("重放后 sess/ 应为 1（过期被删不复活），got %d", got)
	}
	if _, err := replayed.UserForSession(live.Token, now.Add(time.Minute)); err != nil {
		t.Fatalf("重放后有效会话应存活: %v", err)
	}
}

// ---- 6. 损坏记录：保留证据 + 返回可日志错误 ----

func TestSweepSecurityStateRetainsCorruptRecords(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	now := time.Now()
	if _, _, err := s.BootstrapSecurity("admin", "admin-password-123", now); err != nil {
		t.Fatal(err)
	}
	// 注入一条损坏的过期会话记录（无法 JSON 解析）。
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSecurity).Put(secKeySession(hashOpaqueToken("corrupt")), []byte("{not-json"))
	}); err != nil {
		t.Fatal(err)
	}
	// 同时注入一条可清的正常过期会话，验证损坏不阻断合法清理。
	if err := s.write(func(w *txw) error {
		return putSecurityJSON(w, secKeySession(hashOpaqueToken("stale")), SessionRecord{UserID: 1, ExpiresAt: now.Add(-time.Minute)})
	}); err != nil {
		t.Fatal(err)
	}
	removed, err := s.SweepSecurityState(now)
	if err == nil {
		t.Fatal("存在损坏记录时应返回可日志错误")
	}
	if removed < 1 {
		t.Fatalf("合法过期记录应仍被清理，removed = %d", removed)
	}
	if got := gcKeyCount(t, s, "sess/"); got != 1 {
		t.Fatalf("损坏记录须保留（sess/ = %d，want 1）", got)
	}
}

// ---- 7. challenge 有界上限 + 清扫后可再签 + 同 request 复用 ----

func TestDeviceChallengeOutstandingBoundAndResweep(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	now := time.Now()
	if _, _, err := s.BootstrapSecurity("admin", "admin-password-123", now); err != nil {
		t.Fatal(err)
	}
	id := gcDeviceKey(t, "dev-bound")
	// 一次性设备邀请：NewDeviceChallenge 只校验不烧毁，可用于多个新公钥挑战。
	invite, err := s.CreateDeviceInvite(now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	// 同公钥、不同 endpoint：每条都新增记录，达到 per-identity 上限后拒绝。
	added := 0
	for i := 0; i < maxOutstandingChallengesPerIdentity+4; i++ {
		_, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{
			PublicKey: id.PublicKey(), Addr: "127.0.0.1:" + strconv.Itoa(57100+i), TotalBytes: 1 << 20, Invite: invite,
		}, now)
		if err == nil {
			added++
			continue
		}
		if !errors.Is(err, ErrDeviceChallengeLimit) {
			t.Fatalf("达上限应 ErrDeviceChallengeLimit，got %v", err)
		}
	}
	if added != maxOutstandingChallengesPerIdentity {
		t.Fatalf("per-identity 上限 = %d，实际签发 %d", maxOutstandingChallengesPerIdentity, added)
	}
	// 同 request（同 addr + 同 total）应复用既有未过期 challenge，不新增记录。
	before := gcKeyCount(t, s, "device-challenge/")
	again, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: id.PublicKey(), Addr: "127.0.0.1:57100", TotalBytes: 1 << 20, Invite: invite}, now)
	if err != nil {
		t.Fatalf("同 request 复用应成功: %v", err)
	}
	if after := gcKeyCount(t, s, "device-challenge/"); after != before {
		t.Fatalf("同 request 复用不得新增记录: %d -> %d", before, after)
	}
	if again.Challenge.Extras["addr"] != "127.0.0.1:57100" {
		t.Fatalf("复用挑战的 addr 应一致: %s", again.Challenge.Extras["addr"])
	}
	// 到期清扫后可再签（配额释放）。
	if _, err := s.SweepSecurityState(now.Add(3 * time.Minute)); err != nil {
		t.Fatalf("SweepSecurityState: %v", err)
	}
	if got := gcKeyCount(t, s, "device-challenge/"); got != 0 {
		t.Fatalf("过期 challenge 应清空，got %d", got)
	}
	if _, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: id.PublicKey(), Addr: "127.0.0.1:57200", TotalBytes: 1 << 20, Invite: invite}, now.Add(3*time.Minute)); err != nil {
		t.Fatalf("清扫后应可再签: %v", err)
	}
}

// ---- 8. global 上限 ----

func TestDeviceChallengeGlobalBound(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	now := time.Now()
	if _, _, err := s.BootstrapSecurity("admin", "admin-password-123", now); err != nil {
		t.Fatal(err)
	}
	// 用不同公钥填充到 global 上限：每个 identity 上限 8，故需 ceil(global/8) 个身份。
	// 单一未用未过期邀请可催生多个新公钥的挑战（创建不烧邀请）。
	invite, err := s.CreateDeviceInvite(now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	identities := (maxOutstandingChallengesGlobal + maxOutstandingChallengesPerIdentity - 1) / maxOutstandingChallengesPerIdentity
	added := 0
	blocked := false
	for i := 0; i < identities+2 && !blocked; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		for j := 0; j < maxOutstandingChallengesPerIdentity; j++ {
			_, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: pub, Addr: "127.0.0.1:" + strconv.Itoa(58000+i*10+j), TotalBytes: 1 << 20, Invite: invite}, now)
			if err == nil {
				added++
				continue
			}
			if !errors.Is(err, ErrDeviceChallengeLimit) {
				t.Fatalf("global 上限应 ErrDeviceChallengeLimit，got %v", err)
			}
			blocked = true
			break
		}
	}
	if added != maxOutstandingChallengesGlobal {
		t.Fatalf("global 上限 = %d，实际签发 %d", maxOutstandingChallengesGlobal, added)
	}
	if !blocked {
		t.Fatal("超过 global 上限后应被拒")
	}
}
