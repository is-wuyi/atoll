package meta

// 反证/回归测试：对 GC 审查提出的候选缺陷先尝试证明其不存在，断言写"应该怎样"。
// 当前实现下失败的断言即缺陷证据；修复后本文件全部通过，作为回归护栏。
// 全部走 store 层，不依赖 HTTP。

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/edgeidentity"
	bolt "go.etcd.io/bbolt"
)

// gcFalsifyDevice 建一个一次性设备身份（只用于派生公钥/签名）。
func gcFalsifyDevice(t *testing.T, name string) *edgeidentity.Identity {
	t.Helper()
	id, err := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), name+".key"))
	if err != nil {
		t.Fatalf("LoadOrCreate %s: %v", name, err)
	}
	return id
}

// ---- 1. ticket 清扫必须有界：单轮不得在全桶 ticket/ 上做无界扫描/分配 ----

func TestSweepSecurityTicketsBoundedPerPass(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	now := time.Now()
	if _, _, err := s.BootstrapSecurity("admin", "admin-password-123", now); err != nil {
		t.Fatal(err)
	}
	const total = securitySweepBatch + 64
	// 注入 total 条已过期 ticket（直写 db.Update，绕开在线签发路径的设备/空间校验）。
	if err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSecurity)
		for i := 0; i < total; i++ {
			rec := accessTicketRecord{Issuer: "control", Request: access.TicketRequest{Path: "/objects/1"}, ExpiresAt: now.Add(-time.Minute)}
			raw, err := json.Marshal(rec)
			if err != nil {
				return err
			}
			if err := b.Put(securityDataKey("ticket", secHash("tk-"+strconv.Itoa(i))), raw); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// 一轮清扫：若 ticket 有界，最多清 securitySweepBatch 条；全桶实现会一次清空。
	removed, err := s.SweepSecurityState(now)
	if err != nil {
		t.Fatalf("SweepSecurityState: %v", err)
	}
	if removed > securitySweepBatch {
		t.Fatalf("单轮清扫删除了 %d 条 ticket，超过有界批次 %d——ticket/ 仍是无界全桶扫描", removed, securitySweepBatch)
	}
	if removed >= total {
		t.Fatalf("单轮清扫清空了全部 %d 条 ticket（removed=%d），未按游标分批", total, removed)
	}
	// 续扫最终必须把剩余过期 ticket 清干净（有界不等于漏清）。
	for pass := 0; pass < 8; pass++ {
		left := gcKeyCount(t, s, "ticket/")
		if left == 0 {
			break
		}
		if _, err := s.SweepSecurityState(now); err != nil {
			t.Fatalf("续扫: %v", err)
		}
		if gcKeyCount(t, s, "ticket/") == left {
			t.Fatalf("第 %d 轮续扫无进展（ticket/ 停留 %d），游标饥饿", pass, left)
		}
	}
	if got := gcKeyCount(t, s, "ticket/"); got != 0 {
		t.Fatalf("多轮续扫后过期 ticket 应清空，剩 %d", got)
	}
}

// ---- 2. 损坏 ticket 与其它前缀口径一致：保留证据、不阻断合法清理 ----

func TestSweepSecurityTicketsCorruptRecordRetained(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	now := time.Now()
	if _, _, err := s.BootstrapSecurity("admin", "admin-password-123", now); err != nil {
		t.Fatal(err)
	}
	// 一条损坏 ticket + 一条正常过期 ticket。
	if err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSecurity)
		if err := b.Put(securityDataKey("ticket", secHash("corrupt")), []byte("{not-json")); err != nil {
			return err
		}
		rec := accessTicketRecord{Issuer: "control", Request: access.TicketRequest{Path: "/objects/1"}, ExpiresAt: now.Add(-time.Minute)}
		raw, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put(securityDataKey("ticket", secHash("stale")), raw)
	}); err != nil {
		t.Fatal(err)
	}
	removed, err := s.SweepSecurityState(now)
	if err == nil {
		t.Fatal("存在损坏记录时应返回可日志错误")
	}
	if removed < 1 {
		t.Fatalf("合法过期 ticket 应仍被清理，removed = %d", removed)
	}
	// 损坏记录保留（ticket/ 应恰好剩 1 条），且不得 panic。
	if got := gcKeyCount(t, s, "ticket/"); got != 1 {
		t.Fatalf("损坏 ticket 须保留（ticket/ = %d，want 1）", got)
	}
}

// ---- 3. 无头部饥饿：前缀内前 securitySweepBatch 个 key 全未过期时，
// 后续已过期 key 不得被永久挡住。 ----

func TestSweepSecurityStateNoHeadOfLineStarvation(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	now := time.Now()
	if _, _, err := s.BootstrapSecurity("admin", "admin-password-123", now); err != nil {
		t.Fatal(err)
	}
	// sess/ 前缀内：先 securitySweepBatch 条未过期，其后 8 条已过期。
	// （BootstrapSecurity 不建会话；全部由测试注入，便于精确计数。）
	if err := s.write(func(w *txw) error {
		for i := 0; i < securitySweepBatch; i++ {
			if err := putSecurityJSON(w, secKeySession(hashOpaqueToken("live-"+strconv.Itoa(i))), SessionRecord{UserID: 1, ExpiresAt: now.Add(time.Hour)}); err != nil {
				return err
			}
		}
		for i := 0; i < 8; i++ {
			if err := putSecurityJSON(w, secKeySession(hashOpaqueToken("dead-"+strconv.Itoa(i))), SessionRecord{UserID: 1, ExpiresAt: now.Add(-time.Minute)}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := gcKeyCount(t, s, "sess/"); got != securitySweepBatch+8 {
		t.Fatalf("前置状态: sess/ = %d，want %d", got, securitySweepBatch+8)
	}
	// 清扫若干轮：游标必须越过未过期头部，最终 8 条 dead 全清、4096 条 live 一条不动。
	for pass := 0; pass < 4; pass++ {
		if _, err := s.SweepSecurityState(now); err != nil {
			t.Fatal(err)
		}
		if gcKeyCount(t, s, "sess/") == securitySweepBatch {
			break
		}
	}
	if got := gcKeyCount(t, s, "sess/"); got != securitySweepBatch {
		t.Fatalf("头部未过期 key 不应永久挡住后续过期 key：sess/ = %d，want %d", got, securitySweepBatch)
	}
}

// ---- 4. 游标不得因写失败而误进：post-commit 钩子失败时（bbolt 事务已提交、
// 删除已持久，write 仅把错误透传给调用方）游标必须停在原处，下轮重扫同一区间
// 不得跳过未扫到的 key，也不得重复删除/误删未过期记录。 ----

func TestSweepCursorDoesNotAdvanceOnWriteFailure(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	now := time.Now()
	if _, _, err := s.BootstrapSecurity("admin", "admin-password-123", now); err != nil {
		t.Fatal(err)
	}
	// 两条过期会话（可清）+ 一条未过期会话（保留作锚点）。
	if err := s.write(func(w *txw) error {
		for _, name := range []string{"c1", "c2"} {
			if err := putSecurityJSON(w, secKeySession(hashOpaqueToken(name)), SessionRecord{UserID: 1, ExpiresAt: now.Add(-time.Minute)}); err != nil {
				return err
			}
		}
		return putSecurityJSON(w, secKeySession(hashOpaqueToken("anchor")), SessionRecord{UserID: 1, ExpiresAt: now.Add(time.Hour)})
	}); err != nil {
		t.Fatal(err)
	}
	if got := gcKeyCount(t, s, "sess/"); got != 3 {
		t.Fatalf("前置状态: sess/ = %d，want 3", got)
	}
	boom := errors.New("hook boom")
	s.SetPostCommitHook(func(uint64, []byte) error { return boom })
	t.Cleanup(func() { s.SetPostCommitHook(nil) })
	// 钩子失败 → write 返回 error；清扫必须把错误透传给调用方（可日志）。
	if _, err := s.SweepSecurityState(now); !errors.Is(err, boom) {
		t.Fatalf("钩子失败应透传，got %v", err)
	}
	// 关键：游标不得推进（失败即下轮重扫同一区间，不跳过未清扫 key）。
	if got := s.securitySweepCursor(secPrefixSession); len(got) != 0 {
		t.Fatalf("写失败后游标不得推进: cursor=%q", got)
	}
	// 恢复钩子后再扫：未过期锚点必须仍在（游标误进会跳过它造成漏判/误判的回归）。
	s.SetPostCommitHook(nil)
	if _, err := s.SweepSecurityState(now); err != nil {
		t.Fatal(err)
	}
	if got := gcKeyCount(t, s, "sess/"); got != 1 {
		t.Fatalf("恢复后仅未过期锚点应保留，sess/ = %d，want 1", got)
	}
}

// ---- 5. same-challenge 复用必须完整绑定：pubkey + addr + total + inviteHash。
// 不同 invite 不得复用同一条未过期挑战——否则"用哪个邀请换会话"与记录脱钩，
// 一次登录烧不掉任何邀请，邀请的一次性语义被旁路。 ----

func TestDeviceChallengeReuseRequiresSameInvite(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	now := time.Now()
	if _, _, err := s.BootstrapSecurity("admin", "admin-password-123", now); err != nil {
		t.Fatal(err)
	}
	id := gcFalsifyDevice(t, "dev-reuse-inv")
	invA, err := s.CreateDeviceInvite(now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	invB, err := s.CreateDeviceInvite(now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	// 邀请 A 开一条挑战。
	chA, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: id.PublicKey(), Addr: "127.0.0.1:57031", TotalBytes: 1 << 20, Invite: invA}, now)
	if err != nil {
		t.Fatalf("NewDeviceChallenge(invA): %v", err)
	}
	before := gcKeyCount(t, s, "device-challenge/")
	// 同 pubkey + addr + total，但换成邀请 B：必须新签一条绑定 invB 的挑战，
	// 不得复用绑定 invA 的既有记录。
	chB, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: id.PublicKey(), Addr: "127.0.0.1:57031", TotalBytes: 1 << 20, Invite: invB}, now)
	if err != nil {
		t.Fatalf("NewDeviceChallenge(invB): %v", err)
	}
	if chB.ID == chA.ID {
		t.Fatalf("不同 invite 不得复用同一 challenge（邀请语义错绑）: %s", chB.ID)
	}
	if after := gcKeyCount(t, s, "device-challenge/"); after != before+1 {
		t.Fatalf("不同 invite 应新签记录: %d -> %d，want %d", before, after, before+1)
	}
	// 同 invite 的相同 request 仍应复用（不新增记录）——复用语义本身保留。
	if again, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: id.PublicKey(), Addr: "127.0.0.1:57031", TotalBytes: 1 << 20, Invite: invB}, now); err != nil {
		t.Fatalf("同 request 同 invite 复用应成功: %v", err)
	} else if again.ID != chB.ID {
		t.Fatalf("同 request 同 invite 应复用既有挑战: got %s want %s", again.ID, chB.ID)
	}

	// 完成 chB 登录：必须烧掉邀请 B（一次性语义不被复用旁路）。
	sig, err := id.Sign(chB.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: chB.ID, Signature: sig}, now); err != nil {
		t.Fatalf("CompleteDeviceChallenge: %v", err)
	}
	// 邀请 B 已用：新公钥再拿它开挑战应被拒（记录缺失/Used 即拒）。
	other := gcFalsifyDevice(t, "dev-reuse-inv-other")
	if _, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: other.PublicKey(), Addr: "127.0.0.1:57032", TotalBytes: 1 << 20, Invite: invB}, now); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("登录后邀请 B 应已烧掉（ErrDeviceAuth），got %v", err)
	}
}

// ---- 6. scan limit 不越限放行：device-challenge 记录超过扫描上限时 fail-closed ----

func TestDeviceChallengeScanLimitFailClosed(t *testing.T) {
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
	// 直写超过 securityChallengeScanLimit 条未过期挑战记录（绕开配额路径）。
	if err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSecurity)
		for i := 0; i <= securityChallengeScanLimit; i++ {
			rec := deviceChallengeRecord{
				Challenge: edgeidentity.Challenge{ExpiresAt: now.Add(time.Hour), Extras: map[string]string{"challenge_id": "dc1_fake"}},
			}
			raw, err := json.Marshal(rec)
			if err != nil {
				return err
			}
			if err := b.Put(securityDataKey("device-challenge", secHash("fake-"+strconv.Itoa(i))), raw); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	id := gcFalsifyDevice(t, "dev-scanlimit")
	if _, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: id.PublicKey(), Addr: "127.0.0.1:57041", TotalBytes: 1 << 20, Invite: invite}, now); !errors.Is(err, ErrDeviceChallengeLimit) {
		t.Fatalf("记录数超过扫描上限应 fail-closed 拒绝（ErrDeviceChallengeLimit），got %v", err)
	}
}

// 保证 ed25519 直接用法在文件内被引用（与其它测试风格一致，避免 lint 报未使用导入）。
var _ = ed25519.PublicKeySize
var _ = rand.Reader
