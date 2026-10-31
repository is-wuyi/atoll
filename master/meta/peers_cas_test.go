package meta

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/peerauth"
)

// raceSubmit 用 start-barrier 并发提交预签名请求。bbolt 单写 + 库内 CAS 保证
// 恰一成功；barrier 只保证所有 goroutine 真正入场，不伪造完成。
func raceSubmit(n int, run func(i int) error) []error {
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = run(i)
		}(i)
	}
	close(start)
	wg.Wait()
	return errs
}

func countSuccesses(errs []error) (int, bool) {
	successes := 0
	pure := true
	for _, err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrPeerConflict):
		default:
			pure = false
		}
	}
	return successes, pure
}

// ---- 并发 CAS：两个同 expected 恰一成功 ----

func TestPeerClientRegisterCASConcurrentBarrier(t *testing.T) {
	env := newPeerEnv(t)
	for round := 0; round < 5; round++ {
		// 每轮独立用户，避免轮次赢家累积触顶 per-user 4 而污染 CAS 断言。
		_, space, session := env.makeUser(t, "casuser"+strconv.Itoa(round))
		notAfter := env.now.Add(time.Minute)
		cp := newPeerIdentity(t)
		reqs := make([]peerauth.ClientRegistration, 2)
		for i := range reqs {
			req, err := buildClientRegisterReq(env, session, space.ID, cp, validOp(t), 0, notAfter)
			if err != nil {
				t.Fatalf("round %d proof: %v", round, err)
			}
			reqs[i] = req
		}
		errs := raceSubmit(2, func(i int) error {
			_, err := env.s.RegisterClientPeer(session, space.ID, reqs[i], env.now)
			return err
		})
		successes, pure := countSuccesses(errs)
		if !pure {
			t.Fatalf("round %d: 意外错误类型 %v", round, errs)
		}
		if successes != 1 {
			t.Fatalf("round %d: 同 expected 并发注册应恰一成功，got %d (%v/%v)", round, successes, errs[0], errs[1])
		}
		if rec, ok := readClientPeerRecord(t, env.s, cp.id); !ok || rec.Endpoint.Revision != 1 {
			t.Fatalf("round %d: rev 应恰为 1，got %d found=%v", round, rec.Endpoint.Revision, ok)
		}
	}
	// 续租同理：两个不同 op 同 expected=1 → 恰一成功，rev 恰为 2。
	_, space, session := env.makeUser(t, "casrenew")
	notAfter := env.now.Add(time.Minute)
	cp := newPeerIdentity(t)
	if _, err := env.registerClient(t, session, space.ID, cp, validOp(t), 0, notAfter); err != nil {
		t.Fatalf("初始注册: %v", err)
	}
	renews := make([]peerauth.ClientRegistration, 2)
	for i := range renews {
		req, err := buildClientRegisterReq(env, session, space.ID, cp, validOp(t), 1, notAfter)
		if err != nil {
			t.Fatal(err)
		}
		renews[i] = req
	}
	errs := raceSubmit(2, func(i int) error {
		_, err := env.s.RegisterClientPeer(session, space.ID, renews[i], env.now)
		return err
	})
	successes, pure := countSuccesses(errs)
	if !pure || successes != 1 {
		t.Fatalf("并发续租应恰一成功，got %d (%v)", successes, errs)
	}
	if rec, ok := readClientPeerRecord(t, env.s, cp.id); !ok || rec.Endpoint.Revision != 2 {
		t.Fatalf("并发续租后 rev 应恰为 2，got %d found=%v", rec.Endpoint.Revision, ok)
	}
}

// ---- 并发续租 vs 释放：恰一成功，终态与赢家一致 ----

func TestPeerReleaseVsRenewConcurrentBarrier(t *testing.T) {
	env := newPeerEnv(t)
	_, space, session := env.makeUser(t, "renewrel")
	for round := 0; round < 4; round++ {
		cp := newPeerIdentity(t)
		if _, err := env.registerClient(t, session, space.ID, cp, validOp(t), 0, env.now.Add(time.Minute)); err != nil {
			t.Fatalf("round %d 初始注册: %v", round, err)
		}
		renew, err := buildClientRegisterReq(env, session, space.ID, cp, validOp(t), 1, env.now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		rel, err := buildClientReleaseReq(env, session, space.ID, cp, validOp(t), 1, env.now.Add(30*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		errs := raceSubmit(2, func(i int) error {
			if i == 0 {
				_, err := env.s.RegisterClientPeer(session, space.ID, renew, env.now)
				return err
			}
			_, err := env.s.ReleaseClientPeer(session, space.ID, rel, env.now)
			return err
		})
		if _, pure := countSuccesses(errs); !pure {
			t.Fatalf("round %d: 意外错误类型 %v", round, errs)
		}
		renewOK, relOK := errs[0] == nil, errs[1] == nil
		if renewOK == relOK {
			t.Fatalf("round %d: renew/release 应恰一成功，got %v/%v", round, errs[0], errs[1])
		}
		rec, ok := readClientPeerRecord(t, env.s, cp.id)
		if !ok {
			t.Fatalf("round %d: 记录丢失", round)
		}
		if rec.Endpoint.Revision != 2 {
			t.Fatalf("round %d: rev 应为 2，got %d", round, rec.Endpoint.Revision)
		}
		if renewOK && (rec.Released || rec.AuthorizationRevision != 1) {
			t.Fatalf("round %d: renew 赢后应 live rev=2 authRev=1，got %+v", round, rec)
		}
		if relOK && (!rec.Released || rec.AuthorizationRevision != 2) {
			t.Fatalf("round %d: release 赢后应 released rev=2 authRev=2，got %+v", round, rec)
		}
	}
}

// ---- 最后一个空位的并发注册：恰一成功，配额不被击穿 ----

func TestPeerLastSlotConcurrentRegistration(t *testing.T) {
	env := newPeerEnv(t)
	nodePeer := newPeerIdentity(t)
	dev := env.enrollDevice(t, filepath.Join(t.TempDir(), "dev.key"), "127.0.0.1:9443", &peerauth.Enrollment{PeerID: nodePeer.id, PublicKey: nodePeer.pub, ExpectedRevision: 0}, nodePeer.priv)
	if _, err := env.publishAddress(t, dev, nodePeer.id, nodePeer.priv, 1, 0, validOp(t), []string{"/ip4/1.2.3.4/tcp/9400"}, env.now.Add(90*time.Second)); err != nil {
		t.Fatalf("发布: %v", err)
	}
	_, racerSpace, racerSession := env.makeUser(t, "lastrace")
	seedUser, seedSpace, _ := env.makeUser(t, "lastseed")
	env.seedClientPeers(t, peerauth.MaxDirectoryPeers-2, seedUser.ID, seedSpace.ID)
	// 510 live + 1 设备 slot = 511，仅剩 1 个空位。
	reqs := make([]peerauth.ClientRegistration, 4)
	for i := range reqs {
		req, err := buildClientRegisterReq(env, racerSession, racerSpace.ID, newPeerIdentity(t), validOp(t), 0, env.now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		reqs[i] = req
	}
	errs := raceSubmit(4, func(i int) error {
		_, err := env.s.RegisterClientPeer(racerSession, racerSpace.ID, reqs[i], env.now)
		return err
	})
	successes, pure := countSuccesses(errs)
	if !pure {
		t.Fatalf("意外错误类型 %v", errs)
	}
	if successes != 1 {
		t.Fatalf("最后一个空位并发注册应恰一成功，got %d (%v)", successes, errs)
	}
	if n := peerSlotCountNow(t, env.s, env.now); n != peerauth.MaxDirectoryPeers {
		t.Fatalf("并发后应恰满 512，got %d", n)
	}
	if eps := mustDirectory(t, env, env.now); len(eps) != peerauth.MaxDirectoryPeers {
		t.Fatalf("满额目录应可读且恰 512 端点，got %d", len(eps))
	}
}

// ---- 期满重激活：authRev++ 使旧票失效，live 记录不可跨用户抢注 ----

func TestPeerExpiredReactivationInvalidatesOldTickets(t *testing.T) {
	env := newPeerEnv(t)
	nodePeer := newPeerIdentity(t)
	target := env.enrollDevice(t, filepath.Join(t.TempDir(), "dev.key"), "127.0.0.1:9443", &peerauth.Enrollment{PeerID: nodePeer.id, PublicKey: nodePeer.pub, ExpectedRevision: 0}, nodePeer.priv)
	user, space, session := env.makeUser(t, "expiries")
	T0 := env.now
	cp := newPeerIdentity(t)
	oldReq, err := buildClientRegisterReq(env, session, space.ID, cp, validOp(t), 0, T0.Add(60*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.RegisterClientPeer(session, space.ID, oldReq, T0); err != nil {
		t.Fatalf("初始注册: %v", err)
	}
	objID := env.setupObjectOnNode(t, WriteActor{UserID: user.ID, SpaceID: space.ID}, space, target)
	path := fmt.Sprintf("/objects/%d", objID)
	ticketReq := func() access.TicketRequest {
		return access.TicketRequest{NodeAddr: "127.0.0.1:9443", Method: "PUT", Path: path, WriteEpoch: 1, SourcePeerID: cp.id}
	}
	checkReq := func(token string) access.CheckRequest {
		return access.CheckRequest{Token: token, Method: "PUT", Path: path, WriteEpoch: 1, SourcePeerID: cp.id}
	}
	ticket, err := env.s.IssueUserTicket(session, space.ID, ticketReq(), T0)
	if err != nil {
		t.Fatalf("签票: %v", err)
	}
	check := checkReq(ticket.Token)
	if _, err := env.s.CheckAccessTicket(target.Token, check, T0); err != nil {
		t.Fatalf("初票应可验: %v", err)
	}
	T1 := T0.Add(61 * time.Second)
	// 期满旧 proof（NotAfter 已过）原样重放：入口时间窗拒绝。
	if _, err := env.s.RegisterClientPeer(session, space.ID, oldReq, T1); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("期满旧 proof 重放应 ErrPeerConflict，got %v", err)
	}
	if allowed, _ := env.s.PeerAllowed(cp.id, T1, time.Minute); allowed {
		t.Fatal("期满 client 不应被允许")
	}
	for _, ep := range mustDirectory(t, env, T1) {
		if ep.PeerID == cp.id {
			t.Fatal("期满 client 不应列入目录")
		}
	}
	if _, err := env.s.CheckAccessTicket(target.Token, check, T1); !errors.Is(err, ErrAccessTicket) {
		t.Fatalf("期满后在途票应失效，got %v", err)
	}
	// 同会话重新激活：rev 连续、authRev++，旧票不得复活。
	react, err := buildClientRegisterReq(env, session, space.ID, cp, validOp(t), 1, T1.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.RegisterClientPeer(session, space.ID, react, T1); err != nil {
		t.Fatalf("同会话重新激活: %v", err)
	}
	rec, ok := readClientPeerRecord(t, env.s, cp.id)
	if !ok || rec.Released || rec.Endpoint.Revision != 2 || rec.AuthorizationRevision != 2 {
		t.Fatalf("重新激活应 rev=2 authRev=2，got %+v found=%v", rec, ok)
	}
	if _, err := env.s.CheckAccessTicket(target.Token, check, T1); !errors.Is(err, ErrAccessTicket) {
		t.Fatalf("authRev++ 后旧票不得复活，got %v", err)
	}
	ticket2, err := env.s.IssueUserTicket(session, space.ID, ticketReq(), T1)
	if err != nil {
		t.Fatalf("重新激活后应可签新票: %v", err)
	}
	if _, err := env.s.CheckAccessTicket(target.Token, checkReq(ticket2.Token), T1); err != nil {
		t.Fatalf("新票应可验: %v", err)
	}
	// 期满后跨用户接管：authRev 再 ++；原会话不得释放/抢回。
	_, otherSpace, otherSession := env.makeUser(t, "taker")
	d := newPeerIdentity(t)
	if _, err := env.registerClient(t, session, space.ID, d, validOp(t), 0, T0.Add(60*time.Second)); err != nil {
		t.Fatalf("d 注册: %v", err)
	}
	take, err := buildClientRegisterReq(env, otherSession, otherSpace.ID, d, validOp(t), 1, T1.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.RegisterClientPeer(otherSession, otherSpace.ID, take, T1); err != nil {
		t.Fatalf("期满接管应成功: %v", err)
	}
	// 原会话 release：记录 session hash 已切换 → 拒（旧 proof 不得作用新纪元记录）。
	relD, err := buildClientReleaseReq(env, session, space.ID, d, validOp(t), 2, T1.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.ReleaseClientPeer(session, space.ID, relD, T1); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("原会话释放他用户接管记录应拒，got %v", err)
	}
	// live 记录不得被原用户以正确 CAS 抢注。
	back, err := buildClientRegisterReq(env, session, space.ID, d, validOp(t), 2, T1.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.RegisterClientPeer(session, space.ID, back, T1); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("live 记录不得被他用户抢注，got %v", err)
	}
}

// ---- tombstone 扫除：RetainUntil 过后移除，旧签请求前后都不得复活 ----

func TestPeerTombstoneSweepRemovesAndBlocksRevival(t *testing.T) {
	env := newPeerEnv(t)
	_, space, session := env.makeUser(t, "sweepr")
	T0 := env.now
	// 票据寿命不得超过 tombstone 保留窗，否则扫除后旧票可借新纪元记录复活
	//（扫除时刻 ≥ RetainUntil = NotAfter+lease，而票据最迟签发于 NotAfter 前）。
	if AccessTicketTTL > peerauth.EndpointLease {
		t.Fatalf("AccessTicketTTL(%v) 超过 tombstone 保留窗(%v)", AccessTicketTTL, peerauth.EndpointLease)
	}
	e1 := newPeerIdentity(t)
	e1Req, err := buildClientRegisterReq(env, session, space.ID, e1, validOp(t), 0, T0.Add(60*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.RegisterClientPeer(session, space.ID, e1Req, T0); err != nil {
		t.Fatalf("e1 注册: %v", err)
	}
	e2 := newPeerIdentity(t)
	if _, err := env.registerClient(t, session, space.ID, e2, validOp(t), 0, T0.Add(60*time.Second)); err != nil {
		t.Fatalf("e2 注册: %v", err)
	}
	rel2, err := buildClientReleaseReq(env, session, space.ID, e2, validOp(t), 1, T0.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.ReleaseClientPeer(session, space.ID, rel2, T0); err != nil {
		t.Fatalf("e2 release: %v", err)
	}
	// 对照：retain 未到的 tombstone 不得被扫除。
	e3 := newPeerIdentity(t)
	if _, err := env.registerClient(t, session, space.ID, e3, validOp(t), 0, T0.Add(115*time.Second)); err != nil {
		t.Fatalf("e3 注册: %v", err)
	}
	T2 := T0.Add(181 * time.Second)
	// 扫除前（tombstone 窗内）旧 proof 重放 → NotAfter 已过 → 拒。
	if _, err := env.s.RegisterClientPeer(session, space.ID, e1Req, T0.Add(90*time.Second)); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("tombstone 窗内旧 proof 重放应拒，got %v", err)
	}
	if _, err := env.s.SweepSecurityState(T2); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if _, ok := readClientPeerRecord(t, env.s, e1.id); ok {
		t.Fatal("过期 e1 应被扫除")
	}
	if _, ok := readClientPeerRecord(t, env.s, e2.id); ok {
		t.Fatal("released e2 RetainUntil 过后应被扫除")
	}
	if _, ok := readClientPeerRecord(t, env.s, e3.id); !ok {
		t.Fatal("retain 未到的 e3 不应被扫除")
	}
	// 扫除后旧签请求仍拒。
	if _, err := env.s.RegisterClientPeer(session, space.ID, e1Req, T2); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("扫除后旧 proof 重放应拒，got %v", err)
	}
	// 记录已扫除时旧 expected 不得凭空建立记录（expected=1 对不存在记录必须错位）。
	stale, err := buildClientRegisterReq(env, session, space.ID, e1, validOp(t), 1, T2.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.RegisterClientPeer(session, space.ID, stale, T2); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("扫除后旧 expected 不得建立记录，got %v", err)
	}
	// 新纪元只能全新注册（expected=0）。
	reborn, err := buildClientRegisterReq(env, session, space.ID, e1, validOp(t), 0, T2.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.RegisterClientPeer(session, space.ID, reborn, T2); err != nil {
		t.Fatalf("扫除后全新注册: %v", err)
	}
}
