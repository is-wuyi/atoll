package meta

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/peerauth"
)

// buildClientRegisterReq 构造并签名一次 client 注册/续租请求。
// proof 只绑定 origin/session/space/peer/op/expected/not_after，与提交时刻无关，
// 可预生成后在任意 now 提交（并发 barrier 依赖这一点）。
func buildClientRegisterReq(env *peerEnv, session string, spaceID uint64, ident peerIdentity, op string, expectedRev uint64, notAfter time.Time) (peerauth.ClientRegistration, error) {
	req := peerauth.ClientRegistration{PeerID: ident.id, PublicKey: ident.pub, ExpectedRevision: expectedRev, OperationID: op, NotAfter: notAfter}
	message, err := peerauth.ClientProof(env.origin, session, spaceID, req)
	if err != nil {
		return req, err
	}
	req.Signature = ed25519.Sign(ident.priv, message)
	return req, nil
}

// buildClientReleaseReq 构造并签名一次 client 释放请求（client-peer-release 签名域）。
func buildClientReleaseReq(env *peerEnv, session string, spaceID uint64, ident peerIdentity, op string, expectedRev uint64, notAfter time.Time) (peerauth.ClientRegistration, error) {
	req := peerauth.ClientRegistration{PeerID: ident.id, PublicKey: ident.pub, ExpectedRevision: expectedRev, OperationID: op, NotAfter: notAfter}
	message, err := peerauth.ClientReleaseProof(env.origin, session, spaceID, req)
	if err != nil {
		return req, err
	}
	req.Signature = ed25519.Sign(ident.priv, message)
	return req, nil
}

// ---- release 生命周期：tombstone 语义、票据失效、无 WAL、签名域分离 ----

func TestPeerClientReleaseLifecycle(t *testing.T) {
	env := newPeerEnv(t)
	nodePeer := newPeerIdentity(t)
	target := env.enrollDevice(t, filepath.Join(t.TempDir(), "dev.key"), "127.0.0.1:9443", &peerauth.Enrollment{PeerID: nodePeer.id, PublicKey: nodePeer.pub, ExpectedRevision: 0}, nodePeer.priv)
	user, space, session := env.makeUser(t, "releaseuser")
	cp := newPeerIdentity(t)
	regNotAfter := env.now.Add(time.Minute)
	ep, err := env.registerClient(t, session, space.ID, cp, validOp(t), 0, regNotAfter)
	if err != nil || ep.Revision != 1 {
		t.Fatalf("注册: %+v %v", ep, err)
	}
	objID := env.setupObjectOnNode(t, WriteActor{UserID: user.ID, SpaceID: space.ID}, space, target)
	path := fmt.Sprintf("/objects/%d", objID)
	ticketReq := func() access.TicketRequest {
		return access.TicketRequest{NodeAddr: "127.0.0.1:9443", Method: "PUT", Path: path, WriteEpoch: 1, SourcePeerID: cp.id}
	}
	checkReq := func(token string) access.CheckRequest {
		return access.CheckRequest{Token: token, Method: "PUT", Path: path, WriteEpoch: 1, SourcePeerID: cp.id}
	}
	ticket, err := env.s.IssueUserTicket(session, space.ID, ticketReq(), env.now)
	if err != nil {
		t.Fatalf("在途签票: %v", err)
	}
	if _, err := env.s.CheckAccessTicket(target.Token, checkReq(ticket.Token), env.now); err != nil {
		t.Fatalf("初票应可验: %v", err)
	}
	walBefore := mustWALSeq(t, env.s)
	relOp := validOp(t)
	rel, err := buildClientReleaseReq(env, session, space.ID, cp, relOp, ep.Revision, env.now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("release proof: %v", err)
	}
	st, err := env.s.ReleaseClientPeer(session, space.ID, rel, env.now)
	if err != nil || st.Revision != 2 {
		t.Fatalf("release 应成功 rev=2，got %+v %v", st, err)
	}
	// client-peer 不落 WAL。
	if walAfter := mustWALSeq(t, env.s); walAfter != walBefore {
		t.Fatalf("release 不应产生 WAL 帧: before=%d after=%d", walBefore, walAfter)
	}
	rec, ok := readClientPeerRecord(t, env.s, cp.id)
	if !ok || !rec.Released {
		t.Fatalf("released 记录应保留 tombstone 标记: found=%v released=%v", ok, rec.Released)
	}
	if !rec.Endpoint.ValidUntil.Equal(regNotAfter.UTC()) {
		t.Fatalf("released 应保留原 ValidUntil: %v want %v", rec.Endpoint.ValidUntil, regNotAfter.UTC())
	}
	wantRetain := regNotAfter.Add(peerauth.EndpointLease)
	if !rec.RetainUntil.Equal(wantRetain) || rec.RetainUntil.Before(rel.NotAfter.Add(peerauth.EndpointLease)) {
		t.Fatalf("RetainUntil 应为 register NotAfter+lease 且 ≥ release NotAfter+lease: %v", rec.RetainUntil)
	}
	if rec.Endpoint.Revision != 2 || rec.AuthorizationRevision != 2 || rec.OperationID != relOp {
		t.Fatalf("released 应 rev=2 authRev=2 op=release op: %+v", rec)
	}
	// released 不再 live：不允许、不进目录、在途票失效、不得再以它为来源签票。
	if allowed, _ := env.s.PeerAllowed(cp.id, env.now, time.Minute); allowed {
		t.Fatal("released client 不应被允许")
	}
	for _, e := range mustDirectory(t, env, env.now) {
		if e.PeerID == cp.id {
			t.Fatal("released client 不应列入目录")
		}
	}
	if _, err := env.s.CheckAccessTicket(target.Token, checkReq(ticket.Token), env.now); !errors.Is(err, ErrAccessTicket) {
		t.Fatalf("release 后在途票应失效，got %v", err)
	}
	if _, err := env.s.IssueUserTicket(session, space.ID, ticketReq(), env.now); !errors.Is(err, ErrAccessTicket) {
		t.Fatalf("released 来源不得再签票，got %v", err)
	}
	// 同 op 重放：幂等同 rev，不重复递增 authRev。
	st2, err := env.s.ReleaseClientPeer(session, space.ID, rel, env.now)
	if err != nil || st2.Revision != 2 {
		t.Fatalf("同 op release 重放应幂等 rev=2，got %+v %v", st2, err)
	}
	if rec2, _ := readClientPeerRecord(t, env.s, cp.id); rec2.AuthorizationRevision != 2 || rec2.Endpoint.Revision != 2 {
		t.Fatalf("幂等重放不得递增: rev=%d authRev=%d", rec2.Endpoint.Revision, rec2.AuthorizationRevision)
	}
	// 同 op 改 NotAfter（hash 不符）→ 拒。
	relBad, err := buildClientReleaseReq(env, session, space.ID, cp, relOp, 2, env.now.Add(45*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.ReleaseClientPeer(session, space.ID, relBad, env.now); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("同 op 改 hash 应 ErrPeerConflict，got %v", err)
	}
	// 签名域分离：注册域签名不能释放，释放域签名不能注册。
	regDom := peerauth.ClientRegistration{PeerID: cp.id, PublicKey: cp.pub, ExpectedRevision: 2, OperationID: validOp(t), NotAfter: env.now.Add(time.Minute)}
	msgReg, err := peerauth.ClientProof(env.origin, session, space.ID, regDom)
	if err != nil {
		t.Fatal(err)
	}
	regDom.Signature = ed25519.Sign(cp.priv, msgReg)
	if _, err := env.s.ReleaseClientPeer(session, space.ID, regDom, env.now); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("注册域签名用于 release 应 ErrDeviceAuth，got %v", err)
	}
	relDom := peerauth.ClientRegistration{PeerID: cp.id, PublicKey: cp.pub, ExpectedRevision: 2, OperationID: validOp(t), NotAfter: env.now.Add(time.Minute)}
	msgRel, err := peerauth.ClientReleaseProof(env.origin, session, space.ID, relDom)
	if err != nil {
		t.Fatal(err)
	}
	relDom.Signature = ed25519.Sign(cp.priv, msgRel)
	if _, err := env.s.RegisterClientPeer(session, space.ID, relDom, env.now); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("释放域签名用于注册应 ErrDeviceAuth，got %v", err)
	}
	// expected=0 / 陈旧 expected / 未知 peer → 拒。
	zero, err := buildClientReleaseReq(env, session, space.ID, cp, validOp(t), 0, env.now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.ReleaseClientPeer(session, space.ID, zero, env.now); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("expected=0 release 应拒，got %v", err)
	}
	stale, err := buildClientReleaseReq(env, session, space.ID, cp, validOp(t), 1, env.now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.ReleaseClientPeer(session, space.ID, stale, env.now); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("陈旧 expected release 应拒，got %v", err)
	}
	unknown, err := buildClientReleaseReq(env, session, space.ID, newPeerIdentity(t), validOp(t), 1, env.now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.ReleaseClientPeer(session, space.ID, unknown, env.now); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("未知 peer release 应拒，got %v", err)
	}
	// 同 user 不同 session：release 的 session 绑定必须是当前记录会话。
	relogin, err := env.s.AuthenticateUser("releaseuser", "invited-password-1", env.now)
	if err != nil {
		t.Fatalf("重登录: %v", err)
	}
	relOtherSess, err := buildClientReleaseReq(env, relogin.Token, space.ID, cp, validOp(t), 2, env.now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.ReleaseClientPeer(relogin.Token, space.ID, relOtherSess, env.now); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("同 user 不同 session release 应拒，got %v", err)
	}
	// release 的 NotAfter 更晚时 tombstone 保留期随之延长（取 max，不缩短）。
	c2 := newPeerIdentity(t)
	if _, err := env.registerClient(t, session, space.ID, c2, validOp(t), 0, env.now.Add(time.Minute)); err != nil {
		t.Fatalf("c2 注册: %v", err)
	}
	relLong, err := buildClientReleaseReq(env, session, space.ID, c2, validOp(t), 1, env.now.Add(110*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.ReleaseClientPeer(session, space.ID, relLong, env.now); err != nil {
		t.Fatalf("c2 release: %v", err)
	}
	recC2, ok := readClientPeerRecord(t, env.s, c2.id)
	if !ok || !recC2.RetainUntil.Equal(env.now.Add(230*time.Second)) {
		t.Fatalf("延长 release 的 RetainUntil 应=release NotAfter+lease(230s)，got %v found=%v", recC2.RetainUntil, ok)
	}

	reactivate, err := buildClientRegisterReq(env, session, space.ID, cp, validOp(t), 2, env.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.RegisterClientPeer(session, space.ID, reactivate, env.now); err != nil {
		t.Fatalf("fresh registration after release: %v", err)
	}
	active, ok := readClientPeerRecord(t, env.s, cp.id)
	if !ok || active.Released || active.Endpoint.Revision != 3 || active.AuthorizationRevision != 3 {
		t.Fatalf("reactivation did not advance authorization: %+v", active)
	}
	if _, err := env.s.CheckAccessTicket(target.Token, checkReq(ticket.Token), env.now); !errors.Is(err, ErrAccessTicket) {
		t.Fatalf("old ticket revived after reactivation: %v", err)
	}
	freshTicket, err := env.s.IssueUserTicket(session, space.ID, ticketReq(), env.now)
	if err != nil {
		t.Fatalf("reactivated peer cannot obtain a fresh ticket: %v", err)
	}
	if _, err := env.s.CheckAccessTicket(target.Token, checkReq(freshTicket.Token), env.now); err != nil {
		t.Fatalf("fresh ticket after reactivation: %v", err)
	}
	if _, err := env.s.ReleaseClientPeer(session, space.ID, rel, env.now); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("old release affected the new authorization: %v", err)
	}
}

func TestPeerClientReleaseRegistrationBoundaries(t *testing.T) {
	t.Run("register-op-as-release-op-while-live", func(t *testing.T) {
		env := newPeerEnv(t)
		_, space, session := env.makeUser(t, "negrel")
		cp := newPeerIdentity(t)
		regOp := validOp(t)
		if _, err := env.registerClient(t, session, space.ID, cp, regOp, 0, env.now.Add(time.Minute)); err != nil {
			t.Fatalf("注册: %v", err)
		}
		rel, err := buildClientReleaseReq(env, session, space.ID, cp, regOp, 1, env.now.Add(30*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.s.ReleaseClientPeer(session, space.ID, rel, env.now); !errors.Is(err, ErrPeerConflict) {
			t.Fatalf("live 记录上以注册 op 当 release op 应拒，got %v", err)
		}
	})
	t.Run("double-release-different-op", func(t *testing.T) {
		env := newPeerEnv(t)
		_, space, session := env.makeUser(t, "negrel2")
		cp := newPeerIdentity(t)
		if _, err := env.registerClient(t, session, space.ID, cp, validOp(t), 0, env.now.Add(time.Minute)); err != nil {
			t.Fatalf("注册: %v", err)
		}
		rel1, err := buildClientReleaseReq(env, session, space.ID, cp, validOp(t), 1, env.now.Add(30*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.s.ReleaseClientPeer(session, space.ID, rel1, env.now); err != nil {
			t.Fatalf("首次 release: %v", err)
		}
		rel2, err := buildClientReleaseReq(env, session, space.ID, cp, validOp(t), 2, env.now.Add(30*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.s.ReleaseClientPeer(session, space.ID, rel2, env.now); !errors.Is(err, ErrPeerConflict) {
			t.Fatalf("released 后不同 op 二次 release 必须拒，got %v", err)
		}
	})
	t.Run("re-register-after-release", func(t *testing.T) {
		env := newPeerEnv(t)
		_, space, session := env.makeUser(t, "negrel3")
		cp := newPeerIdentity(t)
		if _, err := env.registerClient(t, session, space.ID, cp, validOp(t), 0, env.now.Add(time.Minute)); err != nil {
			t.Fatalf("注册: %v", err)
		}
		rel, err := buildClientReleaseReq(env, session, space.ID, cp, validOp(t), 1, env.now.Add(30*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.s.ReleaseClientPeer(session, space.ID, rel, env.now); err != nil {
			t.Fatalf("release: %v", err)
		}
		again, err := buildClientRegisterReq(env, session, space.ID, cp, validOp(t), 2, env.now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.s.RegisterClientPeer(session, space.ID, again, env.now); err != nil {
			t.Fatalf("valid re-registration after release: %v", err)
		}
		if rec, ok := readClientPeerRecord(t, env.s, cp.id); !ok || rec.Released || rec.Endpoint.Revision != 3 || rec.AuthorizationRevision != 3 {
			t.Fatalf("re-registration must create a new authorization: %+v", rec)
		}
	})
	t.Run("old-register-op-replay-after-release", func(t *testing.T) {
		env := newPeerEnv(t)
		_, space, session := env.makeUser(t, "negrel4")
		cp := newPeerIdentity(t)
		regOp := validOp(t)
		original, err := buildClientRegisterReq(env, session, space.ID, cp, regOp, 0, env.now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.s.RegisterClientPeer(session, space.ID, original, env.now); err != nil {
			t.Fatalf("注册: %v", err)
		}
		rel, err := buildClientReleaseReq(env, session, space.ID, cp, validOp(t), 1, env.now.Add(30*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.s.ReleaseClientPeer(session, space.ID, rel, env.now); err != nil {
			t.Fatalf("release: %v", err)
		}
		// 原样重放旧注册请求（NotAfter 未过）：CAS 已错位 → 拒。
		if _, err := env.s.RegisterClientPeer(session, space.ID, original, env.now); !errors.Is(err, ErrPeerConflict) {
			t.Fatalf("旧注册请求原样重放应拒，got %v", err)
		}
		// A new signature over the current revision is not a replay of the old request.
		sameOpNewProof, err := buildClientRegisterReq(env, session, space.ID, cp, regOp, 2, env.now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.s.RegisterClientPeer(session, space.ID, sameOpNewProof, env.now); err != nil {
			t.Fatalf("new signature with current revision: %v", err)
		}
		if _, err := env.s.RegisterClientPeer(session, space.ID, original, env.now); !errors.Is(err, ErrPeerConflict) {
			t.Fatalf("old signed request must remain rejected: %v", err)
		}
		if rec, ok := readClientPeerRecord(t, env.s, cp.id); !ok || rec.Released || rec.AuthorizationRevision != 3 || rec.Endpoint.Revision != 3 {
			t.Fatalf("new proof did not establish a new authorization: %+v", rec)
		}
	})
	t.Run("cross-user-register-released-peer", func(t *testing.T) {
		env := newPeerEnv(t)
		_, space, session := env.makeUser(t, "negrel5")
		cp := newPeerIdentity(t)
		if _, err := env.registerClient(t, session, space.ID, cp, validOp(t), 0, env.now.Add(time.Minute)); err != nil {
			t.Fatalf("注册: %v", err)
		}
		rel, err := buildClientReleaseReq(env, session, space.ID, cp, validOp(t), 1, env.now.Add(30*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.s.ReleaseClientPeer(session, space.ID, rel, env.now); err != nil {
			t.Fatalf("release: %v", err)
		}
		otherUser, otherSpace, otherSession := env.makeUser(t, "taker5")
		take, err := buildClientRegisterReq(env, otherSession, otherSpace.ID, cp, validOp(t), 2, env.now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.s.RegisterClientPeer(otherSession, otherSpace.ID, take, env.now); err != nil {
			t.Fatalf("released identity holder can register a new user binding: %v", err)
		}
		rec, ok := readClientPeerRecord(t, env.s, cp.id)
		if !ok || rec.Released || rec.UserID != otherUser.ID || rec.SpaceID != otherSpace.ID || rec.AuthorizationRevision != 3 {
			t.Fatalf("new user binding not recorded: %+v", rec)
		}
		back, err := buildClientRegisterReq(env, session, space.ID, cp, validOp(t), 3, env.now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.s.RegisterClientPeer(session, space.ID, back, env.now); !errors.Is(err, ErrPeerConflict) {
			t.Fatalf("old user must not take over a live binding: %v", err)
		}
		oldRelease, err := buildClientReleaseReq(env, session, space.ID, cp, validOp(t), 3, env.now.Add(30*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.s.ReleaseClientPeer(session, space.ID, oldRelease, env.now); !errors.Is(err, ErrPeerConflict) {
			t.Fatalf("old user must not release a new user's binding: %v", err)
		}
	})
}
