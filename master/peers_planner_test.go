package master

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/access"
	"atoll/pkg/auth"
	"atoll/pkg/edgeidentity"
	"atoll/pkg/peerauth"
)

// plannerEnv 装配安全 HTTPS + 写计划（可选 transferPlanning）+ peer 目录的 Server，
// 自带一个已绑定但未发布端点的节点。与 mPeerFixture 分开，便于控制 TransferPlanning。
type plannerEnv struct {
	srv      *Server
	store    *meta.Store
	origin   string
	now      time.Time
	boundTok string
	boundID  uint64
	boundKey mPeerIdentity
}

func newPeerPlannerEnv(t *testing.T, transfer bool) *plannerEnv {
	t.Helper()
	now := time.Now()
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if _, _, err := store.BootstrapSecurity("admin", "admin-password-123", now); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, time.Hour)
	if err := srv.EnableSecurity(SecurityConfig{ControlToken: auth.Token(strings.Repeat("c", 32))}); err != nil {
		t.Fatalf("EnableSecurity: %v", err)
	}
	if err := srv.EnableWritePlanning(WritePlanningConfig{MaxReplicas: 2, TransferPlanning: transfer}); err != nil {
		t.Fatalf("EnableWritePlanning: %v", err)
	}
	origin, err := peerauth.CanonicalOrigin("https://master.test")
	if err != nil {
		t.Fatal(err)
	}
	infra := newMPeerIdentity(t)
	if err := srv.EnablePeerDirectory(PeerConfig{Origin: origin, Infrastructure: peerauth.Infrastructure{PeerID: infra.id, PublicKey: infra.pub, Addresses: []string{"/ip4/8.8.8.8/tcp/9400"}, Relay: true}}); err != nil {
		t.Fatalf("EnablePeerDirectory: %v", err)
	}
	tok, id, key := plannerEnroll(t, store, origin, now, "planner-dev", "127.0.0.1:9443")
	return &plannerEnv{srv: srv, store: store, origin: origin, now: now, boundTok: tok, boundID: id, boundKey: key}
}

// plannerEnroll 完成一次绑定 nodePeer 的设备登录（不发布端点）。
func plannerEnroll(t *testing.T, store *meta.Store, origin string, now time.Time, keyName, addr string) (string, uint64, mPeerIdentity) {
	t.Helper()
	id, err := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), keyName+".key"))
	if err != nil {
		t.Fatal(err)
	}
	nodePeer := newMPeerIdentity(t)
	invite, err := store.CreateDeviceInvite(now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := store.NewDeviceChallenge(access.DeviceChallengeRequest{
		PublicKey: id.PublicKey(), Addr: addr, TotalBytes: 1 << 20, Invite: invite,
		Peer: &peerauth.Enrollment{PeerID: nodePeer.id, PublicKey: nodePeer.pub, ExpectedRevision: 0},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	devSig, err := id.Sign(ch.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := store.CompleteDeviceChallenge(access.DeviceLoginRequest{
		ChallengeID: ch.ID, Signature: devSig,
		PeerSignature: ed25519.Sign(nodePeer.priv, peerauth.EnrollmentProof(ch.Challenge)),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	return sess.Token, sess.NodeID, nodePeer
}

func (e *plannerEnv) publish(t *testing.T, tok string, nodeID uint64, peer mPeerIdentity, bindingRev, expectedRev uint64, notAfter time.Time) {
	t.Helper()
	req := peerauth.AddressPublication{PeerID: peer.id, BindingRevision: bindingRev, ExpectedRevision: expectedRev, OperationID: mValidOp(t), Addresses: []string{"/ip4/1.2.3.4/tcp/9400"}, NotAfter: notAfter}
	msg, err := peerauth.PublicationProof(e.origin, nodeID, req)
	if err != nil {
		t.Fatal(err)
	}
	req.Signature = ed25519.Sign(peer.priv, msg)
	if _, err := e.store.PublishPeerAddress(tok, req, e.now); err != nil {
		t.Fatalf("PublishPeerAddress: %v", err)
	}
}

func (e *plannerEnv) snapshotOnline(t *testing.T, at time.Time) map[uint64]bool {
	t.Helper()
	snap, err := e.store.AutonomySnapshot()
	if err != nil {
		t.Fatalf("AutonomySnapshot: %v", err)
	}
	world, err := e.srv.newWriteSnapshot(context.Background(), snap, at)
	if err != nil {
		t.Fatalf("newWriteSnapshot: %v", err)
	}
	online := make(map[uint64]bool)
	for _, n := range world.Nodes {
		id, err := strconv.ParseUint(n.ID, 10, 64)
		if err != nil {
			t.Fatalf("node id %q: %v", n.ID, err)
		}
		online[id] = n.Online
	}
	return online
}

// ---- P2P 启用时规划候选必须持有有效 peer 端点，探针结果不得掩盖 peer 缺失 ----

func TestPeerPlannerSnapshotRequiresLivePeerEndpoint(t *testing.T) {
	e := newPeerPlannerEnv(t, false)
	probes := 0
	e.srv.SetHealthProbe(func(string) bool { probes++; return true })
	// bound：始终未发布 → 排除。
	// fresh：端点 90s 有效 → 在线且被探测。
	// stale：端点 45s 过期 → 60s 时排除。
	freshTok, freshID, freshKey := plannerEnroll(t, e.store, e.origin, e.now, "planner-fresh", "127.0.0.1:9444")
	e.publish(t, freshTok, freshID, freshKey, 1, 0, e.now.Add(90*time.Second))
	staleTok, staleID, staleKey := plannerEnroll(t, e.store, e.origin, e.now, "planner-stale", "127.0.0.1:9445")
	e.publish(t, staleTok, staleID, staleKey, 1, 0, e.now.Add(45*time.Second))
	online := e.snapshotOnline(t, e.now.Add(60*time.Second))
	if online[e.boundID] {
		t.Fatalf("未发布端点的绑定节点不得在线: %+v", online)
	}
	if !online[freshID] {
		t.Fatalf("已发布且端点有效节点应在线: %+v", online)
	}
	if online[staleID] {
		t.Fatalf("端点过期节点不得在线: %+v", online)
	}
	if probes != 1 {
		t.Fatalf("只有合格节点应被探测，probes=%d", probes)
	}
	// 刷新 stale 的端点后恢复资格：发布窗 ≤ now+2min，故以 110s 发布、100s 时刻读取。
	e.publish(t, staleTok, staleID, staleKey, 1, 1, e.now.Add(110*time.Second))
	online = e.snapshotOnline(t, e.now.Add(100*time.Second))
	if !online[staleID] {
		t.Fatalf("刷新端点后节点应恢复在线: %+v", online)
	}
	if online[e.boundID] {
		t.Fatalf("仍未发布的节点不得在线: %+v", online)
	}
}

// ---- TransferPlanning 捷径直接置 Online，但同样必须先过 peer 端点闸 ----

func TestPeerPlannerSnapshotTransferPlanningStillFiltered(t *testing.T) {
	e := newPeerPlannerEnv(t, true)
	probes := 0
	e.srv.SetHealthProbe(func(string) bool { probes++; return true })
	freshTok, freshID, freshKey := plannerEnroll(t, e.store, e.origin, e.now, "planner-transfer", "127.0.0.1:9444")
	e.publish(t, freshTok, freshID, freshKey, 1, 0, e.now.Add(90*time.Second))
	online := e.snapshotOnline(t, e.now.Add(30*time.Second))
	if !online[freshID] {
		t.Fatalf("transfer 模式下已发布节点应在线: %+v", online)
	}
	if online[e.boundID] {
		t.Fatalf("transfer 捷径不得让未发布节点在线: %+v", online)
	}
	if probes != 0 {
		t.Fatalf("transfer 模式不应走探测，probes=%d", probes)
	}
}
