package meta

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/edgeidentity"
	"atoll/pkg/peerauth"
	"atoll/pkg/types"

	crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	bolt "go.etcd.io/bbolt"
)

// peerIdentity 生成一对可互验的 libp2p Ed25519 peer id 与签名密钥。
// peer id 是公钥 protobuf 编码的 multihash，与 edgeidentity 的节点 id 体系无关。
type peerIdentity struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newPeerIdentity(t *testing.T) peerIdentity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.UnmarshalEd25519PublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return peerIdentity{id: id.String(), pub: pub, priv: priv}
}

// peerEnv 提供带安全、写计划与 peer 目录配置的 store 及固定时间基准。
type peerEnv struct {
	s         *Store
	origin    string
	infra     peerauth.Infrastructure
	infraPriv ed25519.PrivateKey
	now       time.Time
	adminID   uint64
}

func newPeerEnv(t *testing.T) *peerEnv {
	t.Helper()
	securityFastHash(t)
	s := newTestStore(t)
	admin, _ := bootstrapAdmin(t, s)
	if err := s.EnableWritePlanning(); err != nil {
		t.Fatal(err)
	}
	infra := newPeerIdentity(t)
	origin, err := peerauth.CanonicalOrigin("https://master.test")
	if err != nil {
		t.Fatal(err)
	}
	cfg := peerauth.Infrastructure{
		PeerID:    infra.id,
		PublicKey: infra.pub,
		Addresses: []string{"/ip4/8.8.8.8/tcp/9400"},
		Relay:     true,
	}
	if err := s.ConfigurePeerDirectory(origin, cfg); err != nil {
		t.Fatalf("ConfigurePeerDirectory: %v", err)
	}
	got, err := s.PeerInfrastructure()
	if err != nil || got.PeerID != infra.id {
		t.Fatalf("PeerInfrastructure: %v %v", got, err)
	}
	return &peerEnv{s: s, origin: origin, infra: cfg, infraPriv: infra.priv, now: time.Now(), adminID: admin.ID}
}

// enrollDevice 用给定 peer 绑定（可为 nil）完成一次设备登录，返回设备会话。
// 同一 keyPath 重复调用即同一设备身份重登录（重绑定 / 0-resume）。
func (env *peerEnv) enrollDevice(t *testing.T, keyPath, addr string, enrollment *peerauth.Enrollment, peerPriv ed25519.PrivateKey) auditDevice {
	t.Helper()
	id, err := edgeidentity.LoadOrCreate(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreate device identity: %v", err)
	}
	invite, err := env.s.CreateDeviceInvite(env.now.Add(time.Hour), env.now)
	if err != nil {
		t.Fatalf("CreateDeviceInvite: %v", err)
	}
	ch, err := env.s.NewDeviceChallenge(access.DeviceChallengeRequest{
		PublicKey:  id.PublicKey(),
		Addr:       addr,
		TotalBytes: 1 << 20,
		Invite:     invite,
		Peer:       enrollment,
	}, env.now)
	if err != nil {
		t.Fatalf("NewDeviceChallenge(%s): %v", addr, err)
	}
	deviceSig, err := id.Sign(ch.Challenge)
	if err != nil {
		t.Fatalf("device Sign challenge: %v", err)
	}
	login := access.DeviceLoginRequest{ChallengeID: ch.ID, Signature: deviceSig}
	if enrollment != nil {
		login.PeerSignature = ed25519.Sign(peerPriv, peerauth.EnrollmentProof(ch.Challenge))
	}
	sess, err := env.s.CompleteDeviceChallenge(login, env.now)
	if err != nil {
		t.Fatalf("CompleteDeviceChallenge(%s): %v", addr, err)
	}
	return auditDevice{Token: sess.Token, NodeID: sess.NodeID, Identity: id}
}

// makeUser 创建一个普通用户并返回其个人空间与登录会话 token。
func (env *peerEnv) makeUser(t *testing.T, name string) (PublicUser, Space, string) {
	t.Helper()
	user, space := inviteAndRegister(t, env.s, env.adminID, name, env.now)
	login, err := env.s.AuthenticateUser(name, "invited-password-1", env.now)
	if err != nil {
		t.Fatalf("AuthenticateUser(%s): %v", name, err)
	}
	return user, space, login.Token
}

func validOp(t *testing.T) string {
	t.Helper()
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw[:])
}

// registerClient 用给定 client 身份注册一次 client peer，返回注册端点（或错误）。
func (env *peerEnv) registerClient(t *testing.T, session string, spaceID uint64, ident peerIdentity, op string, expectedRev uint64, notAfter time.Time) (peerauth.Endpoint, error) {
	t.Helper()
	req := peerauth.ClientRegistration{PeerID: ident.id, PublicKey: ident.pub, ExpectedRevision: expectedRev, OperationID: op, NotAfter: notAfter}
	message, err := peerauth.ClientProof(env.origin, session, spaceID, req)
	if err != nil {
		t.Fatalf("ClientProof: %v", err)
	}
	req.Signature = ed25519.Sign(ident.priv, message)
	return env.s.RegisterClientPeer(session, spaceID, req, env.now)
}

// publishAddress 用给定（已绑定到设备的）peer 身份发布一次地址，返回端点（或错误）。
func (env *peerEnv) publishAddress(t *testing.T, device auditDevice, peerID string, peerPriv ed25519.PrivateKey, bindingRev, expectedRev uint64, op string, addrs []string, notAfter time.Time) (peerauth.Endpoint, error) {
	t.Helper()
	req := peerauth.AddressPublication{PeerID: peerID, BindingRevision: bindingRev, ExpectedRevision: expectedRev, OperationID: op, Addresses: addrs, NotAfter: notAfter}
	message, err := peerauth.PublicationProof(env.origin, device.NodeID, req)
	if err != nil {
		t.Fatalf("PublicationProof: %v", err)
	}
	req.Signature = ed25519.Sign(peerPriv, message)
	return env.s.PublishPeerAddress(device.Token, req, env.now)
}

// seedClientPeers 直接向库写入 count 条 live 的 client-peer 记录（均属 userID/spaceID，
// 复用同一个伪造会话散列），用于逼近全局 MaxDirectoryPeers 上限而无需创建大量用户。
func (env *peerEnv) seedClientPeers(t *testing.T, count int, userID, spaceID uint64) {
	t.Helper()
	sessionHash := bytes.Repeat([]byte{0x5a}, 32)
	future := env.now.Add(time.Minute)
	retain := env.now.Add(2 * time.Minute)
	op := strings.Repeat("0", 32)
	reqHash := strings.Repeat("0", 64)
	var rawSession []byte
	rawSession, _ = json.Marshal(SessionRecord{UserID: userID, CreatedAt: env.now, ExpiresAt: env.now.Add(time.Hour)})
	err := env.s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketSecurity).Put(secKeySession(sessionHash), rawSession); err != nil {
			return err
		}
		for i := 0; i < count; i++ {
			ident := newPeerIdentity(t)
			record := clientPeerRecord{
				Endpoint: peerauth.Endpoint{Role: peerauth.RoleClient, PeerID: ident.id, PublicKey: ident.pub, Revision: 1, ValidUntil: future},
				UserID:   userID, SpaceID: spaceID, SessionHash: sessionHash,
				OperationID: op, RequestHash: reqHash, RetainUntil: retain, AuthorizationRevision: 1,
			}
			raw, _ := json.Marshal(record)
			if err := tx.Bucket(bucketSecurity).Put(securityDataKey("client-peer", ident.id), raw); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seedClientPeers: %v", err)
	}
}

// setupObjectOnNode 在 target 节点上创建一个待写对象（WriteEpoch=1），返回对象 id。
func (env *peerEnv) setupObjectOnNode(t *testing.T, actor WriteActor, space Space, target auditDevice) uint64 {
	t.Helper()
	u, err := env.s.BeginPlannedWrite(actor, space.RootID, "peerfile", types.BeginWriteRequest{Path: "/peerfile", OpID: "begin-peer", Size: 3}, env.now)
	if err != nil {
		t.Fatalf("BeginPlannedWrite: %v", err)
	}
	req, plan := writeChoice(u, 0, []byte("abc"), []uint64{target.NodeID}, []uint64{target.NodeID})
	plan.Recovery = &types.WriteRecovery{Epoch: 1, HardUntil: env.now.Add(time.Minute)}
	if _, _, err := env.s.ReserveWriteChunk(actor, req, plan, 0, time.Hour, env.now); err != nil {
		t.Fatalf("ReserveWriteChunk: %v", err)
	}
	return plan.Object.ID
}

// ---- 配置门：peer 目录未启用 / 配置不一致必须 fail-closed ----

func TestPeerDirectoryConfigGateFailClosed(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	bootstrapAdmin(t, s)
	if err := s.EnableWritePlanning(); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	// 未配置 peer 目录：所有 peer 读/写 API 必须 fail-closed。
	if enabled, err := s.PeerDirectoryEnabled(); err != nil || enabled {
		t.Fatalf("未配置时应为 (false,nil)，got (%v,%v)", enabled, err)
	}
	if _, err := s.PeerInfrastructure(); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("PeerInfrastructure 未配置应 ErrPeerConflict，got %v", err)
	}
	if _, err := s.PeerDirectory(now, time.Minute); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("PeerDirectory 未配置应 ErrPeerConflict，got %v", err)
	}
	if _, err := s.PeerAllowed(peerMustID(t), now, time.Minute); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("PeerAllowed 未配置应 ErrPeerConflict，got %v", err)
	}
	infra := newPeerIdentity(t)
	if err := s.ConfigurePeerDirectory("https://master.test", peerauth.Infrastructure{PeerID: infra.id, PublicKey: infra.pub, Addresses: []string{"/ip4/8.8.8.8/tcp/9400"}, Relay: true}); err != nil {
		t.Fatalf("ConfigurePeerDirectory: %v", err)
	}
	if enabled, err := s.PeerDirectoryEnabled(); err != nil || !enabled {
		t.Fatalf("配置后应为 (true,nil)，got (%v,%v)", enabled, err)
	}
	// 配置后缺写计划必须被 ConfigurePeerDirectory 拒绝（writegate 一致性）。
	s2 := newTestStore(t)
	bootstrapAdmin(t, s2)
	if err := s2.ConfigurePeerDirectory("https://master.test", peerauth.Infrastructure{PeerID: infra.id, PublicKey: infra.pub, Addresses: []string{"/ip4/8.8.8.8/tcp/9400"}, Relay: true}); !errors.Is(err, ErrWritePlanRequired) {
		t.Fatalf("缺写计划应 ErrWritePlanRequired，got %v", err)
	}
}

func peerMustID(t *testing.T) string {
	t.Helper()
	return newPeerIdentity(t).id
}

func TestPeerDirectoryMarkerAndVersionGate(t *testing.T) {
	env := newPeerEnv(t)
	// 配置后 writeconfig 必须升到 v4 且 marker 置位。
	err := env.s.db.View(func(tx *bolt.Tx) error {
		var cfg writeConfig
		if raw := tx.Bucket(bucketWrites).Get(keyWriteConfig); raw == nil || json.Unmarshal(raw, &cfg) != nil || cfg.Version != 4 {
			return fmt.Errorf("writeconfig 应为 v4，got %+v", cfg)
		}
		if marker := tx.Bucket(bucketMeta).Get(keyPeerInitialized); !bytes.Equal(marker, []byte{1}) {
			return fmt.Errorf("peer 初始化 marker 应置位，got %v", marker)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	now := env.now
	// 人为清掉 marker：即使 peerconfig 仍在，也必须 fail-closed。
	if err := env.s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketMeta).Delete(keyPeerInitialized) }); err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.PeerDirectory(now, time.Minute); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("marker 缺失应 ErrPeerConflict，got %v", err)
	}
	// 恢复 marker，再人为把 writeconfig 降回 v3：同样必须 fail-closed。
	if err := env.s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketMeta).Put(keyPeerInitialized, []byte{1}); err != nil {
			return err
		}
		var cfg writeConfig
		if err := json.Unmarshal(tx.Bucket(bucketWrites).Get(keyWriteConfig), &cfg); err != nil {
			return err
		}
		cfg.Version = 3
		raw, _ := json.Marshal(cfg)
		return tx.Bucket(bucketWrites).Put(keyWriteConfig, raw)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.PeerDirectory(now, time.Minute); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("writeconfig 降回 v3 应 ErrPeerConflict，got %v", err)
	}
}

// ---- 设备入网：双证明 + peerAudience origin ----

func TestPeerDeviceEnrollmentDualProof(t *testing.T) {
	env := newPeerEnv(t)
	nodePeer := newPeerIdentity(t)
	keyPath := filepath.Join(t.TempDir(), "dev.key")
	addr := "127.0.0.1:9443"

	// 挑战绑定 peer：Audience 必须是 master origin，extras 携带 peer 信息。
	invite, err := env.s.CreateDeviceInvite(env.now.Add(time.Hour), env.now)
	if err != nil {
		t.Fatal(err)
	}
	id, err := edgeidentity.LoadOrCreate(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := &peerauth.Enrollment{PeerID: nodePeer.id, PublicKey: nodePeer.pub, ExpectedRevision: 0}
	ch, err := env.s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: id.PublicKey(), Addr: addr, TotalBytes: 1 << 20, Invite: invite, Peer: enrollment}, env.now)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Challenge.Audience != env.origin {
		t.Fatalf("peer 挑战 Audience = %q, want origin %q", ch.Challenge.Audience, env.origin)
	}
	if ch.Challenge.Extras["peer_id"] != nodePeer.id {
		t.Fatalf("挑战缺 peer_id extras: %v", ch.Challenge.Extras)
	}
	deviceSig, err := id.Sign(ch.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	wrongPeer := newPeerIdentity(t)

	// 缺 peer 签名：ErrDeviceAuth。
	if _, err := env.s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch.ID, Signature: deviceSig}, env.now); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("缺 peer 签名应 ErrDeviceAuth，got %v", err)
	}
	// 错误 peer 签名：ErrDeviceAuth。
	badSig := ed25519.Sign(wrongPeer.priv, peerauth.EnrollmentProof(ch.Challenge))
	if _, err := env.s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch.ID, Signature: deviceSig, PeerSignature: badSig}, env.now); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("错误 peer 签名应 ErrDeviceAuth，got %v", err)
	}
	// 正确双证明：成功，binding rev=1。
	sess, err := env.s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch.ID, Signature: deviceSig, PeerSignature: ed25519.Sign(nodePeer.priv, peerauth.EnrollmentProof(ch.Challenge))}, env.now)
	if err != nil {
		t.Fatalf("正确双证明应成功：%v", err)
	}
	if sess.Peer == nil || sess.Peer.PeerID != nodePeer.id || sess.Peer.Revision != 1 {
		t.Fatalf("binding = %+v, want peer=%s rev=1", sess.Peer, nodePeer.id)
	}
	rec, err := env.s.DeviceForSession(sess.Token, env.now)
	if err != nil || rec.Peer == nil || rec.Peer.Revision != 1 {
		t.Fatalf("device 记录未绑定 peer: %+v %v", rec, err)
	}
	// 未绑定 peer 时带 PeerSignature：必须拒绝（不能降级/伪造）。
	plainID, _ := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), "plain.key"))
	plainInvite, _ := env.s.CreateDeviceInvite(env.now.Add(time.Hour), env.now)
	pch, err := env.s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: plainID.PublicKey(), Addr: "127.0.0.1:9444", TotalBytes: 1 << 20, Invite: plainInvite}, env.now)
	if err != nil {
		t.Fatal(err)
	}
	plainSig, _ := plainID.Sign(pch.Challenge)
	if _, err := env.s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: pch.ID, Signature: plainSig, PeerSignature: ed25519.Sign(wrongPeer.priv, peerauth.EnrollmentProof(pch.Challenge))}, env.now); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("nil peer + PeerSignature 应 ErrDeviceAuth，got %v", err)
	}
}

// ---- 设备重登：绑定唯一与 CAS ----

func TestPeerDeviceRebindingCAS(t *testing.T) {
	env := newPeerEnv(t)
	keyPath := filepath.Join(t.TempDir(), "dev.key")
	addr := "127.0.0.1:9443"
	p1 := newPeerIdentity(t)
	p2 := newPeerIdentity(t)
	p3 := newPeerIdentity(t)

	dev := env.enrollDevice(t, keyPath, addr, &peerauth.Enrollment{PeerID: p1.id, PublicKey: p1.pub, ExpectedRevision: 0}, p1.priv)
	if dev.NodeID == 0 {
		t.Fatal("设备未获 NodeID")
	}
	// 同一 peer 0-resume：成功，binding 不变（rev 仍为 1）。
	dev2 := env.enrollDevice(t, keyPath, addr, &peerauth.Enrollment{PeerID: p1.id, PublicKey: p1.pub, ExpectedRevision: 0}, p1.priv)
	if rev := env.devicePeerRev(t, dev2.Token); rev != 1 {
		t.Fatalf("0-resume 应保持 rev=1，got %d", rev)
	}
	// 同一 peer 显式 expectedRevision=当前 rev：成功，不变。
	dev3 := env.enrollDevice(t, keyPath, addr, &peerauth.Enrollment{PeerID: p1.id, PublicKey: p1.pub, ExpectedRevision: 1}, p1.priv)
	if rev := env.devicePeerRev(t, dev3.Token); rev != 1 {
		t.Fatalf("同 peer expected=1 应保持 rev=1，got %d", rev)
	}
	// 同一 peer 错误 expectedRevision：冲突。
	if _, err := env.enrollDeviceErr(t, keyPath, addr, &peerauth.Enrollment{PeerID: p1.id, PublicKey: p1.pub, ExpectedRevision: 5}, p1.priv); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("同 peer 错误 expected 应 ErrPeerConflict，got %v", err)
	}
	// 换 peer：strict expectedRevision=当前 rev(1) → 成功，rev=2。
	dev4 := env.enrollDevice(t, keyPath, addr, &peerauth.Enrollment{PeerID: p2.id, PublicKey: p2.pub, ExpectedRevision: 1}, p2.priv)
	if rev := env.devicePeerRev(t, dev4.Token); rev != 2 {
		t.Fatalf("换 peer 应 rev=2，got %d", rev)
	}
	// 旧/晚到的不同 peer（expected=1 旧值）不得覆盖 → 冲突。
	if _, err := env.enrollDeviceErr(t, keyPath, addr, &peerauth.Enrollment{PeerID: p3.id, PublicKey: p3.pub, ExpectedRevision: 1}, p3.priv); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("旧 CAS 换 peer 应 ErrPeerConflict，got %v", err)
	}
	// 已绑定设备省略 peer：不得降级 → ErrDeviceAuth。
	if _, err := env.enrollDeviceErr(t, keyPath, addr, nil, nil); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("绑定后省略 peer 应 ErrDeviceAuth，got %v", err)
	}
	// 另一设备不得占用已绑定 peer（唯一性）。
	if _, err := env.enrollDeviceErr(t, filepath.Join(t.TempDir(), "other.key"), "127.0.0.1:9445", &peerauth.Enrollment{PeerID: p2.id, PublicKey: p2.pub, ExpectedRevision: 0}, p2.priv); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("他设备占用同一 peer 应 ErrPeerConflict，got %v", err)
	}
}

func (env *peerEnv) devicePeerRev(t *testing.T, token string) uint64 {
	t.Helper()
	state, err := env.s.NodePeerState(token, env.now)
	if err != nil || state.Binding == nil {
		t.Fatalf("NodePeerState: %v", err)
	}
	return state.Binding.Revision
}

func (env *peerEnv) enrollDeviceErr(t *testing.T, keyPath, addr string, enrollment *peerauth.Enrollment, peerPriv ed25519.PrivateKey) (auditDevice, error) {
	t.Helper()
	id, err := edgeidentity.LoadOrCreate(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	invite, _ := env.s.CreateDeviceInvite(env.now.Add(time.Hour), env.now)
	ch, err := env.s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: id.PublicKey(), Addr: addr, TotalBytes: 1 << 20, Invite: invite, Peer: enrollment}, env.now)
	if err != nil {
		t.Fatalf("NewDeviceChallenge: %v", err)
	}
	deviceSig, _ := id.Sign(ch.Challenge)
	login := access.DeviceLoginRequest{ChallengeID: ch.ID, Signature: deviceSig}
	if enrollment != nil {
		login.PeerSignature = ed25519.Sign(peerPriv, peerauth.EnrollmentProof(ch.Challenge))
	}
	sess, err := env.s.CompleteDeviceChallenge(login, env.now)
	return auditDevice{Token: sess.Token, NodeID: sess.NodeID}, err
}

// ---- 地址发布：op 幂等 / 过期 / CAS ----

func TestPeerAddressPublicationOpIdempotencyAndExpiry(t *testing.T) {
	env := newPeerEnv(t)
	nodePeer := newPeerIdentity(t)
	dev := env.enrollDevice(t, filepath.Join(t.TempDir(), "dev.key"), "127.0.0.1:9443", &peerauth.Enrollment{PeerID: nodePeer.id, PublicKey: nodePeer.pub, ExpectedRevision: 0}, nodePeer.priv)
	op := validOp(t)
	addr := []string{"/ip4/1.2.3.4/tcp/9400"}
	notAfter := env.now.Add(time.Minute)

	ep, err := env.publishAddress(t, dev, nodePeer.id, nodePeer.priv, 1, 0, op, addr, notAfter)
	if err != nil {
		t.Fatalf("PublishPeerAddress: %v", err)
	}
	if ep.Revision != 1 || ep.Role != peerauth.RoleNode || ep.NodeID != dev.NodeID || ep.PeerID != nodePeer.id || ep.BindingRevision != 1 || !ep.ValidUntil.Equal(notAfter.UTC()) || !reflect.DeepEqual(ep.Addresses, addr) {
		t.Fatalf("发布端点不符: %+v", ep)
	}
	// 同一 op 原样重放：幂等，不续租、不递增 rev。
	ep2, err := env.publishAddress(t, dev, nodePeer.id, nodePeer.priv, 1, 0, op, addr, notAfter)
	if err != nil || ep2.Revision != 1 || !ep2.ValidUntil.Equal(ep.ValidUntil) {
		t.Fatalf("同 op 应幂等（rev=1 不续租），got %+v %v", ep2, err)
	}
	// 同一 op 但改地址：RequestHash 不符 → 冲突。
	if _, err := env.publishAddress(t, dev, nodePeer.id, nodePeer.priv, 1, 0, op, []string{"/ip4/1.2.3.5/tcp/9400"}, notAfter); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("同 op 改地址应 ErrPeerConflict，got %v", err)
	}
	// NotAfter 在过去：拒绝。
	if _, err := env.publishAddress(t, dev, nodePeer.id, nodePeer.priv, 1, 1, validOp(t), addr, env.now.Add(-time.Second)); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("过期 NotAfter 应 ErrPeerConflict，got %v", err)
	}
	// NotAfter 超出 EndpointLease：拒绝。
	if _, err := env.publishAddress(t, dev, nodePeer.id, nodePeer.priv, 1, 1, validOp(t), addr, env.now.Add(peerauth.EndpointLease+time.Minute)); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("超窗 NotAfter 应 ErrPeerConflict，got %v", err)
	}
	// 陈旧 ExpectedRevision：冲突。
	if _, err := env.publishAddress(t, dev, nodePeer.id, nodePeer.priv, 1, 5, validOp(t), addr, notAfter); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("陈旧 expected 应 ErrPeerConflict，got %v", err)
	}
	// 错误 peer 签名：ErrDeviceAuth。
	wrong := newPeerIdentity(t)
	if _, err := env.publishAddress(t, dev, nodePeer.id, wrong.priv, 1, 1, validOp(t), addr, notAfter); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("错误签名应 ErrDeviceAuth，got %v", err)
	}
	// BindingRevision 不符：ErrDeviceAuth。
	if _, err := env.publishAddress(t, dev, nodePeer.id, nodePeer.priv, 2, 1, validOp(t), addr, notAfter); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("bindingRevision 不符应 ErrDeviceAuth，got %v", err)
	}
	// 新 op + 正确 expected=1：rev=2，ValidUntil=新 NotAfter。
	notAfter2 := env.now.Add(2 * time.Minute)
	ep3, err := env.publishAddress(t, dev, nodePeer.id, nodePeer.priv, 1, 1, validOp(t), []string{"/ip4/1.2.3.4/tcp/9400", "/ip6/2001:db8::1/tcp/9400"}, notAfter2)
	if err != nil || ep3.Revision != 2 || !ep3.ValidUntil.Equal(notAfter2.UTC()) {
		t.Fatalf("新 op 应 rev=2，got %+v %v", ep3, err)
	}
}

// ---- 客户端注册：session/space 绑定与每用户 4 peer、全局 512 ----

func TestPeerClientRegistrationSessionSpaceBinding(t *testing.T) {
	env := newPeerEnv(t)
	nodePeer := newPeerIdentity(t)
	env.enrollDevice(t, filepath.Join(t.TempDir(), "dev.key"), "127.0.0.1:9443", &peerauth.Enrollment{PeerID: nodePeer.id, PublicKey: nodePeer.pub, ExpectedRevision: 0}, nodePeer.priv)
	_, space, session := env.makeUser(t, "peeruser")
	cp := newPeerIdentity(t)
	notAfter := env.now.Add(time.Minute)
	opA := validOp(t)

	ep, err := env.registerClient(t, session, space.ID, cp, opA, 0, notAfter)
	if err != nil {
		t.Fatalf("RegisterClientPeer: %v", err)
	}
	if ep.Role != peerauth.RoleClient || ep.PeerID != cp.id || ep.Revision != 1 || !ep.ValidUntil.Equal(notAfter.UTC()) || ep.NodeID != 0 || len(ep.Addresses) != 0 || ep.BindingRevision != 0 {
		t.Fatalf("client 端点不符: %+v", ep)
	}
	// 同 session/space 同 op：幂等（不续租、不递增）。
	ep2, err := env.registerClient(t, session, space.ID, cp, opA, 0, notAfter)
	if err != nil || ep2.Revision != 1 {
		t.Fatalf("同 op 应幂等，got %+v %v", ep2, err)
	}
	// 同 session/space 新 op：CAS rev+1（renew），授权代次保持。
	renewed, err := env.registerClient(t, session, space.ID, cp, validOp(t), 1, notAfter)
	if err != nil || renewed.Revision != 2 {
		t.Fatalf("renew 应 rev=2，got %+v %v", renewed, err)
	}
	// 换另一用户（不同 session）注册同一 peer：旧记录仍 live → 冲突（跨会话绑定）。
	_, otherSpace, otherSession := env.makeUser(t, "peeruser2")
	if _, err := env.registerClient(t, otherSession, otherSpace.ID, cp, validOp(t), 2, notAfter); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("他用户占同 peer 应 ErrPeerConflict，got %v", err)
	}
	// 每用户上限 4：同用户再加 3 个成功，第 5 个失败。
	for i := 0; i < 3; i++ {
		ident := newPeerIdentity(t)
		if _, err := env.registerClient(t, session, space.ID, ident, validOp(t), 0, notAfter); err != nil {
			t.Fatalf("第 %d 个 client 应成功: %v", i+2, err)
		}
	}
	fifth := newPeerIdentity(t)
	if _, err := env.registerClient(t, session, space.ID, fifth, validOp(t), 0, notAfter); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("第 5 个 client 应 ErrPeerConflict，got %v", err)
	}
}

func TestPeerClientGlobalLimit(t *testing.T) {
	env := newPeerEnv(t)
	// 为另一用户铺满全局表（512），再让新用户注册一个 client。
	xUser, xSpace, _ := env.makeUser(t, "seeduser")
	env.seedClientPeers(t, peerauth.MaxDirectoryPeers, xUser.ID, xSpace.ID)
	_, freshSpace, freshSession := env.makeUser(t, "freshuser")
	cp := newPeerIdentity(t)
	if _, err := env.registerClient(t, freshSession, freshSpace.ID, cp, validOp(t), 0, env.now.Add(time.Minute)); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("全局 512 上限应 ErrPeerConflict，got %v", err)
	}
}

// ---- peer 目录 / 允许 / 端点解析 / 撤销 ----

func TestPeerDirectoryListingAndRevocation(t *testing.T) {
	env := newPeerEnv(t)
	nodePeer := newPeerIdentity(t)
	dev := env.enrollDevice(t, filepath.Join(t.TempDir(), "dev.key"), "127.0.0.1:9443", &peerauth.Enrollment{PeerID: nodePeer.id, PublicKey: nodePeer.pub, ExpectedRevision: 0}, nodePeer.priv)
	if _, err := env.publishAddress(t, dev, nodePeer.id, nodePeer.priv, 1, 0, validOp(t), []string{"/ip4/1.2.3.4/tcp/9400"}, env.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	_, space, session := env.makeUser(t, "diruser")
	cp := newPeerIdentity(t)
	if _, err := env.registerClient(t, session, space.ID, cp, validOp(t), 0, env.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	dir, err := env.s.PeerDirectory(env.now, time.Minute)
	if err != nil {
		t.Fatalf("PeerDirectory: %v", err)
	}
	if dir.Protocol != peerauth.Feature || dir.Infrastructure.PeerID != env.infra.PeerID {
		t.Fatalf("目录协议/基础设施不符: %+v", dir)
	}
	var foundNode, foundClient bool
	for _, ep := range dir.Endpoints {
		switch ep.Role {
		case peerauth.RoleNode:
			if ep.PeerID == nodePeer.id {
				foundNode = true
			}
		case peerauth.RoleClient:
			if ep.PeerID == cp.id {
				foundClient = true
			}
		}
	}
	if !foundNode || !foundClient {
		t.Fatalf("目录应含 node+client：node=%v client=%v (%d 端点)", foundNode, foundClient, len(dir.Endpoints))
	}
	// 允许判定。
	if ok, _ := env.s.PeerAllowed(env.infra.PeerID, env.now, time.Minute); !ok {
		t.Fatal("基础设施 peer 应被允许")
	}
	if ok, _ := env.s.PeerAllowed(nodePeer.id, env.now, time.Minute); !ok {
		t.Fatal("活跃节点 peer 应被允许")
	}
	if ok, _ := env.s.PeerAllowed(cp.id, env.now, time.Minute); !ok {
		t.Fatal("live client peer 应被允许")
	}
	if ok, _ := env.s.PeerAllowed(newPeerIdentity(t).id, env.now, time.Minute); ok {
		t.Fatal("未知 peer 不应被允许")
	}
	// 端点按地址解析。
	byAddr, err := env.s.PeerEndpointByAddr("127.0.0.1:9443", env.now, time.Minute)
	if err != nil || byAddr.PeerID != nodePeer.id {
		t.Fatalf("PeerEndpointByAddr: %+v %v", byAddr, err)
	}
	// 撤销设备：节点从目录消失、不再允许、endpoint 解析失败。
	if err := env.s.RevokeDevice(dev.NodeID); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	if ok, _ := env.s.PeerAllowed(nodePeer.id, env.now, time.Minute); ok {
		t.Fatal("撤销后节点 peer 不应被允许")
	}
	if _, err := env.s.PeerEndpointByAddr("127.0.0.1:9443", env.now, time.Minute); !errors.Is(err, ErrNotExist) {
		t.Fatalf("撤销后端点解析应 ErrNotExist，got %v", err)
	}
	dir2, _ := env.s.PeerDirectory(env.now, time.Minute)
	for _, ep := range dir2.Endpoints {
		if ep.PeerID == nodePeer.id {
			t.Fatal("撤销后目录仍列出节点")
		}
	}
	// client 注册独立于设备：仍被允许、仍列出。
	if ok, _ := env.s.PeerAllowed(cp.id, env.now, time.Minute); !ok {
		t.Fatal("client peer 不应随设备撤销而失效")
	}
}

// ---- 持久重开 与 WAL 崩溃重放 ----

func TestPeerDeviceSessionExpiry(t *testing.T) {
	env := newPeerEnv(t)
	nodePeer := newPeerIdentity(t)
	dev := env.enrollDevice(t, filepath.Join(t.TempDir(), "dev.key"), "127.0.0.1:9443", &peerauth.Enrollment{PeerID: nodePeer.id, PublicKey: nodePeer.pub, ExpectedRevision: 0}, nodePeer.priv)
	if _, err := env.s.DeviceForSession(dev.Token, env.now.Add(31*time.Minute)); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("过期设备会话应 ErrDeviceAuth，got %v", err)
	}
	if _, err := env.s.NodePeerState(dev.Token, env.now.Add(31*time.Minute)); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("过期设备会话 NodePeerState 应 ErrDeviceAuth，got %v", err)
	}
	if _, err := env.s.DeviceForSession(dev.Token, env.now); err != nil {
		t.Fatalf("未过期会话应可解析: %v", err)
	}
}

// TestPeerWALReplayRebuildsConfigBindingEndpoint 用仓库既有 FramesSince/ApplyFrames
// 恢复助手，把 WAL 帧重放到全新库，验证 config+binding+endpoint 可重建，client-peer
// 在线记录不落 WAL，且撤销帧重放后节点失效。区别于 TestPeerStatePersistsAcrossReopen
// 的干净 Close→Open（后者不证明崩溃重放）。
func TestPeerWALReplayRebuildsConfigBindingEndpoint(t *testing.T) {
	env := newPeerEnv(t)
	nodePeer := newPeerIdentity(t)
	dev := env.enrollDevice(t, filepath.Join(t.TempDir(), "dev.key"), "127.0.0.1:9443", &peerauth.Enrollment{PeerID: nodePeer.id, PublicKey: nodePeer.pub, ExpectedRevision: 0}, nodePeer.priv)
	if _, err := env.publishAddress(t, dev, nodePeer.id, nodePeer.priv, 1, 0, validOp(t), []string{"/ip4/1.2.3.4/tcp/9400"}, env.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	_, space, session := env.makeUser(t, "replayuser")
	cp := newPeerIdentity(t)
	if _, err := env.registerClient(t, session, space.ID, cp, validOp(t), 0, env.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	frames, err := env.s.FramesSince(0)
	if err != nil || len(frames) == 0 {
		t.Fatalf("FramesSince: %v (%d 帧)", err, len(frames))
	}
	restored := replayInto(t, frames)
	if enabled, err := restored.PeerDirectoryEnabled(); err != nil || !enabled {
		t.Fatalf("重放后配置未启用: %v %v", enabled, err)
	}
	if inf, err := restored.PeerInfrastructure(); err != nil || inf.PeerID != env.infra.PeerID {
		t.Fatalf("重放后基础设施不符: %+v %v", inf, err)
	}
	state, err := restored.NodePeerState(dev.Token, env.now)
	if err != nil || state.Binding == nil || state.Binding.PeerID != nodePeer.id {
		t.Fatalf("重放后 binding 未恢复: %+v %v", state, err)
	}
	dir, err := restored.PeerDirectory(env.now, time.Minute)
	if err != nil {
		t.Fatalf("重放后 PeerDirectory: %v", err)
	}
	foundNode := false
	for _, ep := range dir.Endpoints {
		if ep.PeerID == nodePeer.id && ep.Revision == 1 {
			foundNode = true
		}
		if ep.PeerID == cp.id {
			t.Fatal("client-peer 记录不应经 WAL 重放")
		}
	}
	if !foundNode {
		t.Fatalf("重放后节点端点未恢复: %+v", dir.Endpoints)
	}
	if ok, _ := restored.PeerAllowed(cp.id, env.now, time.Minute); ok {
		t.Fatal("client-peer 不应出现在重放库")
	}
	if err := env.s.RevokeDevice(dev.NodeID); err != nil {
		t.Fatal(err)
	}
	frames2, err := env.s.FramesSince(0)
	if err != nil {
		t.Fatal(err)
	}
	restored2 := replayInto(t, frames2)
	if ok, _ := restored2.PeerAllowed(nodePeer.id, env.now, time.Minute); ok {
		t.Fatal("撤销帧重放后节点仍允许")
	}
	dir2, _ := restored2.PeerDirectory(env.now, time.Minute)
	for _, ep := range dir2.Endpoints {
		if ep.PeerID == nodePeer.id {
			t.Fatal("撤销帧重放后目录仍列出节点")
		}
	}
}

func replayInto(t *testing.T, frames []Frame) *Store {
	t.Helper()
	restored, err := Open(filepath.Join(t.TempDir(), "replay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restored.Close() })
	if err := restored.ApplyFrames(frames); err != nil {
		t.Fatalf("ApplyFrames: %v", err)
	}
	return restored
}

// TestPeerStatePersistsAcrossReopen 干净 Close→Open 后配置与节点端点仍可读
// （持久重开；崩溃 WAL 重放见 TestPeerWALReplayRebuildsConfigBindingEndpoint）。
func TestPeerStatePersistsAcrossReopen(t *testing.T) {
	securityFastHash(t)
	dbPath := filepath.Join(t.TempDir(), "meta.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	infra := newPeerIdentity(t)
	if _, _, err := s.BootstrapSecurity("admin", "admin-password-123", now); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableWritePlanning(); err != nil {
		t.Fatal(err)
	}
	origin, _ := peerauth.CanonicalOrigin("https://master.test")
	cfg := peerauth.Infrastructure{PeerID: infra.id, PublicKey: infra.pub, Addresses: []string{"/ip4/8.8.8.8/tcp/9400"}, Relay: true}
	if err := s.ConfigurePeerDirectory(origin, cfg); err != nil {
		t.Fatal(err)
	}
	devID, _ := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), "dev.key"))
	invite, _ := s.CreateDeviceInvite(now.Add(time.Hour), now)
	nodePeer := newPeerIdentity(t)
	ch, err := s.NewDeviceChallenge(access.DeviceChallengeRequest{PublicKey: devID.PublicKey(), Addr: "127.0.0.1:9443", TotalBytes: 1 << 20, Invite: invite, Peer: &peerauth.Enrollment{PeerID: nodePeer.id, PublicKey: nodePeer.pub, ExpectedRevision: 0}}, now)
	if err != nil {
		t.Fatal(err)
	}
	deviceSig, _ := devID.Sign(ch.Challenge)
	sess, err := s.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch.ID, Signature: deviceSig, PeerSignature: ed25519.Sign(nodePeer.priv, peerauth.EnrollmentProof(ch.Challenge))}, now)
	if err != nil {
		t.Fatal(err)
	}
	pub := peerauth.AddressPublication{PeerID: nodePeer.id, BindingRevision: 1, ExpectedRevision: 0, OperationID: validOp(t), Addresses: []string{"/ip4/1.2.3.4/tcp/9400"}, NotAfter: now.Add(time.Minute)}
	msg, _ := peerauth.PublicationProof(origin, sess.NodeID, pub)
	pub.Signature = ed25519.Sign(nodePeer.priv, msg)
	if _, err := s.PublishPeerAddress(sess.Token, pub, now); err != nil {
		t.Fatal(err)
	}
	beforeWAL := mustWALSeq(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s2.Close() })
	if enabled, err := s2.PeerDirectoryEnabled(); err != nil || !enabled {
		t.Fatalf("重开后 peer 目录应启用，got (%v,%v)", enabled, err)
	}
	dir, err := s2.PeerDirectory(now.Add(time.Second), time.Minute)
	if err != nil {
		t.Fatalf("重开后 PeerDirectory: %v", err)
	}
	found := false
	for _, ep := range dir.Endpoints {
		if ep.PeerID == nodePeer.id && ep.Revision == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("重开后节点端点未恢复: %+v", dir.Endpoints)
	}
	if after := mustWALSeq(t, s2); after < beforeWAL {
		t.Fatalf("重开后 wal_seq 不应回退: before=%d after=%d", beforeWAL, after)
	}
	if err := s2.ConfigurePeerDirectory(origin, cfg); err != nil {
		t.Fatalf("重开后重复 ConfigurePeerDirectory: %v", err)
	}
}

// ---- 票据 SourcePeerID / SourcePeerRevision / AudiencePeer 当前绑定 ----

func TestPeerControlTicketSourceIsInfrastructureOnly(t *testing.T) {
	env := newPeerEnv(t)
	nodePeer := newPeerIdentity(t)
	dev := env.enrollDevice(t, filepath.Join(t.TempDir(), "dev.key"), "127.0.0.1:9443", &peerauth.Enrollment{PeerID: nodePeer.id, PublicKey: nodePeer.pub, ExpectedRevision: 0}, nodePeer.priv)
	bodyHash := strings.Repeat("0", 64)
	req := access.TicketRequest{NodeAddr: "127.0.0.1:9443", Method: "POST", Path: "/pull", BodyHash: bodyHash, SourcePeerID: env.infra.PeerID}
	ticket, err := env.s.IssueControlTicket(req, env.now)
	if err != nil {
		t.Fatalf("control 票应成功: %v", err)
	}
	if _, err := env.s.CheckAccessTicket(dev.Token, access.CheckRequest{Token: ticket.Token, Method: "POST", Path: "/pull", BodyHash: bodyHash, SourcePeerID: env.infra.PeerID}, env.now); err != nil {
		t.Fatalf("control 票验票应成功: %v", err)
	}
	// 非基础设施 peer 不能作为 control 来源。
	if _, err := env.s.IssueControlTicket(access.TicketRequest{NodeAddr: "127.0.0.1:9443", Method: "POST", Path: "/pull", BodyHash: bodyHash, SourcePeerID: nodePeer.id}, env.now); !errors.Is(err, ErrAccessTicket) {
		t.Fatalf("非 infra source 应 ErrAccessTicket，got %v", err)
	}
}

func TestPeerTicketAudiencePeerCurrentBinding(t *testing.T) {
	env := newPeerEnv(t)
	tdPeer := newPeerIdentity(t)
	keyPath := filepath.Join(t.TempDir(), "dev.key")
	dev := env.enrollDevice(t, keyPath, "127.0.0.1:9443", &peerauth.Enrollment{PeerID: tdPeer.id, PublicKey: tdPeer.pub, ExpectedRevision: 0}, tdPeer.priv)
	bodyHash := strings.Repeat("0", 64)
	req := access.TicketRequest{NodeAddr: "127.0.0.1:9443", Method: "POST", Path: "/pull", BodyHash: bodyHash, SourcePeerID: env.infra.PeerID}
	ticket, err := env.s.IssueControlTicket(req, env.now)
	if err != nil {
		t.Fatalf("control 票应成功: %v", err)
	}
	if _, err := env.s.CheckAccessTicket(dev.Token, access.CheckRequest{Token: ticket.Token, Method: "POST", Path: "/pull", BodyHash: bodyHash, SourcePeerID: env.infra.PeerID}, env.now); err != nil {
		t.Fatalf("票应可验: %v", err)
	}
	// 目标设备重绑到另一 peer：audiencePeer 快照与当前 binding 不符 → 旧票失效。
	newPeer := newPeerIdentity(t)
	dev2 := env.enrollDevice(t, keyPath, "127.0.0.1:9443", &peerauth.Enrollment{PeerID: newPeer.id, PublicKey: newPeer.pub, ExpectedRevision: 1}, newPeer.priv)
	if _, err := env.s.CheckAccessTicket(dev2.Token, access.CheckRequest{Token: ticket.Token, Method: "POST", Path: "/pull", BodyHash: bodyHash, SourcePeerID: env.infra.PeerID}, env.now); !errors.Is(err, ErrAccessTicket) {
		t.Fatalf("重绑后旧票应 ErrAccessTicket，got %v", err)
	}
	// 重绑后新票可验（audiencePeer=新 binding）。
	req2 := access.TicketRequest{NodeAddr: "127.0.0.1:9443", Method: "POST", Path: "/pull", BodyHash: bodyHash, SourcePeerID: env.infra.PeerID}
	ticket2, err := env.s.IssueControlTicket(req2, env.now)
	if err != nil {
		t.Fatalf("重绑后新票应成功: %v", err)
	}
	if _, err := env.s.CheckAccessTicket(dev2.Token, access.CheckRequest{Token: ticket2.Token, Method: "POST", Path: "/pull", BodyHash: bodyHash, SourcePeerID: env.infra.PeerID}, env.now); err != nil {
		t.Fatalf("重绑后新票应可验: %v", err)
	}
}

func TestPeerUserTicketSourcePeerRevision(t *testing.T) {
	env := newPeerEnv(t)
	nodePeer := newPeerIdentity(t)
	target := env.enrollDevice(t, filepath.Join(t.TempDir(), "dev.key"), "127.0.0.1:9443", &peerauth.Enrollment{PeerID: nodePeer.id, PublicKey: nodePeer.pub, ExpectedRevision: 0}, nodePeer.priv)
	user, space, session := env.makeUser(t, "ticketuser")
	cp := newPeerIdentity(t)
	notAfter := env.now.Add(time.Minute)

	// 注册 client（authRev=1）作为票据来源。
	cpEp, err := env.registerClient(t, session, space.ID, cp, validOp(t), 0, notAfter)
	if err != nil {
		t.Fatalf("注册 client: %v", err)
	}
	// 同一用户的两个空间：个人空间 + 团队空间，用于切 space 授权代次测试。
	team, err := env.s.CreateTeam(user.ID, "switchteam")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	objID := env.setupObjectOnNode(t, WriteActor{UserID: user.ID, SpaceID: space.ID}, space, target)
	path := fmt.Sprintf("/objects/%d", objID)
	src := func() access.TicketRequest {
		return access.TicketRequest{NodeAddr: "127.0.0.1:9443", Method: "PUT", Path: path, WriteEpoch: 1, SourcePeerID: cp.id}
	}
	ticket, err := env.s.IssueUserTicket(session, space.ID, src(), env.now)
	if err != nil {
		t.Fatalf("user 票应成功: %v", err)
	}
	check := access.CheckRequest{Token: ticket.Token, Method: "PUT", Path: path, WriteEpoch: 1, SourcePeerID: cp.id}
	if _, err := env.s.CheckAccessTicket(target.Token, check, env.now); err != nil {
		t.Fatalf("初票应可验: %v", err)
	}
	// 同 session/space 续租（CAS rev+1，authRev 不变）：在途票仍可验。
	if _, err := env.registerClient(t, session, space.ID, cp, validOp(t), cpEp.Revision, notAfter); err != nil {
		t.Fatalf("续租: %v", err)
	}
	if _, err := env.s.CheckAccessTicket(target.Token, check, env.now); err != nil {
		t.Fatalf("续租后旧票仍应可验（authRev 未变）: %v", err)
	}
	// 切 space（authRev++）：旧票失效。
	if _, err := env.registerClient(t, session, team.ID, cp, validOp(t), cpEp.Revision+1, notAfter); err != nil {
		t.Fatalf("切 space: %v", err)
	}
	if _, err := env.s.CheckAccessTicket(target.Token, check, env.now); !errors.Is(err, ErrAccessTicket) {
		t.Fatalf("切 space 后旧票应 ErrAccessTicket，got %v", err)
	}
	// 切回原 space（authRev 再次递增）：旧票仍不可复活。
	if _, err := env.registerClient(t, session, space.ID, cp, validOp(t), cpEp.Revision+2, notAfter); err != nil {
		t.Fatalf("切回原 space: %v", err)
	}
	if _, err := env.s.CheckAccessTicket(target.Token, check, env.now); !errors.Is(err, ErrAccessTicket) {
		t.Fatalf("切回后旧票仍应 ErrAccessTicket，got %v", err)
	}
	// 新 token 可取（新票成功）。
	ticket2, err := env.s.IssueUserTicket(session, space.ID, src(), env.now)
	if err != nil {
		t.Fatalf("新票应成功: %v", err)
	}
	if _, err := env.s.CheckAccessTicket(target.Token, access.CheckRequest{Token: ticket2.Token, Method: "PUT", Path: path, WriteEpoch: 1, SourcePeerID: cp.id}, env.now); err != nil {
		t.Fatalf("新票应可验: %v", err)
	}
}
