package meta

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"atoll/pkg/peerauth"

	bolt "go.etcd.io/bbolt"
)

// seedRetainedClientPeers 直接写入 count 条 retained tombstone（ValidUntil 已过、
// RetainUntil 未到）：占用 stored 容量，不计 active/目录，也不会被注册路径的过期清扫删除。
func (env *peerEnv) seedRetainedClientPeers(t *testing.T, count int, userID, spaceID uint64) {
	t.Helper()
	sessionHash := strings.Repeat("0", 64)
	session := make([]byte, 32)
	for i := range session {
		session[i] = 0x5a
	}
	past := env.now.Add(-time.Minute)
	retain := env.now.Add(30 * time.Minute)
	op := strings.Repeat("0", 32)
	err := env.s.db.Update(func(tx *bolt.Tx) error {
		for i := 0; i < count; i++ {
			ident := newPeerIdentity(t)
			record := clientPeerRecord{
				Endpoint: peerauth.Endpoint{Role: peerauth.RoleClient, PeerID: ident.id, PublicKey: ident.pub, Revision: 1, ValidUntil: past},
				UserID:   userID, SpaceID: spaceID, SessionHash: session,
				OperationID: op, RequestHash: sessionHash, RetainUntil: retain, AuthorizationRevision: 1,
			}
			raw, _ := json.Marshal(record)
			if err := tx.Bucket(bucketSecurity).Put(securityDataKey("client-peer", ident.id), raw); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seedRetainedClientPeers: %v", err)
	}
}

func readClientPeerRecord(t *testing.T, s *Store, peerID string) (clientPeerRecord, bool) {
	t.Helper()
	var rec clientPeerRecord
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := readSecurityData(tx, "client-peer", peerID, &rec); err != nil {
			if errors.Is(err, ErrNotExist) {
				return nil
			}
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		t.Fatalf("read client-peer %s: %v", peerID, err)
	}
	return rec, found
}

func peerSlotCountNow(t *testing.T, s *Store, now time.Time) int {
	t.Helper()
	n := 0
	if err := s.db.View(func(tx *bolt.Tx) error {
		count, err := peerSlotCountTx(tx, 0, "", now)
		n = count
		return err
	}); err != nil {
		t.Fatalf("peerSlotCountTx: %v", err)
	}
	return n
}

// mustDirectory 读取目录；读取失败即等价线上 503（满额/异常态下既有 directory 仍必须可读）。
func mustDirectory(t *testing.T, env *peerEnv, now time.Time) []peerauth.Endpoint {
	t.Helper()
	dir, err := env.s.PeerDirectory(now, time.Minute)
	if err != nil {
		t.Fatalf("PeerDirectory 读取失败: %v", err)
	}
	return dir.Endpoints
}

// ---- 全局配额：active client + 非撤销绑定设备 slot ≤ 512，未发布/离线设备保 slot ----

func TestPeerGlobalQuotaCountsBoundDeviceSlots(t *testing.T) {
	env := newPeerEnv(t)
	nodePeer := newPeerIdentity(t)
	dev := env.enrollDevice(t, filepath.Join(t.TempDir(), "dev.key"), "127.0.0.1:9443", &peerauth.Enrollment{PeerID: nodePeer.id, PublicKey: nodePeer.pub, ExpectedRevision: 0}, nodePeer.priv)
	// 绑定即占 slot，与是否已发布无关。
	if n := peerSlotCountNow(t, env.s, env.now); n != 1 {
		t.Fatalf("未发布绑定设备应占 1 slot，got %d", n)
	}
	if _, err := env.publishAddress(t, dev, nodePeer.id, nodePeer.priv, 1, 0, validOp(t), []string{"/ip4/1.2.3.4/tcp/9400"}, env.now.Add(90*time.Second)); err != nil {
		t.Fatalf("发布: %v", err)
	}
	if n := peerSlotCountNow(t, env.s, env.now); n != 1 {
		t.Fatalf("发布后仍应占 1 slot，got %d", n)
	}
	xUser, xSpace, _ := env.makeUser(t, "quotaseed")
	env.seedClientPeers(t, peerauth.MaxDirectoryPeers-1, xUser.ID, xSpace.ID)
	// 511 live + 1 设备 slot：目录恰满额且可读。
	if eps := mustDirectory(t, env, env.now); len(eps) != peerauth.MaxDirectoryPeers {
		t.Fatalf("满额目录应有 512 端点，got %d", len(eps))
	}
	_, freshSpace, freshSession := env.makeUser(t, "quotafresh")
	cp := newPeerIdentity(t)
	if _, err := env.registerClient(t, freshSession, freshSpace.ID, cp, validOp(t), 0, env.now.Add(time.Minute)); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("满额(511 client+1 设备 slot)注册应 ErrPeerConflict，got %v", err)
	}
	// 原子拒绝不留半状态：目录仍可读、仍恰 512。
	if eps := mustDirectory(t, env, env.now); len(eps) != peerauth.MaxDirectoryPeers {
		t.Fatalf("拒绝后目录应仍 512 端点，got %d", len(eps))
	}
	// 撤销设备释放 slot：同一 client 原样可注册，随后回到满额。
	if err := env.s.RevokeDevice(dev.NodeID); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	if _, err := env.registerClient(t, freshSession, freshSpace.ID, cp, validOp(t), 0, env.now.Add(time.Minute)); err != nil {
		t.Fatalf("释放 slot 后应可注册: %v", err)
	}
	if eps := mustDirectory(t, env, env.now); len(eps) != peerauth.MaxDirectoryPeers {
		t.Fatalf("补位后目录应 512 端点，got %d", len(eps))
	}
	extra := newPeerIdentity(t)
	if _, err := env.registerClient(t, freshSession, freshSpace.ID, extra, validOp(t), 0, env.now.Add(time.Minute)); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("再次满额应 ErrPeerConflict，got %v", err)
	}
}

func TestPeerNodeBindAtCapRejected(t *testing.T) {
	env := newPeerEnv(t)
	xUser, xSpace, _ := env.makeUser(t, "capseed")
	env.seedClientPeers(t, peerauth.MaxDirectoryPeers, xUser.ID, xSpace.ID)
	if eps := mustDirectory(t, env, env.now); len(eps) != peerauth.MaxDirectoryPeers {
		t.Fatalf("512 live client 目录应可读，got %d", len(eps))
	}
	// 满额时节点首次绑定 peer：同事务计入配额，必须拒。
	nodePeer := newPeerIdentity(t)
	if _, err := env.enrollDeviceErr(t, filepath.Join(t.TempDir(), "dev.key"), "127.0.0.1:9443", &peerauth.Enrollment{PeerID: nodePeer.id, PublicKey: nodePeer.pub, ExpectedRevision: 0}, nodePeer.priv); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("满额节点绑定应 ErrPeerConflict，got %v", err)
	}
	if eps := mustDirectory(t, env, env.now); len(eps) != peerauth.MaxDirectoryPeers {
		t.Fatalf("被拒绑定不得改变目录，got %d", len(eps))
	}
	// 无 peer 绑定的普通设备登录不占 slot，不受配额影响。
	env.enrollDevice(t, filepath.Join(t.TempDir(), "plain.key"), "127.0.0.1:9444", nil, nil)
	if n := peerSlotCountNow(t, env.s, env.now); n != peerauth.MaxDirectoryPeers {
		t.Fatalf("普通设备登录不得增加 slot，got %d", n)
	}
}

// ---- released tombstone：释放 active slot、保留 stored 记录、不进目录 ----

func TestPeerReleasedSlotFreedButTombstoneKept(t *testing.T) {
	env := newPeerEnv(t)
	nodePeer := newPeerIdentity(t)
	dev := env.enrollDevice(t, filepath.Join(t.TempDir(), "dev.key"), "127.0.0.1:9443", &peerauth.Enrollment{PeerID: nodePeer.id, PublicKey: nodePeer.pub, ExpectedRevision: 0}, nodePeer.priv)
	if _, err := env.publishAddress(t, dev, nodePeer.id, nodePeer.priv, 1, 0, validOp(t), []string{"/ip4/1.2.3.4/tcp/9400"}, env.now.Add(90*time.Second)); err != nil {
		t.Fatalf("发布: %v", err)
	}
	_, space, session := env.makeUser(t, "slotfree")
	seedUser, seedSpace, _ := env.makeUser(t, "slotseed")
	cp := newPeerIdentity(t)
	if _, err := env.registerClient(t, session, space.ID, cp, validOp(t), 0, env.now.Add(time.Minute)); err != nil {
		t.Fatalf("注册: %v", err)
	}
	env.seedClientPeers(t, peerauth.MaxDirectoryPeers-2, seedUser.ID, seedSpace.ID)
	// 510 seed + 1 client + 1 设备 slot = 512 满。
	extra := newPeerIdentity(t)
	if _, err := env.registerClient(t, session, space.ID, extra, validOp(t), 0, env.now.Add(time.Minute)); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("满额注册应拒，got %v", err)
	}
	rel, err := buildClientReleaseReq(env, session, space.ID, cp, validOp(t), 1, env.now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("release proof: %v", err)
	}
	if _, err := env.s.ReleaseClientPeer(session, space.ID, rel, env.now); err != nil {
		t.Fatalf("release: %v", err)
	}
	// released 只让出 active slot，stored 记录保留。
	if _, err := env.registerClient(t, session, space.ID, extra, validOp(t), 0, env.now.Add(time.Minute)); err != nil {
		t.Fatalf("release 后空位应可补: %v", err)
	}
	rec, ok := readClientPeerRecord(t, env.s, cp.id)
	if !ok || !rec.Released {
		t.Fatalf("released tombstone 应保留: found=%v released=%v", ok, rec.Released)
	}
	for _, ep := range mustDirectory(t, env, env.now) {
		if ep.PeerID == cp.id {
			t.Fatal("released tombstone 不应列入目录")
		}
	}
	// 补位后重新满额：510 seed + extra + 1 设备 slot = 512。
	again := newPeerIdentity(t)
	if _, err := env.registerClient(t, session, space.ID, again, validOp(t), 0, env.now.Add(time.Minute)); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("补位后满额应拒，got %v", err)
	}
}

func TestPeerReleasedDoesNotOccupyPerUserActive(t *testing.T) {
	env := newPeerEnv(t)
	_, space, session := env.makeUser(t, "peruser")
	notAfter := env.now.Add(time.Minute)
	ids := make([]peerIdentity, 0, 4)
	for i := 0; i < 4; i++ {
		id := newPeerIdentity(t)
		if _, err := env.registerClient(t, session, space.ID, id, validOp(t), 0, notAfter); err != nil {
			t.Fatalf("第 %d 个 client: %v", i+1, err)
		}
		ids = append(ids, id)
	}
	fifth := newPeerIdentity(t)
	if _, err := env.registerClient(t, session, space.ID, fifth, validOp(t), 0, notAfter); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("第 5 个 active 应拒，got %v", err)
	}
	rel, err := buildClientReleaseReq(env, session, space.ID, ids[0], validOp(t), 1, env.now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("release proof: %v", err)
	}
	if _, err := env.s.ReleaseClientPeer(session, space.ID, rel, env.now); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := env.registerClient(t, session, space.ID, fifth, validOp(t), 0, notAfter); err != nil {
		t.Fatalf("release 后应可注册第 4 个 active: %v", err)
	}
	if rec, ok := readClientPeerRecord(t, env.s, ids[0].id); !ok || !rec.Released {
		t.Fatalf("released tombstone 应保留: found=%v released=%v", ok, rec.Released)
	}
	sixth := newPeerIdentity(t)
	if _, err := env.registerClient(t, session, space.ID, sixth, validOp(t), 0, notAfter); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("再次满 4 active 应拒，got %v", err)
	}
}

// ---- stored 上限：retained tombstone 满 4095 后 fail-closed，但不破坏既有记录 ----

func TestPeerStoredTombstoneCapFailClosed(t *testing.T) {
	env := newPeerEnv(t)
	tUser, tSpace, _ := env.makeUser(t, "tombs")
	env.seedRetainedClientPeers(t, peerStateScanLimit-2, tUser.ID, tSpace.ID)
	_, uSpace, uSession := env.makeUser(t, "capregister")
	cp1 := newPeerIdentity(t)
	if _, err := env.registerClient(t, uSession, uSpace.ID, cp1, validOp(t), 0, env.now.Add(time.Minute)); err != nil {
		t.Fatalf("stored=4094 应可注册: %v", err)
	}
	cp2 := newPeerIdentity(t)
	if _, err := env.registerClient(t, uSession, uSpace.ID, cp2, validOp(t), 0, env.now.Add(time.Minute)); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("stored=4095 应 fail-closed 拒绝，got %v", err)
	}
	// 拒绝不影响既有记录：目录可读、allowed 保持。
	eps := mustDirectory(t, env, env.now)
	if len(eps) != 1 || eps[0].PeerID != cp1.id {
		t.Fatalf("目录应只剩 cp1 可读，got %d 端点", len(eps))
	}
	if ok, err := env.s.PeerAllowed(cp1.id, env.now, time.Minute); err != nil || !ok {
		t.Fatalf("既有 client 应仍被允许: %v %v", ok, err)
	}
}

// ---- 配置组合：peerconfig/marker/writeconfig 缺一必须 fail-closed，而非静默当作未启用 ----

func TestPeerDirectoryConfigComboFailClosed(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(tx *bolt.Tx) error
		wantEnabled bool
		wantErr     error
	}{
		{"missing-peerconfig-with-marker-and-v4", func(tx *bolt.Tx) error {
			return tx.Bucket(bucketSecurity).Delete(keyPeerConfig)
		}, false, ErrPeerConflict},
		// marker 在而 writeconfig 丢：初始化中间态必须拒，不得当作可重新初始化。
		{"missing-peerconfig-and-writeconfig-with-marker", func(tx *bolt.Tx) error {
			if err := tx.Bucket(bucketSecurity).Delete(keyPeerConfig); err != nil {
				return err
			}
			return tx.Bucket(bucketWrites).Delete(keyWriteConfig)
		}, false, ErrPeerConflict},
		{"missing-peerconfig-and-marker-with-v4", func(tx *bolt.Tx) error {
			if err := tx.Bucket(bucketSecurity).Delete(keyPeerConfig); err != nil {
				return err
			}
			return tx.Bucket(bucketMeta).Delete(keyPeerInitialized)
		}, false, ErrPeerConflict},
		{"missing-all", func(tx *bolt.Tx) error {
			if err := tx.Bucket(bucketSecurity).Delete(keyPeerConfig); err != nil {
				return err
			}
			if err := tx.Bucket(bucketMeta).Delete(keyPeerInitialized); err != nil {
				return err
			}
			return tx.Bucket(bucketWrites).Delete(keyWriteConfig)
		}, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newPeerEnv(t)
			if enabled, err := env.s.PeerDirectoryEnabled(); err != nil || !enabled {
				t.Fatalf("基线应启用，got (%v,%v)", enabled, err)
			}
			if err := env.s.db.Update(tc.mutate); err != nil {
				t.Fatal(err)
			}
			enabled, err := env.s.PeerDirectoryEnabled()
			if enabled != tc.wantEnabled || !errors.Is(err, tc.wantErr) {
				t.Fatalf("PeerDirectoryEnabled 应 (%v,%v)，got (%v,%v)", tc.wantEnabled, tc.wantErr, enabled, err)
			}
			if _, err := env.s.PeerDirectory(env.now, time.Minute); !errors.Is(err, ErrPeerConflict) {
				t.Fatalf("PeerDirectory 对残缺配置应 ErrPeerConflict，got %v", err)
			}
		})
	}
}

// ---- Configure 幂等：不新增 WAL 帧，但 EnsureDurable 钩子必须仍执行 ----

func TestPeerConfigureIdempotentWALAndDurabilityHook(t *testing.T) {
	env := newPeerEnv(t)
	var hookSeqs []uint64
	env.s.SetPostCommitHook(func(seq uint64, _ []byte) error {
		hookSeqs = append(hookSeqs, seq)
		return nil
	})
	defer env.s.SetPostCommitHook(nil)
	before := mustWALSeq(t, env.s)
	hooksBefore := len(hookSeqs)
	if err := env.s.ConfigurePeerDirectory(env.origin, env.infra); err != nil {
		t.Fatalf("幂等 Configure: %v", err)
	}
	if after := mustWALSeq(t, env.s); after != before {
		t.Fatalf("幂等 Configure 不应新增 WAL 帧: before=%d after=%d", before, after)
	}
	if len(hookSeqs) != hooksBefore+1 {
		t.Fatalf("幂等 Configure 仍须执行一次 EnsureDurable 钩子，hook 调用 %d→%d", hooksBefore, len(hookSeqs))
	}
	// 地址变化（同身份）：非幂等，新帧落 WAL。
	changed := env.infra
	changed.Addresses = []string{"/ip4/8.8.4.4/tcp/9400"}
	if err := env.s.ConfigurePeerDirectory(env.origin, changed); err != nil {
		t.Fatalf("地址变更 Configure: %v", err)
	}
	if after := mustWALSeq(t, env.s); after != before+1 {
		t.Fatalf("地址变更应恰好新增一帧: before=%d after=%d", before, after)
	}
	if inf, err := env.s.PeerInfrastructure(); err != nil || !samePeerAddresses(inf.Addresses, changed.Addresses) {
		t.Fatalf("变更后基础设施地址未生效: %+v %v", inf, err)
	}
	// 换身份（peer id/公钥）→ 拒，目录配置不被篡改。
	other := newPeerIdentity(t)
	if err := env.s.ConfigurePeerDirectory(env.origin, peerauth.Infrastructure{PeerID: other.id, PublicKey: other.pub, Addresses: changed.Addresses, Relay: true}); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("换身份 Configure 应 ErrPeerConflict，got %v", err)
	}
	if inf, _ := env.s.PeerInfrastructure(); inf.PeerID != env.infra.PeerID {
		t.Fatalf("被拒 Configure 不得改变身份: %s", inf.PeerID)
	}
}
