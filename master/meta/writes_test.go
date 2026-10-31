package meta

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

func writeTestStore(t *testing.T) (*Store, []uint64) {
	t.Helper()
	s := newTestStore(t)
	if err := s.EnableWritePlanning(); err != nil {
		t.Fatal(err)
	}
	var nodes []uint64
	for i := 0; i < 3; i++ {
		n, err := s.RegisterNode(fmt.Sprintf("127.0.0.1:%d", 59000+i), 1024)
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, n.ID)
	}
	return s, nodes
}
func beginWriteTest(t *testing.T, s *Store, parent uint64, name string, size int64, overwrite bool) types.WriteUpload {
	t.Helper()
	u, err := s.BeginPlannedWrite(WriteActor{}, parent, name, types.BeginWriteRequest{Path: "/" + name, Size: size, Overwrite: overwrite, OpID: "begin-" + name + fmt.Sprint(time.Now().UnixNano())}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return u
}
func writeChoice(u types.WriteUpload, index int, data []byte, nodes, confirm []uint64) (types.PlanWriteChunkRequest, types.WriteChunkPlan) {
	req := types.PlanWriteChunkRequest{WriteBinding: writeBinding(u), Index: index, LogicalSize: int64(len(data)), StoredSize: int64(len(data)), Encoding: types.PlainEncoding, Checksum: types.CRC32C(data)}
	p := types.WriteChunkPlan{Index: index, Object: types.ContentObject{ID: types.ChunkID(u.ID, index), Version: 1, LogicalSize: int64(len(data)), StoredSize: int64(len(data)), Encoding: types.PlainEncoding, Checksum: req.Checksum, ChecksumKnown: true}, Layout: types.ReplicaLayout{ObjectID: types.ChunkID(u.ID, index), Epoch: 1, Scheme: "replicate", Nodes: append([]uint64(nil), nodes...)}, Confirmations: append([]uint64(nil), confirm...), RequiredConfirmations: len(confirm)}
	return req, p
}
func reserveWriteTest(t *testing.T, s *Store, u types.WriteUpload, data []byte, nodes, confirm []uint64) types.WriteChunkPlan {
	t.Helper()
	req, p := writeChoice(u, 0, data, nodes, confirm)
	snap, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := s.ReserveWriteChunk(WriteActor{}, req, p, snap.ProfileRevision, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return got
}
func confirmWriteTest(t *testing.T, s *Store, id uint64, nodes ...uint64) {
	t.Helper()
	for _, node := range nodes {
		d, err := s.ObjectIntegrity(id)
		if err != nil {
			t.Fatal(err)
		}
		ok, err := s.MarkVerifiedObjectDone(d, node)
		if err != nil || !ok {
			t.Fatalf("confirm node %d: %v %v", node, ok, err)
		}
	}
}
func commitWriteTest(u types.WriteUpload, size int64, count int) types.CommitWriteRequest {
	return types.CommitWriteRequest{WriteBinding: writeBinding(u), OpID: fmt.Sprintf("commit-%d", u.ID), Size: size, ChunkCount: count}
}

func TestPlannedWriteAtomicConfirmationAndCAS(t *testing.T) {
	s, nodes := writeTestStore(t)
	data := []byte{0xab, 0x9b, 0xe0, 0x9b}
	if types.CRC32C(data) != 0 {
		t.Fatal("zero CRC fixture")
	}
	u := beginWriteTest(t, s, RootID, "file", 4, false)
	p := reserveWriteTest(t, s, u, data, nodes, nodes[:2])
	req := commitWriteTest(u, 4, 1)
	if _, err := s.ResolvePath("/file"); !errors.Is(err, ErrNotExist) {
		t.Fatal("pending file visible")
	}
	confirmWriteTest(t, s, p.Object.ID, nodes[0], nodes[2])
	if _, _, _, err := s.CommitPlannedWrite(WriteActor{}, req, time.Hour, time.Now()); !errors.Is(err, ErrWriteNotReady) {
		t.Fatalf("nonrequired confirmation substituted: %v", err)
	}
	confirmWriteTest(t, s, p.Object.ID, nodes[1])
	first, _, _, err := s.CommitPlannedWrite(WriteActor{}, req, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if first.Content == nil || first.Content.ID != u.ID || first.Generation != 1 || first.Content.Extents[0].Object.Checksum != 0 || !first.Content.Extents[0].Object.ChecksumKnown {
		t.Fatalf("content %+v", first)
	}
	replay, _, replaced, err := s.CommitPlannedWrite(WriteActor{}, req, time.Hour, time.Now())
	firstJSON, _ := json.Marshal(first)
	replayJSON, _ := json.Marshal(replay)
	if err != nil || replaced || string(firstJSON) != string(replayJSON) {
		t.Fatalf("replay: %+v %v", replay, err)
	}
	wrong := req
	wrong.Size++
	if _, _, _, err = s.CommitPlannedWrite(WriteActor{}, wrong, time.Hour, time.Now()); !errors.Is(err, ErrOpConflict) {
		t.Fatalf("different replay accepted: %v", err)
	}
	a := beginWriteTest(t, s, RootID, "file", 0, true)
	b := beginWriteTest(t, s, RootID, "file", 0, true)
	second, old, replaced, err := s.CommitPlannedWrite(WriteActor{}, commitWriteTest(a, 0, 0), time.Hour, time.Now())
	if err != nil || !replaced || old.ID != first.ID || second.ID != first.ID || second.Generation != 2 || second.Content.ID == first.Content.ID {
		t.Fatalf("overwrite %+v %v", second, err)
	}
	if _, _, _, err = s.CommitPlannedWrite(WriteActor{}, commitWriteTest(b, 0, 0), time.Hour, time.Now()); !errors.Is(err, ErrObjectChanged) {
		t.Fatalf("target CAS ignored: %v", err)
	}
}

func TestPlannedWriteCapacityConcurrentAndAbort(t *testing.T) {
	s, nodes := writeTestStore(t)
	if err := s.Heartbeat(nodes[0], 800); err != nil {
		t.Fatal(err)
	}
	a := beginWriteTest(t, s, RootID, "a", 150, false)
	b := beginWriteTest(t, s, RootID, "b", 150, false)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, u := range []types.WriteUpload{a, b} {
		wg.Add(1)
		go func(u types.WriteUpload) {
			defer wg.Done()
			req, p := writeChoice(u, 0, make([]byte, 150), nodes[:1], nodes[:1])
			_, _, err := s.ReserveWriteChunk(WriteActor{}, req, p, 0, time.Hour, time.Now())
			results <- err
		}(u)
	}
	wg.Wait()
	close(results)
	success, rejected := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrWriteBudget) {
			rejected++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || rejected != 1 {
		t.Fatalf("capacity oversold: success=%d rejected=%d", success, rejected)
	}
	before, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []types.WriteUpload{a, b} {
		if err = s.AbortPlannedWrite(WriteActor{}, writeBinding(u), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	after, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before.Capacity, after.Capacity) {
		t.Fatal("abort released uncertain bytes")
	}
	if after.Capacity[0].Reserved != 150 || after.Capacity[0].Free != 74 {
		t.Fatalf("accounting %+v", after.Capacity[0])
	}
}

func TestPlannedWriteReplayDurabilityAndRecovery(t *testing.T) {
	s, nodes := writeTestStore(t)
	u := beginWriteTest(t, s, RootID, "recover", 3, false)
	req, p := writeChoice(u, 0, []byte("abc"), nodes[:1], nodes[:1])
	if _, _, err := s.ReserveWriteChunk(WriteActor{}, req, p, 0, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	confirmWriteTest(t, s, p.Object.ID, nodes[0])
	commit := commitWriteTest(u, 3, 1)
	failure := errors.New("synchronous WAL prefix unavailable")
	s.SetPostCommitHook(func(uint64, []byte) error { return failure })
	if _, _, _, err := s.CommitPlannedWrite(WriteActor{}, commit, time.Hour, time.Now()); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if _, _, _, err := s.CommitPlannedWrite(WriteActor{}, commit, time.Hour, time.Now()); !errors.Is(err, failure) {
		t.Fatalf("replay bypassed durability: %v", err)
	}
	s.SetPostCommitHook(nil)
	frames, err := s.FramesSince(0)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Open(filepath.Join(t.TempDir(), "restored.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err = restored.ApplyFrames(frames); err != nil {
		t.Fatal(err)
	}
	out, _, _, err := restored.CommitPlannedWrite(WriteActor{}, commit, time.Hour, time.Now())
	if err != nil || out.Content == nil || out.Size != 3 {
		t.Fatalf("WAL replay: %+v %v", out, err)
	}
	if enabled, err := restored.WritePlanningEnabled(); err != nil || !enabled {
		t.Fatalf("configuration lost: %v %v", enabled, err)
	}
}

func TestPlannedWriteFrozenPolicyAndLegacyGuard(t *testing.T) {
	s, nodes := writeTestStore(t)
	dir, err := s.CreateDir(RootID, "dir")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SetProtection(WriteActor{}, RootID, types.ProtectionSecurity, time.Now()); err != nil {
		t.Fatal(err)
	}
	u := beginWriteTest(t, s, dir.ID, "policy", 4, false)
	if u.Policy.Tier != types.ProtectionSecurity || u.Policy.SourceInodeID != RootID {
		t.Fatalf("inherit: %+v", u.Policy)
	}
	if _, err = s.SetProtection(WriteActor{}, dir.ID, types.ProtectionPerformance, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetPlannedWrite(WriteActor{}, writeBinding(u), time.Now())
	if err != nil || got.Policy != u.Policy {
		t.Fatal("inflight policy changed")
	}
	req, p := writeChoice(u, 0, []byte("test"), nodes[:2], nodes[:2])
	if _, _, err = s.ReserveWriteChunk(WriteActor{}, req, p, 0, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"assign":    func() error { _, e := s.AssignChunk(u.ID, 0, 4, nodes[:1], req.Checksum, true); return e },
		"reassign":  func() error { _, e := s.ReassignChunk(u.ID, 0, nodes[:1], req.Checksum, true); return e },
		"commit":    func() error { _, _, _, e := s.CommitStagingFile(u.ID, "policy", 4); return e },
		"abort":     func() error { return s.AbortStaging(u.ID) },
		"weak-done": func() error { return s.MarkChunkDone(p.Object.ID, nodes[0]) },
		"replace":   func() error { return s.ReplaceChunkReplica(u.ID, 0, nodes[0], nodes[2]) },
	} {
		t.Run(name, func(t *testing.T) {
			if e := call(); !errors.Is(e, ErrWritePlanRequired) {
				t.Fatalf("legacy bypass: %v", e)
			}
		})
	}
	changed := p
	changed.Confirmations = changed.Confirmations[:1]
	changed.RequiredConfirmations = 1
	if _, _, err = s.ReserveWriteChunk(WriteActor{}, req, changed, 0, time.Hour, time.Now()); !errors.Is(err, ErrWritePlanConflict) {
		t.Fatalf("confirmation changed: %v", err)
	}
	if _, err = s.SetProtection(WriteActor{}, dir.ID, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	policy, err := s.GetProtection(WriteActor{}, dir.ID)
	if err != nil || policy.Override != "" || policy.Policy.Tier != types.ProtectionSecurity {
		t.Fatalf("clear override: %+v %v", policy, err)
	}
}

func TestPlannedWriteConfigFailClosed(t *testing.T) {
	for _, mode := range []string{"missing", "null", "empty", "marker", "bad-version"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := writeTestStore(t)
			if err := s.db.Update(func(tx *bolt.Tx) error {
				switch mode {
				case "missing":
					return tx.Bucket(bucketWrites).Delete(keyWriteConfig)
				case "null":
					return tx.Bucket(bucketWrites).Put(keyWriteConfig, []byte("null"))
				case "empty":
					return tx.Bucket(bucketWrites).Put(keyWriteConfig, []byte("{}"))
				case "marker":
					return tx.Bucket(bucketMeta).Delete(keyWriteInitialized)
				default:
					return tx.Bucket(bucketWrites).Put(keyWriteConfig, []byte(`{"version":5,"enabled_at":"2026-10-17T00:00:00Z"}`))
				}
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.WritePlanningEnabled(); err == nil {
				t.Fatal("damaged config downgraded")
			}
			if err := s.EnableWritePlanning(); err == nil {
				t.Fatal("damaged config silently reinitialized")
			}
		})
	}
}

func TestPlannedWriteSecureACLAndTickets(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	admin, adminSpace := bootstrapAdmin(t, s)
	bob, bobSpace := inviteAndRegister(t, s, admin.ID, "plannedbob", time.Now())
	if err := s.EnableWritePlanning(); err != nil {
		t.Fatal(err)
	}
	dev := auditLoginDevice(t, s, "127.0.0.1:59444", "")
	actor := WriteActor{UserID: bob.ID, SpaceID: bobSpace.ID}
	if _, err := s.SetProtection(WriteActor{UserID: admin.ID, SpaceID: adminSpace.ID}, adminSpace.RootID, types.ProtectionSecurity, time.Now()); err != nil {
		t.Fatal(err)
	}
	u, err := s.BeginPlannedWrite(actor, bobSpace.RootID, "file", types.BeginWriteRequest{Path: "/file", OpID: "begin", Size: 3}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if u.Policy.Tier != types.ProtectionNormal {
		t.Fatal("policy leaked across spaces")
	}
	req, p := writeChoice(u, 0, []byte("abc"), []uint64{dev.NodeID}, []uint64{dev.NodeID})
	if _, _, err = s.ReserveWriteChunk(actor, req, p, 0, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	login, err := s.AuthenticateUser("plannedbob", "invited-password-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ticketReq := access.TicketRequest{NodeAddr: "127.0.0.1:59444", Method: "PUT", Path: fmt.Sprintf("/objects/%d", p.Object.ID)}
	if _, err = s.IssueUserTicket(login.Token, bobSpace.ID, ticketReq, time.Now()); err != nil {
		t.Fatalf("planned PUT ticket denied: %v", err)
	}
	if _, _, _, err = s.CommitPlannedWrite(WriteActor{UserID: admin.ID, SpaceID: bobSpace.ID}, commitWriteTest(u, 3, 1), time.Hour, time.Now()); !errors.Is(err, ErrAuthentication) {
		t.Fatal("actor binding ignored")
	}
	confirmWriteTest(t, s, p.Object.ID, dev.NodeID)
	if err = s.DisableUser(admin.ID, bob.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = s.CommitPlannedWrite(actor, commitWriteTest(u, 3, 1), time.Hour, time.Now()); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("disabled writer published: %v", err)
	}
	if _, err = s.IssueUserTicket(login.Token, bobSpace.ID, ticketReq, time.Now()); err == nil {
		t.Fatal("disabled user still gets write ticket")
	}
}

func TestPlannedWriteSuspectDeadAndExpired(t *testing.T) {
	for _, mode := range []string{"suspect", "dead", "expired"} {
		t.Run(mode, func(t *testing.T) {
			s, nodes := writeTestStore(t)
			u := beginWriteTest(t, s, RootID, "blocked", 3, false)
			p := reserveWriteTest(t, s, u, []byte("abc"), nodes[:2], nodes[:2])
			confirmWriteTest(t, s, p.Object.ID, nodes[:2]...)
			now := time.Now()
			switch mode {
			case "suspect":
				d, _ := s.ObjectIntegrity(p.Object.ID)
				if _, err := s.MarkPhysicalObjectSuspect(d, nodes[1]); err != nil {
					t.Fatal(err)
				}
			case "dead":
				if err := s.SetNodeHeartbeatAt(nodes[1], now.Add(-2*time.Hour)); err != nil {
					t.Fatal(err)
				}
			case "expired":
				now = u.ExpiresAt
			}
			_, _, _, err := s.CommitPlannedWrite(WriteActor{}, commitWriteTest(u, 3, 1), time.Hour, now)
			if err == nil {
				t.Fatal("invalid confirmation accepted")
			}
			if mode == "expired" && !errors.Is(err, ErrWriteExpired) {
				t.Fatal(err)
			}
		})
	}
}
