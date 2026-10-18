package meta

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"atoll/pkg/types"
)

func integrityChunk(t *testing.T, s *Store, name string) (types.Inode, types.ObjectIntegrity) {
	t.Helper()
	st, err := s.CreateStagingFile(RootID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AssignChunk(st.ID, 0, 4, []uint64{7, 8}, types.CRC32C([]byte("data"))); err != nil {
		t.Fatal(err)
	}
	d, err := s.ObjectIntegrity(types.ChunkID(st.ID, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range d.Replicas {
		if ok, err := s.MarkVerifiedObjectDone(d, id); !ok || err != nil {
			t.Fatalf("initial confirmation: %v %v", ok, err)
		}
	}
	in, _, _, err := s.CommitStagingFile(st.ID, name, 4)
	if err != nil {
		t.Fatal(err)
	}
	d, err = s.ObjectIntegrity(d.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	return in, d
}

func TestSuspectCannotBeRevivedByOldOrLateReceipt(t *testing.T) {
	s := newTestStore(t)
	in, before := integrityChunk(t, s, "file")
	if ok, err := s.MarkChunkSuspect(in.ID, in.Generation, 0, before.ObjectID, 7, before.Size, before.Checksum); !ok || err != nil {
		t.Fatalf("suspect: %v %v", ok, err)
	}
	if err := s.MarkChunkDone(before.ObjectID, 7); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkChunkDoneAt(in.ID, 0, 7); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.MarkVerifiedObjectDone(before, 7); ok || err != nil {
		t.Fatalf("late receipt restored suspect: %v %v", ok, err)
	}
	after, err := s.ObjectIntegrity(before.ObjectID)
	if err != nil || types.ContainsUint64(after.Done, 7) || !types.ContainsUint64(after.Suspect, 7) || after.IntegrityEpoch == before.IntegrityEpoch {
		t.Fatalf("invalid suspect state: %+v %v", after, err)
	}
	if ok, err := s.MarkVerifiedObjectDone(after, 7); !ok || err != nil {
		t.Fatalf("fresh verified repair: %v %v", ok, err)
	}
	after, _ = s.ObjectIntegrity(before.ObjectID)
	if !types.ContainsUint64(after.Done, 7) || types.ContainsUint64(after.Suspect, 7) {
		t.Fatalf("repair did not restore healthy state: %+v", after)
	}
}

func TestSuspectChunkIdentityCAS(t *testing.T) {
	s := newTestStore(t)
	in, d := integrityChunk(t, s, "file")
	for _, mutate := range []func(*types.ObjectIntegrity){
		func(d *types.ObjectIntegrity) { d.InodeID++ },
		func(d *types.ObjectIntegrity) { d.Generation++ },
		func(d *types.ObjectIntegrity) { d.ChunkIndex++ },
		func(d *types.ObjectIntegrity) { d.ObjectID++ },
		func(d *types.ObjectIntegrity) { d.Size++ },
		func(d *types.ObjectIntegrity) { d.Checksum++ },
	} {
		wrong := d
		mutate(&wrong)
		if ok, err := s.MarkChunkSuspect(wrong.InodeID, wrong.Generation, wrong.ChunkIndex, wrong.ObjectID, 7, wrong.Size, wrong.Checksum); ok || err != nil {
			t.Fatalf("mismatched report changed metadata: %+v %v %v", wrong, ok, err)
		}
	}
	if ok, err := s.MarkChunkSuspect(in.ID, in.Generation, 0, d.ObjectID, 99, d.Size, d.Checksum); ok || err != nil {
		t.Fatalf("non-member report: %v %v", ok, err)
	}
	after, _ := s.ObjectIntegrity(d.ObjectID)
	if len(after.Done) != 2 || len(after.Suspect) != 0 {
		t.Fatalf("healthy state changed: %+v", after)
	}
}

func TestVerifiedReceiptBindsContentAndAssignment(t *testing.T) {
	s := newTestStore(t)
	_, d := integrityChunk(t, s, "file")
	for _, mutate := range []func(*types.ObjectIntegrity){
		func(d *types.ObjectIntegrity) { d.InodeID++ },
		func(d *types.ObjectIntegrity) { d.Generation++ },
		func(d *types.ObjectIntegrity) { d.Size++ },
		func(d *types.ObjectIntegrity) { d.Checksum++ },
		func(d *types.ObjectIntegrity) { d.ChecksumKnown = false },
		func(d *types.ObjectIntegrity) { d.ChunkIndex++ },
		func(d *types.ObjectIntegrity) { d.IntegrityEpoch++ },
	} {
		wrong := d
		mutate(&wrong)
		if ok, err := s.MarkVerifiedObjectDone(wrong, 7); ok || err != nil {
			t.Fatalf("invalid verified receipt: %+v %v %v", wrong, ok, err)
		}
	}
	if ok, err := s.MarkVerifiedObjectDone(d, 99); ok || err != nil {
		t.Fatalf("non-member verified receipt: %v %v", ok, err)
	}
}

func TestAdoptedChunkLookupAndStaleRepair(t *testing.T) {
	s := newTestStore(t)
	old, oldDesc := integrityChunk(t, s, "file")
	current, currentDesc := integrityChunk(t, s, "file")
	if old.ID != current.ID || current.Generation != old.Generation+1 || currentDesc.InodeID != current.ID || currentDesc.ObjectID == oldDesc.ObjectID {
		t.Fatalf("bad adopted descriptor: %+v %+v", current, currentDesc)
	}
	if _, err := s.ObjectIntegrity(oldDesc.ObjectID); !errors.Is(err, ErrNotExist) {
		t.Fatalf("retired chunk described as live: %v", err)
	}
	if err := s.ReplaceChunkReplicaIfCurrent(oldDesc, 7, 9); !errors.Is(err, ErrObjectChanged) {
		t.Fatalf("old repair modified current layout: %v", err)
	}
	if ok, err := s.MarkVerifiedObjectDone(oldDesc, 7); ok || err != nil {
		t.Fatalf("old receipt accepted: %v %v", ok, err)
	}
	if err := s.ReplaceChunkReplicaIfCurrent(currentDesc, 8, 9); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.MarkVerifiedObjectDone(currentDesc, 8); ok || err != nil {
		t.Fatalf("reassigned replica resurrected: %v %v", ok, err)
	}
}

func TestPendingAndLiveObjectSuspectEpoch(t *testing.T) {
	s := newTestStore(t)
	obj, _, err := s.PrepareSmallFile(SmallFileTarget{ParentID: RootID, Name: "file", Size: 4,
		Checksum: types.CRC32C([]byte("data")), Replicas: []uint64{7, 8}, PrimaryID: 7, Mtime: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := s.ObjectIntegrity(obj.ID)
	if ok, err := s.MarkPhysicalObjectSuspect(before, 7); !ok || err != nil {
		t.Fatalf("pending suspect: %v %v", ok, err)
	}
	if _, _, _, _, err := s.CommitSmallFile(obj.ID); !errors.Is(err, ErrCommitFailed) {
		t.Fatalf("suspect primary published: %v", err)
	}
	if err := s.MarkObjectDone(obj.ID, 7); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.MarkVerifiedObjectDone(before, 7); ok {
		t.Fatal("pending old receipt restored suspect")
	}
	fresh, _ := s.ObjectIntegrity(obj.ID)
	if ok, err := s.MarkVerifiedObjectDone(fresh, 7); !ok || err != nil {
		t.Fatalf("pending repair: %v %v", ok, err)
	}
	in, _, _, _, err := s.CommitSmallFile(obj.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.MarkVerifiedObjectDone(fresh, 8); !ok || err != nil {
		t.Fatalf("pending-to-live receipt lost: %v %v", ok, err)
	}
	if ok, err := s.MarkLegacyReplicaSuspect(in.ID, 8, in.Generation, in.Size, in.Checksum); !ok || err != nil {
		t.Fatalf("live suspect: %v %v", ok, err)
	}
	s.MarkObjectDone(obj.ID, 8)
	s.AddReplicaDone(in.ID, 8)
	after, _ := s.ObjectIntegrity(obj.ID)
	if types.ContainsUint64(after.Done, 8) || !types.ContainsUint64(after.Suspect, 8) {
		t.Fatalf("live object revived by unverified confirmation: %+v", after)
	}
}

func TestUnknownChecksumCannotClearSuspect(t *testing.T) {
	s := newTestStore(t)
	st, _ := s.CreateStagingFile(RootID)
	c, err := s.AssignChunk(st.ID, 0, 4, []uint64{7}, 0)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := s.ObjectIntegrity(c.ID)
	if d.ChecksumKnown {
		t.Fatal("old checksum became known")
	}
	if ok, err := s.MarkObjectPresent(d, 7); !ok || err != nil {
		t.Fatalf("legacy presence: %v %v", ok, err)
	}
	s.MarkChunkSuspect(st.ID, st.Generation, 0, c.ID, 7, c.Size, 0)
	fresh, _ := s.ObjectIntegrity(c.ID)
	if ok, _ := s.MarkObjectPresent(fresh, 7); ok {
		t.Fatal("presence cleared suspect")
	}
	if ok, _ := s.MarkVerifiedObjectDone(fresh, 7); ok {
		t.Fatal("unknown checksum treated as verified")
	}
}

func TestLegacySuspectSurvivesSameContentCommit(t *testing.T) {
	s := newTestStore(t)
	in, err := s.CreateFile(RootID, "legacy", []uint64{7, 8})
	if err != nil {
		t.Fatal(err)
	}
	crc := types.CRC32C([]byte("data"))
	if err := s.UpdateFileSize(in.ID, 4, crc); err != nil {
		t.Fatal(err)
	}
	d, _ := s.ObjectIntegrity(in.ID)
	if ok, err := s.MarkLegacyReplicaSuspect(in.ID, 7, d.Generation, 4, crc); !ok || err != nil {
		t.Fatalf("legacy suspect: %v %v", ok, err)
	}
	if err := s.UpdateFileSize(in.ID, 4, crc); err != nil {
		t.Fatal(err)
	}
	after, _ := s.ObjectIntegrity(in.ID)
	if types.ContainsUint64(after.Done, 7) || !types.ContainsUint64(after.Suspect, 7) {
		t.Fatalf("same-content commit revived suspect: %+v", after)
	}
	if err := s.UpdateFileSize(in.ID, 5, 123); err != nil {
		t.Fatal(err)
	}
	changed, _ := s.ObjectIntegrity(in.ID)
	if changed.Generation != after.Generation+1 || len(changed.Suspect) != 0 {
		t.Fatalf("new legacy content inherited old suspicion: %+v", changed)
	}
	if ok, _ := s.MarkVerifiedObjectDone(after, 7); ok {
		t.Fatal("old content receipt accepted")
	}
}

func TestIntegrityStateSurvivesSnapshot(t *testing.T) {
	s := newTestStore(t)
	in, d := integrityChunk(t, s, "snapshot")
	if ok, err := s.MarkChunkSuspect(in.ID, in.Generation, 0, d.ObjectID, 7, d.Size, d.Checksum); !ok || err != nil {
		t.Fatalf("mark before snapshot: %v %v", ok, err)
	}
	var snapshot bytes.Buffer
	if _, err := s.Snapshot(&snapshot); err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreFromReader(filepath.Join(t.TempDir(), "restored.db"), bytes.NewReader(snapshot.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	got, err := restored.ObjectIntegrity(d.ObjectID)
	if err != nil || !got.ChecksumKnown || got.IntegrityEpoch != d.IntegrityEpoch+1 ||
		!types.ContainsUint64(got.Suspect, 7) || types.ContainsUint64(got.Done, 7) {
		t.Fatalf("integrity state lost in restore: %+v %v", got, err)
	}
	if ok, err := restored.MarkVerifiedObjectDone(d, 7); ok || err != nil {
		t.Fatalf("restored store accepted pre-suspicion receipt: %v %v", ok, err)
	}
}

func TestReceiptReplayCannotBypassDurability(t *testing.T) {
	for _, known := range []bool{false, true} {
		t.Run(map[bool]string{false: "present", true: "verified"}[known], func(t *testing.T) {
			s := newTestStore(t)
			st, _ := s.CreateStagingFile(RootID)
			ch, err := s.AssignChunk(st.ID, 0, 4, []uint64{7}, 0, known)
			if err != nil {
				t.Fatal(err)
			}
			d, _ := s.ObjectIntegrity(ch.ID)
			s.SetPostCommitHook(func(uint64, []byte) error { return errors.New("backup unavailable") })
			defer s.SetPostCommitHook(nil)
			receipt := s.MarkObjectPresent
			if known {
				receipt = s.MarkVerifiedObjectDone
			}
			if _, err := receipt(d, 7); err == nil {
				t.Fatal("first receipt acknowledged despite failed durability confirmation")
			}
			if _, err := receipt(d, 7); err == nil {
				t.Fatal("replayed receipt bypassed failed durability confirmation")
			}
			s.SetPostCommitHook(nil)
			if ok, err := receipt(d, 7); !ok || err != nil {
				t.Fatalf("receipt after confirmation restored: %v %v", ok, err)
			}
		})
	}
}

func TestExplicitZeroChecksumIsKnown(t *testing.T) {
	s := newTestStore(t)
	st, _ := s.CreateStagingFile(RootID)
	c, err := s.AssignChunk(st.ID, 0, 4, []uint64{7}, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := s.ObjectIntegrity(c.ID)
	if !d.ChecksumKnown || d.Checksum != 0 {
		t.Fatalf("zero checksum lost: %+v", d)
	}
	if ok, err := s.MarkVerifiedObjectDone(d, 7); !ok || err != nil {
		t.Fatalf("explicit zero receipt: %v %v", ok, err)
	}
}
