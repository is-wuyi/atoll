package meta

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

func TestRetirementRecoveryRejectsMissingDurableJournal(t *testing.T) {
	for _, scenario := range []string{"missing-journal", "missing-marker", "invalid-marker"} {
		t.Run(scenario, func(t *testing.T) {
			s, nodes := writeTestStore(t)
			u := beginWriteTest(t, s, RootID, "pending", 3, false)
			reserveWriteTest(t, s, u, []byte("abc"), nodes[:1], nodes[:1])
			if err := s.AbortPlannedWrite(WriteActor{}, writeBinding(u), time.Now()); err != nil {
				t.Fatal(err)
			}
			snapshot := filepath.Join(t.TempDir(), "invalid-snapshot.db")
			if _, err := s.SnapshotToFile(snapshot); err != nil {
				t.Fatal(err)
			}
			db, err := bolt.Open(snapshot, 0o600, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Update(func(tx *bolt.Tx) error {
				switch scenario {
				case "missing-journal":
					return tx.DeleteBucket(bucketRetired)
				case "missing-marker":
					return tx.Bucket(bucketMeta).Delete(keyRetirementInitialized)
				default:
					return tx.Bucket(bucketMeta).Put(keyRetirementInitialized, []byte{2})
				}
			}); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateSnapshotFile(snapshot); err == nil {
				t.Fatal("incomplete retirement snapshot accepted")
			}
			if reopened, err := Open(snapshot); err == nil {
				reopened.Close()
				t.Fatal("incomplete retirement journal was silently recreated")
			}
			after, err := os.ReadFile(snapshot)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("rejected database changed: %v", err)
			}
		})
	}
}

func TestRetirementApplyFramesRejectsMissingBucketWithoutPanic(t *testing.T) {
	s := newTestStore(t)
	if err := s.db.Update(func(tx *bolt.Tx) error { return tx.DeleteBucket(bucketRetired) }); err != nil {
		t.Fatal(err)
	}
	frame := Frame{Seq: 1, Muts: []mutation{{Bucket: bcRetired, Key: []byte("retirement"), Value: []byte("value")}}}
	if err := s.ApplyFrames([]Frame{frame}); err == nil {
		t.Fatal("WAL applied to a missing retirement bucket")
	}
	if seq, err := s.WALSeq(); err != nil || seq != 0 {
		t.Fatalf("rejected WAL advanced sequence: %d %v", seq, err)
	}
}

func TestRetirementUnpublishedSmallObjectQueuesBeforeRegistrySweep(t *testing.T) {
	s, nodes := writeTestStore(t)
	obj, _, err := s.PrepareSmallFile(SmallFileTarget{ParentID: RootID, Name: "never-published", Size: 4, Checksum: 123,
		Replicas: nodes[:1], PrimaryID: nodes[0], Mtime: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AbortSmallFile(obj.ID); err != nil {
		t.Fatal(err)
	}
	records, err := s.ListRetirements()
	if err != nil || len(records) != 1 || records[0].State != RetirementPending {
		t.Fatalf("abort did not journal the pending object: %+v %v", records, err)
	}
	req, claimed, err := s.ClaimRetirement(obj.ID, nodes[0], time.Now(), time.Minute, time.Hour)
	if err != nil || !claimed {
		t.Fatalf("small-object claim: %v %v", claimed, err)
	}
	receipt := types.ObjectRetirementReceipt{ObjectRetirement: req, State: types.RetirementRemoved,
		Usage: types.NodeUsage{Epoch: "boot", Sequence: 1}}
	if ok, err := s.ConfirmRetirement(receipt, time.Now(), time.Hour); err != nil || !ok {
		t.Fatalf("small-object absence: %v %v", ok, err)
	}
	if capacity := capacityFor(t, s, nodes[0]); capacity.Reserved != 0 || capacity.Accounted != 0 {
		t.Fatalf("confirmed registry object still charged: %+v", capacity)
	}
}
