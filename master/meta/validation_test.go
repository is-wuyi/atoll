package meta

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestValidateSnapshotFilePreservesBytes(t *testing.T) {
	s := newTestStore(t)
	seedTree(t, s)
	file := filepath.Join(t.TempDir(), "snapshot.db")
	if _, err := s.SnapshotToFile(file); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSnapshotFile(file); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("snapshot validation changed the database")
	}
}

func TestValidateSnapshotFileRejectsInvalidWithoutInitializing(t *testing.T) {
	for _, kind := range []string{"missing", "empty", "not_bbolt", "empty_bbolt", "missing_root"} {
		t.Run(kind, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "invalid.db")
			switch kind {
			case "empty":
				if err := os.WriteFile(file, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case "not_bbolt":
				if err := os.WriteFile(file, bytes.Repeat([]byte("invalid"), 2000), 0o600); err != nil {
					t.Fatal(err)
				}
			case "empty_bbolt":
				db, err := bolt.Open(file, 0o600, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			case "missing_root":
				s, err := Open(file)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket(bucketInodes).Delete(u64be(RootID))
				}); err != nil {
					s.Close()
					t.Fatal(err)
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			}
			before, readErr := os.ReadFile(file)
			if readErr != nil && kind != "missing" {
				t.Fatal(readErr)
			}
			if err := ValidateSnapshotFile(file); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
			after, err := os.ReadFile(file)
			if kind == "missing" {
				if !os.IsNotExist(err) {
					t.Fatalf("validation created missing database: %v", err)
				}
			} else if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("invalid snapshot was modified: %v", err)
			}
		})
	}
}
