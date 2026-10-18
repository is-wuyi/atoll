package meta

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

// ValidateSnapshotFile 不初始化或修补数据库，避免把无效快照当成空库打开。
func ValidateSnapshotFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() == 0 {
		return fmt.Errorf("snapshot is not a nonempty regular file")
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true, Timeout: 3 * time.Second})
	if err != nil {
		return err
	}
	defer db.Close()
	return db.View(func(tx *bolt.Tx) error {
		var firstErr error
		for err := range tx.Check() {
			if firstErr == nil {
				firstErr = err
			}
		}
		if firstErr != nil {
			return firstErr
		}
		for _, name := range [][]byte{bucketInodes, bucketChildren, bucketNodes, bucketMeta, bucketWAL} {
			if tx.Bucket(name) == nil {
				return fmt.Errorf("snapshot missing bucket %q", name)
			}
		}
		marker := tx.Bucket(bucketMeta).Get(keyRetirementInitialized)
		journal := tx.Bucket(bucketRetired)
		if marker != nil && (len(marker) != 1 || marker[0] != 1 || journal == nil) {
			return fmt.Errorf("snapshot retirement journal missing or invalid")
		}
		if journal != nil {
			if key, _ := journal.Cursor().First(); marker == nil && key != nil {
				return fmt.Errorf("snapshot retirement initialization marker missing")
			}
			if err := journal.ForEach(func(key, raw []byte) error {
				_, err := decodeRetirementRecord(key, raw)
				return err
			}); err != nil {
				return err
			}
		}
		var root types.Inode
		if err := json.Unmarshal(tx.Bucket(bucketInodes).Get(u64be(RootID)), &root); err != nil {
			return fmt.Errorf("snapshot root: %w", err)
		}
		if root.ID != RootID || root.Type != types.TypeDir || root.ParentID != 0 {
			return fmt.Errorf("invalid snapshot root")
		}
		return nil
	})
}
