package meta

import (
	"encoding/json"

	bolt "go.etcd.io/bbolt"
)

type autonomyScanCursor struct {
	After uint64 `json:"after"`
}

// The cursor is resumable local work progress, not an execution authorization.
func (s *Store) SetAutonomyScanAfter(after uint64) error {
	raw, err := json.Marshal(autonomyScanCursor{After: after})
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAutonomy).Put(autonomyKey("cursor", "planning"), raw)
	})
}
