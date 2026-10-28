package meta

import (
	"encoding/json"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestPlannedWriteConfigRecoveryVersionIsAccepted(t *testing.T) {
	s, _ := writeTestStore(t)
	if err := s.db.Update(func(tx *bolt.Tx) error {
		raw, _ := json.Marshal(writeConfig{Version: 2, EnabledAt: time.Now()})
		return tx.Bucket(bucketWrites).Put(keyWriteConfig, raw)
	}); err != nil {
		t.Fatal(err)
	}
	if enabled, err := s.WritePlanningEnabled(); err != nil || !enabled {
		t.Fatalf("recovery configuration rejected: enabled=%v err=%v", enabled, err)
	}
	if err := s.EnableWritePlanning(); err != nil {
		t.Fatalf("idempotent enable rejected recovery configuration: %v", err)
	}
}
