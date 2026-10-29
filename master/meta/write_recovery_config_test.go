package meta

import (
	"encoding/json"
	"testing"
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

func TestPlannedWriteConfigRecoveryVersionIsAccepted(t *testing.T) {
	for _, version := range []int{2, 3} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			s, _ := writeTestStore(t)
			if err := s.db.Update(func(tx *bolt.Tx) error {
				raw, _ := json.Marshal(writeConfig{Version: version, EnabledAt: time.Now()})
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
		})
	}
}

func TestWriteProgressRegistrationUpgradesConfigurationDurably(t *testing.T) {
	s, nodes := writeTestStore(t)
	_, plan := recoveryFixture(t, s, nodes)
	enabledAt := time.Now().Add(-time.Hour).UTC()
	if err := s.write(func(w *txw) error {
		raw, err := json.Marshal(writeConfig{Version: 2, EnabledAt: enabledAt})
		if err != nil {
			return err
		}
		return w.put(bcWrites, bucketWrites, keyWriteConfig, raw)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginWriteProgress(types.BeginWriteProgressRequest{ObjectID: plan.Object.ID, NodeID: nodes[0], Epoch: plan.Recovery.Epoch, RequestID: "configuration-upgrade"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	check := func(store *Store) {
		t.Helper()
		if err := store.db.View(func(tx *bolt.Tx) error {
			var cfg writeConfig
			if err := json.Unmarshal(tx.Bucket(bucketWrites).Get(keyWriteConfig), &cfg); err != nil {
				return err
			}
			if cfg.Version != 3 || !cfg.EnabledAt.Equal(enabledAt) {
				t.Fatalf("attempt registration did not preserve and upgrade configuration: %+v", cfg)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	check(s)
	frames, err := s.FramesSince(0)
	if err != nil {
		t.Fatal(err)
	}
	restored := newTestStore(t)
	if err := restored.ApplyFrames(frames); err != nil {
		t.Fatal(err)
	}
	check(restored)
}
