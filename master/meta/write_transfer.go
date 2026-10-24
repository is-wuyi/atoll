package meta

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
)

var keyTransferConfig = []byte("transfer_config")
var keyTransferInitialized = []byte("write_transfer_initialized_v1")

func transferPlanningEnabledTx(tx *bolt.Tx) (bool, error) {
	b := tx.Bucket(bucketWrites)
	if b == nil {
		if tx.Bucket(bucketMeta).Get(keyTransferInitialized) != nil {
			return false, errors.New("write transfer configuration unavailable")
		}
		return false, nil
	}
	raw := b.Get(keyTransferConfig)
	marker := tx.Bucket(bucketMeta).Get(keyTransferInitialized)
	if raw == nil && marker == nil {
		return false, nil
	}
	var cfg writeConfig
	if raw == nil || json.Unmarshal(raw, &cfg) != nil || cfg.Version != 1 || cfg.EnabledAt.IsZero() || !bytes.Equal(marker, []byte{1}) {
		return false, errors.New("invalid write transfer configuration")
	}
	return true, nil
}

func (s *Store) TransferPlanningEnabled() (bool, error) {
	var enabled bool
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		enabled, err = transferPlanningEnabledTx(tx)
		return err
	})
	return enabled, err
}

func (s *Store) EnableTransferPlanning() error {
	err := s.write(func(w *txw) error {
		if err := requireWritePlanningTx(w.tx); err != nil {
			return err
		}
		enabled, err := transferPlanningEnabledTx(w.tx)
		if err != nil || enabled {
			return err
		}
		raw, err := json.Marshal(writeConfig{Version: 1, EnabledAt: time.Now()})
		if err != nil {
			return err
		}
		if err := w.put(bcWrites, bucketWrites, keyTransferConfig, raw); err != nil {
			return err
		}
		return w.put(bcMeta, bucketMeta, keyTransferInitialized, []byte{1})
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return err
}
