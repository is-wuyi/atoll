package meta

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

func protectionHardUntil(t ProtectionTarget) (hard time.Time) {
	if t.AttemptToken == "" {
		return hard
	}
	if !t.HardUntil.IsZero() {
		return t.HardUntil
	}
	return t.LeaseStart.Add(30 * time.Minute)
}

func protectionFailureBackoff(attempt uint32) time.Duration {
	shift := min(max(attempt, 1)-1, 6)
	return min(5*time.Second*time.Duration(uint64(1)<<shift), 5*time.Minute)
}

func protectionTransfer(t ProtectionTarget) *types.ReplicaTransfer {
	out := &types.ReplicaTransfer{SourceID: t.SourceID, TargetID: t.NodeID, UploadBPS: t.UploadBPS, DownloadBPS: t.DownloadBPS, ExpiresAt: t.NextAttempt}
	if t.AttemptToken != "" {
		out.PlanAttempt, out.PlanAttemptToken, out.HardUntil = t.Attempts, t.AttemptToken, protectionHardUntil(t)
	}
	return out
}

var keyProtectionFeedback = []byte("protection_feedback_v1")

func protectionFeedbackEnabledTx(tx *bolt.Tx) (bool, error) {
	raw := tx.Bucket(bucketMeta).Get(keyProtectionFeedback)
	if raw == nil {
		return false, nil
	}
	if !bytes.Equal(raw, []byte{1}) {
		return false, errors.New("invalid protection feedback capability")
	}
	return true, nil
}

func (s *Store) ProtectionFeedbackEnabled() (bool, error) {
	var enabled bool
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		enabled, err = protectionFeedbackEnabledTx(tx)
		if err != nil || enabled {
			return err
		}
		return walkAutonomy(tx, "plan", func(raw []byte) error {
			var plan ProtectionPlan
			if err := json.Unmarshal(raw, &plan); err != nil {
				return err
			}
			for _, target := range plan.Targets {
				if target.AttemptToken != "" {
					return errors.New("feedback plans require explicit capability migration")
				}
			}
			if plan.Feedback {
				return errors.New("protection feedback marker missing")
			}
			return nil
		})
	})
	return enabled, err
}

// Enabling is durable and irreversible; older feedback plans migrate only by explicit opt-in.
func (s *Store) EnableProtectionFeedback() error {
	err := s.write(func(w *txw) error {
		enabled, err := protectionFeedbackEnabledTx(w.tx)
		if err != nil || enabled {
			return err
		}
		return w.put(bcMeta, bucketMeta, keyProtectionFeedback, []byte{1})
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return err
}
