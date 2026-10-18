package meta

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

const securitySweepBatch = 4096

// The caller holds securitySweepMu until the transaction and cursor update finish.
func (s *Store) securitySweepCursor(prefix []byte) []byte {
	return s.securitySweepCursors[string(prefix)]
}

func (s *Store) setSecuritySweepCursor(prefix, next []byte) {
	if len(next) == 0 {
		delete(s.securitySweepCursors, string(prefix))
		return
	}
	if s.securitySweepCursors == nil {
		s.securitySweepCursors = make(map[string][]byte)
	}
	s.securitySweepCursors[string(prefix)] = append([]byte(nil), next...)
}

func securitySweepScanTx(tx *bolt.Tx, prefix, after []byte, expired func([]byte) (bool, error)) (victims [][]byte, next []byte, corrupt int, err error) {
	b := tx.Bucket(bucketSecurity)
	if b == nil {
		return nil, nil, 0, errors.New("security bucket missing")
	}
	cursor := b.Cursor()
	key, value := cursor.Seek(prefix)
	if bytes.HasPrefix(after, prefix) {
		key, value = cursor.Seek(after)
		if bytes.Equal(key, after) {
			key, value = cursor.Next()
		}
	}
	for examined := 0; key != nil && bytes.HasPrefix(key, prefix); examined++ {
		if examined == securitySweepBatch {
			return victims, next, corrupt, nil
		}
		next = append(next[:0], key...)
		drop, decodeErr := expired(value)
		if decodeErr != nil {
			corrupt++
		} else if drop {
			victims = append(victims, append([]byte(nil), key...))
		}
		key, value = cursor.Next()
	}
	return victims, nil, corrupt, nil
}

// Durable credentials are deleted through the WAL; short-lived tickets stay local
// so backup authorization cannot recursively create another durable commit.
func (s *Store) SweepSecurityState(now time.Time) (int, error) {
	s.securitySweepMu.Lock()
	defer s.securitySweepMu.Unlock()
	if now.IsZero() {
		now = time.Now()
	}
	total, corrupt := 0, 0
	durable := []struct {
		prefix  []byte
		expired func([]byte) (bool, error)
	}{
		{[]byte("device-invite/"), func(v []byte) (bool, error) {
			var record deviceInviteRecord
			if err := json.Unmarshal(v, &record); err != nil {
				return false, err
			}
			return record.Used || !now.Before(record.ExpiresAt), nil
		}},
		{[]byte("device-challenge/"), func(v []byte) (bool, error) {
			var record deviceChallengeRecord
			if err := json.Unmarshal(v, &record); err != nil {
				return false, err
			}
			return !now.Before(record.Challenge.ExpiresAt), nil
		}},
		{[]byte("device-session/"), func(v []byte) (bool, error) {
			var record deviceSessionRecord
			if err := json.Unmarshal(v, &record); err != nil {
				return false, err
			}
			return !now.Before(record.ExpiresAt), nil
		}},
		{secPrefixSession, func(v []byte) (bool, error) {
			var record SessionRecord
			if err := json.Unmarshal(v, &record); err != nil {
				return false, err
			}
			return !now.Before(record.ExpiresAt), nil
		}},
		{secPrefixInvite, func(v []byte) (bool, error) {
			var record InviteRecord
			if err := json.Unmarshal(v, &record); err != nil {
				return false, err
			}
			return record.Used || !now.Before(record.ExpiresAt), nil
		}},
	}
	for _, spec := range durable {
		var victims [][]byte
		var next []byte
		bad := 0
		err := s.write(func(w *txw) error {
			var err error
			victims, next, bad, err = securitySweepScanTx(w.tx, spec.prefix, s.securitySweepCursor(spec.prefix), spec.expired)
			if err != nil {
				return err
			}
			for _, key := range victims {
				if err := w.del(bcSecurity, bucketSecurity, key); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return total, err
		}
		s.setSecuritySweepCursor(spec.prefix, next)
		total += len(victims)
		corrupt += bad
	}
	removed, bad, err := s.sweepSecurityTicketsLocked(now)
	if err != nil {
		return total, err
	}
	total += removed
	corrupt += bad
	if corrupt > 0 {
		return total, fmt.Errorf("security sweep skipped %d corrupt record(s); retained for inspection", corrupt)
	}
	return total, nil
}
