package meta

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestSecurityConfigInvalidStatesFailClosed(t *testing.T) {
	securityFastHash(t)
	for _, mode := range []string{"missing", "empty", "null", "empty-object", "duplicate-anchors"} {
		t.Run(mode, func(t *testing.T) {
			s := newTestStore(t)
			bootstrapAdmin(t, s)
			legacy, err := s.RegisterNode("127.0.0.1:59801", 1024)
			if err != nil {
				t.Fatal(err)
			}
			err = s.db.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket(bucketSecurity)
				switch mode {
				case "missing":
					return b.Delete(keySecConfig)
				case "empty":
					return b.Put(keySecConfig, []byte{})
				case "null":
					return b.Put(keySecConfig, []byte("null"))
				case "empty-object":
					return b.Put(keySecConfig, []byte("{}"))
				default:
					var cfg securityConfig
					if err := json.Unmarshal(b.Get(keySecConfig), &cfg); err != nil {
						return err
					}
					cfg.TeamsDirID = cfg.PersonalDirID
					raw, err := json.Marshal(cfg)
					if err != nil {
						return err
					}
					return b.Put(keySecConfig, raw)
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.SecurityEnabled(); err == nil {
				t.Fatal("invalid configuration was accepted as a usable mode")
			}
			if err := s.Heartbeat(legacy.ID, 1); err == nil {
				t.Fatal("invalid configuration admitted a legacy heartbeat")
			}
			if nodes, err := s.ListAliveNodes(time.Hour); err == nil || len(nodes) != 0 {
				t.Fatalf("invalid configuration exposed nodes: %d, %v", len(nodes), err)
			}
			if _, _, err := s.BootstrapSecurity("replacement", "replacement-password", time.Now()); err == nil {
				t.Fatal("invalid configuration allowed another bootstrap")
			}
		})
	}
}

func TestDeviceRevocationRetryRequiresDurability(t *testing.T) {
	s := newTestStore(t)
	dev := auditLoginDevice(t, s, "127.0.0.1:59802", "")
	unavailable := errors.New("durability unavailable")
	calls := 0
	s.SetPostCommitHook(func(uint64, []byte) error {
		calls++
		return unavailable
	})
	t.Cleanup(func() { s.SetPostCommitHook(nil) })
	for attempt := 0; attempt < 2; attempt++ {
		if err := s.RevokeDevice(dev.NodeID); !errors.Is(err, unavailable) {
			t.Fatalf("revocation attempt %d bypassed durability: %v", attempt, err)
		}
		if _, err := s.DeviceForSession(dev.Token, time.Now()); !errors.Is(err, ErrDeviceAuth) {
			t.Fatalf("locally revoked session remained valid: %v", err)
		}
	}
	if calls != 2 {
		t.Fatalf("durability hook calls = %d, want 2", calls)
	}
	before, err := s.WALSeq()
	if err != nil {
		t.Fatal(err)
	}
	s.SetPostCommitHook(func(uint64, []byte) error { calls++; return nil })
	if err := s.RevokeDevice(dev.NodeID); err != nil {
		t.Fatalf("revocation retry after recovery: %v", err)
	}
	after, err := s.WALSeq()
	if err != nil || after != before || calls != 3 {
		t.Fatalf("idempotent retry: seq %d -> %d, calls %d, error %v", before, after, calls, err)
	}
}

func TestDeviceRevocationWithoutLivenessRow(t *testing.T) {
	s := newTestStore(t)
	dev := auditLoginDevice(t, s, "127.0.0.1:59803", "")
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketNodes).Delete(u64be(dev.NodeID))
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeDevice(dev.NodeID); err != nil {
		t.Fatalf("missing liveness row blocked revocation: %v", err)
	}
	if _, err := s.DeviceForSession(dev.Token, time.Now()); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("revoked session accepted: %v", err)
	}
}
