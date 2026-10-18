package meta

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestSweepSecurityTicketsDirectCallerAdvances(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	live, err := json.Marshal(accessTicketRecord{ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	expired, err := json.Marshal(accessTicketRecord{ExpiresAt: now.Add(-time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketSecurity)
		for i := 0; i < securitySweepBatch; i++ {
			if err := bucket.Put([]byte(fmt.Sprintf("ticket/a%08d", i)), live); err != nil {
				return err
			}
		}
		return bucket.Put([]byte("ticket/z-expired"), expired)
	}); err != nil {
		t.Fatal(err)
	}
	if removed, err := s.SweepSecurityTickets(now); err != nil || removed != 0 {
		t.Fatalf("first batch: removed %d error %v", removed, err)
	}
	if removed, err := s.SweepSecurityTickets(now); err != nil || removed != 1 {
		t.Fatalf("direct caller did not reach the expired suffix: removed %d error %v", removed, err)
	}
	if got := gcKeyCount(t, s, "ticket/"); got != securitySweepBatch {
		t.Fatalf("live records changed: %d", got)
	}
	if len(s.securitySweepCursors) != 0 {
		t.Fatal("finished prefix retained a cursor")
	}
}

func TestSecuritySweepCursorIsStoreLocal(t *testing.T) {
	one, two := newTestStore(t), newTestStore(t)
	one.setSecuritySweepCursor([]byte("ticket/"), []byte("ticket/a"))
	if got := two.securitySweepCursor([]byte("ticket/")); len(got) != 0 {
		t.Fatalf("another store inherited a cursor: %q", got)
	}
}
