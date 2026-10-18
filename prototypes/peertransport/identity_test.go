package peertransport

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestIdentitySurvivesRestart: the identity file is created once with mode
// 0600 (O_CREATE|O_EXCL, never overwritten) and the PeerID is identical after
// reload and after a full node restart.
func TestIdentitySurvivesRestart(t *testing.T) {
	dir := t.TempDir()

	id1, err := LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}
	raw1, err := id1.RawEd25519()
	if err != nil {
		t.Fatalf("raw key: %v", err)
	}

	info, err := os.Stat(id1.Path)
	if err != nil {
		t.Fatalf("stat identity file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("identity file mode = %o, want 600", got)
	}

	// Reload from disk ("restart" of the identity layer).
	id2, err := LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatalf("reload identity: %v", err)
	}
	if id2.ID != id1.ID {
		t.Errorf("PeerID changed after reload: %s -> %s", id1.ID, id2.ID)
	}
	raw2, _ := id2.RawEd25519()
	if !bytes.Equal(raw1, raw2) {
		t.Errorf("private key bytes changed after reload")
	}

	// Full node restart: a new StoragePeer on the same dir keeps the PeerID.
	p1, err := newTestPeer(dir)
	if err != nil {
		t.Fatalf("peer 1: %v", err)
	}
	if p1.ID != id1.ID {
		t.Errorf("first node PeerID = %s, want %s", p1.ID, id1.ID)
	}
	endpoints1 := p1.Endpoints()
	if err := p1.Close(); err != nil {
		t.Fatalf("close node: %v", err)
	}

	p2, err := newTestPeer(dir)
	if err != nil {
		t.Fatalf("peer 2: %v", err)
	}
	defer p2.Close()
	if p2.ID != id1.ID {
		t.Errorf("PeerID changed after node restart: %s -> %s", id1.ID, p2.ID)
	}
	// PeerID and mutable endpoints are separate concepts: the endpoints may
	// differ between runs while the PeerID is stable.
	t.Logf("PeerID %s stable across restart; endpoints run1=%v run2=%v", id1.ID, endpoints1, p2.Endpoints())
}

func newTestPeer(dir string) (*StoragePeer, error) {
	return NewStoragePeer(context.Background(), PeerConfig{DataDir: dir, Peers: NewAllowlist(), Logger: testLog})
}

// TestIdentityCorruptFileNeverOverwritten: a corrupt existing identity file
// must be an error, and the file must be left byte-for-byte untouched —
// regeneration would silently change the PeerID.
func TestIdentityCorruptFileNeverOverwritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, IdentityFileName)
	garbage := []byte("this is definitely not a valid protobuf key")
	if err := os.WriteFile(path, garbage, 0o600); err != nil {
		t.Fatalf("seed corrupt identity: %v", err)
	}

	if _, err := LoadOrCreateIdentity(dir); err == nil {
		t.Fatalf("expected error for corrupt identity file, got nil")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read identity file after failed load: %v", err)
	}
	if !bytes.Equal(got, garbage) {
		t.Errorf("corrupt identity file was modified/overwritten")
	}
}
