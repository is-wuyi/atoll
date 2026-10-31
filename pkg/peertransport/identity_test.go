package peertransport

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestIdentityPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")

	id, err := loadOrCreateRuntimeIdentity(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600", fi.Mode().Perm())
	}
	if fi.Size() == 0 || fi.Size() > maxIdentityFileSize {
		t.Fatalf("size = %d", fi.Size())
	}

	again, err := loadOrCreateRuntimeIdentity(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if again.id != id.id {
		t.Fatalf("reload peer %s != %s", again.id, id.id)
	}
	if !bytes.Equal(again.pub, id.pub) {
		t.Fatalf("reload public key differs")
	}
}

func TestIdentityRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.key")
	link := filepath.Join(dir, "link.key")
	if _, err := loadOrCreateRuntimeIdentity(target); err != nil {
		t.Fatalf("create target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := loadOrCreateRuntimeIdentity(link); err == nil {
		t.Fatal("symlink identity was accepted")
	}
}

func TestIdentityRejectsCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt.key")
	blob := []byte("this is not a private key at all, definitely corrupt")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateRuntimeIdentity(path); err == nil {
		t.Fatal("corrupt identity was accepted")
	}
	// The corrupt file must be left untouched.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, blob) {
		t.Fatal("corrupt identity file was modified")
	}
}

func TestIdentityRejectsWrongKeyType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rsa.key")
	priv, _, err := testRSAKey()
	if err != nil {
		t.Skipf("rsa unavailable: %v", err)
	}
	blob, err := marshalRSA(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateRuntimeIdentity(path); err == nil {
		t.Fatal("non-Ed25519 identity was accepted")
	}
}

func TestIdentityRejectsOversize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0xaa}, maxIdentityFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateRuntimeIdentity(path); err == nil {
		t.Fatal("oversize identity was accepted")
	}
}

func TestIdentityRejectsFIFO(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fifo.key")
	if err := mkfifo(path); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	if _, err := loadOrCreateRuntimeIdentity(path); err == nil {
		t.Fatal("FIFO identity was accepted")
	}
}

func TestIdentityConcurrentCreators(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shared.key")
	const n = 8
	ids := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, err := loadOrCreateRuntimeIdentity(path)
			if err != nil {
				errs[i] = err
				return
			}
			ids[i] = id.id.String()
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("creator %d: %v", i, err)
		}
		if ids[i] != ids[0] {
			t.Fatalf("creator %d got peer %s, want %s", i, ids[i], ids[0])
		}
	}
}

func TestIdentityFormatNoSecret(t *testing.T) {
	id, err := newEphemeralIdentity()
	if err != nil {
		t.Fatal(err)
	}
	s := fmt.Sprintf("%v", id)
	want := "runtimeIdentity(" + id.id.String() + ")"
	if s != want {
		t.Fatalf("String() = %q, want %q", s, want)
	}
	if bytes.Contains([]byte(s), id.pub) {
		t.Fatal("String() leaked public key bytes")
	}
}
