package keyfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateLoadAndRefuseOverwrite(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "keys")
	path := filepath.Join(parent, "master.key")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	kek, err := Create(path, "master-20261018")
	if err != nil {
		t.Fatal(err)
	}
	if kek.KeyID() != "master-20261018" {
		t.Fatalf("key id = %q", kek.KeyID())
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v err=%v", st.Mode().Perm(), err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.KeyID() != kek.KeyID() {
		t.Fatalf("load = %v %q", err, loaded.KeyID())
	}
	if _, err := Create(path, "other"); err == nil {
		t.Fatal("existing key file was overwritten")
	}
}

func TestLoadRejectsSymlinkAndBroadPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if _, err := Create(target, "master"); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil {
		t.Fatal("symlink key file accepted")
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(target); err == nil {
		t.Fatal("key file with broad permissions accepted")
	}
}

func TestLoadRejectsMalformedKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.key")
	if err := os.WriteFile(path, []byte("not-a-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("malformed key file accepted")
	}
}
