//go:build fuse

package mount

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"atoll/pkg/types"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestKernelPlannedWriteRoundTrip(t *testing.T) {
	withChunkSize(t, 64<<10)
	cl := newPlannedMountCluster(t)
	if _, err := cl.client.SetProtection("/", types.ProtectionSecurity); err != nil {
		t.Fatal(err)
	}
	mnt := t.TempDir()
	srv, err := fs.Mount(mnt, cl.mount.Root(), &fs.Options{MountOptions: fuse.MountOptions{Name: "atoll-planned-write"}})
	if err != nil {
		t.Fatalf("planned write kernel mount: %v", err)
	}
	t.Cleanup(func() {
		if err := srv.Unmount(); err != nil {
			t.Errorf("unmount: %v", err)
		}
	})
	if err = os.Mkdir(filepath.Join(mnt, "dir"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{{"empty", nil}, {"small", []byte("planned small file")}, {"stream", bytes.Repeat([]byte("data"), 100000)}} {
		path := filepath.Join(mnt, "dir", tc.name)
		if err = os.WriteFile(path, tc.data, 0600); err != nil {
			t.Fatalf("write %s: %v", tc.name, err)
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, tc.data) {
			t.Fatalf("read %s: %v bytes=%d", tc.name, err, len(got))
		}
		in, _, err := cl.client.Lookup("/dir/" + tc.name)
		if err != nil || in.Content == nil {
			t.Fatalf("published %s: %v %+v", tc.name, err, in)
		}
		if err = os.WriteFile(path, []byte("replacement"), 0600); err != nil {
			t.Fatal(err)
		}
		after, _, err := cl.client.Lookup("/dir/" + tc.name)
		if err != nil || after.ID != in.ID || after.Generation != in.Generation+1 {
			t.Fatalf("overwrite identity: %v %+v", err, after)
		}
		if err = os.Rename(path, path+"-new"); err != nil {
			t.Fatal(err)
		}
		if err = os.Remove(path + "-new"); err != nil {
			t.Fatal(err)
		}
	}
	cl.assertPlanned(t)
}
