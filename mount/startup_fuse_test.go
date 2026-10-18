//go:build fuse

package mount

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type startupLog struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *startupLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

func (b *startupLog) snapshot() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

func TestKernelMountFirstMutation(t *testing.T) {
	for i := 0; i < 40; i++ {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			_, m := newTestCluster(t, 1)
			var output startupLog
			mnt := t.TempDir()
			server, err := fs.Mount(mnt, m.Root(), &fs.Options{MountOptions: fuse.MountOptions{
				Name: "atoll-startup", Debug: true, Logger: log.New(&output, "", log.Lmicroseconds),
			}})
			if err != nil {
				t.Fatalf("mount: %v", err)
			}
			defer func() {
				if err := server.Unmount(); err != nil {
					t.Errorf("unmount: %v", err)
				}
				if t.Failed() || os.Getenv("ATOLL_FUSE_STARTUP_TRACE") == "1" {
					t.Logf("FUSE protocol:\n%s", output.snapshot())
				}
			}()
			if i%2 == 0 {
				if err := os.Mkdir(filepath.Join(mnt, "first"), 0o755); err != nil {
					t.Fatalf("first mkdir: %v", err)
				}
			} else {
				if err := os.WriteFile(filepath.Join(mnt, "first"), []byte("startup"), 0o644); err != nil {
					t.Fatalf("first create/write/close: %v", err)
				}
			}
		})
	}
}
