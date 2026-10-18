//go:build unix

package edgeidentity

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestFIFOAtPathRejected 私钥路径上是 FIFO 等非普通文件时必须拒绝；
// O_NONBLOCK 保证 open 不会因等待写端而挂死。
func TestFIFOAtPathRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo 不可用: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := LoadOrCreate(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("FIFO 被接受")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("LoadOrCreate 在 FIFO 上挂死（O_NONBLOCK 未生效）")
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("FIFO 被改写: %v %v", fi, err)
	}
}
