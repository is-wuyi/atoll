package mount

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"

	"atoll/client"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type namespaceTransport struct {
	base http.RoundTripper
	fail func(*http.Request) bool
}

func (tr namespaceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if tr.fail(r) {
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBufferString(`{"error":"injected metadata failure"}`)),
			Request:    r,
		}, nil
	}
	return tr.base.RoundTrip(r)
}

func injectNamespaceFailure(c *client.Client, fail func(*http.Request) bool) {
	hc := *c.HTTP
	base := hc.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	hc.Transport = namespaceTransport{base: base, fail: fail}
	c.HTTP = &hc
}

func namespaceFS(m *Mount) (*node, fuse.RawFileSystem) {
	root := m.Root().(*node)
	return root, fs.NewNodeFS(root, &fs.Options{})
}

type namespaceFile struct {
	raw      fuse.RawFileSystem
	entry    fuse.EntryOut
	fh       uint64
	released bool
}

func (f *namespaceFile) release() {
	if !f.released {
		f.raw.Release(nil, &fuse.ReleaseIn{InHeader: fuse.InHeader{NodeId: f.entry.NodeId}, Fh: f.fh})
		f.released = true
	}
}

func (f *namespaceFile) write(t *testing.T, data []byte, off uint64) {
	t.Helper()
	n, status := f.raw.Write(nil, &fuse.WriteIn{
		InHeader: fuse.InHeader{NodeId: f.entry.NodeId},
		Fh:       f.fh,
		Offset:   off,
		Size:     uint32(len(data)),
	}, data)
	if status != fuse.OK || n != uint32(len(data)) {
		t.Fatalf("Write: size=%d status=%v", n, status)
	}
}

func (f *namespaceFile) flush() fuse.Status {
	return f.raw.Flush(nil, &fuse.FlushIn{InHeader: fuse.InHeader{NodeId: f.entry.NodeId}, Fh: f.fh})
}

func createNamespaceFile(t *testing.T, raw fuse.RawFileSystem, name string) *namespaceFile {
	t.Helper()
	var out fuse.CreateOut
	status := raw.Create(nil, &fuse.CreateIn{
		InHeader: fuse.InHeader{NodeId: 1},
		Flags:    syscall.O_CREAT | syscall.O_WRONLY | syscall.O_EXCL,
		Mode:     fuse.S_IFREG | 0o644,
	}, name, &out)
	if status != fuse.OK {
		t.Fatalf("Create: %v", status)
	}
	f := &namespaceFile{raw: raw, entry: out.EntryOut, fh: out.Fh}
	t.Cleanup(f.release)
	return f
}

func checkNamespaceIdentity(t *testing.T, root *node, raw fuse.RawFileSystem, name string, want fuse.EntryOut) {
	t.Helper()
	var out fuse.EntryOut
	if status := raw.Lookup(nil, &fuse.InHeader{NodeId: 1}, name, &out); status != fuse.OK {
		t.Fatalf("Lookup %s: %v", name, status)
	}
	if out.Ino != want.Ino || out.NodeId != want.NodeId {
		t.Errorf("Lookup changed identity: inode=%d node=%d, want inode=%d node=%d", out.Ino, out.NodeId, want.Ino, want.NodeId)
	}
	stream, errno := root.Readdir(context.Background())
	if errno != 0 {
		t.Fatalf("Readdir: %v", errno)
	}
	defer stream.Close()
	found := false
	for stream.HasNext() {
		entry, errno := stream.Next()
		if errno != 0 {
			t.Fatalf("DirStream.Next: %v", errno)
		}
		if entry.Name == name {
			found = true
			if entry.Ino != want.Ino {
				t.Errorf("Readdir inode=%d, want %d", entry.Ino, want.Ino)
			}
		}
	}
	if !found {
		t.Errorf("Readdir omitted %s", name)
	}
}

func TestNamespaceErrorsPreserveMeaning(t *testing.T) {
	cases := []struct {
		name string
		code int
		text string
		want syscall.Errno
	}{
		{"unavailable", 503, "temporarily unavailable", syscall.EIO},
		{"upstream_not_found", 500, "upstream service not found", syscall.EIO},
		{"unauthorized", 401, "unauthorized", syscall.EACCES},
		{"forbidden", 403, "forbidden", syscall.EACCES},
		{"missing", 404, "missing entry", syscall.ENOENT},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.code)
				if err := json.NewEncoder(w).Encode(map[string]string{"error": tc.text}); err != nil {
					t.Error(err)
				}
			}))
			t.Cleanup(ts.Close)
			m, err := New(client.New(ts.URL), t.TempDir(), 1)
			if err != nil {
				t.Fatal(err)
			}
			root, raw := namespaceFS(m)
			var entry fuse.EntryOut
			if status := raw.Lookup(nil, &fuse.InHeader{NodeId: 1}, "file", &entry); status != fuse.Status(tc.want) {
				t.Errorf("Lookup=%v, want %v", status, tc.want)
			}
			var attr fuse.AttrOut
			if errno := root.Getattr(context.Background(), nil, &attr); errno != tc.want {
				t.Errorf("Getattr=%v, want %v", errno, tc.want)
			}
			stream, errno := root.Readdir(context.Background())
			if stream != nil {
				stream.Close()
				t.Error("failed directory fetch must not return a successful partial listing")
			}
			if errno != tc.want {
				t.Errorf("Readdir=%v, want %v", errno, tc.want)
			}
			for _, flags := range []uint32{syscall.O_RDONLY, syscall.O_RDWR} {
				_, _, errno := root.Open(context.Background(), flags)
				if errno != tc.want {
					t.Errorf("Open(%d)=%v, want %v", flags, errno, tc.want)
				}
			}
		})
	}
}

func TestDirectoryFailureRetainsPendingFile(t *testing.T) {
	c, m := newTestCluster(t, 1)
	root, raw := namespaceFS(m)
	f := createNamespaceFile(t, raw, "pending")
	f.write(t, []byte("local pending data"), 0)
	injectNamespaceFailure(c, func(r *http.Request) bool { return r.URL.Path == "/dirs/children" })
	stream, errno := root.Readdir(context.Background())
	if stream != nil {
		stream.Close()
		t.Fatal("directory failure returned a partial success")
	}
	if errno != syscall.EIO {
		t.Errorf("Readdir=%v, want EIO rather than ENOENT", errno)
	}
	var out fuse.EntryOut
	if status := raw.Lookup(nil, &fuse.InHeader{NodeId: 1}, "pending", &out); status != fuse.OK {
		t.Fatalf("local pending file became unavailable: %v", status)
	}
	if out.Ino != f.entry.Ino || out.Size != uint64(len("local pending data")) {
		t.Errorf("local pending metadata changed: %+v", out.Attr)
	}
}

func TestMountOverwriteKeepsInode(t *testing.T) {
	for _, flags := range []uint32{syscall.O_WRONLY | syscall.O_TRUNC, syscall.O_RDWR} {
		t.Run(map[bool]string{true: "truncate", false: "in_place"}[flags&syscall.O_TRUNC != 0], func(t *testing.T) {
			withChunkSize(t, 1024)
			c, m := newTestCluster(t, 1)
			if err := c.PutChunkedReader("/file", 11, bytes.NewBufferString("old-content"), 1); err != nil {
				t.Fatal(err)
			}
			root, raw := namespaceFS(m)
			var entry fuse.EntryOut
			if status := raw.Lookup(nil, &fuse.InHeader{NodeId: 1}, "file", &entry); status != fuse.OK {
				t.Fatal(status)
			}
			var opened fuse.OpenOut
			if status := raw.Open(nil, &fuse.OpenIn{InHeader: fuse.InHeader{NodeId: entry.NodeId}, Flags: flags}, &opened); status != fuse.OK {
				t.Fatal(status)
			}
			f := &namespaceFile{raw: raw, entry: entry, fh: opened.Fh}
			t.Cleanup(f.release)
			f.write(t, []byte("new-content"), 0)
			checkNamespaceIdentity(t, root, raw, "file", entry)
			if status := f.flush(); status != fuse.OK {
				t.Fatal(status)
			}
			checkNamespaceIdentity(t, root, raw, "file", entry)
			f.release()
			checkNamespaceIdentity(t, root, raw, "file", entry)
			out := filepath.Join(t.TempDir(), "out")
			if err := c.Get("/file", out); err != nil {
				t.Fatal(err)
			}
			if got, err := os.ReadFile(out); err != nil || string(got) != "new-content" {
				t.Fatalf("readback=%q err=%v", got, err)
			}
		})
	}
}

func TestMountCreateKeepsInodeAcrossFallback(t *testing.T) {
	for _, scenario := range []string{"empty", "rewrite", "begin_failure", "commit_retry"} {
		t.Run(scenario, func(t *testing.T) {
			withChunkSize(t, 1024)
			c, m := newTestCluster(t, 1)
			var failBegin, failCommit atomic.Bool
			failBegin.Store(scenario == "begin_failure")
			injectNamespaceFailure(c, func(r *http.Request) bool {
				return r.Method == http.MethodPost && ((r.URL.Path == "/files" && failBegin.Swap(false)) ||
					(r.URL.Path == "/files/commit" && failCommit.Swap(false)))
			})
			root, raw := namespaceFS(m)
			if scenario == "commit_retry" {
				m.NoSmallPath = true // 该场景专测 chunked commit 重试的 inode 稳定性
			}
			f := createNamespaceFile(t, raw, "file")
			want := []byte{}
			if scenario != "empty" {
				want = bytes.Repeat([]byte("x"), 2048)
				f.write(t, want, 0)
				if scenario == "rewrite" {
					f.write(t, []byte("new"), 0)
					copy(want, "new")
				}
			}
			checkNamespaceIdentity(t, root, raw, "file", f.entry)
			if scenario == "commit_retry" {
				failCommit.Store(true)
				if status := f.flush(); status == fuse.OK {
					t.Fatal("injected commit failure was not observed")
				}
				checkNamespaceIdentity(t, root, raw, "file", f.entry)
			}
			if status := f.flush(); status != fuse.OK {
				t.Fatal(status)
			}
			checkNamespaceIdentity(t, root, raw, "file", f.entry)
			f.release()
			checkNamespaceIdentity(t, root, raw, "file", f.entry)
			out := filepath.Join(t.TempDir(), "out")
			if err := c.Get("/file", out); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(out)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("readback length=%d want=%d err=%v", len(got), len(want), err)
			}
		})
	}
}

func TestMountInodeSurvivesForgetAndRename(t *testing.T) {
	c, m := newTestCluster(t, 1)
	root, raw := namespaceFS(m)
	f := createNamespaceFile(t, raw, "file")
	if status := f.flush(); status != fuse.OK {
		t.Fatal(status)
	}
	f.release()
	raw.Forget(f.entry.NodeId, 1)
	var found fuse.EntryOut
	if status := raw.Lookup(nil, &fuse.InHeader{NodeId: 1}, "file", &found); status != fuse.OK {
		t.Fatal(status)
	}
	if found.Ino != f.entry.Ino {
		t.Errorf("Forget changed inode: %d != %d", found.Ino, f.entry.Ino)
	}
	if status := raw.Rename(nil, &fuse.RenameIn{InHeader: fuse.InHeader{NodeId: 1}, Newdir: 1}, "file", "renamed"); status != fuse.OK {
		t.Fatal(status)
	}
	checkNamespaceIdentity(t, root, raw, "renamed", found)
	if status := raw.Unlink(nil, &fuse.InHeader{NodeId: 1}, "renamed"); status != fuse.OK {
		t.Fatal(status)
	}
	fresh := createNamespaceFile(t, raw, "renamed")
	if fresh.entry.Ino == found.Ino {
		t.Error("delete and recreate reused the old file identity")
	}
	if _, _, err := c.Lookup("/file"); err == nil {
		t.Error("rename left the old remote path")
	}
}
