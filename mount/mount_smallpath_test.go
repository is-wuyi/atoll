package mount

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"atoll/client"
	"atoll/pkg/types"

	"github.com/hanwen/go-fuse/v2/fuse"
)

type writeRPCRecorder struct {
	base  http.RoundTripper
	host  string
	mu    sync.Mutex
	calls []string
}

func (r *writeRPCRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == r.host {
		r.mu.Lock()
		r.calls = append(r.calls, req.Method+" "+req.URL.Path)
		r.mu.Unlock()
	}
	return r.base.RoundTrip(req)
}

func recordWriteRPCs(c *client.Client) *writeRPCRecorder {
	hc := *c.HTTP
	base := hc.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	r := &writeRPCRecorder{base: base, host: strings.TrimPrefix(c.MasterURL, "http://")}
	hc.Transport = r
	c.HTTP = &hc
	return r
}

func (r *writeRPCRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func (r *writeRPCRecorder) count(call string) int {
	n := 0
	for _, got := range r.snapshot() {
		if got == call {
			n++
		}
	}
	return n
}

// statusInjectTransport 对命中的请求返回固定状态码（JSON error body），其余透传。
// namespaceTransport 只会注入 503；这里可指定任意状态码，用于验证 Flush 对
// small 通道“明确拒绝”类错误（409/401/403/426）不得回退通用覆盖路径。
type statusInjectTransport struct {
	base   http.RoundTripper
	match  func(*http.Request) bool
	status int
}

func (tr statusInjectTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if tr.match(r) {
		return &http.Response{
			StatusCode: tr.status,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"error":"injected small failure"}`)),
			Request:    r,
		}, nil
	}
	return tr.base.RoundTrip(r)
}

func injectHTTPStatus(c *client.Client, match func(*http.Request) bool, status int) {
	hc := *c.HTTP
	base := hc.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	hc.Transport = statusInjectTransport{base: base, match: match, status: status}
	c.HTTP = &hc
}

func verifySmallPathContent(t *testing.T, c *client.Client, remote string, want []byte) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "readback")
	if err := c.Get(remote, out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("readback bytes=%d, want %d, err=%v", len(got), len(want), err)
	}
}

func TestMountSmallCreateUsesOnlySmallRequest(t *testing.T) {
	for _, size := range []int{1, 4096, int(types.SmallFileMax)} {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			c, m := newTestCluster(t, 1)
			rpc := recordWriteRPCs(c)
			_, raw := namespaceFS(m)
			f := createNamespaceFile(t, raw, "small")
			if calls := rpc.snapshot(); len(calls) != 0 {
				t.Errorf("Create issued remote requests before content was known: %v", calls)
			}
			want := bytes.Repeat([]byte{0x5a}, size)
			for off := 0; off < len(want); off += 1024 {
				end := min(off+1024, len(want))
				f.write(t, want[off:end], uint64(off))
			}
			if calls := rpc.snapshot(); len(calls) != 0 {
				t.Errorf("small Write issued remote requests before Flush: %v", calls)
			}
			if status := f.flush(); status != fuse.OK {
				t.Fatal(status)
			}
			if status := f.flush(); status != fuse.OK {
				t.Fatal(status)
			}
			f.release()
			if calls := rpc.snapshot(); len(calls) != 1 || calls[0] != "POST /files/small" {
				t.Errorf("small create/write/flush/release requests=%v, want only POST /files/small", calls)
			}
			verifySmallPathContent(t, c, "/small", want)
		})
	}
}

func TestMountSmallOverwriteUsesOnlySmallRequest(t *testing.T) {
	c, m := newTestCluster(t, 1)
	old, err := c.PutSmall("/small", []byte("old content"), 1, false)
	if err != nil {
		t.Fatal(err)
	}
	root, raw := namespaceFS(m)
	var entry fuse.EntryOut
	if status := raw.Lookup(nil, &fuse.InHeader{NodeId: 1}, "small", &entry); status != fuse.OK {
		t.Fatal(status)
	}
	var opened fuse.OpenOut
	if status := raw.Open(nil, &fuse.OpenIn{
		InHeader: fuse.InHeader{NodeId: entry.NodeId}, Flags: syscall.O_WRONLY | syscall.O_TRUNC,
	}, &opened); status != fuse.OK {
		t.Fatal(status)
	}
	f := &namespaceFile{raw: raw, entry: entry, fh: opened.Fh}
	t.Cleanup(f.release)
	rpc := recordWriteRPCs(c)
	want := []byte("new content")
	f.write(t, want, 0)
	if status := f.flush(); status != fuse.OK {
		t.Fatal(status)
	}
	f.release()
	if calls := rpc.snapshot(); len(calls) != 1 || calls[0] != "POST /files/small" {
		t.Errorf("overwrite write/flush requests=%v", calls)
	}
	in, _, err := c.Lookup("/small")
	if err != nil || in.ID != old.ID || in.Generation != old.Generation+1 {
		t.Fatalf("overwrite metadata=%+v err=%v", in, err)
	}
	// v2-4b：FileID 保留、Generation++，但内容切换到新的不复用显式 ObjID。
	if in.ObjID == 0 || in.ObjID == old.ObjID {
		t.Fatalf("overwrite must switch to a fresh explicit ObjID: new=%+v old=%+v", in, old)
	}
	checkNamespaceIdentity(t, root, raw, "small", entry)
	verifySmallPathContent(t, c, "/small", want)
}

func TestMountSmallFailureFallsBackWithoutPrecreatedSession(t *testing.T) {
	withChunkSize(t, 1024)
	c, m := newTestCluster(t, 1)
	injectNamespaceFailure(c, func(r *http.Request) bool { return r.URL.Path == "/files/small" })
	rpc := recordWriteRPCs(c)
	root, raw := namespaceFS(m)
	f := createNamespaceFile(t, raw, "fallback")
	want := bytes.Repeat([]byte{0x6b}, 2300)
	f.write(t, want, 0)
	if calls := rpc.snapshot(); len(calls) != 0 {
		t.Errorf("small write prematurely created a stream: %v", calls)
	}
	if status := f.flush(); status != fuse.OK {
		t.Fatal(status)
	}
	f.release()
	calls := rpc.snapshot()
	if len(calls) == 0 || calls[0] != "POST /files/small" || rpc.count("POST /files") != 1 || rpc.count("POST /files/commit") != 1 {
		t.Errorf("fallback requests=%v, want small attempt followed by one chunked upload", calls)
	}
	for _, call := range calls {
		if strings.HasPrefix(call, "DELETE /files/staging/") {
			t.Errorf("fallback aborted an unnecessary session: %v", calls)
		}
	}
	checkNamespaceIdentity(t, root, raw, "fallback", f.entry)
	verifySmallPathContent(t, c, "/fallback", want)
}

// TestMountSmallFlushConflictDoesNotFallback small 通道被服务端“明确拒绝”时，
// Flush 必须把错误如实上抛，绝不能落回通用覆盖路径——那条路径会重传整个文件，
// 绕过 small 通道事务里的目标状态校验（CAS）。可重试错误（网络/503）与旧 master
// 未实现该通道（404/405）仍然回退（见 TestMountSmallFailureFallsBackWithoutPrecreatedSession）。
func TestMountSmallFlushConflictDoesNotFallback(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   fuse.Status
	}{
		{http.StatusConflict, fuse.Status(syscall.EEXIST)},
		{http.StatusUnauthorized, fuse.Status(syscall.EACCES)},
		{http.StatusForbidden, fuse.Status(syscall.EACCES)},
		{http.StatusUpgradeRequired, fuse.Status(syscall.EIO)},
	} {
		t.Run(fmt.Sprintf("status_%d", tc.status), func(t *testing.T) {
			c, m := newTestCluster(t, 1)
			injectHTTPStatus(c, func(r *http.Request) bool { return r.URL.Path == "/files/small" }, tc.status)
			rpc := recordWriteRPCs(c)
			_, raw := namespaceFS(m)
			f := createNamespaceFile(t, raw, "conflict")
			want := bytes.Repeat([]byte{0x3c}, 512)
			f.write(t, want, 0)
			if status := f.flush(); status != tc.want {
				t.Fatalf("flush status=%v, want %v", status, tc.want)
			}
			calls := rpc.snapshot()
			if n := rpc.count("POST /files/small"); n != 1 || len(calls) != 1 {
				t.Fatalf("conflict must surface without fallback or retries, requests=%v", calls)
			}
			f.release()
		})
	}
}

func TestMountLazyStreamStartsAtFirstFullChunk(t *testing.T) {
	withChunkSize(t, 1024)
	c, m := newTestCluster(t, 1)
	m.NoSmallPath = true
	rpc := recordWriteRPCs(c)
	root, raw := namespaceFS(m)
	f := createNamespaceFile(t, raw, "stream")
	want := bytes.Repeat([]byte{0x7c}, 2300)
	f.write(t, want[512:1024], 512)
	if calls := rpc.snapshot(); len(calls) != 0 {
		t.Errorf("out-of-order fragment started a stream: %v", calls)
	}
	f.write(t, want[:256], 0)
	if calls := rpc.snapshot(); len(calls) != 0 {
		t.Errorf("partial first chunk started a stream: %v", calls)
	}
	f.write(t, want[256:512], 256)
	m.mu.Lock()
	w := m.writes["/stream"]
	m.mu.Unlock()
	w.mu.Lock()
	streaming, sent := w.stream != nil, w.sentIdx
	w.mu.Unlock()
	if !streaming || sent != 1024 || rpc.count("POST /files") != 1 {
		t.Fatalf("first full chunk not streamed: streaming=%v sent=%d calls=%v", streaming, sent, rpc.snapshot())
	}
	f.write(t, want[1024:], 1024)
	if status := f.flush(); status != fuse.OK {
		t.Fatal(status)
	}
	f.release()
	if rpc.count("POST /files") != 1 || rpc.count("POST /files/commit") != 1 || rpc.count("POST /files/small") != 0 {
		t.Errorf("stream requests=%v", rpc.snapshot())
	}
	checkNamespaceIdentity(t, root, raw, "stream", f.entry)
	verifySmallPathContent(t, c, "/stream", want)
}

func TestMountLazyStreamBeginFailureCanRetryFlush(t *testing.T) {
	withChunkSize(t, 1024)
	c, m := newTestCluster(t, 1)
	m.NoSmallPath = true
	failBegin := true
	injectNamespaceFailure(c, func(r *http.Request) bool {
		if r.Method == http.MethodPost && r.URL.Path == "/files" && failBegin {
			failBegin = false
			return true
		}
		return false
	})
	_, raw := namespaceFS(m)
	f := createNamespaceFile(t, raw, "retry")
	want := bytes.Repeat([]byte{0x8d}, 1536)
	_, status := raw.Write(nil, &fuse.WriteIn{
		InHeader: fuse.InHeader{NodeId: f.entry.NodeId}, Fh: f.fh, Size: uint32(len(want)),
	}, want)
	if status != fuse.EIO {
		t.Errorf("failed lazy begin status=%v, want EIO", status)
	}
	if status := f.flush(); status != fuse.OK {
		t.Fatal(status)
	}
	f.release()
	verifySmallPathContent(t, c, "/retry", want)
}

func TestMountLazyStreamCrossesSmallFileLimit(t *testing.T) {
	withChunkSize(t, types.SmallFileMax/2)
	c, m := newTestCluster(t, 1)
	rpc := recordWriteRPCs(c)
	_, raw := namespaceFS(m)
	f := createNamespaceFile(t, raw, "growing")
	want := bytes.Repeat([]byte{0x91}, int(types.SmallFileMax)+1)
	f.write(t, want[:types.SmallFileMax], 0)
	if calls := rpc.snapshot(); len(calls) != 0 {
		t.Errorf("small file started a stream despite staying within the limit: %v", calls)
	}
	f.write(t, want[types.SmallFileMax:], uint64(types.SmallFileMax))
	m.mu.Lock()
	w := m.writes["/growing"]
	m.mu.Unlock()
	w.mu.Lock()
	streaming, sent := w.stream != nil, w.sentIdx
	w.mu.Unlock()
	if !streaming || sent != types.SmallFileMax || rpc.count("POST /files") != 1 {
		t.Fatalf("growing file did not start streaming: streaming=%v sent=%d calls=%v", streaming, sent, rpc.snapshot())
	}
	if status := f.flush(); status != fuse.OK {
		t.Fatal(status)
	}
	f.release()
	if rpc.count("POST /files/commit") != 1 || rpc.count("POST /files/small") != 0 {
		t.Errorf("growing file requests=%v", rpc.snapshot())
	}
	verifySmallPathContent(t, c, "/growing", want)
}

func TestMountSmallFlushThenAppendUsesSmallRequests(t *testing.T) {
	c, m := newTestCluster(t, 1)
	rpc := recordWriteRPCs(c)
	_, raw := namespaceFS(m)
	f := createNamespaceFile(t, raw, "append")
	f.write(t, []byte("first"), 0)
	if status := f.flush(); status != fuse.OK {
		t.Fatal(status)
	}
	f.write(t, []byte(" second"), 5)
	if status := f.flush(); status != fuse.OK {
		t.Fatal(status)
	}
	f.release()
	if calls := rpc.snapshot(); len(calls) != 2 || rpc.count("POST /files/small") != 2 {
		t.Errorf("two small flushes requests=%v, want two small commits", calls)
	}
	in, _, err := c.Lookup("/append")
	if err != nil || in.Generation != 2 {
		t.Fatalf("second flush metadata=%+v err=%v", in, err)
	}
	verifySmallPathContent(t, c, "/append", []byte("first second"))
}

func TestMountLazyEmptyFileDoesNotAbortSession(t *testing.T) {
	c, m := newTestCluster(t, 1)
	rpc := recordWriteRPCs(c)
	root, raw := namespaceFS(m)
	f := createNamespaceFile(t, raw, "empty")
	if calls := rpc.snapshot(); len(calls) != 0 {
		t.Errorf("empty Create requests=%v", calls)
	}
	if status := f.flush(); status != fuse.OK {
		t.Fatal(status)
	}
	f.release()
	if rpc.count("POST /files") != 1 || rpc.count("POST /files/small") != 0 {
		t.Errorf("empty commit requests=%v", rpc.snapshot())
	}
	for _, call := range rpc.snapshot() {
		if strings.HasPrefix(call, "DELETE /files/staging/") {
			t.Errorf("empty create aborted an unused session: %v", rpc.snapshot())
		}
	}
	checkNamespaceIdentity(t, root, raw, "empty", f.entry)
	verifySmallPathContent(t, c, "/empty", nil)
}
