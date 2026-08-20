package mount

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"atoll/client"
	"atoll/master"
	"atoll/master/meta"
	atollnode "atoll/node"
)

// newTestCluster 拉起 httptest 集群（1 master + N node，真实注册）。
func newTestCluster(t *testing.T, numNodes int) (*client.Client, *Mount) {
	t.Helper()

	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	masterSrv := httptest.NewServer(master.NewServer(store, time.Hour).Handler())
	t.Cleanup(func() { masterSrv.Close() })

	for i := 0; i < numNodes; i++ {
		n := atollnode.New(filepath.Join(t.TempDir(), "data"), masterSrv.URL, "", 1<<30)
		nodeSrv := httptest.NewServer(n.Handler())
		t.Cleanup(func() { nodeSrv.Close() })

		body := fmt.Sprintf(`{"addr": %q, "total_bytes": 1073741824}`,
			nodeSrv.Listener.Addr().String())
		resp, err := http.Post(masterSrv.URL+"/nodes/register", "application/json", strings.NewReader(body))
		if err != nil || resp.StatusCode != http.StatusCreated {
			t.Fatalf("node 注册失败: %v status=%d", err, resp.StatusCode)
		}
		var reg struct {
			ID uint64 `json:"id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
			t.Fatalf("解析注册响应: %v", err)
		}
		resp.Body.Close()
		n.SetNodeIDForTest(reg.ID)
	}

	c := client.New(masterSrv.URL)
	m, err := New(c, filepath.Join(t.TempDir(), "cache"), numNodes)
	if err != nil {
		t.Fatalf("mount.New: %v", err)
	}
	return c, m
}

// 纯函数：candidateAddrs 的 done 优先语义。
func TestCandidateAddrs(t *testing.T) {
	reps := []client.Replica{
		{Addr: "a", Done: false},
		{Addr: "b", Done: true},
		{Addr: "c", Done: true},
		{Addr: "d", Done: false},
	}
	for i := 0; i < 20; i++ { // 随机打散下 done 组内顺序会变，但组间次序不变
		got := candidateAddrs(reps)
		if len(got) != 4 {
			t.Fatalf("长度: %v", got)
		}
		set := map[string]bool{got[0]: true, got[1]: true}
		if !set["b"] || !set["c"] {
			t.Fatalf("done 副本应排前: %v", got)
		}
	}
}

// 纯函数：mapErrno 错误映射。
func TestMapErrno(t *testing.T) {
	cases := []struct {
		msg  string
		want syscall.Errno
	}{
		{"http 404: path not found", syscall.ENOENT},
		{"http 409: already exists", syscall.EEXIST},
		{"http 400: directory not empty", syscall.ENOTEMPTY},
		{"http 500: boom", syscall.EIO},
	}
	for _, c := range cases {
		if got := mapErrno(fmt.Errorf("%s", c.msg)); got != c.want {
			t.Errorf("mapErrno(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
}

// 内核挂载 e2e 测试在 mount_fuse_test.go 中（需要 //go:build fuse）。
// 运行方式: go test -tags fuse -run TestKernelMount ./mount/