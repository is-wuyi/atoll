package mount

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// 纯函数：candidateReplicas 的 done 优先语义（保留节点 ID 供损坏上报）。
func TestCandidateReplicas(t *testing.T) {
	reps := []client.Replica{
		{ID: 1, Addr: "a", Done: false},
		{ID: 2, Addr: "b", Done: true},
		{ID: 3, Addr: "c", Done: true},
		{ID: 4, Addr: "d", Done: false},
	}
	for i := 0; i < 20; i++ { // 随机打散下 done 组内顺序会变，但组间次序不变
		got := candidateReplicas(reps)
		if len(got) != 4 {
			t.Fatalf("长度: %v", got)
		}
		set := map[uint64]bool{got[0].ID: true, got[1].ID: true}
		if !set[2] || !set[3] {
			t.Fatalf("done 副本应排前: %v", got)
		}
		if got[0].ID == 0 {
			t.Fatalf("候选必须保留节点 ID: %v", got)
		}
	}
}

// 纯函数：mapErrno 按 HTTP 状态码映射（传输层错误一律 EIO，不臆断 ENOENT）。
func TestMapErrno(t *testing.T) {
	cases := []struct {
		err  error
		want syscall.Errno
	}{
		{&client.HTTPError{StatusCode: 404, Message: "path not found"}, syscall.ENOENT},
		{&client.HTTPError{StatusCode: 409, Message: "already exists"}, syscall.EEXIST},
		{&client.HTTPError{StatusCode: 400, Message: "directory not empty"}, syscall.ENOTEMPTY},
		{&client.HTTPError{StatusCode: 401, Message: "unauthorized"}, syscall.EACCES},
		{&client.HTTPError{StatusCode: 507, Message: "no space"}, syscall.ENOSPC},
		{&client.HTTPError{StatusCode: 500, Message: "boom"}, syscall.EIO},
		{fmt.Errorf("dial tcp: i/o timeout"), syscall.EIO},         // 传输错误 → EIO
		{fmt.Errorf("lookup host: server not found"), syscall.EIO}, // 含 "not found" 也不误判 ENOENT
	}
	for _, c := range cases {
		if got := mapErrno(c.err); got != c.want {
			t.Errorf("mapErrno(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

// 内核挂载 e2e 测试在 mount_fuse_test.go 中（需要 //go:build fuse）。
// 运行方式: go test -tags fuse -run TestKernelMount ./mount/