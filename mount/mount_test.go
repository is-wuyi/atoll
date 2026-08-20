package mount

import (
	"bytes"
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

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

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

// 内核挂载 e2e：需要 /dev/fuse；不可用（如无权限环境）则跳过。
// 覆盖：mkdir/写文件/读回/分段读/ls/rename/跨目录拒绝/rm/stat。
func TestKernelMount(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("/dev/fuse 不可用，跳过内核挂载测试")
	}
	c, m := newTestCluster(t, 2)

	mnt := t.TempDir()
	server, err := fs.Mount(mnt, m.Root(), &fs.Options{
		MountOptions: fuse.MountOptions{Name: "atoll-test"},
	})
	if err != nil {
		t.Skipf("挂载失败（环境不支持）: %v", err)
	}
	t.Cleanup(func() { server.Unmount() })

	// ---- 目录 ----
	if err := os.Mkdir(filepath.Join(mnt, "dir"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// ---- 写文件（Create→Write→Flush 整传）----
	content := []byte("kernel mounted atoll! 0123456789")
	if err := os.WriteFile(filepath.Join(mnt, "dir", "k.txt"), content, 0o644); err != nil {
		t.Fatalf("写文件: %v", err)
	}

	// ---- 读回（Range 读）----
	got, err := os.ReadFile(filepath.Join(mnt, "dir", "k.txt"))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("读回: %v %q", err, got)
	}

	// ---- 分段读（dd 式 offset 读取，验证 Range 逻辑）----
	f, err := os.Open(filepath.Join(mnt, "dir", "k.txt"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	buf := make([]byte, 6)
	if _, err := f.ReadAt(buf, 7); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(buf) != "mounted" {
		t.Fatalf("分段读: %q", buf)
	}
	f.Close()

	// ---- 覆盖写（Open O_TRUNC）----
	if err := os.WriteFile(filepath.Join(mnt, "dir", "k.txt"), []byte("short"), 0o644); err != nil {
		t.Fatalf("覆盖写: %v", err)
	}
	got2, _ := os.ReadFile(filepath.Join(mnt, "dir", "k.txt"))
	if string(got2) != "short" {
		t.Fatalf("覆盖后内容: %q", got2)
	}

	// ---- ls ----
	ents, err := os.ReadDir(filepath.Join(mnt, "dir"))
	if err != nil || len(ents) != 1 || ents[0].Name() != "k.txt" {
		t.Fatalf("ls: %v %+v", err, ents)
	}

	// ---- stat ----
	st, err := os.Stat(filepath.Join(mnt, "dir", "k.txt"))
	if err != nil || st.Size() != 5 || st.Mode().IsRegular() == false {
		t.Fatalf("stat: %v %+v", err, st)
	}

	// ---- rename 同目录 ----
	if err := os.Rename(filepath.Join(mnt, "dir", "k.txt"), filepath.Join(mnt, "dir", "k2.txt")); err != nil {
		t.Fatalf("rename: %v", err)
	}

	// ---- 跨目录 rename → EXDEV ----
	if err := os.Rename(filepath.Join(mnt, "dir", "k2.txt"), filepath.Join(mnt, "top.txt")); err == nil {
		t.Fatal("跨目录 rename 应失败（EXDEV）")
	}

	// ---- rm ----
	if err := os.Remove(filepath.Join(mnt, "dir", "k2.txt")); err != nil {
		t.Fatalf("remove: %v", err)
	}
	// ---- rmdir（空目录）----
	if err := os.Remove(filepath.Join(mnt, "dir")); err != nil {
		t.Fatalf("rmdir: %v", err)
	}

	// ---- 集群侧独立验证 ----
	if _, err := c.Lookup("/dir"); err == nil {
		t.Fatal("集群侧 /dir 应已删除")
	}

	// ---- 大文件 Range 读验证（512KB，跨多个读块）----
	big := bytes.Repeat([]byte("A"), 512*1024)
	if err := os.WriteFile(filepath.Join(mnt, "big.bin"), big, 0o644); err != nil {
		t.Fatalf("写大文件: %v", err)
	}
	bf, _ := os.Open(filepath.Join(mnt, "big.bin"))
	tail := make([]byte, 4096)
	if _, err := bf.ReadAt(tail, 500*1024); err != nil {
		t.Fatalf("大文件尾部分段读: %v", err)
	}
	if !bytes.Equal(tail, bytes.Repeat([]byte("A"), 4096)) {
		t.Fatal("大文件分段读内容不符")
	}
	bf.Close()
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
