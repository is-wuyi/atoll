package master

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"atoll/master/meta"
)

// 27348 事故复现：PUT 成功但节点→master 上报链断了（Done 全空）→
// 修复扫描的探测兜底应发现"对象在而未标 Done"，补标，下一轮触发 pull。
func TestRepairScanProbesUnmarkedDone(t *testing.T) {
	scanner, store := newTestScanner(t, time.Minute)
	nodeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// 该节点上对象确实存在：GET objects/* → 206
		w.WriteHeader(http.StatusPartialContent)
	}))
	t.Cleanup(nodeSrv.Close)

	n, err := store.RegisterNode(nodeSrv.Listener.Addr().String(), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	// staging 分块文件：两块副本，Done 全空（模拟上报链断了）。
	st, err := store.CreateStagingFile(meta.RootID)
	if err != nil {
		t.Fatal(err)
	}
	for idx := 0; idx < 2; idx++ {
		if _, err := store.AssignChunk(st.ID, idx, 100, []uint64{n.ID}, 0); err != nil {
			t.Fatal(err)
		}
		// 注意：不 MarkChunkDone —— 事故现场。
	}

	scanner.RepairScanOnce()

	// 补标后每块应有 1 个 Done（= 主副本节点）。
	in, err := store.GetInode(st.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range in.Chunks {
		if len(c.Done) == 0 {
			t.Fatalf("块 %d：对象在而未标 Done，探测兜底应补标", c.Index)
		}
	}
}

// 节点上对象不存在（真 404）时不得补标（保守承诺）。
func TestRepairScanNoFalseDone(t *testing.T) {
	scanner, store := newTestScanner(t, time.Minute)
	nodeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil) // 对象不存在
	}))
	t.Cleanup(nodeSrv.Close)

	n, _ := store.RegisterNode(nodeSrv.Listener.Addr().String(), 1<<30)
	st, _ := store.CreateStagingFile(meta.RootID)
	if _, err := store.AssignChunk(st.ID, 0, 100, []uint64{n.ID}, 0); err != nil {
		t.Fatal(err)
	}

	scanner.RepairScanOnce()

	in, _ := store.GetInode(st.ID)
	if len(in.Chunks[0].Done) != 0 {
		t.Fatal("对象 404 却被标 Done —— 会对 commit 做出虚假持久性承诺")
	}
}

// 节点不可达（网络错误）时不得补标。
func TestRepairScanNoDoneOnUnreachable(t *testing.T) {
	scanner, store := newTestScanner(t, time.Minute)
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusPartialContent)
	}))
	addr := dead.Listener.Addr().String()
	dead.Close() // 立即关闭 → 连接拒绝

	n, _ := store.RegisterNode(addr, 1<<30)
	st, _ := store.CreateStagingFile(meta.RootID)
	if _, err := store.AssignChunk(st.ID, 0, 100, []uint64{n.ID}, 0); err != nil {
		t.Fatal(err)
	}

	scanner.RepairScanOnce()

	in, _ := store.GetInode(st.ID)
	if len(in.Chunks[0].Done) != 0 {
		t.Fatal("节点不可达却标 Done —— 必须保守")
	}
}
