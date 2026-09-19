package master

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"atoll/pkg/types"
)

// P0-2: probeObject 只有 200/206 才算对象存在；401/500/503 一律判不存在。
func TestProbeObjectStrict(t *testing.T) {
	s := &Server{}
	cases := map[int]bool{
		http.StatusOK:                  true,
		http.StatusPartialContent:      true,
		http.StatusUnauthorized:        false,
		http.StatusInternalServerError: false,
		http.StatusServiceUnavailable:  false,
		http.StatusNotFound:            false,
	}
	for code, want := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
		}))
		addr := srv.URL[len("http://"):]
		got := s.probeObject(addr, 12345)
		srv.Close()
		if got != want {
			t.Errorf("status %d: probeObject=%v, want %v", code, got, want)
		}
	}
}

// P0-3: planRepairs 按去重节点计数——[5,5,1] Done=[5,1] 只有 2 个物理副本，
// 应判定需修复（产出修复任务），而不是被重复计数误判为满健康。
func TestPlanRepairsDedupsHealthy(t *testing.T) {
	now := time.Now()
	nodes := []types.NodeInfo{
		{ID: 1, Addr: "n1", LastHeartbeat: now, TotalBytes: 1 << 30},
		{ID: 5, Addr: "n5", LastHeartbeat: now, TotalBytes: 1 << 30},
		{ID: 9, Addr: "n9", LastHeartbeat: now, TotalBytes: 1 << 30}, // 可用新目标
	}
	in := types.Inode{
		ID: 100, Size: 10,
		Replicas:     []uint64{5, 5, 1},
		DoneReplicas: []uint64{5, 1},
	}
	tasks := planRepairs(in, nodes, 30*time.Second)
	if len(tasks) == 0 {
		t.Fatal("重复副本 [5,5,1] 只有 2 物理副本，应产出修复任务（去重计数）")
	}
	// 修复应指向一个不在副本集中的新节点（node 9）。
	foundNewTarget := false
	for _, tk := range tasks {
		if tk.Action == repairReplaceDead && tk.NewNodeID == 9 {
			foundNewTarget = true
		}
	}
	if !foundNewTarget {
		t.Fatalf("重复槽应换成新节点 9，实际任务: %+v", tasks)
	}
}

// 正常 3 副本全健康时不产任务（回归保护：去重逻辑没把正常情况也判成需修复）。
func TestPlanRepairsHealthyNoop(t *testing.T) {
	now := time.Now()
	nodes := []types.NodeInfo{
		{ID: 1, LastHeartbeat: now}, {ID: 2, LastHeartbeat: now}, {ID: 3, LastHeartbeat: now},
	}
	in := types.Inode{ID: 100, Replicas: []uint64{1, 2, 3}, DoneReplicas: []uint64{1, 2, 3}}
	if tasks := planRepairs(in, nodes, 30*time.Second); len(tasks) != 0 {
		t.Fatalf("全健康不应产任务，实际: %+v", tasks)
	}
}
