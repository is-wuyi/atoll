package master

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/types"
)

// newTestServer 启动一个内存态 master（临时 bbolt + httptest）。
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	srv := NewServer(store, time.Hour) // 测试里节点心跳 1 小时内都算存活
	srv.SetCommitWait(200 * time.Millisecond) // min_copies 测试不阻塞在 20s 默认等待
	srv.SetHealthProbe(func(string) bool { return true }) // 假地址节点无 /healthz，桩为始终可达
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close() })
	return ts
}

// postJSON 发送 JSON POST 并解析响应到 out。
func postJSON(t *testing.T, url string, body, out any) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewReader(mustJSON(t, body)))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("解码响应失败: %v", err)
		}
	}
	return resp
}

func getJSON(t *testing.T, url string, out any) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("解码响应失败: %v", err)
		}
	}
	return resp
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// registerNode 注册一个存储节点。
func registerNode(t *testing.T, base string, i int) uint64 {
	t.Helper()
	var node struct {
		ID uint64 `json:"id"`
	}
	resp := postJSON(t, base+"/nodes/register", map[string]any{
		"addr":        fmt.Sprintf("127.0.0.1:900%d", i),
		"total_bytes": 1 << 30,
	}, &node)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("注册节点状态码 = %d", resp.StatusCode)
	}
	return node.ID
}

func TestHealthz(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz = %d", resp.StatusCode)
	}
}

func TestNodeRegisterAndHeartbeat(t *testing.T) {
	ts := newTestServer(t)
	id := registerNode(t, ts.URL, 1)
	if id == 0 {
		t.Fatal("节点 ID 为 0")
	}
	resp := postJSON(t, ts.URL+"/nodes/heartbeat", map[string]any{
		"node_id": id, "used_bytes": 100,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("心跳状态码 = %d", resp.StatusCode)
	}
}

func TestCreateFileAllocatesReplicas(t *testing.T) {
	ts := newTestServer(t)
	registerNode(t, ts.URL, 1)
	registerNode(t, ts.URL, 2)

	var out struct {
		Inode struct {
			ID   uint64 `json:"id"`
			Name string `json:"name"`
		} `json:"inode"`
		Nodes []struct {
			ID uint64 `json:"id"`
		} `json:"nodes"`
	}
	resp := postJSON(t, ts.URL+"/files", map[string]any{
		"path": "/a.txt", "replicas": 2,
	}, &out)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("创建文件状态码 = %d", resp.StatusCode)
	}
	if out.Inode.Name != "a.txt" {
		t.Fatalf("文件名 = %s", out.Inode.Name)
	}
	if len(out.Nodes) != 2 {
		t.Fatalf("分配节点数 = %d, want 2", len(out.Nodes))
	}
}

func TestCreateFileNotEnoughNodes(t *testing.T) {
	ts := newTestServer(t)
	registerNode(t, ts.URL, 1) // 只有 1 个节点
	resp := postJSON(t, ts.URL+"/files", map[string]any{
		"path": "/a.txt", "replicas": 3,
	}, nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("节点不足应返回 503, got %d", resp.StatusCode)
	}
}

func TestMkdirAndListChildren(t *testing.T) {
	ts := newTestServer(t)
	resp := postJSON(t, ts.URL+"/dirs", map[string]any{"path": "/docs"}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("mkdir 状态码 = %d", resp.StatusCode)
	}
	registerNode(t, ts.URL, 1)
	postJSON(t, ts.URL+"/files", map[string]any{"path": "/docs/a.txt"}, nil)

	var kids []struct {
		Name string `json:"name"`
		Type uint8  `json:"type"`
	}
	resp = getJSON(t, ts.URL+"/dirs/children?path=/docs", &kids)
	if resp.StatusCode != http.StatusOK || len(kids) != 1 || kids[0].Name != "a.txt" {
		t.Fatalf("列目录结果不符: code=%d kids=%+v", resp.StatusCode, kids)
	}
}

func TestLookupReturnsNodeAddrs(t *testing.T) {
	ts := newTestServer(t)
	registerNode(t, ts.URL, 1)
	postJSON(t, ts.URL+"/files", map[string]any{"path": "/a.txt", "replicas": 1}, nil)

	var out struct {
		Inode struct {
			ID   uint64 `json:"id"`
			Type uint8  `json:"type"`
		} `json:"inode"`
		Nodes []struct {
			ID   uint64 `json:"id"`
			Addr string `json:"addr"`
		} `json:"nodes"`
	}
	resp := getJSON(t, ts.URL+"/meta?path=/a.txt", &out)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lookup 状态码 = %d", resp.StatusCode)
	}
	if len(out.Nodes) != 1 || out.Nodes[0].Addr == "" {
		t.Fatalf("lookup 应返回节点地址: %+v", out)
	}
}

// 覆盖写节点不足时不得删旧文件：先校验可用性、再动旧文件。
// 回归：此前先 DeleteFile 再查节点，节点不足返回 503 时旧文件已丢。
func TestLegacyOverwriteInsufficientNodesKeepsOld(t *testing.T) {
	ts := newTestServer(t)
	registerNode(t, ts.URL, 1) // 只有 1 个节点

	if resp := postJSON(t, ts.URL+"/files", map[string]any{"path": "/a.txt", "replicas": 1}, nil); resp.StatusCode != http.StatusCreated {
		t.Fatalf("建文件状态码 = %d", resp.StatusCode)
	}
	// 覆盖写要 2 副本、只有 1 个节点 → 必须 503。
	resp := postJSON(t, ts.URL+"/files", map[string]any{"path": "/a.txt", "replicas": 2, "overwrite": true}, nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("节点不足的覆盖写应 503, got %d", resp.StatusCode)
	}
	// 关键：旧文件必须还在（没被 503 顺手删掉）。
	if r := getJSON(t, ts.URL+"/meta?path=/a.txt", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("覆盖失败后旧文件应仍在, /meta 状态码 = %d", r.StatusCode)
	}
}

// TestLegacyOverwriteDefersOldDeletionUntilCommit 覆盖写失败不得丢旧数据：
// POST /files?overwrite 只建 staging 新版本、绝不在此刻删旧；旧文件必须一直可解析，
// 直到新版本 commit 成功才原子替换。此前 create 阶段就 DeleteFile+回收旧对象，
// 上传若随后失败（节点拒收/掉线）旧数据即永久丢失（本测试在修复前必失败）。
func TestLegacyOverwriteDefersOldDeletionUntilCommit(t *testing.T) {
	ts := newTestServer(t)
	registerNode(t, ts.URL, 1)

	// 先放一个已提交的旧版本。
	var oldCreate struct {
		Inode struct {
			ID uint64 `json:"id"`
		} `json:"inode"`
	}
	postJSON(t, ts.URL+"/files", map[string]any{"path": "/a.txt", "replicas": 1}, &oldCreate)
	oldID := oldCreate.Inode.ID
	if resp := postJSON(t, ts.URL+"/files/commit", map[string]any{"inode_id": oldID, "size": 1024}, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("旧版本 commit 状态码 = %d", resp.StatusCode)
	}

	// 覆盖写：只建 staging 新版本，返回的 inode ID 应不同于旧版本。
	var ow struct {
		Inode struct {
			ID      uint64 `json:"id"`
			Staging bool   `json:"staging"`
		} `json:"inode"`
	}
	if resp := postJSON(t, ts.URL+"/files", map[string]any{"path": "/a.txt", "replicas": 1, "overwrite": true}, &ow); resp.StatusCode != http.StatusCreated {
		t.Fatalf("覆盖写建 staging 状态码 = %d", resp.StatusCode)
	}
	newID := ow.Inode.ID
	if newID == oldID {
		t.Fatalf("覆盖写应分配新的 staging inode，仍是旧 ID %d", oldID)
	}

	// 关键断言：commit 之前，/a.txt 必须仍解析到旧版本（旧数据未被动过）。
	var mid struct {
		Inode struct {
			ID   uint64 `json:"id"`
			Size int64  `json:"size"`
		} `json:"inode"`
	}
	if r := getJSON(t, ts.URL+"/meta?path=/a.txt", &mid); r.StatusCode != http.StatusOK {
		t.Fatalf("覆盖写 commit 前旧文件应仍在, /meta 状态码 = %d", r.StatusCode)
	}
	if mid.Inode.ID != oldID || mid.Inode.Size != 1024 {
		t.Fatalf("commit 前应仍是旧版本 (ID=%d size=1024)，实际 ID=%d size=%d", oldID, mid.Inode.ID, mid.Inode.Size)
	}

	// 模拟上传失败 → 放弃 staging。旧文件必须原样幸存。
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/files/staging/"+fmt.Sprintf("%d", newID), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("abort staging: %v", err)
	}
	resp.Body.Close()
	var afterAbort struct {
		Inode struct {
			ID   uint64 `json:"id"`
			Size int64  `json:"size"`
		} `json:"inode"`
	}
	if r := getJSON(t, ts.URL+"/meta?path=/a.txt", &afterAbort); r.StatusCode != http.StatusOK {
		t.Fatalf("覆盖失败后旧文件应仍在, /meta 状态码 = %d", r.StatusCode)
	}
	if afterAbort.Inode.ID != oldID || afterAbort.Inode.Size != 1024 {
		t.Fatalf("覆盖失败后应完好保留旧版本 (ID=%d size=1024)，实际 ID=%d size=%d", oldID, afterAbort.Inode.ID, afterAbort.Inode.Size)
	}

	// 成功路径：再覆盖一次并 commit，此时才原子替换为新版本。
	var ow2 struct {
		Inode struct {
			ID uint64 `json:"id"`
		} `json:"inode"`
	}
	postJSON(t, ts.URL+"/files", map[string]any{"path": "/a.txt", "replicas": 1, "overwrite": true}, &ow2)
	if resp := postJSON(t, ts.URL+"/files/commit", map[string]any{"inode_id": ow2.Inode.ID, "size": 2048}, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("覆盖 commit 状态码 = %d", resp.StatusCode)
	}
	var final struct {
		Inode struct {
			ID   uint64 `json:"id"`
			Size int64  `json:"size"`
		} `json:"inode"`
	}
	getJSON(t, ts.URL+"/meta?path=/a.txt", &final)
	if final.Inode.ID != ow2.Inode.ID || final.Inode.Size != 2048 {
		t.Fatalf("commit 后应替换为新版本 (ID=%d size=2048)，实际 ID=%d size=%d", ow2.Inode.ID, final.Inode.ID, final.Inode.Size)
	}
}

func TestCommitUpdatesSize(t *testing.T) {
	ts := newTestServer(t)
	registerNode(t, ts.URL, 1)
	var created struct {
		Inode struct {
			ID uint64 `json:"id"`
		} `json:"inode"`
	}
	postJSON(t, ts.URL+"/files", map[string]any{"path": "/a.txt"}, &created)

	resp := postJSON(t, ts.URL+"/files/commit", map[string]any{
		"inode_id": created.Inode.ID, "size": 4096,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("commit 状态码 = %d", resp.StatusCode)
	}

	var out struct {
		Inode struct {
			Size     int64   `json:"size"`
			Replicas []uint64 `json:"replicas"`
		} `json:"inode"`
	}
	getJSON(t, ts.URL+"/meta?path=/a.txt", &out)
	if out.Inode.Size != 4096 {
		t.Fatalf("size = %d, want 4096", out.Inode.Size)
	}
	if len(out.Inode.Replicas) != 1 {
		t.Fatalf("commit 不应清空副本列表: %+v", out.Inode)
	}
}

func TestDeleteFile(t *testing.T) {
	ts := newTestServer(t)
	registerNode(t, ts.URL, 1)
	postJSON(t, ts.URL+"/files", map[string]any{"path": "/a.txt"}, nil)

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/entry?path=/a.txt", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("删除状态码 = %d", resp.StatusCode)
	}
	resp2 := getJSON(t, ts.URL+"/meta?path=/a.txt", nil)
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("删除后 lookup 应 404, got %d", resp2.StatusCode)
	}
}

func TestInvalidPathRejected(t *testing.T) {
	ts := newTestServer(t)
	resp := postJSON(t, ts.URL+"/dirs", map[string]any{"path": "/"}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("根目录创建应 400, got %d", resp.StatusCode)
	}
}

// 阶段2：replica-targets 查询（跳过自己与已完成节点）+ replicated 上报。
func TestReplicaTargetsAndReplicated(t *testing.T) {
	ts := newTestServer(t)
	n1 := registerNode(t, ts.URL, 1)
	n2 := registerNode(t, ts.URL, 2)
	registerNode(t, ts.URL, 3)

	// 3 副本文件。
	var created struct {
		Inode struct {
			ID uint64 `json:"id"`
		} `json:"inode"`
	}
	postJSON(t, ts.URL+"/files", map[string]any{"path": "/r.bin", "replicas": 3}, &created)
	id := created.Inode.ID

	// n1 视角：目标应是 n2、n3（不含自己）。
	var targets []struct {
		ID   uint64 `json:"id"`
		Addr string `json:"addr"`
	}
	resp := getJSON(t, ts.URL+fmt.Sprintf("/files/replica-targets?inode_id=%d&node_id=%d", id, n1), &targets)
	if resp.StatusCode != http.StatusOK || len(targets) != 2 {
		t.Fatalf("replica-targets = %d 个目标 (status %d), want 2", len(targets), resp.StatusCode)
	}
	for _, tg := range targets {
		if tg.ID == n1 || tg.Addr == "" {
			t.Fatalf("目标不应包含自己或空地址: %+v", tg)
		}
	}

	// commit（主副本完成）后，n2 上报同步完成。
	postJSON(t, ts.URL+"/files/commit", map[string]any{"inode_id": id, "size": 10}, nil)
	postJSON(t, ts.URL+"/files/replicated", map[string]any{"inode_id": id, "node_id": n2}, nil)

	// 重新查询元数据，动态计算 n1 视角的期望目标：
	// 全部副本 - 自己(n1) - 已完成(DoneReplicas)。分配是随机 shuffle 的，不能硬编码。
	var meta2 struct {
		Inode struct {
			Replicas     []uint64 `json:"replicas"`
			DoneReplicas []uint64 `json:"done_replicas"`
		} `json:"inode"`
	}
	getJSON(t, ts.URL+"/meta?path=/r.bin", &meta2)
	doneSet := map[uint64]bool{}
	for _, d := range meta2.Inode.DoneReplicas {
		doneSet[d] = true
	}
	var want []uint64
	for _, r := range meta2.Inode.Replicas {
		if r != n1 && !doneSet[r] {
			want = append(want, r)
		}
	}
	resp = getJSON(t, ts.URL+fmt.Sprintf("/files/replica-targets?inode_id=%d&node_id=%d", id, n1), &targets)
	if resp.StatusCode != http.StatusOK || len(targets) != len(want) {
		t.Fatalf("目标数 = %d (status %d), 期望 %d 个: %+v", len(targets), resp.StatusCode, len(want), targets)
	}
	gotSet := map[uint64]bool{}
	for _, tg := range targets {
		gotSet[tg.ID] = true
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Fatalf("期望目标 %d 不在结果中: %+v", w, targets)
		}
	}

	// lookup 应正确标注 done：完成集合 = {主副本, n2}。
	var out struct {
		Inode struct {
			Replicas     []uint64 `json:"replicas"`
			DoneReplicas []uint64 `json:"done_replicas"`
		} `json:"inode"`
		Nodes []struct {
			ID   uint64 `json:"id"`
			Done bool   `json:"done"`
		} `json:"nodes"`
	}
	getJSON(t, ts.URL+"/meta?path=/r.bin", &out)
	primary := out.Inode.Replicas[0] // commit 标记的是主副本
	wantDone := map[uint64]bool{primary: true, n2: true}
	for _, nd := range out.Nodes {
		if nd.Done != wantDone[nd.ID] {
			t.Fatalf("节点 %d done=%v, 期望 %v", nd.ID, nd.Done, wantDone[nd.ID])
		}
	}
}

func TestCreateFileOverwrite(t *testing.T) {
	// 场景 1：覆盖成功 — 创建 /a.txt → 覆写建 staging → commit 后 /meta 返回新 inode / 新 size。
	// 覆盖语义已改：新版本先进 staging，commit 才原子替换旧版本（防覆盖失败丢旧数据）。
	t.Run("OverwriteSuccess", func(t *testing.T) {
		ts := newTestServer(t)
		registerNode(t, ts.URL, 1)

		// 首次创建。
		var first struct {
			Inode struct {
				ID uint64 `json:"id"`
			} `json:"inode"`
		}
		resp := postJSON(t, ts.URL+"/files", map[string]any{
			"path": "/a.txt", "replicas": 1,
		}, &first)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("首次创建状态码 = %d", resp.StatusCode)
		}
		oldID := first.Inode.ID

		// commit 写入一些数据。
		postJSON(t, ts.URL+"/files/commit", map[string]any{
			"inode_id": oldID, "size": 100,
		}, nil)

		// 覆写：得到一个新的 staging inode（此刻旧版本仍在）。
		var overwritten struct {
			Inode struct {
				ID   uint64 `json:"id"`
				Size int64  `json:"size"`
			} `json:"inode"`
		}
		resp = postJSON(t, ts.URL+"/files", map[string]any{
			"path": "/a.txt", "overwrite": true, "replicas": 1,
		}, &overwritten)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("覆写状态码 = %d", resp.StatusCode)
		}
		if overwritten.Inode.ID == oldID {
			t.Fatalf("覆写后 inode ID 应变化: 旧 %d == 新 %d", oldID, overwritten.Inode.ID)
		}

		// commit 新版本，原子替换旧版本。
		if resp = postJSON(t, ts.URL+"/files/commit", map[string]any{
			"inode_id": overwritten.Inode.ID, "size": 42,
		}, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("覆写 commit 状态码 = %d", resp.StatusCode)
		}

		// 验证 /meta 返回的是新 inode 与新 size。
		var out struct {
			Inode struct {
				ID   uint64 `json:"id"`
				Size int64  `json:"size"`
			} `json:"inode"`
		}
		resp = getJSON(t, ts.URL+"/meta?path=/a.txt", &out)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("lookup 状态码 = %d", resp.StatusCode)
		}
		if out.Inode.ID != overwritten.Inode.ID {
			t.Fatalf("meta 返回旧 inode: got %d, want %d", out.Inode.ID, overwritten.Inode.ID)
		}
		if out.Inode.Size != 42 {
			t.Fatalf("覆写 commit 后 size 应为 42, got %d", out.Inode.Size)
		}
	})

	// 场景 2：不带 overwrite 仍返回 409。
	t.Run("ConflictWithoutOverwrite", func(t *testing.T) {
		ts := newTestServer(t)
		registerNode(t, ts.URL, 1)

		postJSON(t, ts.URL+"/files", map[string]any{
			"path": "/b.txt", "replicas": 1,
		}, nil)

		// 不带 overwrite 再次创建同一路径。
		resp := postJSON(t, ts.URL+"/files", map[string]any{
			"path": "/b.txt", "replicas": 1,
		}, nil)
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("重复创建应 409, got %d", resp.StatusCode)
		}
	})

	// 场景 3：覆写后旧 inode 在元数据中不存在。
	// 场景 3：覆写并 commit 后，旧 inode 在元数据中不存在（commit 前旧 inode 仍在）。
	t.Run("OldInodeGone", func(t *testing.T) {
		store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
		if err != nil {
			t.Fatalf("meta.Open: %v", err)
		}
		t.Cleanup(func() { store.Close() })
		srv := NewServer(store, time.Hour)
		srv.SetHealthProbe(func(string) bool { return true })
		ts := httptest.NewServer(srv.Handler())
		t.Cleanup(func() { ts.Close() })

		registerNode(t, ts.URL, 1)

		// 首次创建。
		var first struct {
			Inode struct {
				ID uint64 `json:"id"`
			} `json:"inode"`
		}
		postJSON(t, ts.URL+"/files", map[string]any{
			"path": "/a.txt", "replicas": 1,
		}, &first)
		oldID := first.Inode.ID

		// 覆写建 staging。commit 前旧 inode 必须仍在（覆盖失败不丢旧数据）。
		var ow struct {
			Inode struct {
				ID uint64 `json:"id"`
			} `json:"inode"`
		}
		postJSON(t, ts.URL+"/files", map[string]any{
			"path": "/a.txt", "overwrite": true, "replicas": 1,
		}, &ow)
		if _, err = store.GetInode(oldID); err != nil {
			t.Fatalf("commit 前旧 inode %d 应仍在: %v", oldID, err)
		}

		// commit 新版本 → 原子替换，旧 inode 应被删除。
		postJSON(t, ts.URL+"/files/commit", map[string]any{
			"inode_id": ow.Inode.ID, "size": 7,
		}, nil)
		if _, err = store.GetInode(oldID); err == nil {
			t.Fatalf("commit 后旧 inode %d 应已被删除", oldID)
		}
	})
}

// TestSymlinkEndpoint 符号链接 API：POST /files/symlink 创建（201、元数据含 target）、
// 重复 409、父目录缺失 404、DELETE /entry 删除。Finder 拷贝含符号链接的目录必走此路径
//（rustfs 事故：.claude/skills -> ../.agents/skills）。
func TestSymlinkEndpoint(t *testing.T) {
	ts := newTestServer(t)

	var out struct {
		Inode struct {
			ID     uint64 `json:"id"`
			Type   int    `json:"type"`
			Target string `json:"target"`
		} `json:"inode"`
	}
	resp := postJSON(t, ts.URL+"/files/symlink", map[string]any{"path": "/lnk", "target": "../d/file.txt"}, &out)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("创建符号链接状态码 = %d", resp.StatusCode)
	}
	if out.Inode.Target != "../d/file.txt" {
		t.Fatalf("响应 target = %q", out.Inode.Target)
	}

	// /meta 能查到，类型为符号链接且带 target。
	var meta struct {
		Inode struct {
			Type   int    `json:"type"`
			Target string `json:"target"`
		} `json:"inode"`
	}
	getJSON(t, ts.URL+"/meta?path=/lnk", &meta)
	if meta.Inode.Type != int(types.TypeSymlink) || meta.Inode.Target != "../d/file.txt" {
		t.Fatalf("meta 不符: type=%d target=%q", meta.Inode.Type, meta.Inode.Target)
	}

	// 重复创建 → 409。
	if resp := postJSON(t, ts.URL+"/files/symlink", map[string]any{"path": "/lnk", "target": "x"}, nil); resp.StatusCode != http.StatusConflict {
		t.Fatalf("重复创建应 409, got %d", resp.StatusCode)
	}
	// 父目录缺失 → 404。
	if resp := postJSON(t, ts.URL+"/files/symlink", map[string]any{"path": "/no/such/lnk", "target": "x"}, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("父目录缺失应 404, got %d", resp.StatusCode)
	}
	// 空 target → 400。
	if resp := postJSON(t, ts.URL+"/files/symlink", map[string]any{"path": "/lnk2", "target": ""}, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("空 target 应 400, got %d", resp.StatusCode)
	}

	// 删除（DELETE /entry 与文件同路径）→ 200，随后 404。
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/entry?path=/lnk", nil)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("删除符号链接状态码 = %d", resp2.StatusCode)
	}
	if r := getJSON(t, ts.URL+"/meta?path=/lnk", nil); r.StatusCode != http.StatusNotFound {
		t.Fatalf("删除后应 404, got %d", r.StatusCode)
	}
}

func TestSplitPath(t *testing.T) {
	cases := []struct{ in, parent, name string }{
		{"/a/b/c.txt", "/a/b", "c.txt"},
		{"/a", "/", "a"},
		{"a", "/", "a"},
		{"/a/", "/", "a"},
	}
	for _, c := range cases {
		p, n := splitPath(c.in)
		if p != c.parent || n != c.name {
			t.Errorf("splitPath(%q) = (%q, %q), want (%q, %q)", c.in, p, n, c.parent, c.name)
		}
	}
}
