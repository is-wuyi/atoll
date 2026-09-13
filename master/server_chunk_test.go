package master

import (
	"net/http"
	"strconv"
	"testing"

	"atoll/pkg/types"
)

// stagingCreate POST /files（chunked=true）创建 staging inode。
func stagingCreate(t *testing.T, base, path string, overwrite bool) types.Inode {
	t.Helper()
	var out struct {
		Inode types.Inode `json:"inode"`
	}
	body := map[string]any{"path": path, "chunked": true, "overwrite": overwrite, "replicas": 2}
	resp := postJSON(t, base+"/files", body, &out)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("staging 创建状态码 = %d", resp.StatusCode)
	}
	if !out.Inode.Staging || !out.Inode.Chunked {
		t.Fatalf("staging inode 字段不符: %+v", out.Inode)
	}
	return out.Inode
}

// assignChunk POST /files/chunks，返回块分配与状态码。
func assignChunk(t *testing.T, base string, inodeID uint64, index int, size int64, reassign bool) (types.ChunkInfo, int) {
	t.Helper()
	var out chunkAssignResp
	resp := postJSON(t, base+"/files/chunks", map[string]any{
		"inode_id": inodeID, "index": index, "size": size, "replicas": 2, "reassign": reassign,
	}, &out)
	return out.Chunk, resp.StatusCode
}

// chunked 全链路：staging → assign → markDone → commit 原子换名 → lookup 块表。
func TestChunkedUploadFlow(t *testing.T) {
	ts := newTestServer(t)
	registerNode(t, ts.URL, 1)
	registerNode(t, ts.URL, 2)

	// 先放一个旧版本（legacy 整文件模型）。
	postJSON(t, ts.URL+"/files", map[string]any{"path": "/f.bin", "replicas": 1}, nil)

	// staging + 两块。
	st := stagingCreate(t, ts.URL, "/f.bin", true)
	c0, code := assignChunk(t, ts.URL, st.ID, 0, 64<<20, false)
	if code != http.StatusOK {
		t.Fatalf("assign chunk0 状态码 = %d", code)
	}
	c1, code := assignChunk(t, ts.URL, st.ID, 1, 1000, false)
	if code != http.StatusOK {
		t.Fatalf("assign chunk1 状态码 = %d", code)
	}
	// 幂等：重复 assign 返回同一分配。
	c1b, _ := assignChunk(t, ts.URL, st.ID, 1, 1000, false)
	if c1b.Replicas[0] != c1.Replicas[0] {
		t.Fatalf("重复 assign 不幂等: %+v vs %+v", c1, c1b)
	}
	if len(c0.Replicas) != 2 || len(c1.Replicas) != 2 {
		t.Fatalf("块副本数不符: %+v %+v", c0, c1)
	}

	// staging 期间路径不可见（仍指向旧版本、非 chunked）。
	var before struct {
		Inode struct {
			Chunked bool `json:"chunked"`
		} `json:"inode"`
	}
	resp := getJSON(t, ts.URL+"/meta?path=/f.bin", &before)
	if resp.StatusCode != http.StatusOK || before.Inode.Chunked {
		t.Fatalf("staging 期间路径应仍指旧版本: code=%d chunked=%v", resp.StatusCode, before.Inode.Chunked)
	}

	// 模拟两个块的主副本节点上报落盘完成（走 /files/replicated，传 chunkID）。
	postJSON(t, ts.URL+"/files/replicated", map[string]any{
		"inode_id": types.ChunkID(st.ID, 0), "node_id": c0.Replicas[0]}, nil)
	postJSON(t, ts.URL+"/files/replicated", map[string]any{
		"inode_id": types.ChunkID(st.ID, 1), "node_id": c1.Replicas[0]}, nil)

	// commit：单事务原子换名。
	var committed types.Inode
	resp = postJSON(t, ts.URL+"/files/commit", map[string]any{
		"inode_id": st.ID, "name": "f.bin", "size": (64 << 20) + 1000, "chunk_count": 2,
	}, &committed)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("commit 状态码 = %d", resp.StatusCode)
	}
	// lookup 现在返回新分块 inode（chunked=true；nodes 为全部块副本节点地址表）。
	var after struct {
		Inode types.Inode `json:"inode"`
		Nodes []struct {
			ID   uint64 `json:"id"`
			Addr string `json:"addr"`
		} `json:"nodes"`
	}
	getJSON(t, ts.URL+"/meta?path=/f.bin", &after)
	if !after.Inode.Chunked || after.Inode.ID != st.ID || after.Inode.Size != (64<<20)+1000 {
		t.Fatalf("commit 后 lookup 不符: %+v", after.Inode)
	}
	// 两块副本节点（去重后）都应在地址表里（客户端靠它把块表的 nodeID 解析成 addr）。
	if len(after.Nodes) != 2 {
		t.Fatalf("chunked 文件应返回 2 个块副本节点地址, got %+v", after.Nodes)
	}
	for _, nd := range after.Nodes {
		if nd.Addr == "" {
			t.Fatalf("节点地址为空: %+v", nd)
		}
	}
	if len(after.Inode.Chunks) != 2 || after.Inode.Chunks[1].Size != 1000 {
		t.Fatalf("块表不符: %+v", after.Inode.Chunks)
	}
	// 块 Done 状态已持久化在元数据中。
	if !chunkDoneByNode(after.Inode.Chunks[0], c0.Replicas[0]) {
		t.Fatalf("chunk0 主副本 Done 未记录: %+v", after.Inode.Chunks[0])
	}
}

func chunkDoneByNode(c types.ChunkInfo, nodeID uint64) bool {
	for _, d := range c.Done {
		if d == nodeID {
			return true
		}
	}
	return false
}

// commit 前主副本未 Done → 拒绝。
func TestChunkedCommitRejectedWithoutPrimaryDone(t *testing.T) {
	ts := newTestServer(t)
	registerNode(t, ts.URL, 1)
	registerNode(t, ts.URL, 2)

	postJSON(t, ts.URL+"/files", map[string]any{"path": "/g.bin", "replicas": 1}, nil)
	st := stagingCreate(t, ts.URL, "/g.bin", true)
	if _, code := assignChunk(t, ts.URL, st.ID, 0, 100, false); code != http.StatusOK {
		t.Fatalf("assign 状态码 = %d", code)
	}
	resp := postJSON(t, ts.URL+"/files/commit", map[string]any{
		"inode_id": st.ID, "name": "g.bin", "size": 100, "chunk_count": 1,
	}, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("主副本未 Done 的 commit 应 409, got %d", resp.StatusCode)
	}
}

// abort：staging 元数据消失；重复 abort 404。
func TestChunkedAbort(t *testing.T) {
	ts := newTestServer(t)
	registerNode(t, ts.URL, 1)
	st := stagingCreate(t, ts.URL, "/h.bin", false)
	assignChunk(t, ts.URL, st.ID, 0, 100, false)

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/files/staging/"+strconv.FormatUint(st.ID, 10), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("abort 状态码 = %d err=%v", resp.StatusCode, err)
	}
	// 再 abort：inode 已删，404。
	req2, _ := http.NewRequest(http.MethodDelete, ts.URL+"/files/staging/"+strconv.FormatUint(st.ID, 10), nil)
	resp2, _ := http.DefaultClient.Do(req2)
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("重复 abort 应 404, got %d", resp2.StatusCode)
	}
}

// 不带 overwrite 的 chunked 创建，同名文件已存在 → 409（避免白传整个文件）。
func TestChunkedCreateConflictWithoutOverwrite(t *testing.T) {
	ts := newTestServer(t)
	registerNode(t, ts.URL, 1)
	postJSON(t, ts.URL+"/files", map[string]any{"path": "/x.bin", "replicas": 1}, nil)
	resp := postJSON(t, ts.URL+"/files", map[string]any{"path": "/x.bin", "chunked": true, "replicas": 2}, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("无 overwrite 的 chunked 重名创建应 409, got %d", resp.StatusCode)
	}
}
