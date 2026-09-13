package mount

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"atoll/client"
	"atoll/master"
	"atoll/master/meta"
	atollnode "atoll/node"
	"atoll/pkg/types"
)

// chunkCluster 测试集群：暴露 store（直铺块表用）与 nodeID→addr 映射。
type chunkCluster struct {
	client *client.Client
	m      *Mount
	store  *meta.Store
	addrs  map[uint64]string
}

// newChunkedCluster 拉起 1 master + N node（真实注册），返回集群句柄。
func newChunkedCluster(t *testing.T, numNodes int) *chunkCluster {
	t.Helper()

	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	masterSrv := httptest.NewServer(master.NewServer(store, time.Hour).Handler())
	t.Cleanup(func() { masterSrv.Close() })

	addrs := make(map[uint64]string)
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
		addrs[reg.ID] = nodeSrv.Listener.Addr().String()
	}

	c := client.New(masterSrv.URL)
	m, err := New(c, filepath.Join(t.TempDir(), "cache"), numNodes)
	if err != nil {
		t.Fatalf("mount.New: %v", err)
	}
	return &chunkCluster{client: c, m: m, store: store, addrs: addrs}
}

// putChunkObject 直连节点 PUT 块对象（测试铺数据用）。
func putChunkObject(t *testing.T, addr string, chunkID uint64, data []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut,
		fmt.Sprintf("http://%s/objects/%d", addr, chunkID), bytes.NewReader(data))
	if err != nil {
		t.Fatalf("构造 PUT: %v", err)
	}
	req.ContentLength = int64(len(data))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT chunk %d → %s: %v", chunkID, addr, err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT chunk %d → %s: status %d", chunkID, addr, resp.StatusCode)
	}
}

// waitChunkDone 轮询直到分块文件全部块达到 n 个 done 副本。
// 注意：chunked 文件 Lookup 的顶层 nodes 是地址表（Done 恒 false），
// 必须看 in.Chunks[i].Done。
func waitChunkDone(t *testing.T, c *client.Client, path string, n int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		in, _, err := c.Lookup(path)
		if err == nil && len(in.Chunks) > 0 {
			ok := true
			for _, ch := range in.Chunks {
				if len(ch.Done) < n {
					ok = false
				}
			}
			if ok {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("等待分块副本同步超时: %s", path)
}

// TestChunkedWriteFlushRelease 验证 writeHandle.Flush 走分块流水线：
// 上传后 inode 为 Chunked、客户端分块 Get 读回一致、Release 清理缓冲。
func TestChunkedWriteFlushRelease(t *testing.T) {
	cc := newChunkedCluster(t, 2)
	c, m := cc.client, cc.m

	if _, err := c.Mkdir("/wr"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	w, err := m.newWriteHandle("/wr/big.bin", true)
	if err != nil {
		t.Fatalf("newWriteHandle: %v", err)
	}
	data := bytes.Repeat([]byte("atoll-chunk-flush-test!"), 4000) // ~100KB
	if _, errno := w.Write(context.Background(), data, 0); errno != 0 {
		t.Fatalf("Write: %v", errno)
	}
	if errno := w.Flush(context.Background()); errno != 0 {
		t.Fatalf("Flush: %v", errno)
	}
	waitChunkDone(t, c, "/wr/big.bin", 2)
	if errno := w.Release(context.Background()); errno != 0 {
		t.Fatalf("Release: %v", errno)
	}

	in, _, err := c.Lookup("/wr/big.bin")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !in.Chunked {
		t.Fatalf("Flush 应走分块流水线, got legacy inode: %+v", in)
	}
	out := filepath.Join(t.TempDir(), "out.bin")
	if err := c.Get("/wr/big.bin", out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, data) {
		t.Fatalf("读回不符: got %d bytes want %d", len(got), len(data))
	}
}

// TestChunkedReadHandleRanges 分块读句柄：跨块 Range 读、分段全量读、EOF、尾读。
// 真实 ChunkSize 64MB 没法在单测里造多块——用 meta 直铺小尺寸块表。
func TestChunkedReadHandleRanges(t *testing.T) {
	cc := newChunkedCluster(t, 3)
	c := cc.client
	if len(cc.addrs) != 3 {
		t.Fatalf("需 3 个节点, got %d", len(cc.addrs))
	}
	var ids []uint64 // 注册顺序即 nodeID 升序？不保证——按 ID 排序稳定铺块。
	for id := range cc.addrs {
		ids = append(ids, id)
	}
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			if ids[j] < ids[i] {
				ids[i], ids[j] = ids[j], ids[i]
			}
		}
	}

	dir, err := c.Mkdir("/docs")
	if err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	store := cc.store
	st, err := store.CreateStagingFile(dir.ID)
	if err != nil {
		t.Fatalf("CreateStagingFile: %v", err)
	}
	const blk = 1024
	data := make([]byte, 3*blk)
	for i := range data {
		data[i] = byte(i)
	}
	spread := [][]uint64{{ids[0], ids[1]}, {ids[1], ids[2]}, {ids[0], ids[2]}}
	for i := 0; i < 3; i++ {
		if _, err := store.AssignChunk(st.ID, i, blk, spread[i]); err != nil {
			t.Fatalf("AssignChunk %d: %v", i, err)
		}
		chunkID := types.ChunkID(st.ID, i)
		for _, nid := range spread[i] {
			putChunkObject(t, cc.addrs[nid], chunkID, data[i*blk:(i+1)*blk])
			if err := store.MarkChunkDone(chunkID, nid); err != nil {
				t.Fatalf("MarkChunkDone: %v", err)
			}
		}
	}
	if _, _, _, err := store.CommitStagingFile(st.ID, "chunked-r.bin", 3*blk); err != nil {
		t.Fatalf("CommitStagingFile: %v", err)
	}

	in, reps, err := c.Lookup("/docs/chunked-r.bin")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !in.Chunked || len(in.Chunks) != 3 {
		t.Fatalf("块表不符: chunked=%v chunks=%+v", in.Chunked, in.Chunks)
	}
	addr := make(map[uint64]string)
	for _, r := range reps {
		addr[r.ID] = r.Addr
	}
	h := &chunkedReadHandle{
		ino:    in.ID,
		size:   in.Size,
		chunks: in.Chunks,
		addr:   addr,
		next:   make(map[int]int),
		http:   http.DefaultClient,
	}

	ctx := context.Background()
	read := func(off int64, n int) []byte {
		res, errno := h.Read(ctx, make([]byte, n), off)
		if errno != 0 {
			t.Fatalf("Read(off=%d,n=%d): %v", off, n, errno)
		}
		got, status := res.Bytes(make([]byte, n))
		if status != 0 {
			t.Fatalf("Read(off=%d,n=%d) Bytes: %v", off, n, status)
		}
		return got
	}

	// 跨块读：从块 0 尾部跨入块 1。
	got := read(blk/2, blk)
	want := data[blk/2 : blk/2+blk]
	if !bytes.Equal(got, want) {
		t.Fatalf("跨块读不符: got %d bytes want %d", len(got), len(want))
	}

	// 分段全量读（步长 777 覆盖块边界任意对齐）。
	var all []byte
	for off := 0; off < len(data); off += 777 {
		n := min(777, len(data)-off)
		all = append(all, read(int64(off), n)...)
	}
	if !bytes.Equal(all, data) {
		t.Fatalf("全量读不符: got %d bytes want %d", len(all), len(data))
	}

	// EOF：off >= size 返回空。
	res, errno := h.Read(ctx, make([]byte, 16), 3*blk)
	eb, est := res.Bytes(make([]byte, 16))
	if errno != 0 || est != 0 || len(eb) != 0 {
		t.Fatalf("EOF 读应返回空: %v %v %d bytes", errno, est, len(eb))
	}

	// 尾读：最后一块的尾巴。
	tail := read(3*blk-100, 100)
	if !bytes.Equal(tail, data[3*blk-100:]) {
		t.Fatal("尾读不符")
	}
}

// TestChunkedReadHandleFailover 读块首选节点无数据（404）→ 轮换到 Done 副本成功。
func TestChunkedReadHandleFailover(t *testing.T) {
	cc := newChunkedCluster(t, 2)
	c := cc.client

	dir, err := c.Mkdir("/docs")
	if err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	var ids []uint64
	for id := range cc.addrs {
		ids = append(ids, id)
	}
	if ids[1] < ids[0] {
		ids[0], ids[1] = ids[1], ids[0]
	}
	primary, secondary := ids[0], ids[1]

	store := cc.store
	st, err := store.CreateStagingFile(dir.ID)
	if err != nil {
		t.Fatalf("CreateStagingFile: %v", err)
	}
	data := []byte("failover-chunk-data-0123456789")
	if _, err := store.AssignChunk(st.ID, 0, int64(len(data)), []uint64{primary, secondary}); err != nil {
		t.Fatalf("AssignChunk: %v", err)
	}
	chunkID := types.ChunkID(st.ID, 0)
	// 数据只铺在 primary；secondary 无数据（404）→ 读必须轮换回 primary。
	putChunkObject(t, cc.addrs[primary], chunkID, data)
	if err := store.MarkChunkDone(chunkID, primary); err != nil {
		t.Fatalf("MarkChunkDone: %v", err)
	}
	if _, _, _, err := store.CommitStagingFile(st.ID, "failover.bin", int64(len(data))); err != nil {
		t.Fatalf("CommitStagingFile: %v", err)
	}

	in, reps, err := c.Lookup("/docs/failover.bin")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	addr := make(map[uint64]string)
	for _, r := range reps {
		addr[r.ID] = r.Addr
	}
	h := &chunkedReadHandle{
		ino:    in.ID,
		size:   in.Size,
		chunks: in.Chunks,
		addr:   addr,
		next:   make(map[int]int),
		http:   http.DefaultClient,
	}
	// next[0]=1：候选顺序 [primary(done), secondary(pending)]，
	// 从 secondary 起步 → 404 → 轮换回 primary。
	h.next[0] = 1
	res, errno := h.Read(context.Background(), make([]byte, len(data)), 0)
	if errno != 0 {
		t.Fatalf("Read 故障转移失败: %v", errno)
	}
	got, status := res.Bytes(make([]byte, len(data)))
	if status != 0 {
		t.Fatalf("Bytes: %v", status)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("故障转移读回不符: %q", got)
	}
}
