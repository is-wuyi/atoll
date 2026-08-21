// Package node 实现存储节点：接收客户端直连的对象读写，并向 master 注册与心跳。
package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Node 是一个存储节点实例。
type Node struct {
	dataDir           string // 对象文件根目录
	used              atomic.Int64
	masterURL         string
	advertise         string // 注册到 master 的直连地址 host:port
	nodeID            atomic.Int64
	totalBytes        int64
	heartbeatInterval time.Duration
	httpClient        *http.Client // 与 master/peer 通信复用
	pulling           sync.Map     // map[uint64]struct{}: 正在拉取的 inode，去重用
}

func New(dataDir, masterURL, advertise string, totalBytes int64) *Node {
	return &Node{
		dataDir:           dataDir,
		masterURL:         strings.TrimRight(masterURL, "/"),
		advertise:         advertise,
		totalBytes:        totalBytes,
		heartbeatInterval: 5 * time.Second,
		httpClient:        &http.Client{Timeout: 60 * time.Second},
	}
}

// ---- 对象存储 HTTP API ----

// Handler 返回对象存储路由。对象以 inode ID 命名，直接落盘。
func (n *Node) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("PUT /objects/{id}", n.handlePut)
	mux.HandleFunc("GET /objects/{id}", n.handleGet)
	mux.HandleFunc("DELETE /objects/{id}", n.handleDelete)
	mux.HandleFunc("PUT /replicate/{id}", n.handleReplicate)
	mux.HandleFunc("POST /pull", n.handlePull)
	mux.HandleFunc("GET /admin/objects", n.handleAdminObjects)
	return mux
}

// handlePut 写入对象：先写临时文件再原子改名，避免读到半份数据。
func (n *Node) handlePut(w http.ResponseWriter, r *http.Request) {
	id, ok := parseObjectID(w, r)
	if !ok {
		return
	}
	objPath := n.objectPath(id)
	if err := os.MkdirAll(filepath.Dir(objPath), 0o755); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// 覆盖写场景：先记下旧对象大小，成功后按差值计费。
	var oldSize int64
	if st, err := os.Stat(objPath); err == nil {
		oldSize = st.Size()
	}
	tmp, err := os.CreateTemp(filepath.Dir(objPath), ".tmp-*")
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tmpName := tmp.Name()
	size, err := io.Copy(tmp, r.Body)
	closeErr := tmp.Close()
	if err != nil || closeErr != nil {
		os.Remove(tmpName)
		httpError(w, http.StatusInternalServerError, "write object failed")
		return
	}
	if err := os.Rename(tmpName, objPath); err != nil {
		os.Remove(tmpName)
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	n.used.Add(size - oldSize)
	writeJSON(w, http.StatusCreated, map[string]int64{"size": size})
	// 客户端直写视为"我是主副本"：成功后异步推送到其余副本节点。
	if n.nodeID.Load() != 0 {
		go n.replicateToPeers(id)
	}
}

// replicateToPeers 把指定对象推送到 master 分配的其余副本节点（带重试）。
// 目标列表实时从 master 获取，已完成的节点会被 master 过滤掉，因此重试天然幂等。
func (n *Node) replicateToPeers(inodeID uint64) {
	const maxAttempts = 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		targets, err := n.fetchReplicaTargets(inodeID)
		if err != nil {
			log.Printf("replicate %d: 获取目标失败(尝试 %d/%d): %v", inodeID, attempt, maxAttempts, err)
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}
		if len(targets) == 0 {
			return // 全部同步完成
		}
		allOK := true
		for _, addr := range targets {
			if err := n.pushObject(addr, inodeID); err != nil {
				log.Printf("replicate %d → %s 失败(尝试 %d/%d): %v", inodeID, addr, attempt, maxAttempts, err)
				allOK = false
			}
		}
		if allOK {
			return
		}
		time.Sleep(time.Duration(attempt) * time.Second)
	}
	log.Printf("replicate %d: 达到最大重试次数，放弃（等待对账任务兜底）", inodeID)
}

// fetchReplicaTargets 向 master 查询除自己外待同步的副本节点地址。
func (n *Node) fetchReplicaTargets(inodeID uint64) ([]string, error) {
	url := fmt.Sprintf("%s/files/replica-targets?inode_id=%d&node_id=%d", n.masterURL, inodeID, n.nodeID.Load())
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var nodes []struct {
		Addr string `json:"addr"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
		return nil, err
	}
	var addrs []string
	for _, nd := range nodes {
		addrs = append(addrs, nd.Addr)
	}
	return addrs, nil
}

// pushObject 把本地对象推送到目标节点（目标节点会落盘并上报 master）。
func (n *Node) pushObject(peerAddr string, inodeID uint64) error {
	f, err := os.Open(n.objectPath(inodeID))
	if err != nil {
		return err
	}
	defer f.Close()
	// io.NopCloser 包裹：防止 http transport 上传后关闭 *os.File（同 client.putObject）。
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("http://%s/replicate/%d", peerAddr, inodeID), io.NopCloser(f))
	if err != nil {
		return err
	}
	resp, err := n.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// reportReplicated 向 master 上报"我已完成该对象的同步"。
func (n *Node) reportReplicated(inodeID uint64) error {
	body, _ := json.Marshal(map[string]any{
		"inode_id": inodeID,
		"node_id":  n.nodeID.Load(),
	})
	resp, err := http.Post(n.masterURL+"/files/replicated", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// handleReplicate 接收主副本推送的对象数据：落盘后向 master 上报同步完成。
// 与 handlePut 的区别：来源是主副本节点而非客户端，成功后需要上报。
func (n *Node) handleReplicate(w http.ResponseWriter, r *http.Request) {
	id, ok := parseObjectID(w, r)
	if !ok {
		return
	}
	objPath := n.objectPath(id)
	if err := os.MkdirAll(filepath.Dir(objPath), 0o755); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var oldSize int64
	if st, err := os.Stat(objPath); err == nil {
		oldSize = st.Size()
	}
	tmp, err := os.CreateTemp(filepath.Dir(objPath), ".tmp-*")
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tmpName := tmp.Name()
	size, err := io.Copy(tmp, r.Body)
	closeErr := tmp.Close()
	if err != nil || closeErr != nil {
		os.Remove(tmpName)
		httpError(w, http.StatusInternalServerError, "write object failed")
		return
	}
	if err := os.Rename(tmpName, objPath); err != nil {
		os.Remove(tmpName)
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	n.used.Add(size - oldSize)
	// 落盘成功后向 master 上报，把自己加入 DoneReplicas。上报失败仅记日志：
	// 主副本的重试机制会再次推送，重复落盘是幂等的。
	if err := n.reportReplicated(id); err != nil {
		log.Printf("report replicated %d: %v", id, err)
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"size": size})
}

// handlePull 接收拉取请求，立即返回 202，后台异步从源节点拉取对象并落盘。
// 同一 inode 的并发 pull 会去重：若已在拉取则直接返回 202。
func (n *Node) handlePull(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InodeID    uint64 `json:"inode_id"`
		SourceAddr string `json:"source_addr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.InodeID == 0 || req.SourceAddr == "" {
		httpError(w, http.StatusBadRequest, "inode_id and source_addr are required")
		return
	}
	// 去重：已有人在拉同一 inode，直接返回 202。
	if _, loaded := n.pulling.LoadOrStore(req.InodeID, struct{}{}); loaded {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	go n.pullObject(req.InodeID, req.SourceAddr)
}

// pullObject 后台从源节点拉取对象并落盘，完成后上报 master。
func (n *Node) pullObject(inodeID uint64, sourceAddr string) {
	defer n.pulling.Delete(inodeID)
	url := fmt.Sprintf("http://%s/objects/%d", sourceAddr, inodeID)
	resp, err := n.httpClient.Get(url)
	if err != nil {
		log.Printf("pull %d from %s: %v", inodeID, sourceAddr, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("pull %d from %s: status %d", inodeID, sourceAddr, resp.StatusCode)
		return
	}
	objPath := n.objectPath(inodeID)
	if err := os.MkdirAll(filepath.Dir(objPath), 0o755); err != nil {
		log.Printf("pull %d: mkdir: %v", inodeID, err)
		return
	}
	var oldSize int64
	if st, err := os.Stat(objPath); err == nil {
		oldSize = st.Size()
	}
	tmp, err := os.CreateTemp(filepath.Dir(objPath), ".tmp-*")
	if err != nil {
		log.Printf("pull %d: create temp: %v", inodeID, err)
		return
	}
	tmpName := tmp.Name()
	size, err := io.Copy(tmp, resp.Body)
	closeErr := tmp.Close()
	if err != nil || closeErr != nil {
		os.Remove(tmpName)
		log.Printf("pull %d: write: %v", inodeID, err)
		return
	}
	if err := os.Rename(tmpName, objPath); err != nil {
		os.Remove(tmpName)
		log.Printf("pull %d: rename: %v", inodeID, err)
		return
	}
	n.used.Add(size - oldSize)
	if err := n.reportReplicated(inodeID); err != nil {
		log.Printf("pull %d: report replicated: %v", inodeID, err)
	}
}

// handleAdminObjects 返回本机全部对象的 ID 和大小，跳过 .tmp-* 临时文件。
func (n *Node) handleAdminObjects(w http.ResponseWriter, _ *http.Request) {
	type objInfo struct {
		ID   uint64 `json:"id"`
		Size int64  `json:"size"`
	}
	var objects []objInfo
	objectsDir := filepath.Join(n.dataDir, "objects")
	entries, err := os.ReadDir(objectsDir)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, []objInfo{})
			return
		}
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, bucket := range entries {
		if !bucket.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(objectsDir, bucket.Name()))
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || strings.HasPrefix(f.Name(), ".tmp-") {
				continue
			}
			info, err := f.Info()
			if err != nil {
				continue
			}
			id, err := strconv.ParseUint(f.Name(), 10, 64)
			if err != nil {
				continue
			}
			objects = append(objects, objInfo{ID: id, Size: info.Size()})
		}
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].ID < objects[j].ID })
	writeJSON(w, http.StatusOK, objects)
}

// handleGet 读出对象内容。支持单区间 Range 请求（206 部分内容），
// 供 FUSE 客户端按偏移读取，避免拉取整个对象。
func (n *Node) handleGet(w http.ResponseWriter, r *http.Request) {
	id, ok := parseObjectID(w, r)
	if !ok {
		return
	}
	f, err := os.Open(n.objectPath(id))
	if err != nil {
		if os.IsNotExist(err) {
			httpError(w, http.StatusNotFound, "object not found")
			return
		}
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Accept-Ranges", "bytes")

	if rng := r.Header.Get("Range"); rng != "" {
		start, end, ok := parseRange(rng, st.Size())
		if !ok {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", st.Size()))
			httpError(w, http.StatusRequestedRangeNotSatisfiable, "invalid range")
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, st.Size()))
		w.WriteHeader(http.StatusPartialContent)
		if _, err := f.Seek(start, io.SeekStart); err == nil {
			if _, err := io.CopyN(w, f, end-start+1); err != nil {
				log.Printf("serve object %d range: %v", id, err)
			}
		}
		return
	}
	if _, err := io.Copy(w, f); err != nil {
		log.Printf("serve object %d: %v", id, err)
	}
}

// parseRange 解析 "bytes=start-end"（end 可省略；后缀式 bytes=-N 也支持）。
// 返回闭区间 [start, end]；非法、多区间或越界返回 ok=false。
func parseRange(h string, size int64) (start, end int64, ok bool) {
	const prefix = "bytes="
	if !strings.HasPrefix(h, prefix) {
		return 0, 0, false
	}
	spec := h[len(prefix):]
	if strings.Contains(spec, ",") {
		return 0, 0, false // 多区间不支持
	}
	dash := strings.Index(spec, "-")
	if dash < 0 {
		return 0, 0, false
	}
	left, right := spec[:dash], spec[dash+1:]
	if left == "" {
		// 后缀长度：bytes=-N，取最后 N 字节（N 超过文件大小则整个文件）。
		var n int64
		if _, err := fmt.Sscanf(right, "%d", &n); err != nil || n <= 0 {
			return 0, 0, false
		}
		start = size - n
		if start < 0 {
			start = 0
		}
		return start, size - 1, true
	}
	if _, err := fmt.Sscanf(left, "%d", &start); err != nil {
		return 0, 0, false
	}
	if right == "" {
		end = size - 1
	} else if _, err := fmt.Sscanf(right, "%d", &end); err != nil {
		return 0, 0, false
	}
	if start < 0 || end < start || start >= size {
		return 0, 0, false
	}
	if end >= size {
		end = size - 1
	}
	return start, end, true
}

// handleDelete 删除对象。
func (n *Node) handleDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseObjectID(w, r)
	if !ok {
		return
	}
	objPath := n.objectPath(id)
	if st, err := os.Stat(objPath); err == nil {
		if err := os.Remove(objPath); err != nil {
			httpError(w, http.StatusInternalServerError, err.Error())
			return
		}
		n.used.Add(-st.Size())
	}
	// 不存在视为幂等成功。
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (n *Node) objectPath(id uint64) string {
	// 按 ID 前 2 位分桶，避免单目录文件过多。
	sub := fmt.Sprintf("%02x", id%256)
	return filepath.Join(n.dataDir, "objects", sub, strconv.FormatUint(id, 10))
}

func parseObjectID(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || id == 0 {
		httpError(w, http.StatusBadRequest, "invalid object id")
		return 0, false
	}
	return id, true
}

// ---- 与 master 交互 ----

// 节点重加入行为说明：
// 节点重启后幂等注册复用原 ID（同一地址重复注册时 master 返回原 ID），
// 心跳恢复即回池；其上旧对象不校验、不裁剪。
// 若该节点曾被修复扫描替换（Replicas 中被新节点替代），其旧副本成为额外副本，
// GC 不删除仍在元数据 inode 集合中的对象（即文件仍存活则不删）。

// Register 向 master 注册并启动心跳循环（阻塞直到首次注册成功）。
func (n *Node) Register() error {
	if err := n.registerOnce(); err != nil {
		return err
	}
	go n.heartbeatLoop()
	return nil
}

func (n *Node) registerOnce() error {
	body, _ := json.Marshal(map[string]any{
		"addr":        n.advertise,
		"total_bytes": n.totalBytes,
	})
	resp, err := http.Post(n.masterURL+"/nodes/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("register: status %d", resp.StatusCode)
	}
	var out struct {
		ID uint64 `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("register: decode: %w", err)
	}
	n.nodeID.Store(int64(out.ID))
	log.Printf("node registered: id=%d addr=%s", out.ID, n.advertise)
	return nil
}

// heartbeatLoop 定期心跳；master 重启后重新注册。
func (n *Node) heartbeatLoop() {
	t := time.NewTicker(n.heartbeatInterval)
	defer t.Stop()
	for range t.C {
		if err := n.heartbeatOnce(); err != nil {
			if errors.Is(err, errUnknownNode) {
				// master 丢了注册信息（比如 master 数据被清空），重新注册。
				log.Printf("heartbeat: unknown node, re-registering: %v", err)
				if rerr := n.registerOnce(); rerr != nil {
					log.Printf("re-register failed: %v", rerr)
				}
				continue
			}
			log.Printf("heartbeat: %v", err)
		}
	}
}

var errUnknownNode = errors.New("master: node not found")

func (n *Node) heartbeatOnce() error {
	body, _ := json.Marshal(map[string]any{
		"node_id":    n.nodeID.Load(),
		"used_bytes": n.used.Load(),
	})
	resp, err := http.Post(n.masterURL+"/nodes/heartbeat", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errUnknownNode
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat: status %d", resp.StatusCode)
	}
	return nil
}

// InitUsedBytes 启动时统计已有数据量（对象目录遍历一次）。
func (n *Node) InitUsedBytes() error {
	var total int64
	err := filepath.WalkDir(filepath.Join(n.dataDir, "objects"), func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil // objects 目录还不存在
			}
			return err
		}
		if !d.IsDir() {
			if info, err := d.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	n.used.Store(total)
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// ---- 测试辅助（导出仅供集成测试使用） ----

// SetNodeIDForTest 直接设置节点 ID（绕过注册流程，用于测试）。
func (n *Node) SetNodeIDForTest(id uint64) { n.nodeID.Store(int64(id)) }

// NodeIDForTest 返回节点 ID（供测试发送心跳用）。
func (n *Node) NodeIDForTest() uint64 { return uint64(n.nodeID.Load()) }

// DataDirForTest 返回数据目录路径。
func (n *Node) DataDirForTest() string { return n.dataDir }

func httpError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
