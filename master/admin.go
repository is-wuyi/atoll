package master

import (
	"net/http"
	"strings"
	"time"

	"atoll/master/meta"
	"atoll/pkg/types"
)

// 管理后台只读 read-model 端点（供 atoll console 消费）。
// 全部走既有 auth 包装：普通读用集群 token，破坏性操作（/admin/gc）已单列 adminToken。
// 设计约束：只读、薄包装 store/scanner，不引入新的写路径。
//
// 为路线图预留两个维度（当前恒为默认值，未来多用户/EC 只填充不重构）：
//   - Namespace：命名空间/租户，现恒为 "default"。
//   - Redundancy：冗余策略，现为 {type:"replica", n:副本数}；EC 时变 {type:"ec",k,m}。

// Redundancy 冗余策略描述（副本数或 EC 参数）。
type Redundancy struct {
	Type string `json:"type"`      // "replica" | 未来 "ec"
	N    int    `json:"n"`         // replica: 副本数
	K    int    `json:"k,omitempty"`
	M    int    `json:"m,omitempty"`
}

// nodeView 是节点在管理后台的视图（含存活判定与用量派生字段）。
type nodeView struct {
	ID            uint64    `json:"id"`
	Addr          string    `json:"addr"`
	TotalBytes    int64     `json:"total_bytes"`
	UsedBytes     int64     `json:"used_bytes"`
	FreeBytes     int64     `json:"free_bytes"`
	UsedPercent   float64   `json:"used_percent"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	Alive         bool      `json:"alive"`
}

func (s *Server) nodeViews() ([]nodeView, error) {
	nodes, err := s.store.ListNodes()
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().Add(-s.nodeMaxAge)
	out := make([]nodeView, 0, len(nodes))
	for _, n := range nodes {
		free := n.TotalBytes - n.UsedBytes
		if free < 0 {
			free = 0
		}
		pct := 0.0
		if n.TotalBytes > 0 {
			pct = float64(n.UsedBytes) / float64(n.TotalBytes) * 100
		}
		out = append(out, nodeView{
			ID: n.ID, Addr: n.Addr, TotalBytes: n.TotalBytes, UsedBytes: n.UsedBytes,
			FreeBytes: free, UsedPercent: pct, LastHeartbeat: n.LastHeartbeat,
			Alive: n.LastHeartbeat.After(cutoff),
		})
	}
	return out, nil
}

// handleAdminNodes GET /admin/nodes —— 节点列表 + 存活/用量。
func (s *Server) handleAdminNodes(w http.ResponseWriter, _ *http.Request) {
	views, err := s.nodeViews()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, views)
}

// overviewResp 是 /admin/overview 的聚合视图（落地页一屏）。
type overviewResp struct {
	Namespace     string `json:"namespace"` // 恒 "default"（路线图预留）
	NodesTotal    int    `json:"nodes_total"`
	NodesAlive    int    `json:"nodes_alive"`
	TotalBytes    int64  `json:"total_bytes"`
	UsedBytes     int64  `json:"used_bytes"`
	Files         int    `json:"files"`         // 已提交文件数（不含 staging）
	Staging       int    `json:"staging"`       // 进行中的分块上传
	Objects       int    `json:"objects"`       // 块对象总数（含 legacy 整对象计 1）
	DegradedFiles int    `json:"degraded_files"` // 存在降级块的文件数
}

// handleAdminOverview GET /admin/overview —— 集群一屏摘要。
func (s *Server) handleAdminOverview(w http.ResponseWriter, _ *http.Request) {
	views, err := s.nodeViews()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := overviewResp{Namespace: "default", NodesTotal: len(views)}
	for _, n := range views {
		resp.TotalBytes += n.TotalBytes
		resp.UsedBytes += n.UsedBytes
		if n.Alive {
			resp.NodesAlive++
		}
	}
	// 降级判定：某块 Done∧alive 的去重副本数 < len(Replicas)。
	aliveSet := make(map[uint64]bool, len(views))
	for _, n := range views {
		if n.Alive {
			aliveSet[n.ID] = true
		}
	}
	if err := s.store.ForEachFile(func(in types.Inode) error {
		if in.Staging {
			resp.Staging++
			return nil
		}
		resp.Files++
		if in.Chunked {
			resp.Objects += len(in.Chunks)
			degraded := false
			for _, c := range in.Chunks {
				if healthyReplicaCount(c.Done, c.Replicas, aliveSet) < len(c.Replicas) {
					degraded = true
				}
			}
			if degraded {
				resp.DegradedFiles++
			}
		} else {
			resp.Objects++
			if len(in.Replicas) > 0 && healthyReplicaCount(in.DoneReplicas, in.Replicas, aliveSet) < len(in.Replicas) {
				resp.DegradedFiles++
			}
		}
		return nil
	}); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// healthyReplicaCount 统计 done 中"节点存活"且去重的副本数（不超过 replicas 集合）。
func healthyReplicaCount(done, replicas []uint64, alive map[uint64]bool) int {
	replicaSet := make(map[uint64]bool, len(replicas))
	for _, id := range replicas {
		replicaSet[id] = true
	}
	seen := make(map[uint64]bool, len(done))
	n := 0
	for _, id := range done {
		if alive[id] && replicaSet[id] && !seen[id] {
			seen[id] = true
			n++
		}
	}
	return n
}

// handleAdminRepairs GET /admin/repairs —— 扫描器降级/修复退避快照。
func (s *Server) handleAdminRepairs(w http.ResponseWriter, _ *http.Request) {
	if s.scanner == nil {
		httpError(w, http.StatusInternalServerError, "scanner not initialized")
		return
	}
	writeJSON(w, http.StatusOK, s.scanner.Snapshot())
}

// degradedItem 是完整性页的一行：某文件（或其某块）副本不足。
type degradedItem struct {
	Path     string `json:"path"`
	Inode    uint64 `json:"inode"`
	Chunked  bool   `json:"chunked"`
	Index    int    `json:"index"`   // 分块文件的块下标；legacy 为 -1
	Healthy  int    `json:"healthy"` // 去重的"已落盘且节点存活"副本数
	Target   int    `json:"target"`  // 目标副本数
	SinceSec int64  `json:"since_sec"` // 已降级秒数（来自 scanner 追踪，未追踪为 0）
	Warned   bool   `json:"warned"`
}

// handleAdminIntegrity GET /admin/integrity —— 实时扫描所有文件，列出副本不足的块/文件。
// 现扫现算（不依赖 scanner 是否已追踪），再叠加 scanner 的降级时长/告警状态。
func (s *Server) handleAdminIntegrity(w http.ResponseWriter, _ *http.Request) {
	views, err := s.nodeViews()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	aliveSet := make(map[uint64]bool, len(views))
	for _, n := range views {
		if n.Alive {
			aliveSet[n.ID] = true
		}
	}
	snap := map[uint64]DegradedEntry{} // chunkID/inodeID → since+warned；scanner 未初始化则空
	if s.scanner != nil {
		for _, d := range s.scanner.Snapshot().Degraded {
			snap[d.ChunkID] = d
		}
	}
	pathCache := map[uint64]string{}
	var items []degradedItem
	if err := s.store.ForEachFile(func(in types.Inode) error {
		if in.Staging {
			return nil // staging 降级是上传中的正常态
		}
		if in.Chunked {
			for _, c := range in.Chunks {
				h := healthyReplicaCount(c.Done, c.Replicas, aliveSet)
				if h < len(c.Replicas) {
					items = append(items, buildDegraded(s, in, c.Index, h, len(c.Replicas),
						types.ChunkID(in.ID, c.Index), snap, pathCache))
				}
			}
		} else if len(in.Replicas) > 0 {
			h := healthyReplicaCount(in.DoneReplicas, in.Replicas, aliveSet)
			if h < len(in.Replicas) {
				items = append(items, buildDegraded(s, in, -1, h, len(in.Replicas), in.ID, snap, pathCache))
			}
		}
		return nil
	}); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func buildDegraded(s *Server, in types.Inode, index, healthy, target int, trackID uint64,
	snap map[uint64]DegradedEntry, cache map[uint64]string) degradedItem {
	it := degradedItem{
		Path: s.resolveInodePath(in, cache), Inode: in.ID, Chunked: in.Chunked,
		Index: index, Healthy: healthy, Target: target,
	}
	if d, ok := snap[trackID]; ok {
		it.SinceSec = int64(time.Since(d.Since).Seconds())
		it.Warned = d.Warned
	}
	return it
}

// resolveInodePath 沿 ParentID 向上回溯拼出绝对路径（带缓存）。
func (s *Server) resolveInodePath(in types.Inode, cache map[uint64]string) string {
	if p, ok := cache[in.ID]; ok {
		return p
	}
	if in.ID == meta.RootID || in.ParentID == 0 {
		return "/"
	}
	segs := []string{in.Name}
	pid := in.ParentID
	for pid != 0 && pid != meta.RootID {
		p, err := s.store.GetInode(pid)
		if err != nil {
			break
		}
		segs = append([]string{p.Name}, segs...)
		pid = p.ParentID
	}
	path := "/" + strings.Join(segs, "/")
	cache[in.ID] = path
	return path
}
