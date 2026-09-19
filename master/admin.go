package master

import (
	"net/http"
	"time"

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
