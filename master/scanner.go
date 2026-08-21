// Package master 实现中心服务器：元数据管理 + 副本位置分配。
package master

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"atoll/master/meta"
	"atoll/pkg/types"
)

// Scanner 是 master 的后台扫描器，负责死亡判定、副本修复和 GC。
type Scanner struct {
	store      *meta.Store
	nodeMaxAge time.Duration
	repairIntv time.Duration
	gcIntv     time.Duration
	httpClient *http.Client

	mu        sync.Mutex
	prevAlive map[uint64]bool // 上轮 alive 集合
}

// NewScanner 创建一个新的 Scanner 实例。
func NewScanner(store *meta.Store, nodeMaxAge, repairIntv, gcIntv time.Duration) *Scanner {
	return &Scanner{
		store:      store,
		nodeMaxAge: nodeMaxAge,
		repairIntv: repairIntv,
		gcIntv:     gcIntv,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		prevAlive:  make(map[uint64]bool),
	}
}

// Start 启动三个后台扫描器，ctx 取消时退出。
func (s *Scanner) Start(ctx context.Context) {
	go s.runDeathMonitor(ctx)
	go s.runRepairLoop(ctx)
	go s.runGCLoop(ctx)
}

// runDeathMonitor 死亡判定：10s 周期。
func (s *Scanner) runDeathMonitor(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.deathMonitorOnce()
		}
	}
}

// runRepairLoop 副本修复：repairIntv 周期。
func (s *Scanner) runRepairLoop(ctx context.Context) {
	ticker := time.NewTicker(s.repairIntv)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.repairScanOnce()
		}
	}
}

// runGCLoop GC 比对：gcIntv 周期。
func (s *Scanner) runGCLoop(ctx context.Context) {
	ticker := time.NewTicker(s.gcIntv)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.gcScanOnce()
		}
	}
}

// deathMonitorOnce 执行一次死亡判定扫描。
func (s *Scanner) deathMonitorOnce() {
	nodes, err := s.store.ListNodes()
	if err != nil {
		log.Printf("死亡判定: 列出节点失败: %v", err)
		return
	}

	cutoff := time.Now().Add(-s.nodeMaxAge)
	alive := make(map[uint64]bool, len(nodes))
	for _, n := range nodes {
		if n.LastHeartbeat.After(cutoff) {
			alive[n.ID] = true
		}
	}

	s.mu.Lock()
	prev := s.prevAlive
	s.prevAlive = alive
	s.mu.Unlock()

	// diff: alive → dead
	for id := range prev {
		if !alive[id] {
			addr := ""
			for _, n := range nodes {
				if n.ID == id {
					addr = n.Addr
					break
				}
			}
			log.Printf("node %d (%s) 判定死亡", id, addr)
		}
	}

	// diff: dead → alive
	for id := range alive {
		if !prev[id] {
			addr := ""
			for _, n := range nodes {
				if n.ID == id {
					addr = n.Addr
					break
				}
			}
			log.Printf("node %d (%s) 心跳恢复，重新入池", id, addr)
		}
	}
}

// ---- 副本修复 ----

// repairAction 修复动作类型。
type repairAction int

const (
	repairReplaceDead repairAction = iota // dead 槽 → 选新目标 ReplaceReplica + pull
	repairTriggerPull                     // alive 未 Done → 直接 pull
	repairSkipNoSource                    // 无 alive Done 源，跳过
	repairSkipNoTarget                    // 无合格新目标，跳过
)

// repairTask 一个文件的一个槽位修复任务。
type repairTask struct {
	Action      repairAction
	SlotIdx     int    // Replicas 中的下标
	OldNodeID   uint64 // dead 节点（仅 repairReplaceDead）
	NewNodeID   uint64 // 新目标（仅 repairReplaceDead）
	NewNodeAddr string
	TargetAddr  string // pull 目标地址（triggerPull 场景为该槽节点地址）
	SourceAddr  string // 源节点地址
}

// planRepairs 对单个文件产出修复计划（纯函数，便于单测）。
// 健康副本数 < len(Replicas) 时，对每个不健康槽位产出动作。
func planRepairs(inode types.Inode, nodes []types.NodeInfo, maxAge time.Duration) []repairTask {
	now := time.Now()
	cutoff := now.Add(-maxAge)
	aliveSet := make(map[uint64]bool, len(nodes))
	nodeByID := make(map[uint64]types.NodeInfo, len(nodes))
	for _, n := range nodes {
		nodeByID[n.ID] = n
		if n.LastHeartbeat.After(cutoff) {
			aliveSet[n.ID] = true
		}
	}

	// 健康副本 = Replicas 中 Done ∧ alive
	doneSet := make(map[uint64]bool, len(inode.DoneReplicas))
	for _, id := range inode.DoneReplicas {
		doneSet[id] = true
	}
	healthyCount := 0
	var aliveDoneAddrs []string // 可用源地址
	for _, id := range inode.Replicas {
		if aliveSet[id] && doneSet[id] {
			healthyCount++
			if n, ok := nodeByID[id]; ok {
				aliveDoneAddrs = append(aliveDoneAddrs, n.Addr)
			}
		}
	}
	if healthyCount >= len(inode.Replicas) {
		return nil // 全部健康，无需修复
	}

	var tasks []repairTask
	for i, id := range inode.Replicas {
		// 跳过健康的槽位。
		if aliveSet[id] && doneSet[id] {
			continue
		}

		// 选择源节点（随机一个 alive Done 副本）。
		if len(aliveDoneAddrs) == 0 {
			tasks = append(tasks, repairTask{Action: repairSkipNoSource, SlotIdx: i})
			continue
		}
		srcIdx := rand.Intn(len(aliveDoneAddrs))

		if aliveSet[id] {
			// alive 但未 Done：直接对该槽节点触发 pull。
			var targetAddr string
			if n, ok := nodeByID[id]; ok {
				targetAddr = n.Addr
			}
			tasks = append(tasks, repairTask{
				Action:     repairTriggerPull,
				SlotIdx:    i,
				TargetAddr: targetAddr,
				SourceAddr: aliveDoneAddrs[srcIdx],
			})
		} else {
			// dead：需要选新目标替换。
			// 候选：alive ∧ 不在 Replicas ∧ 剩余容量 ≥ 文件大小。
			replicaSet := make(map[uint64]bool, len(inode.Replicas))
			for _, rid := range inode.Replicas {
				replicaSet[rid] = true
			}
			var candidates []types.NodeInfo
			for nid, n := range nodeByID {
				if aliveSet[nid] && !replicaSet[nid] && (n.TotalBytes-n.UsedBytes) >= inode.Size {
					candidates = append(candidates, n)
				}
			}
			if len(candidates) == 0 {
				tasks = append(tasks, repairTask{Action: repairSkipNoTarget, SlotIdx: i, OldNodeID: id})
				continue
			}
			chosen := candidates[rand.Intn(len(candidates))]
			tasks = append(tasks, repairTask{
				Action:      repairReplaceDead,
				SlotIdx:     i,
				OldNodeID:   id,
				NewNodeID:   chosen.ID,
				NewNodeAddr: chosen.Addr,
				SourceAddr:  aliveDoneAddrs[srcIdx],
			})
		}
	}
	return tasks
}

// RepairScanOnce 是 repairScanOnce 的可导出版本，供测试调用。
func (s *Scanner) RepairScanOnce() { s.repairScanOnce() }

// repairScanOnce 执行一次副本修复扫描。
func (s *Scanner) repairScanOnce() {
	nodes, err := s.store.ListNodes()
	if err != nil {
		log.Printf("修复扫描: 列出节点失败: %v", err)
		return
	}

	// 先在 View 事务内收集文件快照，事务退出后再执行修复。
	// 不能在 ForEachFile 回调里直接 ReplaceReplica（Update）：
	// bbolt 同库读写事务嵌套会自死锁。
	var inodes []types.Inode
	if err := s.store.ForEachFile(func(in types.Inode) error {
		inodes = append(inodes, in)
		return nil
	}); err != nil {
		log.Printf("修复扫描: ForEachFile 失败: %v", err)
		return
	}

	for _, in := range inodes {
		tasks := planRepairs(in, nodes, s.nodeMaxAge)
		for _, t := range tasks {
			s.executeRepair(in.ID, t)
		}
	}
}

// executeRepair 执行单个修复任务。
// 任何失败只记日志，不影响其他文件与扫描器（不 panic、不阻塞）。
func (s *Scanner) executeRepair(inodeID uint64, t repairTask) {
	switch t.Action {
	case repairSkipNoSource:
		log.Printf("inode %d slot %d: 无可用源节点，跳过", inodeID, t.SlotIdx)
	case repairSkipNoTarget:
		log.Printf("inode %d slot %d: 无合格新目标（dead node %d），跳过", inodeID, t.SlotIdx, t.OldNodeID)
	case repairReplaceDead:
		if err := s.store.ReplaceReplica(inodeID, t.OldNodeID, t.NewNodeID); err != nil {
			if errors.Is(err, meta.ErrNotExist) {
				return // 文件被并发删除，静默跳过
			}
			log.Printf("inode %d slot %d: ReplaceReplica 失败: %v", inodeID, t.SlotIdx, err)
			return
		}
		log.Printf("inode %d slot %d: 替换 dead node %d → %d，触发 pull", inodeID, t.SlotIdx, t.OldNodeID, t.NewNodeID)
		s.triggerPull(t.NewNodeAddr, inodeID, t.SourceAddr)
	case repairTriggerPull:
		log.Printf("inode %d slot %d: 触发 pull（alive 未 Done）", inodeID, t.SlotIdx)
		s.triggerPull(t.TargetAddr, inodeID, t.SourceAddr)
	}
}

// triggerPull 调用目标节点 POST /pull。
func (s *Scanner) triggerPull(targetAddr string, inodeID uint64, sourceAddr string) {
	body, _ := json.Marshal(map[string]any{
		"inode_id":    inodeID,
		"source_addr": sourceAddr,
	})
	resp, err := s.httpClient.Post(fmt.Sprintf("http://%s/pull", targetAddr), "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("pull inode %d → %s 失败: %v", inodeID, targetAddr, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		log.Printf("pull inode %d → %s: status %d", inodeID, targetAddr, resp.StatusCode)
	}
}

// ---- 垃圾回收 ----

// ObjectEntry 是 node /admin/objects 返回的单条记录。
type ObjectEntry struct {
	ID   uint64 `json:"id"`
	Size int64  `json:"size"`
}

// GCNodeReport 是 GC 扫描中单个节点的孤儿报告。
type GCNodeReport struct {
	NodeID      uint64         `json:"node_id"`
	NodeAddr    string         `json:"node_addr"`
	Orphans     []ObjectEntry  `json:"orphans"`
	OrphanBytes int64          `json:"orphan_bytes"`
}

// findOrphans 纯函数：节点对象列表 + 元数据 inode 集合 → 孤儿列表。
func findOrphans(objects []ObjectEntry, validIDs map[uint64]bool) []ObjectEntry {
	var orphans []ObjectEntry
	for _, obj := range objects {
		if !validIDs[obj.ID] {
			orphans = append(orphans, obj)
		}
	}
	return orphans
}

// gcScanOnce 执行一次 GC dry-run 比对，输出日志摘要。
func (s *Scanner) gcScanOnce() {
	reports, err := s.runGC(false)
	if err != nil {
		log.Printf("GC dry-run: %v", err)
		return
	}
	for _, r := range reports {
		if len(r.Orphans) > 0 {
			log.Printf("GC 节点 %d (%s): %d 个孤儿, %d 字节", r.NodeID, r.NodeAddr, len(r.Orphans), r.OrphanBytes)
		}
	}
}

// RunGC 是 gcScanOnce 的可导出版本，供 HTTP handler 调用。
// execute=true 时通知节点删除孤儿。
func (s *Scanner) RunGC(execute bool) ([]GCNodeReport, error) {
	return s.runGC(execute)
}

// runGC 执行 GC 比对，execute=true 时删除孤儿。
func (s *Scanner) runGC(execute bool) ([]GCNodeReport, error) {
	nodes, err := s.store.ListNodes()
	if err != nil {
		return nil, fmt.Errorf("列出节点: %w", err)
	}
	cutoff := time.Now().Add(-s.nodeMaxAge)

	// 收集全部文件 inode ID。
	validIDs := make(map[uint64]bool)
	if err := s.store.ForEachFile(func(in types.Inode) error {
		validIDs[in.ID] = true
		return nil
	}); err != nil {
		return nil, fmt.Errorf("遍历文件: %w", err)
	}

	var reports []GCNodeReport
	for _, n := range nodes {
		if !n.LastHeartbeat.After(cutoff) {
			continue // 跳过 dead 节点
		}
		objects, err := s.fetchNodeObjects(n.Addr)
		if err != nil {
			log.Printf("GC: 获取节点 %d (%s) 对象清单失败: %v", n.ID, n.Addr, err)
			continue
		}
		orphans := findOrphans(objects, validIDs)
		report := GCNodeReport{
			NodeID:   n.ID,
			NodeAddr: n.Addr,
			Orphans:  orphans,
		}
		for _, o := range orphans {
			report.OrphanBytes += o.Size
		}
		reports = append(reports, report)

		if execute && len(orphans) > 0 {
			deleted := s.deleteOrphans(n.Addr, orphans)
			log.Printf("GC 节点 %d (%s): 删除 %d/%d 个孤儿", n.ID, n.Addr, deleted, len(orphans))
		}
	}
	return reports, nil
}

// fetchNodeObjects 获取节点的对象清单。
func (s *Scanner) fetchNodeObjects(addr string) ([]ObjectEntry, error) {
	resp, err := s.httpClient.Get(fmt.Sprintf("http://%s/admin/objects", addr))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var objects []ObjectEntry
	if err := json.NewDecoder(resp.Body).Decode(&objects); err != nil {
		return nil, err
	}
	return objects, nil
}

// deleteOrphans 通知节点删除孤儿对象，返回成功删除数。
func (s *Scanner) deleteOrphans(addr string, orphans []ObjectEntry) int {
	deleted := 0
	for _, o := range orphans {
		req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("http://%s/objects/%d", addr, o.ID), nil)
		if err != nil {
			continue
		}
		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			deleted++
		}
	}
	return deleted
}
