// Package master 实现中心服务器：元数据管理 + 副本位置分配。
package master

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"atoll/master/meta"
	"atoll/pkg/auth"
	"atoll/pkg/types"
)

// Scanner 是 master 的后台扫描器，负责死亡判定、副本修复和 GC。
type Scanner struct {
	store      *meta.Store
	nodeMaxAge time.Duration
	repairIntv time.Duration
	gcIntv     time.Duration
	httpClient *http.Client
	scheme     string // 出站访问节点的 URL scheme：http（默认）或 https

	wg sync.WaitGroup // 后台循环生命周期，供 Wait() 优雅关闭

	mu          sync.Mutex
	prevAlive   map[uint64]bool      // 上轮 alive 集合
	failStreak  map[uint64]int       // 修复连续未收敛轮数（按 inode / chunkID）
	nextAttempt map[uint64]time.Time // 修复退避：下次允许触发修复的时间

	prevOrphans     map[uint64]map[uint64]bool // GC 两轮确认：上轮孤儿集合 nodeID → objectID
	stagingTTL      time.Duration              // staging inode 超时回收阈值
	degradedSince   map[uint64]time.Time       // 块降级追踪（改进项2）：chunkID → 首次发现单副本时刻
	degradedWarn    map[uint64]bool            // 已告警标记（避免重复刷日志）
	degradedWarnDur time.Duration              // 持续降级多久后告警
}

// NewScanner 创建一个新的 Scanner 实例。token 由 SetToken 设置后对出站请求生效。
func NewScanner(store *meta.Store, nodeMaxAge, repairIntv, gcIntv time.Duration) *Scanner {
	return &Scanner{
		store:           store,
		nodeMaxAge:      nodeMaxAge,
		repairIntv:      repairIntv,
		gcIntv:          gcIntv,
		httpClient:      &http.Client{Timeout: 10 * time.Second, Transport: &auth.Transport{Token: ""}},
		scheme:          "http",
		prevAlive:       make(map[uint64]bool),
		failStreak:      make(map[uint64]int),
		nextAttempt:     make(map[uint64]time.Time),
		stagingTTL:      24 * time.Hour,
		degradedSince:   make(map[uint64]time.Time),
		degradedWarn:    make(map[uint64]bool),
		degradedWarnDur: 30 * time.Minute,
	}
}

// SetToken 设置出站请求的认证 token（触发 pull、GC、删除通知等）。
func (s *Scanner) SetToken(t auth.Token) {
	s.httpClient.Transport = &auth.Transport{Token: t}
}

// SetTLS 启用出站 TLS（scheme 切到 https 并给 httpClient 装 TLS 配置）。
// 必须在 SetToken 之后调用（会保留当前 token）。cfg 为空则不启用。
func (s *Scanner) SetTLS(cfg *tls.Config) {
	if cfg == nil {
		return
	}
	tok := auth.Token("")
	if tr, ok := s.httpClient.Transport.(*auth.Transport); ok {
		tok = tr.Token
	}
	s.httpClient.Transport = auth.HTTPTransport(tok, cfg, nil)
	s.scheme = "https"
}

// Start 启动三个后台扫描器，ctx 取消时退出。
func (s *Scanner) Start(ctx context.Context) {
	s.wg.Add(3)
	go func() { defer s.wg.Done(); s.runDeathMonitor(ctx) }()
	go func() { defer s.wg.Done(); s.runRepairLoop(ctx) }()
	go func() { defer s.wg.Done(); s.runGCLoop(ctx) }()
}

// Wait 阻塞直到三个后台扫描器全部退出（ctx 取消后调用）。
// runMaster 在关闭 store 前调用它，避免扫描器还在用 store 时库被关闭。
func (s *Scanner) Wait() { s.wg.Wait() }

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
			s.sweepStaging()
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
	repairReplaceDead  repairAction = iota // dead 槽 → 选新目标 ReplaceReplica + pull
	repairTriggerPull                      // alive 未 Done → 直接 pull
	repairSkipNoSource                     // 无 alive Done 源，跳过
	repairSkipNoTarget                     // 无合格新目标，跳过
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

	// 健康副本 = Replicas 中 Done ∧ alive，且按节点 ID 去重计数。
	// 关键修复：healthyCount 必须数"不同的物理节点"。此前逐个槽位计数，
	// [5,5,1] Done=[5,1] 会把 node 5 数两次 → 判定 3 副本满健康，但实际只有
	// 2 个物理副本。一个降级/单副本文件会被持续误判为健康，修复与告警双双沉默
	// （27472 "单副本裸奔无人知晓" 的元数据侧根因）。
	doneSet := make(map[uint64]bool, len(inode.DoneReplicas))
	for _, id := range inode.DoneReplicas {
		doneSet[id] = true
	}
	healthySeen := make(map[uint64]bool, len(inode.Replicas)) // 已计入健康的去重节点集
	var aliveDoneAddrs []string                               // 可用源地址（去重）
	for _, id := range inode.Replicas {
		if aliveSet[id] && doneSet[id] && !healthySeen[id] {
			healthySeen[id] = true
			if n, ok := nodeByID[id]; ok {
				aliveDoneAddrs = append(aliveDoneAddrs, n.Addr)
			}
		}
	}
	if len(healthySeen) >= len(inode.Replicas) {
		return nil // 去重后健康副本已满，无需修复
	}

	var tasks []repairTask
	slotHealthy := make(map[uint64]bool, len(inode.Replicas)) // 逐槽消费：每个健康节点只认一个槽
	for i, id := range inode.Replicas {
		// 健康且未被前序槽位占用的节点：跳过。重复节点（同一 ID 占多个槽）的
		// 第 2 个及以后落到 dupe 分支，当作"需换成不同物理节点"修，恢复冗余度。
		dupe := aliveSet[id] && doneSet[id] && slotHealthy[id]
		if aliveSet[id] && doneSet[id] && !slotHealthy[id] {
			slotHealthy[id] = true
			continue
		}

		// 选择源节点（随机一个 alive Done 副本）。
		if len(aliveDoneAddrs) == 0 {
			tasks = append(tasks, repairTask{Action: repairSkipNoSource, SlotIdx: i})
			continue
		}
		srcIdx := rand.Intn(len(aliveDoneAddrs))

		if aliveSet[id] && !dupe {
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
			// dead 或 重复槽：选一个不在 Replicas 中的新目标替换。
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
// 带 per-inode（legacy）/ per-chunk（分块）指数退避：连续未收敛的目标按
// 1x→2x→4x... 周期倍增间隔（封顶 40x），避免源节点长期故障时每轮重拉造成流量风暴。
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

	now := time.Now()
	for _, in := range inodes {
		// 分块文件（含 staging）：按块粒度修复。
		// staging 期间从副本未 Done 是正常态，但 pull 有 probeSource 404 探测
		// 兜底（主副本写完前 GET 是 404 → 跳过），不会拉半成品。
		if in.Chunked {
			s.repairChunkedInode(in, nodes, now)
			continue
		}
		s.repairLegacyInode(in, nodes, now)
	}
}

// repairLegacyInode 修复一个 legacy 整文件 inode（原 per-inode 路径）。
func (s *Scanner) repairLegacyInode(in types.Inode, nodes []types.NodeInfo, now time.Time) {
	// legacy 文件也纳入降级告警：此前只有分块路径有可见性，legacy 文件单副本
	// 裸奔完全静默（healthyCount 重复计数 bug 修复后，这里的 healthy 也已去重）。
	if !in.Staging && len(in.Replicas) > 0 {
		healthy := countHealthy(in.DoneReplicas, in.Replicas, nodes, s.nodeMaxAge, now)
		s.trackDegraded(in.ID, healthy, len(in.Replicas), now, fmt.Sprintf("inode %d (legacy)", in.ID))
	}
	tasks := planRepairs(in, nodes, s.nodeMaxAge)
	if len(tasks) == 0 {
		s.mu.Lock()
		delete(s.failStreak, in.ID)
		delete(s.nextAttempt, in.ID)
		s.mu.Unlock()
		return
	}
	s.mu.Lock()
	next, backed := s.nextAttempt[in.ID]
	s.mu.Unlock()
	if backed && now.Before(next) {
		return
	}
	s.bumpRepairBackoff(in.ID)
	for _, t := range tasks {
		s.executeRepair(in.ID, t)
	}
}

// repairChunkedInode 修复一个分块文件：每块视作独立小文件跑同一套修复逻辑。
// 退避 key 用 chunkID（staging inode 与已提交 inode 的块都修——
// staging 的块也要保持副本数，客户端可能传得很慢）。
func (s *Scanner) repairChunkedInode(in types.Inode, nodes []types.NodeInfo, now time.Time) {
	for _, c := range in.Chunks {
		chunkID := types.ChunkID(in.ID, c.Index)
		// 单副本窗口告警（改进项2）：块存活副本数（Done 且节点 alive）< len(Replicas)
		// 持续超过阈值 → WARN 一次；恢复 → INFO + 清记录。失败告警期间用户至少知道
		// 哪些块在裸奔（27472 宕机事故的教训：3 块单副本裸奔近 1 小时无人知晓）。
		s.trackDegradedChunk(in, c, chunkID, nodes, now)
		// 块任务以 ChunkInfo 为"迷你 inode"复用 planRepairs。
		pseudo := types.Inode{
			ID:           chunkID,
			Replicas:     c.Replicas,
			DoneReplicas: c.Done,
			Size:         c.Size,
		}
		tasks := planRepairs(pseudo, nodes, s.nodeMaxAge)
		if len(tasks) == 0 {
			s.mu.Lock()
			delete(s.failStreak, chunkID)
			delete(s.nextAttempt, chunkID)
			s.mu.Unlock()
			continue
		}
		s.mu.Lock()
		next, backed := s.nextAttempt[chunkID]
		s.mu.Unlock()
		if backed && now.Before(next) {
			continue
		}
		s.bumpRepairBackoff(chunkID)
		for _, t := range tasks {
			s.executeChunkRepair(in.ID, c.Index, t)
		}
	}
}

// trackDegradedChunk 单副本窗口告警（改进项2）。
// 降级定义：Done 且节点 alive 的副本数 < len(Replicas)（含 staging 期间从副本未同步的正常态，
// 但 staging TTL 会兜底回收；已 commit 文件的降级才是真风险）。
// 逻辑：首次发现记时刻；持续超 degradedWarnDur → WARN 一次（此后不再重复刷）；
// 恢复满副本或块消失 → 清记录，恢复时 INFO。
func (s *Scanner) trackDegradedChunk(in types.Inode, c types.ChunkInfo, chunkID uint64, nodes []types.NodeInfo, now time.Time) {
	if in.Staging {
		return // staging 文件降级是正常态（从副本还在路上），不告警
	}
	healthy := countHealthy(c.Done, c.Replicas, nodes, s.nodeMaxAge, now)
	s.trackDegraded(chunkID, healthy, len(c.Replicas), now,
		fmt.Sprintf("inode %d chunk %d", in.ID, c.Index))
}

// countHealthy 统计 done 集合里"节点仍 alive"且去重后的副本数（不超过 want）。
func countHealthy(done, replicas []uint64, nodes []types.NodeInfo, maxAge time.Duration, now time.Time) int {
	alive := make(map[uint64]bool, len(nodes))
	for _, n := range nodes {
		if now.Sub(n.LastHeartbeat) <= maxAge {
			alive[n.ID] = true
		}
	}
	replicaSet := make(map[uint64]bool, len(replicas))
	for _, id := range replicas {
		replicaSet[id] = true
	}
	seen := make(map[uint64]bool, len(done))
	healthy := 0
	for _, id := range done {
		if alive[id] && replicaSet[id] && !seen[id] {
			seen[id] = true
			healthy++
		}
	}
	return healthy
}

// trackDegraded 通用降级窗口告警（分块块 / legacy 文件共用）：
// healthy < want 持续超 degradedWarnDur → WARN 一次；恢复 → 清记录 + INFO。
// id 用 chunkID 或 legacy inode ID——两者数值空间不重叠，同一组 map 不会串。
func (s *Scanner) trackDegraded(id uint64, healthy, want int, now time.Time, desc string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if healthy >= want {
		if since, ok := s.degradedSince[id]; ok {
			delete(s.degradedSince, id)
			delete(s.degradedWarn, id)
			log.Printf("WARN-解除: %s 恢复满副本（降级时长 %s）", desc, now.Sub(since).Round(time.Second))
		}
		return
	}
	if _, ok := s.degradedSince[id]; !ok {
		s.degradedSince[id] = now
		return
	}
	if !s.degradedWarn[id] && now.Sub(s.degradedSince[id]) >= s.degradedWarnDur {
		s.degradedWarn[id] = true
		log.Printf("WARN: %s 单副本/降级已持续 %s（healthy=%d/%d）——再丢一节点数据可能丢失",
			desc, now.Sub(s.degradedSince[id]).Round(time.Second), healthy, want)
	}
}

// executeChunkRepair 执行单个块的修复任务（与 executeRepair 同构，写路径换块级 API）。
func (s *Scanner) executeChunkRepair(inodeID uint64, index int, t repairTask) {
	switch t.Action {
	case repairSkipNoSource:
		log.Printf("inode %d chunk %d: 无可用源节点，跳过", inodeID, index)
	case repairSkipNoTarget:
		log.Printf("inode %d chunk %d: 无合格新目标（dead node %d），跳过", inodeID, index, t.OldNodeID)
	case repairReplaceDead:
		chunkID := types.ChunkID(inodeID, index)
		if !s.probeSource(t.SourceAddr, chunkID) {
			log.Printf("inode %d chunk %d: 源 %s 上对象缺失（404），跳过修复", inodeID, index, t.SourceAddr)
			return
		}
		if err := s.store.ReplaceChunkReplica(inodeID, index, t.OldNodeID, t.NewNodeID); err != nil {
			if errors.Is(err, meta.ErrNotExist) || errors.Is(err, meta.ErrChunkNotExist) || errors.Is(err, meta.ErrReplicaDup) {
				return // 文件/块被并发删除 / 候选已是副本（下轮换一个），静默跳过
			}
			log.Printf("inode %d chunk %d: ReplaceChunkReplica 失败: %v", inodeID, index, err)
			return
		}
		log.Printf("inode %d chunk %d: 替换 dead node %d → %d，触发 pull", inodeID, index, t.OldNodeID, t.NewNodeID)
		s.triggerPull(t.NewNodeAddr, chunkID, t.SourceAddr)
	case repairTriggerPull:
		chunkID := types.ChunkID(inodeID, index)
		if !s.probeSource(t.SourceAddr, chunkID) {
			log.Printf("inode %d chunk %d: 源 %s 上对象缺失（404），跳过 pull", inodeID, index, t.SourceAddr)
			return
		}
		log.Printf("inode %d chunk %d: 触发 pull（alive 未 Done）", inodeID, index)
		s.triggerPull(t.TargetAddr, chunkID, t.SourceAddr)
	}
}

// bumpRepairBackoff 修复连续未收敛时推迟下次触发：1x→2x→4x…封顶 40 个 repairIntv。
// 收敛（len(tasks)==0）时由扫描循环直接清零 failStreak/nextAttempt。
func (s *Scanner) bumpRepairBackoff(inodeID uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failStreak[inodeID]++
	mult := int64(1 << min(s.failStreak[inodeID]-1, 6)) // streak 1,2,3… → 1x,2x,4x…封顶 64x
	if mult > 40 {
		mult = 40
	}
	s.nextAttempt[inodeID] = time.Now().Add(time.Duration(mult) * s.repairIntv)
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
		// 先探源：源上对象已丢失（404）时，换目标 + 重拉只会永远失败，
		// 白白 churn 元数据与流量——跳过并保持退避，等源恢复或人工介入。
		if !s.probeSource(t.SourceAddr, inodeID) {
			log.Printf("inode %d slot %d: 源 %s 上对象缺失（404），跳过修复", inodeID, t.SlotIdx, t.SourceAddr)
			return
		}
		if err := s.store.ReplaceReplica(inodeID, t.OldNodeID, t.NewNodeID); err != nil {
			if errors.Is(err, meta.ErrNotExist) || errors.Is(err, meta.ErrReplicaDup) {
				return // 文件被并发删除 / 候选已是副本（下轮换一个），静默跳过
			}
			log.Printf("inode %d slot %d: ReplaceReplica 失败: %v", inodeID, t.SlotIdx, err)
			return
		}
		log.Printf("inode %d slot %d: 替换 dead node %d → %d，触发 pull", inodeID, t.SlotIdx, t.OldNodeID, t.NewNodeID)
		s.triggerPull(t.NewNodeAddr, inodeID, t.SourceAddr)
	case repairTriggerPull:
		if !s.probeSource(t.SourceAddr, inodeID) {
			log.Printf("inode %d slot %d: 源 %s 上对象缺失（404），跳过 pull", inodeID, t.SlotIdx, t.SourceAddr)
			return
		}
		log.Printf("inode %d slot %d: 触发 pull（alive 未 Done）", inodeID, t.SlotIdx)
		s.triggerPull(t.TargetAddr, inodeID, t.SourceAddr)
	}
}

// probeSource 探测源节点上对象是否存在（Range 请求 1 字节，开销极小）。
// 仅当明确返回 404 才判"源数据丢失"；网络错误等其他失败保持乐观（仍触发 pull，由重试兜底）。
func (s *Scanner) probeSource(sourceAddr string, inodeID uint64) bool {
	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("%s://%s/objects/%d", s.scheme, sourceAddr, inodeID), nil)
	if err != nil {
		return true
	}
	req.Header.Set("Range", "bytes=0-0")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return true // 网络暂不可达：不阻止修复（可能是瞬时抖动）
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) // 排空以便连接复用
	return resp.StatusCode != http.StatusNotFound
}

// triggerPull 调用目标节点 POST /pull。
func (s *Scanner) triggerPull(targetAddr string, inodeID uint64, sourceAddr string) {
	body, _ := json.Marshal(map[string]any{
		"inode_id":    inodeID,
		"source_addr": sourceAddr,
	})
	resp, err := s.httpClient.Post(fmt.Sprintf("%s://%s/pull", s.scheme, targetAddr), "application/json", bytes.NewReader(body))
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
	NodeID      uint64        `json:"node_id"`
	NodeAddr    string        `json:"node_addr"`
	Orphans     []ObjectEntry `json:"orphans"`
	OrphanBytes int64         `json:"orphan_bytes"`
	// Deleted 本轮实际删除的孤儿数（仅 execute）。两轮确认下首轮恒为 0——
	// 此前 CLI 直接拿 len(Orphans) 当删除数打印"已删除 N"，首轮会虚报。
	Deleted int `json:"deleted"`
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
// 孤儿两轮确认：只有连续两轮扫描都在孤儿集合中的对象才允许删除。
// 这消除了"上传中的新块 vs GC 快照"竞态（快照没含新块 → 新块被误判孤儿）。
func (s *Scanner) runGC(execute bool) ([]GCNodeReport, error) {
	nodes, err := s.store.ListNodes()
	if err != nil {
		return nil, fmt.Errorf("列出节点: %w", err)
	}
	cutoff := time.Now().Add(-s.nodeMaxAge)

	// 收集全部有效对象 ID：legacy 文件自身 ID + 分块文件的块 ID（含 staging 块）。
	validIDs := make(map[uint64]bool)
	if err := s.store.ForEachFile(func(in types.Inode) error {
		if in.Chunked {
			for _, c := range in.Chunks {
				validIDs[types.ChunkID(in.ID, c.Index)] = true
			}
		} else {
			validIDs[in.ID] = true
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("遍历文件: %w", err)
	}

	var reports []GCNodeReport
	curOrphans := make(map[uint64]map[uint64]bool) // 本轮孤儿快照
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

		set := make(map[uint64]bool, len(orphans))
		for _, o := range orphans {
			set[o.ID] = true
		}
		curOrphans[n.ID] = set

		if execute {
			// 只删上轮也判孤儿的对象（两轮确认）。
			s.mu.Lock()
			prev := s.prevOrphans[n.ID]
			s.mu.Unlock()
			var confirmed []ObjectEntry
			for _, o := range orphans {
				if prev == nil || !prev[o.ID] {
					continue // 上轮没见过它，本轮留它到下轮再删
				}
				confirmed = append(confirmed, o)
			}
			if len(confirmed) > 0 {
				report.Deleted = s.deleteOrphans(n.Addr, confirmed)
				log.Printf("GC 节点 %d (%s): 两轮确认删除 %d/%d 个孤儿", n.ID, n.Addr, report.Deleted, len(confirmed))
			}
		}
		reports = append(reports, report)
	}
	// 保存本轮孤儿集合作为下轮的"上轮"快照。
	s.mu.Lock()
	s.prevOrphans = curOrphans
	s.mu.Unlock()
	return reports, nil
}

// sweepStaging 清扫超时 staging inode（客户端崩溃残留）：
// 删 staging 元数据 + 通知节点回收已落盘的块。TTL 默认 24h。
func (s *Scanner) sweepStaging() {
	var expired []types.Inode
	if err := s.store.ForEachStaging(func(in types.Inode) error {
		if time.Since(in.Mtime) > s.stagingTTL {
			expired = append(expired, in)
		}
		return nil
	}); err != nil {
		log.Printf("staging 清扫: %v", err)
		return
	}
	for _, in := range expired {
		if err := s.store.AbortStaging(in.ID); err != nil {
			log.Printf("staging 清扫: 回收 %d 失败: %v", in.ID, err)
			continue
		}
		for _, c := range in.Chunks {
			s.notifyDeleteAsync(types.ChunkID(in.ID, c.Index), c.Replicas)
		}
		log.Printf("staging 清扫: 回收超时上传 %d（%d 块）", in.ID, len(in.Chunks))
	}
}

// notifyDeleteAsync 异步通知节点删除对象（staging 清扫用，失败只记日志）。
func (s *Scanner) notifyDeleteAsync(objectID uint64, replicaNodeIDs []uint64) {
	for _, id := range replicaNodeIDs {
		n, err := s.store.GetNode(id)
		if err != nil {
			continue
		}
		go func(addr string) {
			req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s://%s/objects/%d", s.scheme, addr, objectID), nil)
			if err != nil {
				return
			}
			resp, err := s.httpClient.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()
		}(n.Addr)
	}
}

// fetchNodeObjects 获取节点的对象清单。
func (s *Scanner) fetchNodeObjects(addr string) ([]ObjectEntry, error) {
	resp, err := s.httpClient.Get(fmt.Sprintf("%s://%s/admin/objects", s.scheme, addr))
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
		req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s://%s/objects/%d", s.scheme, addr, o.ID), nil)
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
