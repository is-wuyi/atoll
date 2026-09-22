package master

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"

	"atoll/master/meta"
	"atoll/pkg/types"
)

// 元数据恢复（HA 第一阶段，步骤 4）：master 启动时决定用本地 bbolt 还是从集群重建。
//
// 两件事分开（见 HA 设计决策点 3）：
//   - 成员发现"有哪些节点"：靠种子列表（配置里 ≥1 个已知节点地址）。完整 gossip 是后续
//     优化；当前直接把种子当作可达节点集合查询。
//   - 版本发现"哪个最新"：向种子收 manifest 取 max 版本（读写集合相交 R+W>N 保证看到最新）。
//
// fail-stop（决策点 4）：干净情形静默用本地；危险/歧义情形硬停等人，绝不自作主张覆盖。

// RecoverMode 恢复模式（对应 --recover-from）。
type RecoverMode string

const (
	RecoverAuto    RecoverMode = "auto"    // 默认：按规则判断，歧义则硬停
	RecoverLocal   RecoverMode = "local"   // 强制用本地（人工裁决后）
	RecoverCluster RecoverMode = "cluster" // 强制从集群重建（人工裁决后）
)

// RecoverAction 恢复决策结果。
type RecoverAction int

const (
	ActionUseLocal    RecoverAction = iota // 直接打开本地库
	ActionRebuild                          // 从集群拉快照+WAL 重建
	ActionFreshStart                       // 全新集群，无本地也无集群备份
	ActionFailStop                         // 硬停，等人工裁决
)

func (a RecoverAction) String() string {
	switch a {
	case ActionUseLocal:
		return "use-local"
	case ActionRebuild:
		return "rebuild-from-cluster"
	case ActionFreshStart:
		return "fresh-start"
	default:
		return "fail-stop"
	}
}

// RecoverInput 是决策所需的全部事实（纯数据，便于单测决策逻辑）。
type RecoverInput struct {
	Mode          RecoverMode
	LocalExists   bool
	LocalSeq      uint64 // 本地库的 WAL seq（LocalExists=true 时有效）
	ClusterFound  bool   // 是否从种子收到任何 manifest
	ClusterSeq    uint64 // 集群 manifest 的 max LatestSeq（ClusterFound=true 时有效）
	SeedsGiven    bool   // 是否配置了种子（未配置 = 不启用 HA 恢复，走 legacy 行为）
}

// decideRecovery 是纯决策函数：给定事实，返回动作与人类可读理由。
// 不做任何 IO，全部分支可单测。
func decideRecovery(in RecoverInput) (RecoverAction, string) {
	// 显式人工裁决优先。
	switch in.Mode {
	case RecoverLocal:
		if !in.LocalExists {
			return ActionFailStop, "--recover-from=local 但本地库不存在"
		}
		return ActionUseLocal, "人工指定用本地库"
	case RecoverCluster:
		if !in.ClusterFound {
			return ActionFailStop, "--recover-from=cluster 但集群没有可用 manifest"
		}
		return ActionRebuild, "人工指定从集群重建"
	}

	// auto 模式。
	// 未配置种子：不启用 HA 恢复，保持 legacy 行为（本地有就用，没有就新建空库）。
	if !in.SeedsGiven {
		return ActionUseLocal, "未配置种子，按 legacy 直接使用/新建本地库"
	}

	if in.LocalExists {
		if !in.ClusterFound {
			// 集群不可达/无备份，但本地在：用本地，大声记日志（无法核对新鲜度）。
			return ActionUseLocal, "本地库存在但集群 manifest 不可达，暂用本地（无法核对新鲜度，请关注）"
		}
		if in.ClusterSeq <= in.LocalSeq {
			// 本地 >= 集群：本地是最新或更新，静默用本地。
			return ActionUseLocal, fmt.Sprintf("本地 seq %d ≥ 集群 seq %d，用本地", in.LocalSeq, in.ClusterSeq)
		}
		// 本地落后于集群：危险，硬停等人核对（自动覆盖任一方向都可能毁数据）。
		return ActionFailStop, fmt.Sprintf("本地 seq %d < 集群 seq %d，本地落后，硬停等人工核对（--recover-from=cluster 从集群重建 / =local 坚持用本地）", in.LocalSeq, in.ClusterSeq)
	}

	// 本地不存在。
	if !in.ClusterFound {
		// 本地无、集群也无：全新集群首次启动。
		return ActionFreshStart, "本地与集群均无元数据，全新集群启动"
	}
	// 本地没了但集群有备份：疑似换机/盘坏，硬停等人决定是否从集群重建。
	return ActionFailStop, "本地库不存在但集群有元数据备份（疑似换机/盘损），硬停等人工决定（--recover-from=cluster 重建 / 确认全新则先清空集群备份）"
}

// ErrFailStop 表示恢复需要人工介入，master 应停止启动。
type ErrFailStop struct{ Reason string }

func (e *ErrFailStop) Error() string { return "元数据恢复需人工裁决: " + e.Reason }

// gatherClusterSeq 向种子收 manifest，返回 max LatestSeq 与承载它的 manifest。
// 任一种子不可达/无 manifest 只跳过；全都没有则 found=false。
func (b *MetaBackup) gatherClusterManifest(seeds []string) (best Manifest, found bool) {
	for _, addr := range seeds {
		raw, ok, err := b.getBlob(addr, ManifestKey)
		if err != nil || !ok {
			continue
		}
		m, err := unmarshalManifest(raw)
		if err != nil {
			continue
		}
		if !found || m.LatestSeq() > best.LatestSeq() {
			best = m
			found = true
		}
	}
	return best, found
}

// rebuildFromCluster 按 manifest 从种子拉快照块（CRC 校验）拼成快照字节，恢复到 dbPath。
// holder ID 无法直接映射地址（成员表尚未持久化），故对每个块 key 遍历种子试取，取到 CRC
// 符合的即用——块 key 全局唯一，任一持有者的副本都一样。
func (b *MetaBackup) rebuildFromCluster(dbPath string, m Manifest, seeds []string) (*meta.Store, error) {
	// 块按 idx 升序拼接。manifest.Chunks 构造时即升序，这里再排一次防御。
	chunks := append([]ChunkRef(nil), m.Chunks...)
	sort.Slice(chunks, func(i, j int) bool { return chunks[i].Key < chunks[j].Key })

	var snapshot []byte
	for _, ch := range chunks {
		part, err := b.fetchChunk(ch, seeds)
		if err != nil {
			return nil, err
		}
		snapshot = append(snapshot, part...)
	}
	if len(snapshot) == 0 {
		return nil, fmt.Errorf("rebuild: 快照为空")
	}

	// 落地重建（RestoreFromReader 拒绝覆盖，故先确保 dbPath 不存在）。
	if _, err := os.Stat(dbPath); err == nil {
		return nil, fmt.Errorf("rebuild: 目标 %s 已存在，拒绝覆盖（请人工确认后移除）", dbPath)
	}
	store, err := meta.RestoreFromReader(dbPath, bytes.NewReader(snapshot))
	if err != nil {
		return nil, err
	}

	// 重放快照之后的 WAL：既包括 manifest 记录的成段 WAL（后台异步 ship），也包括
	// 散落的同步帧 blob（wal-sync-<seq>，同步旋钮直接落集群、可能还没进 manifest）。
	// 两者按 seq 合并去重、升序重放——否则"同步落盘但没进 manifest"的帧会丢。
	frames, err := b.gatherAllFramesAfter(m, store, seeds)
	if err != nil {
		store.Close()
		return nil, err
	}
	if len(frames) > 0 {
		if err := store.ApplyFrames(frames); err != nil {
			store.Close()
			return nil, err
		}
	}
	return store, nil
}

// gatherAllFramesAfter 汇集快照点之后的所有 WAL 帧：manifest 成段 + 散落同步帧 blob。
// 按 seq 去重升序，交给 ApplyFrames（它要求连续无缺口）。
func (b *MetaBackup) gatherAllFramesAfter(m Manifest, store *meta.Store, seeds []string) ([]meta.Frame, error) {
	bySeq := map[uint64]meta.Frame{}

	// 1) manifest 记录的成段 WAL。
	if len(m.WALSegs) > 0 {
		segFrames, err := b.fetchWALFrames(m, seeds)
		if err != nil {
			return nil, err
		}
		for _, f := range segFrames {
			bySeq[f.Seq] = f
		}
	}

	// 2) 散落的同步帧 blob（wal-sync-<seq>）：LIST 每个种子，取 seq > 快照点的。
	after := m.SnapshotSeq
	for _, addr := range seeds {
		blobs, err := b.listBlobs(addr)
		if err != nil {
			continue // 单节点不可达跳过，其它节点可能也有同一帧
		}
		for _, bl := range blobs {
			seq, ok := parseSyncFrameSeq(bl.Key)
			if !ok || seq <= after {
				continue
			}
			if _, have := bySeq[seq]; have {
				continue // 已从成段 WAL 拿到
			}
			data, found, err := b.getBlob(addr, bl.Key)
			if err != nil || !found {
				continue
			}
			fs, err := meta.DecodeWALSegment(data) // 同步帧也是"单帧的段"，复用解码
			if err != nil || len(fs) == 0 {
				continue
			}
			bySeq[seq] = fs[0]
		}
	}

	if len(bySeq) == 0 {
		return nil, nil
	}
	// 按 seq 升序输出；ApplyFrames 要求从 (快照点+1) 起连续。
	seqs := make([]uint64, 0, len(bySeq))
	for s := range bySeq {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	frames := make([]meta.Frame, 0, len(seqs))
	for _, s := range seqs {
		frames = append(frames, bySeq[s])
	}
	return frames, nil
}

// parseSyncFrameSeq 解析同步帧 blob key：wal-sync-<seq>。非此格式返回 ok=false。
func parseSyncFrameSeq(key string) (uint64, bool) {
	const prefix = "wal-sync-"
	if len(key) <= len(prefix) || key[:len(prefix)] != prefix {
		return 0, false
	}
	v, err := strconv.ParseUint(key[len(prefix):], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// fetchChunk 从种子里试取一个块，校验 CRC 与大小。
func (b *MetaBackup) fetchChunk(ch ChunkRef, seeds []string) ([]byte, error) {
	for _, addr := range seeds {
		data, ok, err := b.getBlob(addr, ch.Key)
		if err != nil || !ok {
			continue
		}
		if int64(len(data)) != ch.Size || types.CRC32C(data) != ch.CRC32C {
			continue // 损坏/不符，试下一个持有者
		}
		return data, nil
	}
	return nil, fmt.Errorf("rebuild: 块 %s 在所有种子上都取不到或校验失败", ch.Key)
}

// fetchWALFrames 从种子取 manifest 记录的 WAL 段，解码成帧序列（按 seq 升序）。
func (b *MetaBackup) fetchWALFrames(m Manifest, seeds []string) ([]meta.Frame, error) {
	segs := append([]WALSegRef(nil), m.WALSegs...)
	sort.Slice(segs, func(i, j int) bool { return segs[i].FromSeq < segs[j].FromSeq })
	var frames []meta.Frame
	for _, seg := range segs {
		var raw []byte
		got := false
		for _, addr := range seeds {
			data, ok, err := b.getBlob(addr, seg.Key)
			if err != nil || !ok {
				continue
			}
			if int64(len(data)) != seg.Size || types.CRC32C(data) != seg.CRC32C {
				continue
			}
			raw = data
			got = true
			break
		}
		if !got {
			return nil, fmt.Errorf("rebuild: WAL 段 %s 取不到或校验失败", seg.Key)
		}
		fs, err := meta.DecodeWALSegment(raw)
		if err != nil {
			return nil, err
		}
		frames = append(frames, fs...)
	}
	return frames, nil
}

// Recover 是恢复入口：按 mode + 本地/集群事实决策，返回可用 store 或 fail-stop 错误。
// dbPath 本地库路径；seeds 种子节点地址（host:port）。
func (b *MetaBackup) Recover(dbPath string, seeds []string, mode RecoverMode) (*meta.Store, error) {
	in := RecoverInput{Mode: mode, SeedsGiven: len(seeds) > 0}

	// 本地事实：文件是否存在 + 其 WAL seq。
	if _, err := os.Stat(dbPath); err == nil {
		in.LocalExists = true
		// 打开读一下 seq 再关（决策后可能重开或改用集群）。
		s, err := meta.Open(dbPath)
		if err != nil {
			return nil, fmt.Errorf("恢复: 打开本地库读 seq 失败: %w", err)
		}
		seq, err := s.WALSeq()
		s.Close()
		if err != nil {
			return nil, err
		}
		in.LocalSeq = seq
	}

	// 集群事实：向种子收 manifest 取 max（仅在配了种子时）。
	var clusterMF Manifest
	if in.SeedsGiven {
		clusterMF, in.ClusterFound = b.gatherClusterManifest(seeds)
		if in.ClusterFound {
			in.ClusterSeq = clusterMF.LatestSeq()
		}
	}

	action, reason := decideRecovery(in)
	log.Printf("元数据恢复决策: %s（%s）", action, reason)

	var store *meta.Store
	var err error
	switch action {
	case ActionUseLocal, ActionFreshStart:
		store, err = meta.Open(dbPath) // 本地在则打开，不在则新建空库
	case ActionRebuild:
		store, err = b.rebuildFromCluster(dbPath, clusterMF, seeds)
	default: // ActionFailStop
		return nil, &ErrFailStop{Reason: reason}
	}
	if err != nil {
		return nil, err
	}

	// 版本号权威在本地 bbolt（NextBackupVersion 持久自增）。这里只做防御性对账：
	// 若集群 manifest 的版本号比本地持久值还高（例如从集群重建、或本地曾回退），
	// 把本地抬到不低于它，确保后续 NextBackupVersion 续增时不会倒退、prune cutoff 正确。
	if in.ClusterFound && clusterMF.Version > 0 {
		if err := store.SetBackupVersionAtLeast(clusterMF.Version); err != nil {
			store.Close()
			return nil, err
		}
	}
	// 把持久版本号载入内存缓存（Status/prune 快速读，避免每次读盘）。
	pv, err := store.BackupVersion()
	if err != nil {
		store.Close()
		return nil, err
	}
	b.mu.Lock()
	b.version = pv
	b.mu.Unlock()
	return store, nil
}
