package master

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"atoll/master/meta"
	"atoll/pkg/types"
)

// chunkKeyIdx 解析快照分块 key（snapshot-<ver>-<idx>）末尾的数字下标。
// 用于拼接排序：绝不能按 key 字符串排——idx≥10 时 "snapshot-5-10" 会排到
// "snapshot-5-2" 前面，快照字节错位、bbolt 能打开却内容全乱（元数据静默损坏）。
// 解析失败返回 -1（排到最前，尽早暴露异常 key），调用方再兜底。
func chunkKeyIdx(key string) int {
	i := strings.LastIndexByte(key, '-')
	if i < 0 || i == len(key)-1 {
		return -1
	}
	n, err := strconv.Atoi(key[i+1:])
	if err != nil {
		return -1
	}
	return n
}

// 元数据恢复（HA 第一阶段，步骤 4）：master 启动时决定用本地 bbolt 还是从集群重建。
//
// 两件事分开（见 HA 设计决策点 3）：
//   - 成员发现"有哪些节点"：靠种子列表（配置里 ≥1 个已知节点地址）。完整 gossip 是后续
//     优化；当前直接把种子当作可达节点集合查询。
//   - 版本发现：向可达种子收 manifest，选择最大日志水位；这不是多数派读取证明。
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
	ActionUseLocal   RecoverAction = iota // 直接打开本地库
	ActionRebuild                         // 从集群拉快照+WAL 重建
	ActionFreshStart                      // 全新集群，无本地也无集群备份
	ActionFailStop                        // 硬停，等人工裁决
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
	Mode           RecoverMode
	LocalExists    bool
	LocalSeq       uint64 // 本地库的 WAL seq（LocalExists=true 时有效）
	ClusterFound   bool   // 是否从种子收到任何 manifest
	ClusterUnknown bool   // 是否有种子不可达/响应损坏（无法确认"没有"）
	ClusterSeq     uint64 // 集群 manifest 的 max LatestSeq（ClusterFound=true 时有效）
	SeedsGiven     bool   // 是否配置了种子（未配置 = 不启用 HA 恢复，走 legacy 行为）
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
	default:
		if in.Mode != RecoverAuto && in.Mode != "" {
			return ActionFailStop, fmt.Sprintf("未知恢复模式 %q", in.Mode)
		}
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
		if in.ClusterUnknown {
			// 有种子答不上来："没查到 manifest"不等于"确认没有旧集群"——
			// 若这是旧集群 master 换机，建空库开始写会制造脑裂/旧对象被 GC 误删。
			return ActionFailStop, "本地库不存在且种子备份状态不可确认（不可达或响应无效）；请恢复种子连接并核对备份后重试，不能据此初始化空库"
		}
		// 全部种子明确回答无 manifest：全新集群首次启动。
		return ActionFreshStart, "本地与集群均确认无元数据，全新集群启动"
	}
	// 本地没了但集群有备份：疑似换机/盘坏，硬停等人决定是否从集群重建。
	return ActionFailStop, "本地库不存在但集群有元数据备份（疑似换机/盘损），硬停等人工决定（--recover-from=cluster 重建 / 确认全新则先清空集群备份）"
}

// ErrFailStop 表示恢复需要人工介入，master 应停止启动。
type ErrFailStop struct{ Reason string }

func (e *ErrFailStop) Error() string { return "元数据恢复需人工裁决: " + e.Reason }

// gatherClusterManifest 向种子收 manifest，返回 max LatestSeq 的 manifest、是否找到、
// 以及是否有种子"状态未知"（网络错误/损坏响应）。关键区分：found=false 且 unknown=false
// 才是"所有种子都明确说没有"（可 fresh start）；只要有一个种子没答上来，
// 本地库又不在，就绝不能把它当全新集群。
func (b *MetaBackup) gatherClusterManifest(seeds []string) (best Manifest, found bool, unknown bool) {
	for _, addr := range seeds {
		wire, ok, err := b.getBlob(addr, ManifestKey)
		if err != nil {
			unknown = true
			log.Printf("恢复: 种子 %s 的 manifest 不可达: %v", addr, err)
			continue
		}
		if !ok {
			// 路由不存在也可能返回 404；必须确认节点有备份接口且清单为空。
			blobs, listErr := b.listBlobs(addr)
			if listErr != nil || blobs == nil || len(blobs) != 0 {
				unknown = true
				log.Printf("恢复: 种子 %s 缺 manifest，但不能确认备份为空（条目=%d，错误=%v）", addr, len(blobs), listErr)
			}
			continue
		}
		raw, err := b.decodeBlob(ManifestKey, wire)
		if err != nil {
			unknown = true
			log.Printf("恢复: 种子 %s 的 manifest 无法解密: %v", addr, err)
			continue
		}
		m, err := unmarshalManifest(raw)
		if err == nil {
			err = validateRecoveryManifest(m)
		}
		if err != nil {
			unknown = true
			log.Printf("恢复: 种子 %s 的 manifest 无效: %v", addr, err)
			continue
		}
		if !found || m.LatestSeq() > best.LatestSeq() ||
			(m.LatestSeq() == best.LatestSeq() && m.Version > best.Version) {
			best = m
			found = true
		}
	}
	return best, found, unknown
}

func validateRecoveryManifest(m Manifest) error {
	if m.Version == 0 || len(m.Chunks) == 0 || m.SnapshotBytes <= 0 || m.SnapshotSeq == ^uint64(0) {
		return fmt.Errorf("missing snapshot identity, chunks or size")
	}
	seen := make(map[string]bool, len(m.Chunks))
	var size int64
	for _, ch := range m.Chunks {
		if ch.Size <= 0 || ch.Size > m.SnapshotBytes-size || seen[ch.Key] {
			return fmt.Errorf("invalid snapshot chunk %q", ch.Key)
		}
		size += ch.Size
		seen[ch.Key] = true
	}
	if size != m.SnapshotBytes {
		return fmt.Errorf("snapshot size %d != manifest %d", size, m.SnapshotBytes)
	}
	for i := range m.Chunks {
		if !seen[fmt.Sprintf("snapshot-%d-%d", m.Version, i)] {
			return fmt.Errorf("snapshot chunk index %d missing", i)
		}
	}
	segs := append([]WALSegRef(nil), m.WALSegs...)
	sort.Slice(segs, func(i, j int) bool { return segs[i].FromSeq < segs[j].FromSeq })
	seq := m.SnapshotSeq
	for _, seg := range segs {
		if seg.FromSeq != seq+1 || seg.ToSeq < seg.FromSeq || seg.ToSeq == ^uint64(0) || seg.Size <= 0 {
			return fmt.Errorf("invalid WAL range %d-%d after %d", seg.FromSeq, seg.ToSeq, seq)
		}
		if seg.Key != fmt.Sprintf("wal-%d-%d-%d", m.Version, seg.FromSeq, seg.ToSeq) {
			return fmt.Errorf("WAL key %q does not match its range", seg.Key)
		}
		seq = seg.ToSeq
	}
	return nil
}

// rebuildFromCluster 只在快照与 WAL 全部校验成功后发布最终数据库。
func (b *MetaBackup) rebuildFromCluster(dbPath string, m Manifest, seeds []string) (*meta.Store, error) {
	if err := validateRecoveryManifest(m); err != nil {
		return nil, fmt.Errorf("rebuild: manifest: %w", err)
	}
	if _, err := os.Lstat(dbPath); err == nil {
		return nil, fmt.Errorf("rebuild: 目标 %s 已存在，拒绝覆盖", dbPath)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("rebuild: 检查目标 %s: %w", dbPath, err)
	}

	// 与目标同一文件系统、且只清理本次创建的目录，避免踩到中断恢复的残留文件。
	workDir, err := os.MkdirTemp(filepath.Dir(dbPath), ".atoll-rebuild-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(workDir)
	snapshotPath := filepath.Join(workDir, "snapshot.db")
	snapshot, err := os.OpenFile(snapshotPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	defer snapshot.Close()
	chunks := append([]ChunkRef(nil), m.Chunks...)
	sort.Slice(chunks, func(i, j int) bool { return chunkKeyIdx(chunks[i].Key) < chunkKeyIdx(chunks[j].Key) })
	for _, ch := range chunks {
		part, err := b.fetchChunk(ch, seeds)
		if err != nil {
			return nil, err
		}
		if _, err := snapshot.Write(part); err != nil {
			return nil, err
		}
	}
	if err := snapshot.Sync(); err != nil {
		return nil, err
	}
	if err := snapshot.Close(); err != nil {
		return nil, err
	}
	if err := meta.ValidateSnapshotFile(snapshotPath); err != nil {
		return nil, fmt.Errorf("rebuild: 快照无效: %w", err)
	}

	store, err := meta.Open(snapshotPath)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	snapshotSeq, err := store.WALSeq()
	if err != nil {
		return nil, err
	}
	// 旧版先取 WALSeq 再取快照，两者间的提交可令快照比 manifest 锚点更新。
	if snapshotSeq < m.SnapshotSeq {
		return nil, fmt.Errorf("rebuild: snapshot seq %d < manifest %d", snapshotSeq, m.SnapshotSeq)
	}
	frames, err := b.gatherAllFramesAfter(m, store, seeds)
	if err != nil {
		return nil, err
	}
	if err := store.ApplyFrames(frames); err != nil {
		return nil, err
	}
	seq, err := store.WALSeq()
	if err != nil {
		return nil, err
	}
	if seq < m.LatestSeq() {
		return nil, fmt.Errorf("rebuild: restored seq %d < manifest %d", seq, m.LatestSeq())
	}
	if err := store.SetBackupVersionAtLeast(m.Version); err != nil {
		return nil, err
	}
	if err := store.Close(); err != nil {
		return nil, err
	}
	if err := meta.ValidateSnapshotFile(snapshotPath); err != nil {
		return nil, fmt.Errorf("rebuild: 恢复库无效: %w", err)
	}
	file, err := os.OpenFile(snapshotPath, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if syncErr != nil {
		return nil, syncErr
	}
	if closeErr != nil {
		return nil, closeErr
	}

	// Link 的 no-replace 语义保证并发出现的目标不会被 rename 覆盖。
	if err := os.Link(snapshotPath, dbPath); err != nil {
		return nil, fmt.Errorf("rebuild: 发布 %s: %w", dbPath, err)
	}
	dir, err := os.Open(filepath.Dir(dbPath))
	if err != nil {
		return nil, fmt.Errorf("rebuild: 完整库已发布，但打开父目录同步失败: %w", err)
	}
	syncErr = dir.Sync()
	closeErr = dir.Close()
	if syncErr != nil {
		return nil, fmt.Errorf("rebuild: 完整库已发布，但目录同步失败: %w", syncErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return meta.Open(dbPath)
}

// gatherAllFramesAfter 汇集快照点之后的所有 WAL 帧：manifest 成段 + 散落同步帧 blob。
// 按 seq 去重升序，交给 ApplyFrames（它要求连续无缺口）。
func (b *MetaBackup) gatherAllFramesAfter(m Manifest, store *meta.Store, seeds []string) ([]meta.Frame, error) {
	bySeq := map[uint64]meta.Frame{}
	addFrame := func(f meta.Frame) error {
		if previous, ok := bySeq[f.Seq]; ok &&
			!bytes.Equal(meta.EncodeWALSegment([]meta.Frame{previous}), meta.EncodeWALSegment([]meta.Frame{f})) {
			return fmt.Errorf("rebuild: conflicting WAL payloads at seq %d", f.Seq)
		}
		bySeq[f.Seq] = f
		return nil
	}
	if len(m.WALSegs) > 0 {
		segFrames, err := b.fetchWALFrames(m, seeds)
		if err != nil {
			return nil, err
		}
		for _, f := range segFrames {
			if err := addFrame(f); err != nil {
				return nil, err
			}
		}
	}

	after, err := store.WALSeq()
	if err != nil {
		return nil, err
	}
	observed := make(map[uint64]bool)
	for _, addr := range seeds {
		blobs, err := b.listBlobs(addr)
		if err != nil {
			log.Printf("恢复: 无法枚举种子 %s 的同步帧: %v", addr, err)
			continue
		}
		for _, bl := range blobs {
			seq, ok := parseSyncFrameSeq(bl.Key)
			if !ok || seq <= after {
				continue
			}
			observed[seq] = true
			wire, found, err := b.getBlob(addr, bl.Key)
			if err != nil || !found {
				continue
			}
			plain, derr := b.decodeBlob(bl.Key, wire)
			if derr != nil {
				continue
			}
			fs, err := meta.DecodeWALSegment(plain)
			if err != nil || len(fs) != 1 || fs[0].Seq != seq {
				continue
			}
			if err := addFrame(fs[0]); err != nil {
				return nil, err
			}
		}
	}
	// 见过但无法读取的尾帧也不能默默丢弃，仅中间缺口检测不足以保护最后一笔写。
	for seq := range observed {
		if _, ok := bySeq[seq]; !ok {
			return nil, fmt.Errorf("rebuild: observed WAL seq %d has no valid copy", seq)
		}
	}
	seqs := make([]uint64, 0, len(bySeq))
	for seq := range bySeq {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	frames := make([]meta.Frame, 0, len(seqs))
	for _, seq := range seqs {
		frames = append(frames, bySeq[seq])
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

// fetchChunk 从种子里试取一个块：解密后按 manifest 记录的明文尺寸/CRC 校验
// （加密批次 wire 每次不同，不能按线格式比对）。任一持有者解密+校验通过即用。
func (b *MetaBackup) fetchChunk(ch ChunkRef, seeds []string) ([]byte, error) {
	for _, addr := range seeds {
		wire, ok, err := b.getBlob(addr, ch.Key)
		if err != nil || !ok {
			continue
		}
		plain, derr := b.decodeBlob(ch.Key, wire)
		if derr == nil && int64(len(plain)) == ch.Size && types.CRC32C(plain) == ch.CRC32C {
			return plain, nil
		}
		// 损坏、密文不符或解密失败：试下一个持有者。
	}
	return nil, fmt.Errorf("rebuild: 块 %s 在所有种子上都取不到或校验失败", ch.Key)
}

// fetchWALFrames 从种子取 manifest 记录的 WAL 段（先解密再校验/解码），成帧序列
// （按 seq 升序）。
func (b *MetaBackup) fetchWALFrames(m Manifest, seeds []string) ([]meta.Frame, error) {
	segs := append([]WALSegRef(nil), m.WALSegs...)
	sort.Slice(segs, func(i, j int) bool { return segs[i].FromSeq < segs[j].FromSeq })
	var frames []meta.Frame
	for _, seg := range segs {
		var raw []byte
		got := false
		for _, addr := range seeds {
			wire, ok, err := b.getBlob(addr, seg.Key)
			if err != nil || !ok {
				continue
			}
			plain, derr := b.decodeBlob(seg.Key, wire)
			if derr != nil || int64(len(plain)) != seg.Size || types.CRC32C(plain) != seg.CRC32C {
				continue
			}
			raw = plain
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
		if uint64(len(fs)) != seg.ToSeq-seg.FromSeq+1 {
			return nil, fmt.Errorf("rebuild: WAL segment %s count does not match its range", seg.Key)
		}
		for i, f := range fs {
			if f.Seq != seg.FromSeq+uint64(i) {
				return nil, fmt.Errorf("rebuild: WAL segment %s is not contiguous", seg.Key)
			}
		}
		frames = append(frames, fs...)
	}
	return frames, nil
}

// Recover 是恢复入口：按 mode + 本地/集群事实决策，返回可用 store 或 fail-stop 错误。
// dbPath 本地库路径；seeds 种子节点地址（host:port）。
func (b *MetaBackup) Recover(dbPath string, seeds []string, mode RecoverMode) (*meta.Store, error) {
	in := RecoverInput{Mode: mode, SeedsGiven: len(seeds) > 0}

	// 已存在的目标必须是可验证的本地库；断链符号链接不是“库不存在”。
	if st, statErr := os.Lstat(dbPath); statErr == nil {
		if !st.Mode().IsRegular() || st.Size() == 0 {
			return nil, &ErrFailStop{Reason: "本地元数据库不是有效的普通文件，拒绝初始化或覆盖"}
		}
		if err := meta.ValidateSnapshotFile(dbPath); err != nil {
			return nil, fmt.Errorf("恢复: 校验本地库: %w", err)
		}
		in.LocalExists = true
		s, err := meta.Open(dbPath)
		if err != nil {
			return nil, fmt.Errorf("恢复: 打开本地库读 seq 失败: %w", err)
		}
		seq, err := s.WALSeq()
		closeErr := s.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		in.LocalSeq = seq
	} else if !os.IsNotExist(statErr) {
		return nil, fmt.Errorf("恢复: 检查本地库: %w", statErr)
	}

	// 集群事实：向种子收 manifest 取 max（仅在配了种子时）。
	var clusterMF Manifest
	if in.SeedsGiven {
		clusterMF, in.ClusterFound, in.ClusterUnknown = b.gatherClusterManifest(seeds)
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
