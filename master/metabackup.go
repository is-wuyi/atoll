package master

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"atoll/master/meta"
	"atoll/pkg/auth"
	"atoll/pkg/types"
)

// marshalManifest / unmarshalManifest 是 manifest 的编解码（JSON，人类可读便于诊断）。
func marshalManifest(m *Manifest) ([]byte, error) { return json.Marshal(m) }

func unmarshalManifest(raw []byte) (Manifest, error) {
	var m Manifest
	err := json.Unmarshal(raw, &m)
	return m, err
}

// 元数据备份进集群（HA 第一阶段）：master 把元数据快照+WAL 当特殊 blob 复制到存储
// 节点，本机 bbolt 从"唯一副本"降级为"热副本"。堵死"元数据文件永久丢失"这条不可逆风险。
//
// 放置策略（见 HA 设计）：
//   - 快照/WAL blob：K=min(3, 存活节点数) 份，放当前负载最低的 K 个节点（每次重选，
//     不固定绑死）。
//   - manifest：极小（几百字节），宽复制到"尽可能多的节点"——大数据放 3 份、小指针撒
//     一片，恢复时向多节点取 max 版本即可可靠找到最新（读写集合相交）。
//
// 本文件只做"备份进集群"（步骤 3）。恢复/自举/fail-stop 在步骤 4。

// ManifestKey 是 manifest 在节点上的固定 blob key（每节点至多一份，新版本覆盖旧）。
const ManifestKey = "manifest"

// ChunkRef 描述快照的一个块 blob。
type ChunkRef struct {
	Key     string   `json:"key"` // 节点上的 blob key，如 snapshot-<ver>-<idx>
	Size    int64    `json:"size"`
	CRC32C  uint32   `json:"crc32c"`
	Holders []uint64 `json:"holders"` // 持有该块的节点 ID
}

// WALSegRef 描述一个 WAL 段 blob（快照之后的增量）。
type WALSegRef struct {
	Key     string   `json:"key"` // wal-<ver>-<fromSeq>-<toSeq>
	FromSeq uint64   `json:"from_seq"`
	ToSeq   uint64   `json:"to_seq"`
	Size    int64    `json:"size"`
	CRC32C  uint32   `json:"crc32c"`
	Holders []uint64 `json:"holders"`
}

// Manifest 是恢复的索引（宽复制到集群）。版本号单调递增，恢复时取 max。
type Manifest struct {
	Version       uint64      `json:"version"`      // 单调递增，= 快照批次号
	CreatedAt     time.Time   `json:"created_at"`
	SnapshotSeq   uint64      `json:"snapshot_seq"` // 快照落地时刻的 WAL seq（WAL 重放起点）
	Chunks        []ChunkRef  `json:"chunks"`       // 快照分块（按 idx 升序）
	WALSegs       []WALSegRef `json:"wal_segs"`     // 快照之后的 WAL 段（按 seq 升序）
	SnapshotBytes int64       `json:"snapshot_bytes"`
}

// LatestSeq 返回该 manifest 覆盖到的最新 WAL seq。
func (m *Manifest) LatestSeq() uint64 {
	seq := m.SnapshotSeq
	for _, s := range m.WALSegs {
		if s.ToSeq > seq {
			seq = s.ToSeq
		}
	}
	return seq
}

// MetaBackupConfig 备份策略参数（控制台可调，见 HA 设计决策点 1/2）。
type MetaBackupConfig struct {
	Replicas  int // K：快照/WAL 每块副本数上限（默认 3，实际取 min(K, 存活节点数)）
	Retention int // 保留最近 N 个快照版本（默认 3；防"最新快照固化坏状态"无回退）
	Interval  time.Duration
}

// DefaultMetaBackupConfig 默认策略。
func DefaultMetaBackupConfig() MetaBackupConfig {
	return MetaBackupConfig{Replicas: 3, Retention: 3, Interval: 10 * time.Minute}
}

// MetaBackup 执行元数据备份进集群。
type MetaBackup struct {
	store      *meta.Store
	nodeMaxAge time.Duration
	cfg        MetaBackupConfig
	httpClient *http.Client
	scheme     string
	wg         sync.WaitGroup

	// opMu 序列化备份操作（BackupOnce/ShipWAL/手动触发互斥，不重叠）。
	opMu sync.Mutex

	// mu 保护下列状态字段（后台循环写、HTTP 状态查询读，短暂持有）。
	mu           sync.Mutex
	version      uint64    // 最近一次备份的版本号（进程内递增；恢复后由 manifest 校准）
	lastManifest Manifest  // 最近一次备份的 manifest（供 ShipWAL 增量追加）
	lastBackupAt time.Time // 最近一次成功全量备份时刻
	lastErr      string    // 最近一次备份错误（成功则空）
}

// NewMetaBackup 创建备份器。token/TLS 经 SetToken/SetTLS 生效（同 Scanner）。
func NewMetaBackup(store *meta.Store, nodeMaxAge time.Duration, cfg MetaBackupConfig) *MetaBackup {
	if cfg.Replicas <= 0 {
		cfg.Replicas = 3
	}
	if cfg.Retention <= 0 {
		cfg.Retention = 3
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Minute
	}
	return &MetaBackup{
		store:      store,
		nodeMaxAge: nodeMaxAge,
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 30 * time.Second, Transport: &auth.Transport{Token: ""}},
		scheme:     "http",
	}
}

// SetStore 设置元数据库（NewMetaBackup 可传 nil，恢复决策产出 store 后再注入）。
func (b *MetaBackup) SetStore(s *meta.Store) { b.store = s }

// SetToken / SetTLS 同 Scanner：配置出站认证与 TLS。
func (b *MetaBackup) SetToken(t auth.Token) {
	b.httpClient.Transport = &auth.Transport{Token: t}
}

func (b *MetaBackup) SetTLS(cfg *tls.Config) {
	if cfg == nil {
		return
	}
	tok := auth.Token("")
	if tr, ok := b.httpClient.Transport.(*auth.Transport); ok {
		tok = tr.Token
	}
	b.httpClient.Transport = auth.HTTPTransport(tok, cfg, nil)
	b.scheme = "https"
}

// ---- 节点 blob 客户端 ----

// putBlob 把一段 blob PUT 到某节点的 /meta-backup/{key}，带 CRC32C 头。
func (b *MetaBackup) putBlob(addr, key string, data []byte, crc uint32) error {
	url := fmt.Sprintf("%s://%s/meta-backup/%s", b.scheme, addr, key)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set(types.ChecksumHeader, fmt.Sprintf("%08x", crc))
	resp, err := b.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("put blob %s → %s: 状态 %d", key, addr, resp.StatusCode)
	}
	return nil
}

// getBlob 从某节点 GET 一个 blob。found=false 表示 404（该节点没有）。
func (b *MetaBackup) getBlob(addr, key string) (data []byte, found bool, err error) {
	url := fmt.Sprintf("%s://%s/meta-backup/%s", b.scheme, addr, key)
	resp, err := b.httpClient.Get(url)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		io.Copy(io.Discard, resp.Body)
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, false, fmt.Errorf("get blob %s → %s: 状态 %d", key, addr, resp.StatusCode)
	}
	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// deleteBlob 从某节点删除一个 blob（幂等，404 也算成功）。
func (b *MetaBackup) deleteBlob(addr, key string) error {
	url := fmt.Sprintf("%s://%s/meta-backup/%s", b.scheme, addr, key)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	resp, err := b.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("delete blob %s → %s: 状态 %d", key, addr, resp.StatusCode)
	}
	return nil
}

// blobEntry 是节点 LIST /meta-backup 返回的单条。
type blobEntry struct {
	Key  string `json:"key"`
	Size int64  `json:"size"`
}

// listBlobs 列出某节点上的全部元数据 blob。
func (b *MetaBackup) listBlobs(addr string) ([]blobEntry, error) {
	url := fmt.Sprintf("%s://%s/meta-backup", b.scheme, addr)
	resp, err := b.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("list blobs → %s: 状态 %d", addr, resp.StatusCode)
	}
	var out []blobEntry
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- K 个负载最低节点选择 ----

// pickLeastLoaded 返回按已用容量升序排列的前 k 个存活节点。
// 负载 = UsedBytes（越小越优先）；并列按 ID 稳定排序。
func (b *MetaBackup) pickLeastLoaded(k int) ([]types.NodeInfo, error) {
	alive, err := b.store.ListAliveNodes(b.nodeMaxAge)
	if err != nil {
		return nil, err
	}
	sort.Slice(alive, func(i, j int) bool {
		if alive[i].UsedBytes != alive[j].UsedBytes {
			return alive[i].UsedBytes < alive[j].UsedBytes
		}
		return alive[i].ID < alive[j].ID
	})
	if k > len(alive) {
		k = len(alive)
	}
	return alive[:k], nil
}

// shipBlob 把一段 blob 复制到给定节点集合，返回成功持有的节点 ID。
// 部分失败不致命：只要有节点成功即记入 holders（K 副本本就是冗余）。
func (b *MetaBackup) shipBlob(nodes []types.NodeInfo, key string, data []byte) []uint64 {
	crc := types.CRC32C(data)
	var holders []uint64
	for _, n := range nodes {
		if err := b.putBlob(n.Addr, key, data, crc); err != nil {
			continue
		}
		holders = append(holders, n.ID)
	}
	return holders
}

// metaChunkSize 是元数据快照的分块大小。元数据通常远小于此，多数快照就是单块；
// 大到超过时复用同一分块思路（每块独立 K 副本）。
const metaChunkSize = 16 << 20 // 16MB

// 备份错误。
var (
	ErrNoAliveNodes  = fmt.Errorf("metabackup: 无存活节点，无法备份")
	ErrShipIncomplete = fmt.Errorf("metabackup: blob 未能复制到任何节点")
)

// BackupOnce 执行一次完整备份：
//  1. 取当前 WAL seq 作为快照锚点
//  2. 快照 → 分块 → 每块 ship 到 K 个负载最低节点
//  3. 构造 manifest（版本号递增）→ 宽复制到所有存活节点
//  4. 截断 WAL（快照已固化 <= snapshotSeq 的增量）
//
// 返回本次写出的 manifest。任一快照块或 manifest 一个节点都没落上 → 报错（本次备份失败，
// 不推进版本、不截断 WAL；下次重试）。
func (b *MetaBackup) BackupOnce() (Manifest, error) {
	b.opMu.Lock()
	defer b.opMu.Unlock()
	m, err := b.backupOnceLocked()
	b.recordResult(err)
	return m, err
}

// recordResult 记录最近一次操作的错误（成功则清空），供状态页展示。
func (b *MetaBackup) recordResult(err error) {
	b.mu.Lock()
	if err != nil {
		b.lastErr = err.Error()
	} else {
		b.lastErr = ""
	}
	b.mu.Unlock()
}

// backupOnceLocked 是 BackupOnce 的实体（调用方已持 opMu）。
func (b *MetaBackup) backupOnceLocked() (Manifest, error) {
	// 选负载最低的 K 个节点放快照/WAL；manifest 稍后宽复制到全部存活节点。
	targets, err := b.pickLeastLoaded(b.cfg.Replicas)
	if err != nil {
		return Manifest{}, err
	}
	if len(targets) == 0 {
		return Manifest{}, ErrNoAliveNodes
	}

	// 先持久自增版本号，再取快照——这样快照的 meta 桶里就带着这个新版本号，
	// 将来从该快照重建时读回的持久版本 = manifest 版本，两者天然一致。
	ver, err := b.store.NextBackupVersion()
	if err != nil {
		return Manifest{}, err
	}
	b.mu.Lock()
	b.version = ver
	b.mu.Unlock()

	// 快照锚点：此刻的 WAL seq。快照本身包含到此 seq 的全部状态。
	snapSeq, err := b.store.WALSeq()
	if err != nil {
		return Manifest{}, err
	}
	var snap bytes.Buffer
	info, err := b.store.Snapshot(&snap)
	if err != nil {
		return Manifest{}, err
	}

	m := Manifest{
		Version:       ver,
		CreatedAt:     time.Now().UTC(),
		SnapshotSeq:   snapSeq,
		SnapshotBytes: info.Size,
	}

	// 分块 ship。
	data := snap.Bytes()
	for idx, off := 0, 0; off < len(data); idx++ {
		end := off + metaChunkSize
		if end > len(data) {
			end = len(data)
		}
		part := data[off:end]
		key := fmt.Sprintf("snapshot-%d-%d", ver, idx)
		holders := b.shipBlob(targets, key, part)
		if len(holders) == 0 {
			return Manifest{}, fmt.Errorf("%w: %s", ErrShipIncomplete, key)
		}
		m.Chunks = append(m.Chunks, ChunkRef{
			Key: key, Size: int64(len(part)), CRC32C: types.CRC32C(part), Holders: holders,
		})
		off = end
	}
	// 空库理论上快照也非空（bbolt 头页），但兜底：至少要有一块。
	if len(m.Chunks) == 0 {
		return Manifest{}, fmt.Errorf("%w: 快照无数据", ErrShipIncomplete)
	}

	// manifest 宽复制到所有存活节点（小指针撒一片）。
	allAlive, err := b.store.ListAliveNodes(b.nodeMaxAge)
	if err != nil {
		return Manifest{}, err
	}
	mfJSON, err := marshalManifest(&m)
	if err != nil {
		return Manifest{}, err
	}
	mfHolders := b.shipBlob(allAlive, ManifestKey, mfJSON)
	if len(mfHolders) == 0 {
		return Manifest{}, fmt.Errorf("%w: manifest", ErrShipIncomplete)
	}

	// 备份成功：记住当前 manifest（供 ShipWAL 增量追加），截断已固化的 WAL（<= snapSeq）。
	// 截断失败只记录不致命——多留些旧帧只是占点空间，不影响正确性。
	b.mu.Lock()
	b.lastManifest = m
	b.lastBackupAt = time.Now()
	b.mu.Unlock()
	_ = b.store.TruncateWALThrough(snapSeq)

	// 独立元数据 GC：清理超保留数 N 的老快照版本（失败不致命，下次再清）。
	if err := b.PruneOldVersions(); err != nil {
		log.Printf("元数据备份: 清理老版本失败（不致命）: %v", err)
	}
	return m, nil
}

// parseBlobVersion 从 blob key 解析版本号：snapshot-<ver>-<idx> / wal-<ver>-<from>-<to>。
// 返回 ok=false 表示不是带版本的快照/WAL blob（如 manifest），不参与版本清理。
func parseBlobVersion(key string) (ver uint64, ok bool) {
	var prefix string
	switch {
	case strings.HasPrefix(key, "snapshot-"):
		prefix = "snapshot-"
	case strings.HasPrefix(key, "wal-"):
		prefix = "wal-"
	default:
		return 0, false
	}
	rest := key[len(prefix):]
	// 版本号是 prefix 之后到第一个 '-' 之间。
	dash := strings.IndexByte(rest, '-')
	if dash < 0 {
		return 0, false
	}
	v, err := strconv.ParseUint(rest[:dash], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// PruneOldVersions 删除所有版本 < (当前版本 - Retention + 1) 的快照/WAL blob。
// 自纠错：不依赖记忆历史 manifest，直接 LIST 每个节点、按 key 版本号判定——
// 即使中途崩溃/漏删，下次备份会再扫一遍补上。manifest 本身（单 key、每次覆盖）不动。
func (b *MetaBackup) PruneOldVersions() error {
	b.mu.Lock()
	ver := b.version
	b.mu.Unlock()
	if ver == 0 || b.cfg.Retention <= 0 {
		return nil
	}
	// 合法版本窗口是 [cutoff, 当前]。窗口外两头都删：
	//   - ver < cutoff：正常老化出局的旧版本。
	//   - ver > 当前：上一轮 master（版本号更高的"纪元"）遗留的孤儿。单 master 下不
	//     可能有比当前更新的合法版本，所以更高号一定是陈旧孤儿——旧逻辑只删 <cutoff，
	//     这类高号孤儿会永生（本次 bug）。
	var cutoff uint64 = 1
	if ver > uint64(b.cfg.Retention) {
		cutoff = ver - uint64(b.cfg.Retention) + 1
	}
	alive, err := b.store.ListAliveNodes(b.nodeMaxAge)
	if err != nil {
		return err
	}
	var firstErr error
	for _, n := range alive {
		blobs, err := b.listBlobs(n.Addr)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, bl := range blobs {
			bver, ok := parseBlobVersion(bl.Key)
			if !ok {
				continue // manifest 等非版本化 blob 不动
			}
			if bver >= cutoff && bver <= ver {
				continue // 在合法保留窗口内，保留
			}
			if err := b.deleteBlob(n.Addr, bl.Key); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// ShipWAL 增量同步：把上次快照/同步之后的新 WAL 帧打包成一个段复制进集群，并更新
// manifest（追加 WAL 段 + 宽复制）。这是 WAL 相对全量快照的价值——用小代价把"丢数据
// 窗口"从"一个快照间隔"收窄到"一个 WAL 同步间隔"。
//
// 无 manifest（还没做过 BackupOnce）或无新帧则直接返回。段 blob 也不截断本地 WAL——
// 截断只在 BackupOnce 落新快照后做（否则重放起点会丢）。
func (b *MetaBackup) ShipWAL() (Manifest, bool, error) {
	b.opMu.Lock()
	defer b.opMu.Unlock()

	b.mu.Lock()
	base := b.lastManifest
	b.mu.Unlock()
	if base.Version == 0 {
		return Manifest{}, false, nil // 尚无基准快照
	}
	from := base.LatestSeq()
	frames, err := b.store.FramesSince(from)
	if err != nil {
		return Manifest{}, false, err
	}
	if len(frames) == 0 {
		return base, false, nil // 无新增量
	}
	toSeq := frames[len(frames)-1].Seq
	seg := meta.EncodeWALSegment(frames)
	key := fmt.Sprintf("wal-%d-%d-%d", base.Version, from+1, toSeq)

	targets, err := b.pickLeastLoaded(b.cfg.Replicas)
	if err != nil {
		return Manifest{}, false, err
	}
	if len(targets) == 0 {
		return Manifest{}, false, ErrNoAliveNodes
	}
	holders := b.shipBlob(targets, key, seg)
	if len(holders) == 0 {
		return Manifest{}, false, fmt.Errorf("%w: %s", ErrShipIncomplete, key)
	}

	// 追加 WAL 段到 manifest，重新宽复制。
	m := base
	m.WALSegs = append(append([]WALSegRef(nil), base.WALSegs...), WALSegRef{
		Key: key, FromSeq: from + 1, ToSeq: toSeq,
		Size: int64(len(seg)), CRC32C: types.CRC32C(seg), Holders: holders,
	})
	allAlive, err := b.store.ListAliveNodes(b.nodeMaxAge)
	if err != nil {
		return Manifest{}, false, err
	}
	mfJSON, err := marshalManifest(&m)
	if err != nil {
		return Manifest{}, false, err
	}
	if len(b.shipBlob(allAlive, ManifestKey, mfJSON)) == 0 {
		return Manifest{}, false, fmt.Errorf("%w: manifest", ErrShipIncomplete)
	}
	b.mu.Lock()
	b.lastManifest = m
	b.mu.Unlock()
	return m, true, nil
}

// StartLoop 启动后台备份循环：每 walIntv 增量 ShipWAL 一次，每 cfg.Interval 落一次
// 全量 BackupOnce。ctx 取消时退出。首次立即做一次 BackupOnce 建立基准快照。
func (b *MetaBackup) StartLoop(ctx context.Context, walIntv time.Duration) {
	if walIntv <= 0 || walIntv > b.cfg.Interval {
		walIntv = b.cfg.Interval / 5
	}
	if walIntv <= 0 {
		walIntv = time.Minute
	}
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		// 首次建立基准快照（失败只记录，下个周期重试——可能暂时无存活节点）。
		if _, err := b.BackupOnce(); err != nil {
			log.Printf("元数据备份: 首次快照失败（将重试）: %v", err)
		}
		lastSnap := time.Now()
		wal := time.NewTicker(walIntv)
		defer wal.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-wal.C:
				if time.Since(lastSnap) >= b.cfg.Interval {
					if _, err := b.BackupOnce(); err != nil {
						log.Printf("元数据备份: 快照失败: %v", err)
					} else {
						lastSnap = time.Now()
					}
				} else if _, _, err := b.ShipWAL(); err != nil {
					log.Printf("元数据备份: WAL 增量同步失败: %v", err)
				}
			}
		}
	}()
}

// Wait 等待后台循环退出（优雅关闭，先于 store.Close）。
func (b *MetaBackup) Wait() { b.wg.Wait() }

// BackupStatus 是元数据备份的可观测状态（控制台展示用）。
type BackupStatus struct {
	Enabled      bool      `json:"enabled"`       // 是否配了种子、跑着备份循环
	Version      uint64    `json:"version"`       // 当前 manifest 版本
	SnapshotSeq  uint64    `json:"snapshot_seq"`  // 快照锚点 WAL seq
	LatestSeq    uint64    `json:"latest_seq"`    // 含 WAL 段的最新 seq
	SnapshotSize int64     `json:"snapshot_size"` // 快照总字节
	Chunks       []ChunkRef  `json:"chunks"`
	WALSegs      []WALSegRef `json:"wal_segs"`
	LastBackupAt time.Time `json:"last_backup_at"`
	LastError    string    `json:"last_error"`
	Retention    int       `json:"retention"`
	Replicas     int       `json:"replicas"`
	Versions     []VersionInfo `json:"versions"` // 集群实际留存的各代版本（保留策略可视化）
}

// Status 返回当前备份状态快照（线程安全）。
func (b *MetaBackup) Status() BackupStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	m := b.lastManifest
	return BackupStatus{
		Enabled:      b.version > 0 || m.Version > 0,
		Version:      m.Version,
		SnapshotSeq:  m.SnapshotSeq,
		LatestSeq:    m.LatestSeq(),
		SnapshotSize: m.SnapshotBytes,
		Chunks:       m.Chunks,
		WALSegs:      m.WALSegs,
		LastBackupAt: b.lastBackupAt,
		LastError:    b.lastErr,
		Retention:    b.cfg.Retention,
		Replicas:     b.cfg.Replicas,
	}
}

// VersionInfo 是集群里留存的一代快照版本概况（保留策略可视化）。
type VersionInfo struct {
	Version uint64   `json:"version"`
	Chunks  int      `json:"chunks"`  // 该版本的快照块数
	Size    int64    `json:"size"`    // 该版本快照总字节
	Nodes   []uint64 `json:"nodes"`   // 持有该版本任意块的节点 ID（去重升序）
	Current bool     `json:"current"` // 是否为当前最新版本
}

// ClusterVersions 扫描集群，聚合出实际留存的所有快照版本（按版本降序，最新在前）。
// 向存活节点 LIST /meta-backup，按 key 里的版本号归并。有网络 IO，仅状态页调用。
func (b *MetaBackup) ClusterVersions() ([]VersionInfo, error) {
	alive, err := b.store.ListAliveNodes(b.nodeMaxAge)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	cur := b.lastManifest.Version
	b.mu.Unlock()

	type agg struct {
		size  int64
		chunk map[string]int64 // 块 key → size（跨节点去重同一块）
		nodes map[uint64]bool
	}
	byVer := map[uint64]*agg{}
	for _, n := range alive {
		blobs, err := b.listBlobs(n.Addr)
		if err != nil {
			continue // 单节点不可达跳过，聚合仍尽力而为
		}
		for _, bl := range blobs {
			// 只统计快照块（snapshot-<ver>-<idx>）；WAL 段与 manifest 不计入版本。
			if !strings.HasPrefix(bl.Key, "snapshot-") {
				continue
			}
			ver, ok := parseBlobVersion(bl.Key)
			if !ok {
				continue
			}
			a := byVer[ver]
			if a == nil {
				a = &agg{chunk: map[string]int64{}, nodes: map[uint64]bool{}}
				byVer[ver] = a
			}
			a.chunk[bl.Key] = bl.Size
			a.nodes[n.ID] = true
		}
	}

	out := make([]VersionInfo, 0, len(byVer))
	for ver, a := range byVer {
		var size int64
		for _, s := range a.chunk {
			size += s
		}
		nodes := make([]uint64, 0, len(a.nodes))
		for id := range a.nodes {
			nodes = append(nodes, id)
		}
		sort.Slice(nodes, func(i, j int) bool { return nodes[i] < nodes[j] })
		out = append(out, VersionInfo{
			Version: ver, Chunks: len(a.chunk), Size: size, Nodes: nodes, Current: ver == cur,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version > out[j].Version })
	return out, nil
}

// TriggerBackup 手动触发一次全量备份（控制台按钮；与后台循环互斥）。
func (b *MetaBackup) TriggerBackup() (Manifest, error) { return b.BackupOnce() }
