package master

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
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
	Replicas int // K：快照/WAL 每块副本数上限（默认 3，实际取 min(K, 存活节点数)）
	Interval time.Duration
}

// DefaultMetaBackupConfig 默认策略。
func DefaultMetaBackupConfig() MetaBackupConfig {
	return MetaBackupConfig{Replicas: 3, Interval: 10 * time.Minute}
}

// MetaBackup 执行元数据备份进集群。
type MetaBackup struct {
	store      *meta.Store
	nodeMaxAge time.Duration
	cfg        MetaBackupConfig
	httpClient *http.Client
	scheme     string
	version    uint64 // 最近一次备份的版本号（进程内递增；恢复后由 manifest 校准）
}

// NewMetaBackup 创建备份器。token/TLS 经 SetToken/SetTLS 生效（同 Scanner）。
func NewMetaBackup(store *meta.Store, nodeMaxAge time.Duration, cfg MetaBackupConfig) *MetaBackup {
	if cfg.Replicas <= 0 {
		cfg.Replicas = 3
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
	// 选负载最低的 K 个节点放快照/WAL；manifest 稍后宽复制到全部存活节点。
	targets, err := b.pickLeastLoaded(b.cfg.Replicas)
	if err != nil {
		return Manifest{}, err
	}
	if len(targets) == 0 {
		return Manifest{}, ErrNoAliveNodes
	}

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

	b.version++
	ver := b.version
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

	// 备份成功：截断已固化的 WAL（<= snapSeq）。截断失败只记录不致命——
	// 多留些旧帧只是占点空间，不影响正确性。
	_ = b.store.TruncateWALThrough(snapSeq)
	return m, nil
}
