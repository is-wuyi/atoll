// Package meta 实现 master 的元数据持久化层，基于 bbolt。
// 设计：
//   - inodes   bucket: inode ID → Inode JSON
//   - children bucket: parentID(8B) + name → inode ID，用于重名检查与目录遍历
//   - nodes    bucket: node ID → NodeInfo JSON
//   - meta     bucket: 自增计数器
package meta

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"atoll/pkg/types"
)

var (
	bucketInodes   = []byte("inodes")
	bucketChildren = []byte("children")
	bucketNodes    = []byte("nodes")
	bucketMeta     = []byte("meta")
	bucketOps      = []byte("ops") // v2-3a：写操作幂等结果表（op_id → OpRecord）

	keyNextInode = []byte("next_inode")
	keyNextNode  = []byte("next_node")
	// keyBackupVersion 持久化元数据备份的版本计数器。它是 master 自己的权威状态
	// （不是内存临时值），随快照一起进 bbolt，重启后直接读回、单调续增，不依赖集群可达。
	keyBackupVersion = []byte("backup_version")
)

// RootID 是根目录的固定 inode ID。
const RootID uint64 = 1

// 常见错误。
var (
	ErrNotExist   = errors.New("not found")
	ErrExist      = errors.New("already exists")
	ErrNotEmpty   = errors.New("directory not empty")
	ErrNotDir     = errors.New("not a directory")
	ErrNotFile    = errors.New("not a file")
	ErrBadPath    = errors.New("invalid path")
	ErrBadName    = errors.New("invalid name")
)

// validateName 校验单个目录项名字：非空、非 "."/".."、不含 "/"。
// 元数据层的最后一道防线——无论哪条 HTTP 路径进来，非法名一律挡在落库前
// （commit 曾可写入 "../../etc/passwd"、"a/b" 等污染 children bucket）。
func validateName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
		return fmt.Errorf("%w: %q", ErrBadName, name)
	}
	return nil
}

// Store 封装 bbolt 数据库。
type Store struct {
	db         *bolt.DB
	postCommit PostCommitHook // 提交后钩子（同步旋钮用；nil = 不调用）
	// commitMu 把「提交 + postCommit 钩子」串成一个原子段，保证钩子按 seq 顺序执行。
	// 否则同步旋钮开启时 seq6 可能先于 seq5 被 ship+ack，master 掉盘后集群 WAL 现空洞、
	// 整段重放被拒。钩子为 nil（默认）时只是多一层 bbolt 本就有的写串行化，无额外代价。
	commitMu sync.Mutex
}

// Open 打开（或创建）元数据库并完成初始化：建 bucket、写根目录、初始化计数器。
func Open(dbPath string) (*Store, error) {
	db, err := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bbolt: %w", err)
	}
	s := &Store{db: db}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// DBPath 返回底层 bbolt 文件路径（恢复流程判断本地库位置、诊断用）。
func (s *Store) DBPath() string { return s.db.Path() }

func (s *Store) init() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketInodes, bucketChildren, bucketNodes, bucketMeta, bucketWAL, bucketOps} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		// 根目录只创建一次。
		if tx.Bucket(bucketInodes).Get(u64be(RootID)) == nil {
			root := types.Inode{
				ID:       RootID,
				ParentID: 0,
				Name:     "",
				Type:     types.TypeDir,
				Mtime:    time.Now(),
			}
			if err := putInode(tx, &root); err != nil {
				return err
			}
			// 计数器从 2 开始（1 已被根目录占用）。
			if err := tx.Bucket(bucketMeta).Put(keyNextInode, u64be(2)); err != nil {
				return err
			}
		}
		return nil
	})
}

// ---- inode 操作 ----

// GetInode 按 ID 取 inode。
func (s *Store) GetInode(id uint64) (types.Inode, error) {
	var in types.Inode
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketInodes).Get(u64be(id))
		if raw == nil {
			return ErrNotExist
		}
		return json.Unmarshal(raw, &in)
	})
	return in, err
}

// Lookup 返回 parentID 下名为 name 的子项。
func (s *Store) Lookup(parentID uint64, name string) (types.Inode, error) {
	var in types.Inode
	err := s.db.View(func(tx *bolt.Tx) error {
		childID := tx.Bucket(bucketChildren).Get(childKey(parentID, name))
		if childID == nil {
			return ErrNotExist
		}
		raw := tx.Bucket(bucketInodes).Get(childID)
		if raw == nil {
			return fmt.Errorf("children 指向不存在的 inode %d", beU64(childID))
		}
		return json.Unmarshal(raw, &in)
	})
	return in, err
}

// ResolvePath 解析绝对路径，返回对应 inode。根目录 "/" 返回根 inode。
func (s *Store) ResolvePath(p string) (types.Inode, error) {
	p = path.Clean("/" + p)
	if p == "/" {
		return s.GetInode(RootID)
	}
	cur := types.Inode{ID: RootID}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" {
			continue
		}
		next, err := s.Lookup(cur.ID, seg)
		if err != nil {
			return types.Inode{}, err
		}
		cur = next
	}
	return cur, nil
}

// CreateDir 在 parentID 下创建子目录。
func (s *Store) CreateDir(parentID uint64, name string) (types.Inode, error) {
	if err := validateName(name); err != nil {
		return types.Inode{}, err
	}
	var in types.Inode
	err := s.write(func(w *txw) error {
		parent, err := getInodeTx(w.tx, parentID)
		if err != nil {
			return err
		}
		if parent.Type != types.TypeDir {
			return ErrNotDir
		}
		if hasChild(w.tx, parentID, name) {
			return ErrExist
		}
		id, err := w.nextID(keyNextInode)
		if err != nil {
			return err
		}
		in = types.Inode{ID: id, ParentID: parentID, Name: name, Type: types.TypeDir, Mtime: time.Now()}
		if err := w.putInode(&in); err != nil {
			return err
		}
		return w.putChild(parentID, name, id)
	})
	if err != nil {
		return types.Inode{}, err
	}
	return in, nil
}

// CreateFile 在 parentID 下创建文件记录（数据尚未写入，size 初始为 0）。
func (s *Store) CreateFile(parentID uint64, name string, replicas []uint64) (types.Inode, error) {
	if err := validateName(name); err != nil {
		return types.Inode{}, err
	}
	var in types.Inode
	err := s.write(func(w *txw) error {
		parent, err := getInodeTx(w.tx, parentID)
		if err != nil {
			return err
		}
		if parent.Type != types.TypeDir {
			return ErrNotDir
		}
		if hasChild(w.tx, parentID, name) {
			return ErrExist
		}
		id, err := w.nextID(keyNextInode)
		if err != nil {
			return err
		}
		in = types.Inode{ID: id, ParentID: parentID, Name: name, Type: types.TypeFile, Mtime: time.Now(), Replicas: replicas}
		if err := w.putInode(&in); err != nil {
			return err
		}
		return w.putChild(parentID, name, id)
	})
	if err != nil {
		return types.Inode{}, err
	}
	return in, nil
}

// ListChildren 返回目录的直接子项，按名称排序。
func (s *Store) ListChildren(dirID uint64) ([]types.Inode, error) {
	var out []types.Inode
	err := s.db.View(func(tx *bolt.Tx) error {
		dir, err := getInodeTx(tx, dirID)
		if err != nil {
			return err
		}
		if dir.Type != types.TypeDir {
			return ErrNotDir
		}
		prefix := u64be(dirID)
		c := tx.Bucket(bucketChildren).Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			raw := tx.Bucket(bucketInodes).Get(v)
			if raw == nil {
				return fmt.Errorf("children 指向不存在的 inode %d", beU64(v))
			}
			var in types.Inode
			if err := json.Unmarshal(raw, &in); err != nil {
				return err
			}
			out = append(out, in)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// CreateSymlink 创建符号链接：Type=TypeSymlink、Target 原样存储（相对/绝对/悬空皆可）。
// 无副本无对象——修复扫描对空 Replicas 天然跳过，GC 的 validIDs 含其 ID（无对象可回收）。
func (s *Store) CreateSymlink(parentID uint64, name, target string) (types.Inode, error) {
	if err := validateName(name); err != nil {
		return types.Inode{}, err
	}
	if target == "" || len(target) > 4096 {
		return types.Inode{}, errors.New("invalid symlink target")
	}
	var in types.Inode
	err := s.write(func(w *txw) error {
		parent, err := getInodeTx(w.tx, parentID)
		if err != nil {
			return err
		}
		if parent.Type != types.TypeDir {
			return ErrNotDir
		}
		if hasChild(w.tx, parentID, name) {
			return ErrExist
		}
		id, err := w.nextID(keyNextInode)
		if err != nil {
			return err
		}
		in = types.Inode{ID: id, ParentID: parentID, Name: name, Type: types.TypeSymlink, Mtime: time.Now(), Target: target}
		if err := w.putInode(&in); err != nil {
			return err
		}
		return w.putChild(parentID, name, id)
	})
	if err != nil {
		return types.Inode{}, err
	}
	return in, nil
}

// SmallFileTarget 描述小文件单请求通道的一次元数据提交（master 已把数据写到主副本后调用）。
type SmallFileTarget struct {
	ParentID uint64
	Name     string
	FileID   uint64 // 新建：预分配的 inode ID；覆盖：已存在的文件 ID
	Size     int64
	Checksum uint32
	Replicas []uint64
	PrimaryID uint64
	// ReplaceOtherID 被替换的非文件条目（symlink 等），0=无。
	ReplaceOtherID uint64
	Mtime          time.Time
}

// WriteSmallFile 单事务提交小文件元数据（v2-2a）：
//   - FileID 不存在 → 新建（TypeFile、legacy 单对象模型、Generation=1、挂 children）
//   - FileID 存在且是文件 → in-place 内容替换（转 legacy、Size/Checksum/Generation++）
//   - ReplaceOtherID 非 0 → 同事务删除被替换的非文件条目
//
// 数据已由调用方先行写到主副本（节点侧 fsync）；本事务失败留下孤儿对象由 GC 兜底。
// legacy content=ID 不变式保持：对象 ID 即 FileID（新建预分配 / 覆盖沿用）。
func (s *Store) WriteSmallFile(t SmallFileTarget) error {
	if err := validateName(t.Name); err != nil {
		return err
	}
	return s.write(func(w *txw) error {
		if t.ReplaceOtherID != 0 {
			other, err := getInodeTx(w.tx, t.ReplaceOtherID)
			if err != nil {
				return err
			}
			if other.Type == types.TypeDir {
				return ErrExist
			}
			if err := w.delInode(other.ID); err != nil {
				return err
			}
		}
		in, err := getInodeTx(w.tx, t.FileID)
		if err != nil && !errors.Is(err, ErrNotExist) {
			return err
		}
		if errors.Is(err, ErrNotExist) {
			in = types.Inode{
				ID: t.FileID, ParentID: t.ParentID, Name: t.Name, Type: types.TypeFile,
				Size: t.Size, Checksum: t.Checksum, Mtime: t.Mtime,
				Replicas: t.Replicas, DoneReplicas: []uint64{t.PrimaryID},
				Generation: 1,
			}
			if err := w.putInode(&in); err != nil {
				return err
			}
			return w.putChild(t.ParentID, t.Name, t.FileID)
		}
		if in.Type != types.TypeFile {
			return ErrNotFile
		}
		// in-place 内容替换：转 legacy 单对象模型，身份保留。
		in.Chunked = false
		in.Chunks = nil
		in.Size = t.Size
		in.Checksum = t.Checksum
		in.Mtime = t.Mtime
		in.Generation++
		in.Replicas = t.Replicas // chunked 转 legacy 时重挑副本；legacy 覆盖与原值一致
		in.DoneReplicas = []uint64{t.PrimaryID} // 其余副本由 replicateToPeers 补齐后重新上报
		return w.putInode(&in)
	})
}

// AllocateFileID 预分配一个文件 ID（小文件单请求通道需要在写节点数据前确定对象 ID）。
// 分配即持久（记 WAL）；分配后未使用留下的 ID 空洞无害（与计数器语义一致）。
func (s *Store) AllocateFileID() (uint64, error) {
	var id uint64
	err := s.write(func(w *txw) error {
		nid, err := w.nextID(keyNextInode)
		if err != nil {
			return err
		}
		id = nid
		return nil
	})
	return id, err
}

// DeleteFile 删除一个文件记录。符号链接（TypeSymlink）与文件同路径：删元数据即可，
// 无对象需回收。
func (s *Store) DeleteFile(id uint64) error {
	return s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, id)
		if err != nil {
			return err
		}
		if in.Type != types.TypeFile && in.Type != types.TypeSymlink {
			return ErrNotFile
		}
		if err := w.delInode(id); err != nil {
			return err
		}
		return w.delChild(in.ParentID, in.Name)
	})
}

// DeleteDir 删除一个空目录。
func (s *Store) DeleteDir(id uint64) error {
	return s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, id)
		if err != nil {
			return err
		}
		if in.Type != types.TypeDir {
			return ErrNotDir
		}
		if id == RootID {
			return errors.New("cannot delete root")
		}
		if hasAnyChild(w.tx, id) {
			return ErrNotEmpty
		}
		if err := w.delInode(id); err != nil {
			return err
		}
		return w.delChild(in.ParentID, in.Name)
	})
}

// Rename 在同一目录内改名。
func (s *Store) Rename(id uint64, newName string) error {
	if err := validateName(newName); err != nil {
		return err
	}
	return s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, id)
		if err != nil {
			return err
		}
		if in.ID == RootID {
			return errors.New("cannot rename root")
		}
		if hasChild(w.tx, in.ParentID, newName) {
			return ErrExist
		}
		if err := w.delChild(in.ParentID, in.Name); err != nil {
			return err
		}
		in.Name = newName
		in.Mtime = time.Now()
		if err := w.putInode(&in); err != nil {
			return err
		}
		return w.putChild(in.ParentID, newName, id)
	})
}

// UpdateFileSize 更新文件大小，并把主副本（Replicas[0]）标记为已同步。
// 客户端直连主副本写完数据后 commit 时调用。
func (s *Store) UpdateFileSize(id uint64, size int64, checksum uint32) error {
	return s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, id)
		if err != nil {
			return err
		}
		if in.Type != types.TypeFile {
			return ErrNotFile
		}
		in.Size = size
		in.Checksum = checksum
		in.Mtime = time.Now()
		if len(in.Replicas) > 0 {
			in.DoneReplicas = appendUnique(in.DoneReplicas, in.Replicas[0])
		}
		return w.putInode(&in)
	})
}

// AddReplicaDone 把某节点加入文件的已完成副本列表（从副本同步完成后上报）。
func (s *Store) AddReplicaDone(id, nodeID uint64) error {
	return s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, id)
		if err != nil {
			return err
		}
		if in.Type != types.TypeFile {
			return ErrNotFile
		}
		// 成员资格校验：只有副本集内的节点上报才计入 DoneReplicas（同 MarkChunkDone）。
		if !types.ContainsUint64(in.Replicas, nodeID) {
			return nil
		}
		in.DoneReplicas = appendUnique(in.DoneReplicas, nodeID)
		return w.putInode(&in)
	})
}

// appendUnique 追加不重复的元素。
func appendUnique(list []uint64, v uint64) []uint64 {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// UpdateFile 更新文件大小与副本位置（写完成后调用）。
func (s *Store) UpdateFile(id uint64, size int64, replicas []uint64) error {
	return s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, id)
		if err != nil {
			return err
		}
		if in.Type != types.TypeFile {
			return ErrNotFile
		}
		in.Size = size
		in.Replicas = replicas
		in.Mtime = time.Now()
		return w.putInode(&in)
	})
}

// ---- 分块文件操作（批次 C）----
//
// 分块模型：Chunked=true 的文件由 64MB 块组成，每块独立副本，块对象 ID
// 由 types.ChunkID(stagingInodeID, index) 编码。写入流程：
//
//	CreateStagingFile（隐藏 inode，不挂 children）
//	→ AssignChunk × N（每块独立分配副本）
//	→ CommitStagingFile（单事务校验 + 原子换名，解决审计 #1/#8）
//	→ AbortStaging（客户端中断时显式放弃；崩溃残留由 TTL 回收）
//
// staging inode 用独立计数器编号（≥ 2^32，见 types.StagingInodeBase），
// 与 legacy inode ID、块对象 ID 三者空间互不重叠。

var (
	keyNextStagingInode = []byte("next_staging_inode")
)

// ErrNotStaging 对非 staging inode 执行了 staging 专属操作。
var ErrNotStaging = errors.New("not a staging inode")

// ErrChunkBadIndex 块下标越界。
var ErrChunkBadIndex = errors.New("chunk index out of range")

// ErrChunkBadSize 块大小非法。
var ErrChunkBadSize = errors.New("chunk size out of range")

// ErrChunkNotExist 目标 inode 无此块。
var ErrChunkNotExist = errors.New("chunk not found")

// ErrCommitFailed commit 校验失败（块缺失/主副本未落盘/大小不符）。
var ErrCommitFailed = errors.New("commit validation failed")

// ErrReplicaDup 副本替换会造成同一节点在副本集内重复（修复扫描去重用）。
var ErrReplicaDup = errors.New("replica already present")

// CreateStagingFile 在 parentID 下分配一个写入中的隐藏文件 inode。
// Staging=true, Chunked=true，不挂 children——路径解析天然看不见它。
func (s *Store) CreateStagingFile(parentID uint64) (types.Inode, error) {
	var in types.Inode
	err := s.write(func(w *txw) error {
		parent, err := getInodeTx(w.tx, parentID)
		if err != nil {
			return err
		}
		if parent.Type != types.TypeDir {
			return ErrNotDir
		}
		id, err := w.nextStagingID()
		if err != nil {
			return err
		}
		in = types.Inode{
			ID:       id,
			ParentID: parentID,
			Type:     types.TypeFile,
			Mtime:    time.Now(),
			Staging:  true,
			Chunked:  true,
		}
		return w.putInode(&in)
	})
	if err != nil {
		return types.Inode{}, err
	}
	return in, nil
}

// CreateStagingFileLegacy 建一个非分块 staging inode，记住目标名/父目录/副本，但不占用
// 父目录的名字项——旧同名文件继续对外可读。用于 legacy 覆盖写：新数据先传到这个 staging
// inode，直到 CommitLegacyStagingFile 才原子替换旧文件。覆盖中断时旧文件与旧对象原样保留。
func (s *Store) CreateStagingFileLegacy(parentID uint64, name string, replicas []uint64) (types.Inode, error) {
	if err := validateName(name); err != nil {
		return types.Inode{}, err
	}
	var in types.Inode
	err := s.write(func(w *txw) error {
		parent, err := getInodeTx(w.tx, parentID)
		if err != nil {
			return err
		}
		if parent.Type != types.TypeDir {
			return ErrNotDir
		}
		id, err := w.nextStagingID()
		if err != nil {
			return err
		}
		// Name/ParentID 记在 inode 上供 commit 时解析旧同名文件；但不写 children 桶，
		// 故不与旧文件冲突、旧文件仍可解析。
		in = types.Inode{
			ID:       id,
			ParentID: parentID,
			Name:     name,
			Type:     types.TypeFile,
			Mtime:    time.Now(),
			Staging:  true,
			Replicas: replicas,
		}
		return w.putInode(&in)
	})
	if err != nil {
		return types.Inode{}, err
	}
	return in, nil
}

// CommitLegacyStagingFile 提交一个 legacy（非分块）staging 文件：原子替换同名旧文件。
// 单事务内：按 inode 上记的 (ParentID, Name) 解析旧文件 → 删旧 inode/child（若有）→ 挂
// staging inode 到该名 → 设大小/校验和/主副本 Done/清 Staging。返回新 inode、被替换旧
// inode、hadOld。事务前读者看到旧版本，事务后看到新版本，不存在中间态。
func (s *Store) CommitLegacyStagingFile(inodeID uint64, size int64, checksum uint32) (types.Inode, types.Inode, bool, error) {
	var out, old types.Inode
	var hadOld bool
	err := s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, inodeID)
		if err != nil {
			return err
		}
		if !in.Staging || in.Chunked {
			return ErrNotStaging
		}
		parent, err := getInodeTx(w.tx, in.ParentID)
		if err != nil {
			return err
		}
		if parent.Type != types.TypeDir {
			return ErrNotDir
		}
		// 同名旧 inode：目录则拒绝覆盖，文件则同事务删除（原子替换）。
		if oldID := w.tx.Bucket(bucketChildren).Get(childKey(in.ParentID, in.Name)); oldID != nil {
			old, err = getInodeTx(w.tx, beU64(oldID))
			if err != nil {
				return err
			}
			if old.Type == types.TypeDir {
				return ErrExist
			}
			if err := w.delInode(old.ID); err != nil {
				return err
			}
			hadOld = true
		}
		in.Size = size
		in.Checksum = checksum
		in.Staging = false
		in.Mtime = time.Now()
		if len(in.Replicas) > 0 {
			in.DoneReplicas = appendUnique(in.DoneReplicas, in.Replicas[0])
		}
		if err := w.putInode(&in); err != nil {
			return err
		}
		if err := w.putChild(in.ParentID, in.Name, in.ID); err != nil {
			return err
		}
		out = in
		return nil
	})
	if err != nil {
		return types.Inode{}, types.Inode{}, false, err
	}
	return out, old, hadOld, nil
}
// 用于确定性地把 staging 回退到过去，避免 TTL 测试依赖 wall-clock sleep 而在 CI/-race 下偶发）。
func (s *Store) SetInodeMtimeForTest(id uint64, mt time.Time) error {
	return s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, id)
		if err != nil {
			return err
		}
		in.Mtime = mt
		return w.putInode(&in)
	})
}
// AssignChunk 为 staging 文件的第 index 块分配副本节点。
// 幂等：该块已分配则原样返回既有分配（重试安全）。
func (s *Store) AssignChunk(inodeID uint64, index int, size int64, replicas []uint64, checksum uint32) (types.ChunkInfo, error) {
	var chunk types.ChunkInfo
	err := s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, inodeID)
		if err != nil {
			return err
		}
		if !in.Staging {
			return ErrNotStaging
		}
		if index < 0 || index >= types.MaxChunksPerFile {
			return ErrChunkBadIndex
		}
		if size <= 0 || size > types.ChunkSize {
			return ErrChunkBadSize
		}
		for _, c := range in.Chunks {
			if c.Index == index {
				chunk = c // 已分配，幂等返回
				return nil
			}
		}
		in.Chunks = append(in.Chunks, types.ChunkInfo{
			ID:       types.ChunkID(inodeID, index), // v2：块表自描述对象 ID
			Index:    index,
			Size:     size,
			Replicas: replicas,
			Checksum: checksum,
		})
		// 并发 Assign 可能乱序插入，保持块表按 Index 升序。
		sort.Slice(in.Chunks, func(i, j int) bool { return in.Chunks[i].Index < in.Chunks[j].Index })
		// 刷新 Mtime：staging TTL 据此判"多久没活动"。此前锚定创建时间，
		// 上传 >24h 的合法大文件会被连数据一起清掉——改为按活跃度续期。
		in.Mtime = time.Now()
		if err := w.putInode(&in); err != nil {
			return err
		}
		for _, c := range in.Chunks {
			if c.Index == index {
				chunk = c
			}
		}
		return nil
	})
	if err != nil {
		return types.ChunkInfo{}, err
	}
	return chunk, nil
}

// ReassignChunk 废弃某块现有分配并重新分配（主副本持续失败时换节点）。
// 返回新分配。块 Done 集合重置。
func (s *Store) ReassignChunk(inodeID uint64, index int, replicas []uint64, checksum uint32) (types.ChunkInfo, error) {
	var chunk types.ChunkInfo
	err := s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, inodeID)
		if err != nil {
			return err
		}
		if !in.Staging {
			return ErrNotStaging
		}
		for i := range in.Chunks {
			if in.Chunks[i].Index == index {
				in.Chunks[i].Replicas = replicas
				in.Chunks[i].Done = nil
				if in.Chunks[i].ID == 0 {
					in.Chunks[i].ID = types.ChunkID(inodeID, index) // v1 数据补齐自描述 ID
				}
				if checksum != 0 {
					in.Chunks[i].Checksum = checksum
				}
				chunk = in.Chunks[i]
				in.Mtime = time.Now() // 换节点重试也是活跃上传，刷新 TTL
				return w.putInode(&in)
			}
		}
		return ErrChunkNotExist
	})
	if err != nil {
		return types.ChunkInfo{}, err
	}
	return chunk, nil
}

// MarkChunkDone 把 nodeID 记入块 Done 集合（块对象落盘完成上报，幂等）。
// chunkID 由 types.ChunkID 编码；commit 前后调用均合法。
// 注意：采纳式替换后块对象 ID 的前缀（staging ID）不再是文件 ID——此接口按对象 ID
// 反查所属 inode，适用于"staging 仍存在"的窗口；staging 已被采纳删除的迟到上报会返回
// ErrChunkNotExist（无害，scanner 的探测兜底按文件记录补标，见 MarkChunkDoneAt）。
func (s *Store) MarkChunkDone(chunkID, nodeID uint64) error {
	inodeID, index := types.ParseChunkID(chunkID)
	return s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, inodeID)
		if err != nil {
			return err
		}
		if !in.Chunked {
			return ErrChunkNotExist
		}
		for i := range in.Chunks {
			if in.Chunks[i].Index == index {
				// 成员资格校验：只有该块副本集内的节点上报才计入 Done。
				// reassign 后旧节点、或伪造上报的节点不应把自己刷成 Done（否则
				// min-copies 会被虚高副本满足）。非成员静默忽略（保持上报幂等）。
				if !types.ContainsUint64(in.Chunks[i].Replicas, nodeID) {
					return nil
				}
				in.Chunks[i].Done = appendUnique(in.Chunks[i].Done, nodeID)
				return w.putInode(&in)
			}
		}
		return ErrChunkNotExist
	})
}

// MarkChunkDoneAt 按文件记录直接把 nodeID 记入指定块的 Done 集合（scanner 探测兜底用）。
// 与 MarkChunkDone 的区别：不依赖"对象 ID 前缀 = 所属 inode ID"的推导——采纳式替换后
// 块对象挂在 staging 派生的 ID 上，对象 ID 反查不到文件，必须持有文件记录原地补标。
func (s *Store) MarkChunkDoneAt(inodeID uint64, index int, nodeID uint64) error {
	return s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, inodeID)
		if err != nil {
			return err
		}
		if !in.Chunked {
			return ErrChunkNotExist
		}
		for i := range in.Chunks {
			if in.Chunks[i].Index != index {
				continue
			}
			if !types.ContainsUint64(in.Chunks[i].Replicas, nodeID) {
				return nil // 成员资格校验同 MarkChunkDone
			}
			in.Chunks[i].Done = appendUnique(in.Chunks[i].Done, nodeID)
			return w.putInode(&in)
		}
		return ErrChunkNotExist
	})
}

// MarkChunkUndone 把某节点从块的 Done 集合移除（读端发现该副本内容校验和不符时上报）。
// 移除后 planRepairs 视该槽位为不健康 → 下一轮从完好副本重新 pull（带 CRC 校验）覆盖它，
// 自愈闭环由此闭合。此前读端只静默故障转移、从不回报，坏副本永远算健康、永不被修。
// 保留 Replicas 不动（仍是该节点的槽位），只清 Done；非成员/未 Done 静默无操作（幂等）。
func (s *Store) MarkChunkUndone(chunkID, nodeID uint64) error {
	inodeID, index := types.ParseChunkID(chunkID)
	return s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, inodeID)
		if err != nil {
			return err
		}
		if !in.Chunked {
			return ErrChunkNotExist
		}
		for i := range in.Chunks {
			if in.Chunks[i].Index != index {
				continue
			}
			if !types.ContainsUint64(in.Chunks[i].Done, nodeID) {
				return nil // 未 Done，无操作（幂等）
			}
			filtered := in.Chunks[i].Done[:0]
			for _, d := range in.Chunks[i].Done {
				if d != nodeID {
					filtered = append(filtered, d)
				}
			}
			in.Chunks[i].Done = filtered
			return w.putInode(&in)
		}
		return ErrChunkNotExist
	})
}

// RemoveReplicaDone 把某节点从 legacy 文件的 DoneReplicas 移除（读端上报副本内容损坏）。
// 与 MarkChunkUndone 同义（legacy 整对象版）：清 Done 让修复扫描重新拉取覆盖坏副本。
func (s *Store) RemoveReplicaDone(id, nodeID uint64) error {
	return s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, id)
		if err != nil {
			return err
		}
		if in.Type != types.TypeFile {
			return ErrNotFile
		}
		if !types.ContainsUint64(in.DoneReplicas, nodeID) {
			return nil // 幂等
		}
		filtered := in.DoneReplicas[:0]
		for _, d := range in.DoneReplicas {
			if d != nodeID {
				filtered = append(filtered, d)
			}
		}
		in.DoneReplicas = filtered
		return w.putInode(&in)
	})
}

// ReplaceChunkReplica 块级槽位替换（修复扫描）：Replicas 中 oldNodeID → newNodeID，
// 同时从 Done 中移除 oldNodeID。staging 与已提交的分块文件均适用。
func (s *Store) ReplaceChunkReplica(inodeID uint64, index int, oldNodeID, newNodeID uint64) error {
	return s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, inodeID)
		if err != nil {
			return err
		}
		if !in.Chunked {
			return ErrChunkNotExist
		}
		for i := range in.Chunks {
			if in.Chunks[i].Index != index {
				continue
			}
			// 查重：newNodeID 已在该块副本集则拒绝（同 ReplaceReplica，防并发修复造重复）。
			if types.ContainsUint64(in.Chunks[i].Replicas, newNodeID) {
				return fmt.Errorf("%w: node %d already a replica of chunk %d", ErrReplicaDup, newNodeID, index)
			}
			found := false
			for j, rid := range in.Chunks[i].Replicas {
				if rid == oldNodeID {
					in.Chunks[i].Replicas[j] = newNodeID
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("node %d not in replicas of chunk %d", oldNodeID, index)
			}
			filtered := in.Chunks[i].Done[:0]
			for _, d := range in.Chunks[i].Done {
				if d != oldNodeID {
					filtered = append(filtered, d)
				}
			}
			in.Chunks[i].Done = filtered
			return w.putInode(&in)
		}
		return ErrChunkNotExist
	})
}

// CommitStagingFile 校验并单事务原子提交（v2 采纳式替换）：
// 每块主副本 Done 且 Σ块大小 = size → 原子发布内容。
//   - 目标无同名条目：staging 转正为新文件（FileID = staging ID，Generation=1）。
//   - 同名是文件（TypeFile）：**采纳式替换**——保留旧文件的 FileID/children 条目，
//     原子换入 staging 的块表（Size/Mtime/Generation++），删除 staging。覆盖写不再
//     "删旧建新"，文件身份跨覆盖稳定（FUSE st_ino、打开句柄、外部引用不再被换掉）。
//     返回的 old 是被替换前的旧内容快照，供调用方回收旧块对象。
//   - 同名是目录：拒绝；是符号链接等其他条目：保留旧替换语义（删旧、staging 占名）。
//
// 事务前读者看到旧版本，事务后看到新版本——不存在中间态。
func (s *Store) CommitStagingFile(inodeID uint64, name string, size int64) (types.Inode, types.Inode, bool, error) {
	if err := validateName(name); err != nil {
		return types.Inode{}, types.Inode{}, false, err
	}
	var out, old types.Inode
	var hadOld bool
	err := s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, inodeID)
		if err != nil {
			return err
		}
		if !in.Staging || !in.Chunked {
			return ErrNotStaging
		}
		if len(in.Chunks) == 0 {
			return fmt.Errorf("%w: no chunks assigned", ErrCommitFailed)
		}
		// 块表必须恰好是 {0,1,…,n-1} 且升序无缺口——否则读路径按顺序累加偏移会
		// 把后一块的字节当成缺失块的内容返回（静默内容错乱，无校验和可发现）。
		// AssignChunk 已保证升序，这里断言"无跳号、无重复"补齐连续性。
		var sum int64
		for i, c := range in.Chunks {
			if c.Index != i {
				return fmt.Errorf("%w: chunk index gap at position %d (got index %d)", ErrCommitFailed, i, c.Index)
			}
			if len(c.Replicas) == 0 || !types.ContainsUint64(c.Done, c.Replicas[0]) {
				return fmt.Errorf("%w: chunk %d primary not done", ErrCommitFailed, c.Index)
			}
			sum += c.Size
		}
		if sum != size {
			return fmt.Errorf("%w: chunk size sum %d != %d", ErrCommitFailed, sum, size)
		}
		parent, err := getInodeTx(w.tx, in.ParentID)
		if err != nil {
			return err
		}
		if parent.Type != types.TypeDir {
			return ErrNotDir
		}
		// 同名旧条目：按类型分派替换语义。
		if oldID := w.tx.Bucket(bucketChildren).Get(childKey(in.ParentID, name)); oldID != nil {
			old, err = getInodeTx(w.tx, beU64(oldID))
			if err != nil {
				return err
			}
			switch {
			case old.Type == types.TypeDir:
				return ErrExist
			case old.Type == types.TypeFile:
				// 采纳式替换：身份保留，内容换成 staging 的块表。
				// old 保持为替换前快照（调用方回收旧对象用），不在此处修改。
				adopted := old
				adopted.Chunked = true
				adopted.Chunks = in.Chunks
				adopted.Size = size
				adopted.Checksum = 0 // chunked 内容校验和在每块的 ChunkInfo 里
				adopted.Replicas = nil
				adopted.DoneReplicas = nil
				adopted.Mtime = time.Now()
				adopted.Generation++
				if err := w.putInode(&adopted); err != nil {
					return err
				}
				if err := w.delInode(in.ID); err != nil {
					return err
				}
				out = adopted
				hadOld = true
				return nil
			default:
				// 符号链接等非文件条目：删除旧条目，staging 以新身份占名。
				if err := w.delInode(old.ID); err != nil {
					return err
				}
				hadOld = true
			}
		}
		// 新文件路径（含非文件条目替换）：staging 转正。
		in.Name = name
		in.Size = size
		in.Staging = false
		in.Mtime = time.Now()
		in.Generation = 1
		if err := w.putInode(&in); err != nil {
			return err
		}
		if err := w.putChild(in.ParentID, name, in.ID); err != nil {
			return err
		}
		out = in
		return nil
	})
	if err != nil {
		return types.Inode{}, types.Inode{}, false, err
	}
	return out, old, hadOld, nil
}

// AbortStaging 删除 staging inode（幂等）。已落盘块对象的回收由调用方负责。
func (s *Store) AbortStaging(inodeID uint64) error {
	return s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, inodeID)
		if err != nil {
			if errors.Is(err, ErrNotExist) {
				return nil
			}
			return err
		}
		if !in.Staging {
			return ErrNotStaging
		}
		return w.delInode(inodeID)
	})
}

// ForEachStaging 遍历全部 staging inode（TTL 回收/诊断用）。
func (s *Store) ForEachStaging(fn func(types.Inode) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketInodes).ForEach(func(_, v []byte) error {
			var in types.Inode
			if err := json.Unmarshal(v, &in); err != nil {
				return err
			}
			if in.Staging {
				return fn(in)
			}
			return nil
		})
	})
}

// NodeInfos 按 ID 列表取节点详情（缺失的跳过）。
func (s *Store) NodeInfos(ids []uint64) ([]types.NodeInfo, error) {
	var out []types.NodeInfo
	for _, id := range ids {
		n, err := s.GetNode(id)
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	return out, nil
}

// ---- 存储节点操作 ----

// RegisterNode 注册一个存储节点，返回节点信息。
// 幂等：同一 addr 重复注册（如节点重启）复用原 ID，避免同一物理节点多 ID 并存。
func (s *Store) RegisterNode(addr string, totalBytes int64) (types.NodeInfo, error) {
	var n types.NodeInfo
	err := s.write(func(w *txw) error {
		b := w.tx.Bucket(bucketNodes)
		// 按 addr 找已有记录。
		var existing *types.NodeInfo
		err := b.ForEach(func(k, v []byte) error {
			var cand types.NodeInfo
			if err := json.Unmarshal(v, &cand); err != nil {
				return err
			}
			if cand.Addr == addr {
				c := cand
				existing = &c
			}
			return nil
		})
		if err != nil {
			return err
		}
		if existing != nil {
			// 复用 ID，刷新容量与心跳。这是 liveness 刷新（节点重启后重注册），
			// 不记 WAL——走底层 tx，保持 w.rec 为空，s.write 不追加帧（同心跳）。
			existing.TotalBytes = totalBytes
			existing.LastHeartbeat = time.Now()
			n = *existing
			raw, err := json.Marshal(n)
			if err != nil {
				return err
			}
			return b.Put(u64be(n.ID), raw)
		}
		// 首次注册：分配新 ID 是持久变更，记 WAL。
		id, err := w.nextID(keyNextNode)
		if err != nil {
			return err
		}
		n = types.NodeInfo{ID: id, Addr: addr, TotalBytes: totalBytes, LastHeartbeat: time.Now()}
		raw, err := json.Marshal(n)
		if err != nil {
			return err
		}
		return w.putNode(raw, n.ID)
	})
	if err != nil {
		return types.NodeInfo{}, err
	}
	return n, nil
}

// Heartbeat 更新节点心跳与用量。节点不存在时返回 ErrNotExist。
func (s *Store) Heartbeat(nodeID uint64, usedBytes int64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketNodes)
		raw := b.Get(u64be(nodeID))
		if raw == nil {
			return ErrNotExist
		}
		var n types.NodeInfo
		if err := json.Unmarshal(raw, &n); err != nil {
			return err
		}
		n.UsedBytes = usedBytes
		n.LastHeartbeat = time.Now()
		raw2, err := json.Marshal(n)
		if err != nil {
			return err
		}
		return b.Put(u64be(nodeID), raw2)
	})
}

// SetNodeHeartbeatAt 将节点最后心跳设置为指定时刻（诊断/测试用）。
func (s *Store) SetNodeHeartbeatAt(nodeID uint64, at time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketNodes)
		raw := b.Get(u64be(nodeID))
		if raw == nil {
			return ErrNotExist
		}
		var n types.NodeInfo
		if err := json.Unmarshal(raw, &n); err != nil {
			return err
		}
		n.LastHeartbeat = at
		raw2, err := json.Marshal(n)
		if err != nil {
			return err
		}
		return b.Put(u64be(nodeID), raw2)
	})
}

// ListAliveNodes 返回心跳时间在 maxAge 内的节点。
func (s *Store) ListAliveNodes(maxAge time.Duration) ([]types.NodeInfo, error) {
	var out []types.NodeInfo
	cutoff := time.Now().Add(-maxAge)
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketNodes).ForEach(func(_, v []byte) error {
			var n types.NodeInfo
			if err := json.Unmarshal(v, &n); err != nil {
				return err
			}
			if n.LastHeartbeat.After(cutoff) {
				out = append(out, n)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetNode 按 ID 取节点信息。
func (s *Store) GetNode(nodeID uint64) (types.NodeInfo, error) {
	var n types.NodeInfo
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketNodes).Get(u64be(nodeID))
		if raw == nil {
			return ErrNotExist
		}
		return json.Unmarshal(raw, &n)
	})
	return n, err
}

// ListNodes 返回全部节点（含 dead），用于死亡判定与修复扫描。
func (s *Store) ListNodes() ([]types.NodeInfo, error) {
	var out []types.NodeInfo
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketNodes).ForEach(func(_, v []byte) error {
			var n types.NodeInfo
			if err := json.Unmarshal(v, &n); err != nil {
				return err
			}
			out = append(out, n)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ForEachFile 遍历全部文件 inode，用于修复扫描与 GC 元数据集合。
// 只处理 Type == types.TypeFile 的 inode；fn 返回 error 则停止遍历。
func (s *Store) ForEachFile(fn func(types.Inode) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketInodes).ForEach(func(_, v []byte) error {
			var in types.Inode
			if err := json.Unmarshal(v, &in); err != nil {
				return err
			}
			if in.Type != types.TypeFile {
				return nil
			}
			return fn(in)
		})
	})
}

// ReplaceReplica 副本槽位替换，用于修复扫描中替换 dead 节点。
// 在 Replicas 中找到 oldNodeID 并替换为 newNodeID，同时从 DoneReplicas 中移除 oldNodeID。
// inode 不存在返回 ErrNotExist，oldNodeID 不在 Replicas 中返回错误。
func (s *Store) ReplaceReplica(inodeID, oldNodeID, newNodeID uint64) error {
	return s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, inodeID)
		if err != nil {
			return err
		}
		// 查重：newNodeID 已在副本集则拒绝——两轮修复并发可能各自选中同一新节点，
		// 落库后变成 [5,5,x]，物理副本数虚高，扫描器会把降级文件误判为满健康。
		// 拒绝后由下一轮修复重新选一个不重复的候选（ErrReplicaDup 幂等可重试）。
		if types.ContainsUint64(in.Replicas, newNodeID) {
			return fmt.Errorf("%w: node %d already a replica of inode %d", ErrReplicaDup, newNodeID, inodeID)
		}
		found := false
		for i, rid := range in.Replicas {
			if rid == oldNodeID {
				in.Replicas[i] = newNodeID
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("node %d not in replicas of inode %d", oldNodeID, inodeID)
		}
		// 从 DoneReplicas 中移除 oldNodeID。
		filtered := in.DoneReplicas[:0]
		for _, rid := range in.DoneReplicas {
			if rid != oldNodeID {
				filtered = append(filtered, rid)
			}
		}
		in.DoneReplicas = filtered
		return w.putInode(&in)
	})
}

// ---- 内部工具 ----

func putInode(tx *bolt.Tx, in *types.Inode) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return tx.Bucket(bucketInodes).Put(u64be(in.ID), raw)
}

func getInodeTx(tx *bolt.Tx, id uint64) (types.Inode, error) {
	raw := tx.Bucket(bucketInodes).Get(u64be(id))
	if raw == nil {
		return types.Inode{}, ErrNotExist
	}
	var in types.Inode
	if err := json.Unmarshal(raw, &in); err != nil {
		return types.Inode{}, err
	}
	return in, nil
}

// childKey 生成 children bucket 的 key：parentID(8B) + name。
func childKey(parentID uint64, name string) []byte {
	k := make([]byte, 8+len(name))
	binary.BigEndian.PutUint64(k, parentID)
	copy(k[8:], name)
	return k
}

func hasChild(tx *bolt.Tx, parentID uint64, name string) bool {
	return tx.Bucket(bucketChildren).Get(childKey(parentID, name)) != nil
}

func hasAnyChild(tx *bolt.Tx, parentID uint64) bool {
	prefix := u64be(parentID)
	k, _ := tx.Bucket(bucketChildren).Cursor().Seek(prefix)
	return k != nil && bytes.HasPrefix(k, prefix)
}

func u64be(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func beU64(b []byte) uint64 { return binary.BigEndian.Uint64(b) }
