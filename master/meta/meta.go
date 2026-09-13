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
	"time"

	bolt "go.etcd.io/bbolt"

	"atoll/pkg/types"
)

var (
	bucketInodes   = []byte("inodes")
	bucketChildren = []byte("children")
	bucketNodes    = []byte("nodes")
	bucketMeta     = []byte("meta")

	keyNextInode = []byte("next_inode")
	keyNextNode  = []byte("next_node")
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
)

// Store 封装 bbolt 数据库。
type Store struct {
	db *bolt.DB
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

func (s *Store) init() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketInodes, bucketChildren, bucketNodes, bucketMeta} {
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
	var in types.Inode
	err := s.db.Update(func(tx *bolt.Tx) error {
		parent, err := getInodeTx(tx, parentID)
		if err != nil {
			return err
		}
		if parent.Type != types.TypeDir {
			return ErrNotDir
		}
		if hasChild(tx, parentID, name) {
			return ErrExist
		}
		id, err := nextID(tx, keyNextInode)
		if err != nil {
			return err
		}
		in = types.Inode{ID: id, ParentID: parentID, Name: name, Type: types.TypeDir, Mtime: time.Now()}
		if err := putInode(tx, &in); err != nil {
			return err
		}
		return tx.Bucket(bucketChildren).Put(childKey(parentID, name), u64be(id))
	})
	if err != nil {
		return types.Inode{}, err
	}
	return in, nil
}

// CreateFile 在 parentID 下创建文件记录（数据尚未写入，size 初始为 0）。
func (s *Store) CreateFile(parentID uint64, name string, replicas []uint64) (types.Inode, error) {
	var in types.Inode
	err := s.db.Update(func(tx *bolt.Tx) error {
		parent, err := getInodeTx(tx, parentID)
		if err != nil {
			return err
		}
		if parent.Type != types.TypeDir {
			return ErrNotDir
		}
		if hasChild(tx, parentID, name) {
			return ErrExist
		}
		id, err := nextID(tx, keyNextInode)
		if err != nil {
			return err
		}
		in = types.Inode{ID: id, ParentID: parentID, Name: name, Type: types.TypeFile, Mtime: time.Now(), Replicas: replicas}
		if err := putInode(tx, &in); err != nil {
			return err
		}
		return tx.Bucket(bucketChildren).Put(childKey(parentID, name), u64be(id))
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

// DeleteFile 删除一个文件记录。
func (s *Store) DeleteFile(id uint64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		in, err := getInodeTx(tx, id)
		if err != nil {
			return err
		}
		if in.Type != types.TypeFile {
			return ErrNotFile
		}
		if err := tx.Bucket(bucketInodes).Delete(u64be(id)); err != nil {
			return err
		}
		return tx.Bucket(bucketChildren).Delete(childKey(in.ParentID, in.Name))
	})
}

// DeleteDir 删除一个空目录。
func (s *Store) DeleteDir(id uint64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		in, err := getInodeTx(tx, id)
		if err != nil {
			return err
		}
		if in.Type != types.TypeDir {
			return ErrNotDir
		}
		if id == RootID {
			return errors.New("cannot delete root")
		}
		if hasAnyChild(tx, id) {
			return ErrNotEmpty
		}
		if err := tx.Bucket(bucketInodes).Delete(u64be(id)); err != nil {
			return err
		}
		return tx.Bucket(bucketChildren).Delete(childKey(in.ParentID, in.Name))
	})
}

// Rename 在同一目录内改名。
func (s *Store) Rename(id uint64, newName string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		in, err := getInodeTx(tx, id)
		if err != nil {
			return err
		}
		if in.ID == RootID {
			return errors.New("cannot rename root")
		}
		if hasChild(tx, in.ParentID, newName) {
			return ErrExist
		}
		if err := tx.Bucket(bucketChildren).Delete(childKey(in.ParentID, in.Name)); err != nil {
			return err
		}
		in.Name = newName
		in.Mtime = time.Now()
		if err := putInode(tx, &in); err != nil {
			return err
		}
		return tx.Bucket(bucketChildren).Put(childKey(in.ParentID, newName), u64be(id))
	})
}

// UpdateFileSize 更新文件大小，并把主副本（Replicas[0]）标记为已同步。
// 客户端直连主副本写完数据后 commit 时调用。
func (s *Store) UpdateFileSize(id uint64, size int64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		in, err := getInodeTx(tx, id)
		if err != nil {
			return err
		}
		if in.Type != types.TypeFile {
			return ErrNotFile
		}
		in.Size = size
		in.Mtime = time.Now()
		if len(in.Replicas) > 0 {
			in.DoneReplicas = appendUnique(in.DoneReplicas, in.Replicas[0])
		}
		return putInode(tx, &in)
	})
}

// AddReplicaDone 把某节点加入文件的已完成副本列表（从副本同步完成后上报）。
func (s *Store) AddReplicaDone(id, nodeID uint64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		in, err := getInodeTx(tx, id)
		if err != nil {
			return err
		}
		if in.Type != types.TypeFile {
			return ErrNotFile
		}
		in.DoneReplicas = appendUnique(in.DoneReplicas, nodeID)
		return putInode(tx, &in)
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
	return s.db.Update(func(tx *bolt.Tx) error {
		in, err := getInodeTx(tx, id)
		if err != nil {
			return err
		}
		if in.Type != types.TypeFile {
			return ErrNotFile
		}
		in.Size = size
		in.Replicas = replicas
		in.Mtime = time.Now()
		return putInode(tx, &in)
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

// CreateStagingFile 在 parentID 下分配一个写入中的隐藏文件 inode。
// Staging=true, Chunked=true，不挂 children——路径解析天然看不见它。
func (s *Store) CreateStagingFile(parentID uint64) (types.Inode, error) {
	var in types.Inode
	err := s.db.Update(func(tx *bolt.Tx) error {
		parent, err := getInodeTx(tx, parentID)
		if err != nil {
			return err
		}
		if parent.Type != types.TypeDir {
			return ErrNotDir
		}
		id, err := nextStagingID(tx)
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
		return putInode(tx, &in)
	})
	if err != nil {
		return types.Inode{}, err
	}
	return in, nil
}

// nextStagingID 读取并自增 staging 计数器，从 StagingInodeBase 起。
func nextStagingID(tx *bolt.Tx) (uint64, error) {
	b := tx.Bucket(bucketMeta)
	cur := types.StagingInodeBase
	if v := b.Get(keyNextStagingInode); v != nil {
		cur = beU64(v)
	}
	if err := b.Put(keyNextStagingInode, u64be(cur+1)); err != nil {
		return 0, err
	}
	return cur, nil
}

// AssignChunk 为 staging 文件的第 index 块分配副本节点。
// 幂等：该块已分配则原样返回既有分配（重试安全）。
func (s *Store) AssignChunk(inodeID uint64, index int, size int64, replicas []uint64) (types.ChunkInfo, error) {
	var chunk types.ChunkInfo
	err := s.db.Update(func(tx *bolt.Tx) error {
		in, err := getInodeTx(tx, inodeID)
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
		in.Chunks = append(in.Chunks, types.ChunkInfo{Index: index, Size: size, Replicas: replicas})
		// 并发 Assign 可能乱序插入，保持块表按 Index 升序。
		sort.Slice(in.Chunks, func(i, j int) bool { return in.Chunks[i].Index < in.Chunks[j].Index })
		if err := putInode(tx, &in); err != nil {
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
func (s *Store) ReassignChunk(inodeID uint64, index int, replicas []uint64) (types.ChunkInfo, error) {
	var chunk types.ChunkInfo
	err := s.db.Update(func(tx *bolt.Tx) error {
		in, err := getInodeTx(tx, inodeID)
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
				chunk = in.Chunks[i]
				return putInode(tx, &in)
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
func (s *Store) MarkChunkDone(chunkID, nodeID uint64) error {
	inodeID, index := types.ParseChunkID(chunkID)
	return s.db.Update(func(tx *bolt.Tx) error {
		in, err := getInodeTx(tx, inodeID)
		if err != nil {
			return err
		}
		if !in.Chunked {
			return ErrChunkNotExist
		}
		for i := range in.Chunks {
			if in.Chunks[i].Index == index {
				in.Chunks[i].Done = appendUnique(in.Chunks[i].Done, nodeID)
				return putInode(tx, &in)
			}
		}
		return ErrChunkNotExist
	})
}

// ReplaceChunkReplica 块级槽位替换（修复扫描）：Replicas 中 oldNodeID → newNodeID，
// 同时从 Done 中移除 oldNodeID。staging 与已提交的分块文件均适用。
func (s *Store) ReplaceChunkReplica(inodeID uint64, index int, oldNodeID, newNodeID uint64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		in, err := getInodeTx(tx, inodeID)
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
			return putInode(tx, &in)
		}
		return ErrChunkNotExist
	})
}

// CommitStagingFile 校验并单事务原子提交：
// 每块主副本 Done 且 Σ块大小 = size → 同名旧 inode 一并删除 → staging 换名挂 children。
// 事务前读者看到旧版本，事务后看到新版本——不存在中间态（审计 #1）。
// 返回提交后的 inode 与被替换的旧 inode（ok=false 表示无旧版本）。
func (s *Store) CommitStagingFile(inodeID uint64, name string, size int64) (types.Inode, types.Inode, bool, error) {
	var out, old types.Inode
	var hadOld bool
	err := s.db.Update(func(tx *bolt.Tx) error {
		in, err := getInodeTx(tx, inodeID)
		if err != nil {
			return err
		}
		if !in.Staging || !in.Chunked {
			return ErrNotStaging
		}
		if len(in.Chunks) == 0 {
			return fmt.Errorf("%w: no chunks assigned", ErrCommitFailed)
		}
		var sum int64
		for _, c := range in.Chunks {
			if len(c.Replicas) == 0 || !containsUint64(c.Done, c.Replicas[0]) {
				return fmt.Errorf("%w: chunk %d primary not done", ErrCommitFailed, c.Index)
			}
			sum += c.Size
		}
		if sum != size {
			return fmt.Errorf("%w: chunk size sum %d != %d", ErrCommitFailed, sum, size)
		}
		parent, err := getInodeTx(tx, in.ParentID)
		if err != nil {
			return err
		}
		if parent.Type != types.TypeDir {
			return ErrNotDir
		}
		// 同名旧 inode：目录则拒绝覆盖，文件则同事务删除（原子替换）。
		if oldID := tx.Bucket(bucketChildren).Get(childKey(in.ParentID, name)); oldID != nil {
			old, err = getInodeTx(tx, beU64(oldID))
			if err != nil {
				return err
			}
			if old.Type == types.TypeDir {
				return ErrExist
			}
			if err := tx.Bucket(bucketInodes).Delete(u64be(old.ID)); err != nil {
				return err
			}
			hadOld = true
		}
		in.Name = name
		in.Size = size
		in.Staging = false
		in.Mtime = time.Now()
		if err := putInode(tx, &in); err != nil {
			return err
		}
		if err := tx.Bucket(bucketChildren).Put(childKey(in.ParentID, name), u64be(in.ID)); err != nil {
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
	return s.db.Update(func(tx *bolt.Tx) error {
		in, err := getInodeTx(tx, inodeID)
		if err != nil {
			if errors.Is(err, ErrNotExist) {
				return nil
			}
			return err
		}
		if !in.Staging {
			return ErrNotStaging
		}
		return tx.Bucket(bucketInodes).Delete(u64be(inodeID))
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

// containsUint64 判断 v 是否在 list 中。
func containsUint64(list []uint64, v uint64) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
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
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketNodes)
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
			// 复用 ID，刷新容量与心跳。
			existing.TotalBytes = totalBytes
			existing.LastHeartbeat = time.Now()
			n = *existing
		} else {
			id, err := nextID(tx, keyNextNode)
			if err != nil {
				return err
			}
			n = types.NodeInfo{ID: id, Addr: addr, TotalBytes: totalBytes, LastHeartbeat: time.Now()}
		}
		raw, err := json.Marshal(n)
		if err != nil {
			return err
		}
		return b.Put(u64be(n.ID), raw)
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
	return s.db.Update(func(tx *bolt.Tx) error {
		in, err := getInodeTx(tx, inodeID)
		if err != nil {
			return err
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
		return putInode(tx, &in)
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

// nextID 读取并自增计数器。
func nextID(tx *bolt.Tx, key []byte) (uint64, error) {
	b := tx.Bucket(bucketMeta)
	cur := uint64(2)
	if v := b.Get(key); v != nil {
		cur = beU64(v)
	}
	if err := b.Put(key, u64be(cur+1)); err != nil {
		return 0, err
	}
	return cur, nil
}

func u64be(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func beU64(b []byte) uint64 { return binary.BigEndian.Uint64(b) }
