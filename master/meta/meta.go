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

// ---- 存储节点操作 ----

// RegisterNode 注册一个存储节点，返回分配的节点信息。
func (s *Store) RegisterNode(addr string, totalBytes int64) (types.NodeInfo, error) {
	var n types.NodeInfo
	err := s.db.Update(func(tx *bolt.Tx) error {
		id, err := nextID(tx, keyNextNode)
		if err != nil {
			return err
		}
		n = types.NodeInfo{ID: id, Addr: addr, TotalBytes: totalBytes, LastHeartbeat: time.Now()}
		raw, err := json.Marshal(n)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketNodes).Put(u64be(id), raw)
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
