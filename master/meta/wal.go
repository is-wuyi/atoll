package meta

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	bolt "go.etcd.io/bbolt"

	"atoll/pkg/types"
)

// WAL：元数据变更的 redo 日志。
//
// 形式选型见提交记录——记录"往哪个桶 put/del 了什么字节"(物理 redo)，而非"调了
// CreateFile"(逻辑命令)。redo 重放只有一条路径、和原写入逐字节一致、不会分叉；逻辑
// 日志要为每个方法写一个 apply 镜像，两条路径会漂移。
//
// 存储：与状态变更同事务写进同库 `wal` 桶(key=seq 大端, value=编码后的帧)，天然原子
// ——不可能出现"改了状态但 WAL 没记"或反之。seq 单调递增 = 将来 raft 的 log index。
//
// 只记录持久元数据变更(inodes/children/nodes 注册/计数器)，不记录心跳这类 liveness
// churn——通过"写方法走 s.write 还是 s.db.Update"天然筛选。
//
// 恢复 = 最近快照(含快照时刻的 wal 桶与 seq) + 重放其后的帧。

var (
	bucketWAL  = []byte("wal")
	keyWALSeq  = []byte("wal_seq") // 最后分配的帧 seq；帧 seq 从 1 起
)

// 桶编码：帧里用 1 字节标识目标桶，避免存整串桶名。
const (
	bcInodes   byte = 1
	bcChildren byte = 2
	bcNodes    byte = 3
	bcMeta     byte = 4
)

func bucketByCode(c byte) ([]byte, error) {
	switch c {
	case bcInodes:
		return bucketInodes, nil
	case bcChildren:
		return bucketChildren, nil
	case bcNodes:
		return bucketNodes, nil
	case bcMeta:
		return bucketMeta, nil
	default:
		return nil, fmt.Errorf("wal: 未知桶编码 %d", c)
	}
}

// mutation 是一次桶级变更：put(Del=false) 或 delete(Del=true)。
type mutation struct {
	Bucket byte
	Key    []byte
	Value  []byte
	Del    bool
}

// Frame 是一次已提交操作的全部变更(一条 raft-ready 日志条目)。
type Frame struct {
	Seq  uint64
	Muts []mutation
}

// ---- 记录型事务包装 ----

// txw 包装 bolt.Tx：写走它的方法(记进 redo 集 + 落库)，读仍用底层 tx。
type txw struct {
	tx  *bolt.Tx
	rec []mutation
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

// put 记录并写入。key/val 都克隆——bbolt 的 Get 返回 mmap 内存，且调用方常复用缓冲。
func (w *txw) put(bucketCode byte, bkt, key, val []byte) error {
	w.rec = append(w.rec, mutation{Bucket: bucketCode, Key: cloneBytes(key), Value: cloneBytes(val)})
	return w.tx.Bucket(bkt).Put(key, val)
}

// del 记录并删除。
func (w *txw) del(bucketCode byte, bkt, key []byte) error {
	w.rec = append(w.rec, mutation{Bucket: bucketCode, Key: cloneBytes(key), Del: true})
	return w.tx.Bucket(bkt).Delete(key)
}

func (w *txw) putInode(in *types.Inode) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return w.put(bcInodes, bucketInodes, u64be(in.ID), raw)
}

func (w *txw) delInode(id uint64) error {
	return w.del(bcInodes, bucketInodes, u64be(id))
}

func (w *txw) putChild(parentID uint64, name string, childID uint64) error {
	return w.put(bcChildren, bucketChildren, childKey(parentID, name), u64be(childID))
}

func (w *txw) delChild(parentID uint64, name string) error {
	return w.del(bcChildren, bucketChildren, childKey(parentID, name))
}

func (w *txw) putNode(raw []byte, id uint64) error {
	return w.put(bcNodes, bucketNodes, u64be(id), raw)
}

// nextID / nextStagingID 的记录版：把计数器自增也记进 WAL，重放后计数器延续、不复用 ID。
func (w *txw) nextID(key []byte) (uint64, error) {
	b := w.tx.Bucket(bucketMeta)
	cur := uint64(2)
	if v := b.Get(key); v != nil {
		cur = beU64(v)
	}
	if err := w.put(bcMeta, bucketMeta, key, u64be(cur+1)); err != nil {
		return 0, err
	}
	return cur, nil
}

func (w *txw) nextStagingID() (uint64, error) {
	b := w.tx.Bucket(bucketMeta)
	cur := types.StagingInodeBase
	if v := b.Get(keyNextStagingInode); v != nil {
		cur = beU64(v)
	}
	if err := w.put(bcMeta, bucketMeta, keyNextStagingInode, u64be(cur+1)); err != nil {
		return 0, err
	}
	return cur, nil
}

// PostCommitHook 在一个产生了变更的写事务成功提交后被调用，收到该帧的 seq 与编码字节。
// 用途：同步旋钮——钩子里把这一帧同步复制到集群，返回 error 则 write 向调用方返回 error
// （帧已在本地持久，但客户端视为失败，见 HA 设计决策点 1：不撤回本地，靠后台补 ship）。
// 钩子在 bbolt 事务之外调用（提交后），不阻塞其它写者。
type PostCommitHook func(seq uint64, frame []byte) error

// SetPostCommitHook 注册提交后钩子（nil 清除）。非并发安全，应在服务启动、开始写之前设置。
func (s *Store) SetPostCommitHook(h PostCommitHook) { s.postCommit = h }

// write 执行一个记录型写事务：跑 fn，若产生了变更则把这一帧原子追加进 wal 桶。
// 提交成功后，若注册了 post-commit 钩子且本次有变更，调用之——钩子 error 透传给调用方。
func (s *Store) write(fn func(*txw) error) error {
	var committedSeq uint64
	var committedFrame []byte
	err := s.db.Update(func(tx *bolt.Tx) error {
		w := &txw{tx: tx}
		if err := fn(w); err != nil {
			return err
		}
		if len(w.rec) == 0 {
			return nil // 幂等命中等无实际变更的操作不占 seq
		}
		seq, err := appendFrame(tx, w.rec)
		if err != nil {
			return err
		}
		committedSeq = seq
		committedFrame = encodeFrame(w.rec)
		return nil
	})
	if err != nil {
		return err
	}
	// 事务已提交。若本次有变更且注册了钩子，同步调用（同步旋钮在此落集群）。
	if committedSeq != 0 && s.postCommit != nil {
		return s.postCommit(committedSeq, committedFrame)
	}
	return nil
}

// appendFrame 把一帧变更写进 wal 桶(seq = 当前 wal_seq + 1)，返回分配的 seq。
// 用底层 tx.Bucket 直接写——WAL 桶与 wal_seq 是日志本身，不能被再次记录。
func appendFrame(tx *bolt.Tx, muts []mutation) (uint64, error) {
	meta := tx.Bucket(bucketMeta)
	seq := uint64(0)
	if v := meta.Get(keyWALSeq); v != nil {
		seq = beU64(v)
	}
	seq++
	if err := meta.Put(keyWALSeq, u64be(seq)); err != nil {
		return 0, err
	}
	if err := tx.Bucket(bucketWAL).Put(u64be(seq), encodeFrame(muts)); err != nil {
		return 0, err
	}
	return seq, nil
}

// ---- 帧编码(raft-ready 字节格式) ----
//
// 帧字节布局(全大端)：
//   uint32 变更数
//   每条变更: byte 桶编码 | byte 删除标志 | uint32 keyLen | key | uint32 valLen | val
// 删除标志=1 时 valLen 恒为 0。

func encodeFrame(muts []mutation) []byte {
	size := 4
	for _, m := range muts {
		size += 1 + 1 + 4 + len(m.Key) + 4 + len(m.Value)
	}
	buf := make([]byte, size)
	off := 0
	binary.BigEndian.PutUint32(buf[off:], uint32(len(muts)))
	off += 4
	for _, m := range muts {
		buf[off] = m.Bucket
		off++
		if m.Del {
			buf[off] = 1
		}
		off++
		binary.BigEndian.PutUint32(buf[off:], uint32(len(m.Key)))
		off += 4
		off += copy(buf[off:], m.Key)
		binary.BigEndian.PutUint32(buf[off:], uint32(len(m.Value)))
		off += 4
		off += copy(buf[off:], m.Value)
	}
	return buf
}

func decodeFrame(seq uint64, b []byte) (Frame, error) {
	f := Frame{Seq: seq}
	if len(b) < 4 {
		return f, fmt.Errorf("wal: 帧 %d 过短", seq)
	}
	off := 0
	n := binary.BigEndian.Uint32(b[off:])
	off += 4
	for i := uint32(0); i < n; i++ {
		if off+6 > len(b) {
			return f, fmt.Errorf("wal: 帧 %d 变更 %d 头部越界", seq, i)
		}
		var m mutation
		m.Bucket = b[off]
		off++
		m.Del = b[off] == 1
		off++
		kl := int(binary.BigEndian.Uint32(b[off:]))
		off += 4
		if off+kl+4 > len(b) {
			return f, fmt.Errorf("wal: 帧 %d 变更 %d key 越界", seq, i)
		}
		m.Key = cloneBytes(b[off : off+kl])
		off += kl
		vl := int(binary.BigEndian.Uint32(b[off:]))
		off += 4
		if off+vl > len(b) {
			return f, fmt.Errorf("wal: 帧 %d 变更 %d val 越界", seq, i)
		}
		if !m.Del {
			m.Value = cloneBytes(b[off : off+vl])
		}
		off += vl
		f.Muts = append(f.Muts, m)
	}
	return f, nil
}

// ---- WAL 段编解码（复制进集群用）----
//
// 一个 WAL 段 = 若干帧打包成一个 blob。段字节布局(全大端)：
//   每帧: uint64 seq | uint32 frameLen | frameBytes(encodeFrame 的输出)
// 帧之间首尾相接。DecodeWALSegment 还原成带 seq 的帧序列，喂给 ApplyFrames。

// EncodeSyncBlob 把单帧(seq + encodeFrame 的字节)包成一个"段"blob，格式与 EncodeWALSegment
// 一帧时完全一致，故可被 DecodeWALSegment 读回。同步旋钮的 post-commit 钩子用它——钩子拿到的
// 是 encodeFrame 的原始帧体(无 seq 头)，这里补上 seq 头使 blob 自描述。
func EncodeSyncBlob(seq uint64, frameBody []byte) []byte {
	buf := make([]byte, 12+len(frameBody))
	binary.BigEndian.PutUint64(buf[0:], seq)
	binary.BigEndian.PutUint32(buf[8:], uint32(len(frameBody)))
	copy(buf[12:], frameBody)
	return buf
}

// EncodeWALSegment 把一批帧打包成一个段 blob。
func EncodeWALSegment(frames []Frame) []byte {
	var buf []byte
	var hdr [12]byte
	for _, f := range frames {
		body := encodeFrame(f.Muts)
		binary.BigEndian.PutUint64(hdr[0:], f.Seq)
		binary.BigEndian.PutUint32(hdr[8:], uint32(len(body)))
		buf = append(buf, hdr[:]...)
		buf = append(buf, body...)
	}
	return buf
}

// DecodeWALSegment 还原一个段 blob 为帧序列（按出现顺序，即 seq 升序）。
func DecodeWALSegment(b []byte) ([]Frame, error) {
	var frames []Frame
	off := 0
	for off < len(b) {
		if off+12 > len(b) {
			return nil, fmt.Errorf("wal 段: 帧头越界 @%d", off)
		}
		seq := binary.BigEndian.Uint64(b[off:])
		fl := int(binary.BigEndian.Uint32(b[off+8:]))
		off += 12
		if off+fl > len(b) {
			return nil, fmt.Errorf("wal 段: 帧体越界 @%d len=%d", off, fl)
		}
		f, err := decodeFrame(seq, b[off:off+fl])
		if err != nil {
			return nil, err
		}
		frames = append(frames, f)
		off += fl
	}
	return frames, nil
}

// ---- 读取与重放 ----

// WALSeq 返回当前最后一帧的 seq(0 = 尚无帧)。
func (s *Store) WALSeq() (uint64, error) {
	var seq uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bucketMeta).Get(keyWALSeq); v != nil {
			seq = beU64(v)
		}
		return nil
	})
	return seq, err
}

// BackupVersion 返回持久化的备份版本计数器(0 = 从未备份)。
func (s *Store) BackupVersion() (uint64, error) {
	var v uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		if raw := tx.Bucket(bucketMeta).Get(keyBackupVersion); raw != nil {
			v = beU64(raw)
		}
		return nil
	})
	return v, err
}

// NextBackupVersion 原子自增并返回新的备份版本号。这是 master 的权威计数器：
// 存进本地 bbolt(随快照进集群)，重启后从本地读回续增，不依赖集群可达。
func (s *Store) NextBackupVersion() (uint64, error) {
	var next uint64
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMeta)
		cur := uint64(0)
		if raw := b.Get(keyBackupVersion); raw != nil {
			cur = beU64(raw)
		}
		next = cur + 1
		return b.Put(keyBackupVersion, u64be(next))
	})
	return next, err
}

// SetBackupVersionAtLeast 把持久版本抬高到 at 少(若当前已 >= at 则不动)。
// 从集群重建后用：确保本地计数器不低于集群已有的最高版本，避免续增时版本号倒退。
func (s *Store) SetBackupVersionAtLeast(at uint64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMeta)
		cur := uint64(0)
		if raw := b.Get(keyBackupVersion); raw != nil {
			cur = beU64(raw)
		}
		if at <= cur {
			return nil
		}
		return b.Put(keyBackupVersion, u64be(at))
	})
}

// FramesSince 返回 seq > since 的所有帧(升序)，供恢复重放或复制进集群。
func (s *Store) FramesSince(since uint64) ([]Frame, error) {
	var out []Frame
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketWAL).Cursor()
		start := u64be(since + 1)
		for k, v := c.Seek(start); k != nil; k, v = c.Next() {
			f, err := decodeFrame(beU64(k), v)
			if err != nil {
				return err
			}
			out = append(out, f)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ApplyFrames 按 seq 顺序重放帧到库：应用每条变更，并把帧原样写回 wal 桶、推进 wal_seq。
// 用于快照恢复后补齐增量。要求帧 seq 严格大于当前 wal_seq 且连续递增(容忍从快照 seq 接续)。
func (s *Store) ApplyFrames(frames []Frame) error {
	if len(frames) == 0 {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		cur := uint64(0)
		if v := meta.Get(keyWALSeq); v != nil {
			cur = beU64(v)
		}
		for _, f := range frames {
			if f.Seq <= cur {
				continue // 已包含(快照已含该帧)，跳过
			}
			if f.Seq != cur+1 {
				return fmt.Errorf("wal: 重放缺口，期望 seq %d 收到 %d", cur+1, f.Seq)
			}
			for _, m := range f.Muts {
				bkt, err := bucketByCode(m.Bucket)
				if err != nil {
					return err
				}
				if m.Del {
					if err := tx.Bucket(bkt).Delete(m.Key); err != nil {
						return err
					}
				} else if err := tx.Bucket(bkt).Put(m.Key, m.Value); err != nil {
					return err
				}
			}
			if err := meta.Put(keyWALSeq, u64be(f.Seq)); err != nil {
				return err
			}
			if err := tx.Bucket(bucketWAL).Put(u64be(f.Seq), encodeFrame(f.Muts)); err != nil {
				return err
			}
			cur = f.Seq
		}
		return nil
	})
}

// TruncateWALThrough 删除 seq <= through 的帧(快照落地后清理已固化的增量)。
func (s *Store) TruncateWALThrough(through uint64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketWAL).Cursor()
		for k, _ := c.First(); k != nil && beU64(k) <= through; k, _ = c.Next() {
			if err := c.Delete(); err != nil {
				return err
			}
		}
		return nil
	})
}
