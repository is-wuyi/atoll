package meta

import (
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"os"

	bolt "go.etcd.io/bbolt"
)

// 快照 = bbolt 原生一致性热备份。bbolt 的 tx.WriteTo 在一个只读事务里把整个库
// 逐页写出，得到的字节流本身就是一个完整、自洽的 bbolt 库文件——所以"恢复"无需
// 逐条重放，直接把字节落成文件再 Open 即可。这是第一阶段(元数据备份进集群)的地基：
// 上层把这段字节流当作特殊对象复制进集群，恢复时反向落地。
//
// CRC32C(Castagnoli) 与项目其余校验设施一致；SnapshotInfo 里的大小+校验和将来直接
// 进 manifest，供集群侧完整性校验用。

// crc32cTable 是 Castagnoli 多项式表（与块校验同一套）。
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// SnapshotInfo 描述一次快照导出的结果。Size/CRC32C 供上层写入 manifest 与恢复时校验。
type SnapshotInfo struct {
	Size   int64  // 快照字节数
	CRC32C uint32 // Castagnoli 校验和
}

// crcWriter 在写出的同时累计 CRC32C 与字节数，避免为算校验和二次读盘。
type crcWriter struct {
	w io.Writer
	h hash.Hash32
	n int64
}

func (cw *crcWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	if n > 0 {
		cw.h.Write(p[:n])
		cw.n += int64(n)
	}
	return n, err
}

// Snapshot 把当前元数据库一致性导出到 w，返回大小与校验和。
// 在只读事务内进行，不阻塞其它读、也不撕裂并发写——bbolt 的 MVCC 保证这个事务看到
// 的是一个固定时刻的一致视图。
func (s *Store) Snapshot(w io.Writer) (SnapshotInfo, error) {
	cw := &crcWriter{w: w, h: crc32.New(crc32cTable)}
	err := s.db.View(func(tx *bolt.Tx) error {
		_, err := tx.WriteTo(cw)
		return err
	})
	if err != nil {
		return SnapshotInfo{}, fmt.Errorf("snapshot: %w", err)
	}
	return SnapshotInfo{Size: cw.n, CRC32C: cw.h.Sum32()}, nil
}

// SnapshotToFile 把快照写到指定路径（先写临时文件再改名，避免写一半崩溃留下半截快照）。
func (s *Store) SnapshotToFile(path string) (SnapshotInfo, error) {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return SnapshotInfo{}, err
	}
	info, err := s.Snapshot(f)
	if err != nil {
		f.Close()
		os.Remove(tmp)
		return SnapshotInfo{}, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return SnapshotInfo{}, err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return SnapshotInfo{}, err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return SnapshotInfo{}, err
	}
	return info, nil
}

// RestoreFromReader 从快照字节流在 dbPath 处重建库并打开。
// dbPath 必须不存在（拒绝覆盖已有库——覆盖是危险操作，交由调用方显式决定先删）。
// 恢复即"落地 + Open"：快照字节本身就是完整 bbolt 文件，落成文件后 Open 会正常
// 建 bucket（已存在则跳过）、补根目录（已存在则不动），得到与导出时一致的库。
func RestoreFromReader(dbPath string, r io.Reader) (*Store, error) {
	if _, err := os.Stat(dbPath); err == nil {
		return nil, fmt.Errorf("restore: 目标已存在，拒绝覆盖: %s", dbPath)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("restore: stat %s: %w", dbPath, err)
	}
	tmp := dbPath + ".restore.tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		os.Remove(tmp)
		return nil, fmt.Errorf("restore: 写快照: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	if err := os.Rename(tmp, dbPath); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	return Open(dbPath)
}

// VerifyCRC32C 计算一段快照字节流的 Castagnoli 校验和，供恢复前完整性核对。
func VerifyCRC32C(r io.Reader) (uint32, int64, error) {
	h := crc32.New(crc32cTable)
	n, err := io.Copy(h, r)
	if err != nil {
		return 0, 0, err
	}
	return h.Sum32(), n, nil
}
