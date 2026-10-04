package meta

import (
	"encoding/json"
	"errors"
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

// 写操作幂等结果表（v2-3a）。
//
// 背景：commit / 小文件上传这类"最终写"存在经典的两难——响应在网络上丢失时，
// 服务端可能已成功。客户端重试若不带凭据，要么重复执行（小文件新建出第二份）、
// 要么误报失败（对已提交 inode 再 commit 报 ErrNotStaging，审计 F3）。
// 解法：客户端为每个写操作生成唯一 op_id，服务端把"操作→结果"记录下来；
// 同 op_id 的重试直接回放原结果，不重复执行。
//
// 记录随 bbolt 事务进 WAL/快照（与普通元数据同路径备份），master 崩溃恢复后仍可
// 回放。记录由 staging 清扫循环按 TTL 过期清理——只为吸收"分钟级"的重试窗口，
// 不是永久去重表。

// OpRecord 是一次已完成的写操作及其结果。
type OpRecord struct {
	OpID        string      `json:"op_id"`
	Kind        string      `json:"kind"`                  // "small" | "commit"
	Fingerprint string      `json:"fingerprint,omitempty"` // 请求指纹；同 op_id 不同请求必须拒绝
	Inode       types.Inode `json:"inode"`
	CreatedAt   time.Time   `json:"created_at"`
}

func opKey(opID string) []byte { return []byte(opID) }

// ErrOpConflict：同 op_id 但请求指纹不同——绝不能回放无关的旧结果。
var ErrOpConflict = errors.New("op id reused with different request")

// opResultTx 在事务内读取幂等结果：同 op_id+kind+指纹 → 回放；指纹不符 → 冲突。
func opResultTx(tx *bolt.Tx, opID, kind, fingerprint string) (OpRecord, bool, error) {
	var rec OpRecord
	if opID == "" {
		return rec, false, nil
	}
	raw := tx.Bucket(bucketOps).Get(opKey(opID))
	if raw == nil {
		return rec, false, nil
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return rec, false, err
	}
	if rec.Kind != kind || (fingerprint != "" && rec.Fingerprint != "" && rec.Fingerprint != fingerprint) {
		return rec, false, ErrOpConflict
	}
	return rec, true, nil
}

// putOpResult 在记录型事务内写入幂等结果（put-if-absent：已存在且一致则不占帧）。
func (w *txw) putOpResult(opID, kind, fingerprint string, in types.Inode, at time.Time) error {
	if opID == "" {
		return nil
	}
	rec, ok, err := opResultTx(w.tx, opID, kind, fingerprint)
	if err != nil {
		return err
	}
	if ok {
		return nil // 已记录，幂等
	}
	_ = rec
	raw, err := json.Marshal(OpRecord{OpID: opID, Kind: kind, Fingerprint: fingerprint, Inode: in, CreatedAt: at})
	if err != nil {
		return err
	}
	return w.put(bcOps, bucketOps, opKey(opID), raw)
}

// PutOpResult 记录一次写操作的结果（同 op_id 覆盖写为幂等语义）。
func (s *Store) PutOpResult(opID, kind string, in types.Inode) error {
	return s.PutOpResultAt(opID, kind, in, time.Now())
}

// PutOpResultAt 带时间的变体（TTL 清理测试用）。
func (s *Store) PutOpResultAt(opID, kind string, in types.Inode, at time.Time) error {
	raw, err := json.Marshal(OpRecord{OpID: opID, Kind: kind, Inode: in, CreatedAt: at})
	if err != nil {
		return err
	}
	return s.write(func(w *txw) error {
		return w.put(bcOps, bucketOps, opKey(opID), raw)
	})
}

// GetOpResult 查询 op 结果；ok=false 表示该 op_id 未执行过（正常首次执行）。
func (s *Store) GetOpResult(opID string) (OpRecord, bool, error) {
	var rec OpRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketOps).Get(opKey(opID))
		if raw == nil {
			return ErrNotExist
		}
		return json.Unmarshal(raw, &rec)
	})
	if err == ErrNotExist {
		return OpRecord{}, false, nil
	}
	if err != nil {
		return OpRecord{}, false, err
	}
	return rec, true, nil
}

// SweepOpsOlderThan 删除早于 d 的 op 记录，返回删除数（staging 清扫循环调用）。
func (s *Store) SweepOpsOlderThan(d time.Duration) (int, error) {
	removed := 0
	cutoff := time.Now().Add(-d)
	err := s.write(func(w *txw) error {
		b := w.tx.Bucket(bucketOps)
		type victim struct {
			key []byte
		}
		var stale []victim
		if err := b.ForEach(func(k, v []byte) error {
			var rec OpRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return nil // 损坏记录当作过期清理
			}
			if rec.CreatedAt.Before(cutoff) {
				stale = append(stale, victim{key: append([]byte(nil), k...)})
			}
			return nil
		}); err != nil {
			return err
		}
		for _, v := range stale {
			if err := w.del(bcOps, bucketOps, v.key); err != nil {
				return err
			}
			removed++
		}
		return nil
	})
	return removed, err
}
