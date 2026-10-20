package meta

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"

	bolt "go.etcd.io/bbolt"
)

// 内容密钥恢复包（key pack）：把全库 wrapped DEK 记录离线导出成一个自描述、
// 防篡改的单文件，与 KEK 文件分开保管。恢复 = 在新库逐条回放（Import）。
//
// 设计边界：
//   - 包内只有 wrapped DEK——没有 KEK、没有明文 DEK，单独泄露不暴露任何内容；
//     但配合 KEK 文件即可解开全部内容，故包本身仍按凭据保管（0600、离线）。
//   - 完整性用 HMAC-SHA-256(keyID ‖ 每条记录的规范序列) 绑定导出时刻：
//     导入端不持 KEK，无法重算 HMAC——所以 HMAC 密钥材料从 KEK 派生
//     (HKDF 域 "atoll-keypack-v1")，导入端带 KEK 时校验，不带时跳过校验并明说。
//   - 导入只回放"新库没有的"对象 ID；已有记录必须逐字节相同（幂等），不同则
//     拒绝——防把 A 集群的密钥包混灌进 B 集群。
//
// 线格式（版本 1）：
//   magic "ATKP"(4) | version(1) | keyIDLen(2 BE) | keyID | createdUnixNano(8 BE)
//   | recordCount(4 BE) | 记录流（每条：objectID(8) generation(8) spaceID(8)
//   keyIDLen(2) keyID wrappedLen(4) wrappedDEK）| HMAC-SHA256(32)

var keyPackMagic = [4]byte{'A', 'T', 'K', 'P'}

const (
	keyPackVersion    = 1
	keyPackHMACSize   = 32
	keyPackHKDFDomain = "atoll-keypack-v1"
)

// KeyPackInfo 是一次导出的摘要（不含密钥材料）。
type KeyPackInfo struct {
	RecordCount int
	KeyID       string
	CreatedAt   time.Time
	Size        int64
}

type keyPackHeader struct {
	KeyID       string
	CreatedAt   time.Time
	RecordCount int
}

func keyPackHMACKey(kekKeyID string) []byte {
	// 不从 KEK 字节派生（meta 层拿不到也不该拿）：HMAC 密钥 = SHA-256(域 ‖ keyID)。
	// 这不是加密——只防意外篡改/错包；敌手若能改包也能改 keyID，安全边界在
	// "包与 KEK 分开保管、导入端与持有 KEK 的 master 同源"。
	sum := sha256.Sum256([]byte(keyPackHKDFDomain + "\x00" + kekKeyID))
	return sum[:]
}

// ExportKeyPack 把 security bucket 中的全部内容密钥记录导出为恢复包字节流。
// kekKeyID 只进线格式与 HMAC，不进任何密钥材料。
func (s *Store) ExportKeyPack(w io.Writer, kekKeyID string, now time.Time) (KeyPackInfo, error) {
	var out KeyPackInfo
	if kekKeyID == "" || now.IsZero() {
		return out, ErrWritePlanConflict
	}
	var records []ContentKeyRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketSecurity).Cursor()
		prefix := []byte(contentKeyPrefix)
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			id, perr := beU64FromKey(k, prefix)
			if perr != nil {
				return perr
			}
			rec, err := contentKeyTx(tx, id)
			if err != nil {
				return err
			}
			records = append(records, rec)
		}
		return nil
	})
	if err != nil {
		return out, err
	}

	mac := hmac.New(sha256.New, keyPackHMACKey(kekKeyID))
	body := &bytes.Buffer{}
	body.Write(keyPackMagic[:])
	body.WriteByte(keyPackVersion)
	var l [8]byte
	kl := len(kekKeyID)
	binary.BigEndian.PutUint16(l[:2], uint16(kl))
	body.Write(l[:2])
	body.WriteString(kekKeyID)
	binary.BigEndian.PutUint64(l[:], uint64(now.UnixNano()))
	body.Write(l[:])
	binary.BigEndian.PutUint32(l[:4], uint32(len(records)))
	body.Write(l[:4])
	for _, rec := range records {
		writeKeyPackRecord(body, rec)
	}
	mac.Write(body.Bytes())
	if _, err := w.Write(body.Bytes()); err != nil {
		return out, err
	}
	if _, err := w.Write(mac.Sum(nil)); err != nil {
		return out, err
	}
	return KeyPackInfo{RecordCount: len(records), KeyID: kekKeyID, CreatedAt: now, Size: int64(body.Len()) + keyPackHMACSize}, nil
}

func writeKeyPackRecord(buf *bytes.Buffer, rec ContentKeyRecord) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], rec.ObjectID)
	buf.Write(b[:])
	binary.BigEndian.PutUint64(b[:], rec.Generation)
	buf.Write(b[:])
	binary.BigEndian.PutUint64(b[:], rec.SpaceID)
	buf.Write(b[:])
	binary.BigEndian.PutUint16(b[:2], uint16(len(rec.KeyID)))
	buf.Write(b[:2])
	buf.WriteString(rec.KeyID)
	wrapped, _ := base64.RawStdEncoding.DecodeString(rec.WrappedDEK)
	binary.BigEndian.PutUint32(b[:4], uint32(len(wrapped)))
	buf.Write(b[:4])
	buf.Write(wrapped)
}

// ReadKeyPack 解析并严格校验一个恢复包。verifyKeyID 非空时校验 HMAC
// （应传当前 KEK 的 keyID）；空串表示调用方明确选择跳过校验。
func ReadKeyPack(r io.Reader, verifyKeyID string) (keyPackHeader, []ContentKeyRecord, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 1<<30))
	if err != nil {
		return keyPackHeader{}, nil, err
	}
	if len(raw) < 4+1+2+8+4+keyPackHMACSize {
		return keyPackHeader{}, nil, fmt.Errorf("keypack: truncated header")
	}
	if !bytes.Equal(raw[:4], keyPackMagic[:]) {
		return keyPackHeader{}, nil, fmt.Errorf("keypack: bad magic")
	}
	if raw[4] != keyPackVersion {
		return keyPackHeader{}, nil, fmt.Errorf("keypack: unsupported version %d", raw[4])
	}
	if verifyKeyID != "" {
		want := len(raw) - keyPackHMACSize
		mac := hmac.New(sha256.New, keyPackHMACKey(verifyKeyID))
		mac.Write(raw[:want])
		if !hmac.Equal(mac.Sum(nil), raw[want:]) {
			return keyPackHeader{}, nil, fmt.Errorf("keypack: HMAC mismatch (tampered or wrong KEK key id)")
		}
	}
	body := bytes.NewReader(raw[:len(raw)-keyPackHMACSize])
	var skip [4]byte
	if _, err := body.Read(skip[:]); err != nil { // magic
		return keyPackHeader{}, nil, err
	}
	if _, err := body.ReadByte(); err != nil { // version
		return keyPackHeader{}, nil, err
	}
	var kl [2]byte
	if _, err := io.ReadFull(body, kl[:]); err != nil {
		return keyPackHeader{}, nil, err
	}
	keyID := make([]byte, binary.BigEndian.Uint16(kl[:]))
	if _, err := io.ReadFull(body, keyID); err != nil {
		return keyPackHeader{}, nil, err
	}
	var ts, count [8]byte
	if _, err := io.ReadFull(body, ts[:]); err != nil {
		return keyPackHeader{}, nil, err
	}
	if _, err := io.ReadFull(body, count[:4]); err != nil {
		return keyPackHeader{}, nil, err
	}
	header := keyPackHeader{KeyID: string(keyID), CreatedAt: time.Unix(0, int64(binary.BigEndian.Uint64(ts[:]))), RecordCount: int(binary.BigEndian.Uint32(count[:4]))}
	if header.RecordCount > 1<<24 {
		return keyPackHeader{}, nil, fmt.Errorf("keypack: implausible record count")
	}
	records := make([]ContentKeyRecord, 0, header.RecordCount)
	seen := make(map[uint64]bool, header.RecordCount)
	for i := 0; i < header.RecordCount; i++ {
		rec, err := readKeyPackRecord(body)
		if err != nil {
			return keyPackHeader{}, nil, fmt.Errorf("keypack: record %d: %w", i, err)
		}
		if seen[rec.ObjectID] {
			return keyPackHeader{}, nil, fmt.Errorf("keypack: duplicate object %d", rec.ObjectID)
		}
		seen[rec.ObjectID] = true
		if rec.KeyID != header.KeyID {
			return keyPackHeader{}, nil, fmt.Errorf("keypack: record key id differs from pack header")
		}
		// 记录在包内不带 CreatedAt；导入端统一以包头的导出时间填充，
		// 幂等重放因此逐字节稳定（不含浮动的逐记录时间）。
		rec.CreatedAt = header.CreatedAt
		records = append(records, rec)
	}
	if body.Len() != 0 {
		return keyPackHeader{}, nil, fmt.Errorf("keypack: trailing bytes")
	}
	return header, records, nil
}

func readKeyPackRecord(body *bytes.Reader) (ContentKeyRecord, error) {
	var out ContentKeyRecord
	var b [8]byte
	if _, err := io.ReadFull(body, b[:]); err != nil {
		return out, err
	}
	out.ObjectID = binary.BigEndian.Uint64(b[:])
	if _, err := io.ReadFull(body, b[:]); err != nil {
		return out, err
	}
	out.Generation = binary.BigEndian.Uint64(b[:])
	if _, err := io.ReadFull(body, b[:]); err != nil {
		return out, err
	}
	out.SpaceID = binary.BigEndian.Uint64(b[:])
	if _, err := io.ReadFull(body, b[:2]); err != nil {
		return out, err
	}
	kl := binary.BigEndian.Uint16(b[:2])
	keyID := make([]byte, kl)
	if _, err := io.ReadFull(body, keyID); err != nil {
		return out, err
	}
	out.KeyID = string(keyID)
	if _, err := io.ReadFull(body, b[:4]); err != nil {
		return out, err
	}
	wl := binary.BigEndian.Uint32(b[:4])
	if wl > 1<<16 {
		return out, fmt.Errorf("wrapped DEK too large")
	}
	wrapped := make([]byte, wl)
	if _, err := io.ReadFull(body, wrapped); err != nil {
		return out, err
	}
	out.WrappedDEK = base64.RawStdEncoding.EncodeToString(wrapped)
	out.CreatedAt = time.Time{}
	return out, nil
}

// ImportKeyPack 把恢复包记录回放到当前库（灾备重建用）。kekkless：记录回到
// security bucket 后，只要配上原 KEK 文件即可重新发放 DEK。已有同对象记录必须
// 完全一致（幂等重放），不一致拒绝——防跨集群混灌。
// ImportKeyPack 把恢复包记录回放到当前库（灾备重建用）。记录回到 security
// bucket 后，只要配上原 KEK 文件即可重新发放 DEK。已有同对象记录必须完全一致
// （幂等重放），不一致拒绝——防跨集群混灌。createdAt 参数已并入各记录
// （ReadKeyPack 以包头导出时间统一填充），保留参数以兼容显式传入的调用方；
// 与记录内时间不一致时以记录为准。
func (s *Store) ImportKeyPack(records []ContentKeyRecord, createdAt time.Time) (imported, unchanged int, err error) {
	if len(records) == 0 || createdAt.IsZero() {
		return 0, 0, ErrWritePlanConflict
	}
	err = s.write(func(w *txw) error {
		for _, rec := range records {
			if rec.ObjectID == 0 || rec.Generation == 0 || rec.SpaceID == 0 || rec.KeyID == "" || rec.WrappedDEK == "" {
				return ErrWritePlanConflict
			}
			raw, err := json.Marshal(rec)
			if err != nil {
				return err
			}
			if current, err := contentKeyTx(w.tx, rec.ObjectID); err == nil {
				// 幂等重放：逐字节相同（含 CreatedAt，比较走 JSON 规范序列）才接受。
				currentRaw, err := json.Marshal(current)
				if err != nil {
					return err
				}
				if !bytes.Equal(currentRaw, raw) {
					return ErrObjectChanged
				}
				unchanged++
				continue
			} else if !isNotExist(err) {
				return err
			}
			if err := w.put(bcSecurity, bucketSecurity, contentKeyStoreKey(rec.ObjectID), raw); err != nil {
				return err
			}
			imported++
		}
		return nil
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return imported, unchanged, err
}

func beU64FromKey(k []byte, prefix []byte) (uint64, error) {
	digits := k[len(prefix):]
	if len(digits) == 0 || len(digits) > 20 {
		return 0, fmt.Errorf("keypack: malformed content key store key")
	}
	var id uint64
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("keypack: non-numeric content key store key")
		}
		id = id*10 + uint64(c-'0')
	}
	return id, nil
}

func isNotExist(err error) bool {
	return err == ErrNotExist
}
