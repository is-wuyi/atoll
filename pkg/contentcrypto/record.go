package contentcrypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// SealRecord 把一段对象明文封成可持久保存的加密记录。
//
// 绑定：AAD = ProtocolDomain + "record" + RecordVersion + objectID +
// generation + index + 明文长度。解密时任何一个绑定值不匹配都会 tag 失败。
// 每次 Seal 独立生成随机 96bit nonce——同一 (DEK, 记录) 重封会产生不同密文，
// 但 nonce 唯一性受调用次数预算约束（见 README），重写同一记录会消耗预算。
// objectID 按协议定义禁止 0；明文超过 MaxRecordPlaintext 拒绝。
func SealRecord(dek *DEK, objectID, generation, index uint64, plaintext []byte) ([]byte, error) {
	if dek == nil {
		return nil, errors.New("contentcrypto: dek 为 nil")
	}
	if objectID == 0 {
		return nil, errors.New("contentcrypto: objectID 为 0（协议要求非零）")
	}
	if len(plaintext) > MaxRecordPlaintext {
		return nil, fmt.Errorf("contentcrypto: 明文 %d 字节超过单记录上限 %d", len(plaintext), MaxRecordPlaintext)
	}
	aead, err := newGCM((*[KeySize]byte)(dek))
	if err != nil {
		return nil, err
	}
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	aad := recordAAD(objectID, generation, index, len(plaintext))
	ct := aead.Seal(nil, nonce, plaintext, aad)

	out := make([]byte, 0, recordHeaderLen+len(ct))
	out = append(out, recordMagic[:]...)
	out = append(out, RecordVersion)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// OpenRecord 严格解析并解密一条记录。
//
// 拒绝条件（全部在返回任何明文之前）：长度越界（含 trailing bytes 超上限）、
// magic/版本不符、GCM tag 校验失败（篡改、绑定参数不匹配、trailing bytes
// 被并入密文）。Open 永不返回未验证明文：验证失败时明文为 nil。
// 明文长度没有独立线格式字段——由密文长度推导并进 AAD，因此尾部追加字节
// 只可能以 tag 失败被拒绝，不可能被静默剥离。
func OpenRecord(dek *DEK, objectID, generation, index uint64, record []byte) ([]byte, error) {
	if dek == nil {
		return nil, errors.New("contentcrypto: dek 为 nil")
	}
	if objectID == 0 {
		return nil, errors.New("contentcrypto: objectID 为 0（协议要求非零）")
	}
	if len(record) < minRecordLen {
		return nil, fmt.Errorf("contentcrypto: 记录长度 %d 低于最小值 %d（截断）", len(record), minRecordLen)
	}
	if len(record) > maxRecordLen {
		return nil, fmt.Errorf("contentcrypto: 记录长度 %d 超过上限 %d（疑似 trailing bytes）", len(record), maxRecordLen)
	}
	if !bytes.Equal(record[:4], recordMagic[:]) {
		return nil, errors.New("contentcrypto: 记录 magic 不符")
	}
	if v := record[4]; v != RecordVersion {
		return nil, fmt.Errorf("contentcrypto: 记录版本 %d 不支持（本库为 %d）", v, RecordVersion)
	}
	nonce := record[5 : 5+NonceSize]
	ct := record[recordHeaderLen:]
	plaintextLen := len(ct) - TagSize

	aead, err := newGCM((*[KeySize]byte)(dek))
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ct, recordAAD(objectID, generation, index, plaintextLen))
	if err != nil {
		return nil, fmt.Errorf("contentcrypto: 记录验证失败（篡改/绑定参数不匹配/trailing bytes）: %w", err)
	}
	return plaintext, nil
}

// recordAAD：字符串字段长度前缀定界，数值字段定宽，保证编码无歧义。
func recordAAD(objectID, generation, index uint64, plaintextLen int) []byte {
	var buf bytes.Buffer
	writeLP(&buf, []byte(ProtocolDomain))
	writeLP(&buf, []byte("record"))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], RecordVersion)
	buf.Write(b[:])
	binary.BigEndian.PutUint64(b[:], objectID)
	buf.Write(b[:])
	binary.BigEndian.PutUint64(b[:], generation)
	buf.Write(b[:])
	binary.BigEndian.PutUint64(b[:], index)
	buf.Write(b[:])
	binary.BigEndian.PutUint64(b[:], uint64(plaintextLen))
	buf.Write(b[:])
	return buf.Bytes()
}

func writeLP(buf *bytes.Buffer, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	buf.Write(l[:])
	buf.Write(b)
}
