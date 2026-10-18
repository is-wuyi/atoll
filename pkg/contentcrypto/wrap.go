package contentcrypto

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// WrapDEK 用 KEK 包装（加密）一把对象 DEK，产出可持久保存的包裹。
//
// AAD = ProtocolDomain + "dek-wrap" + wrapFormatVersion + keyID + objectID：
// 包裹与对象身份绑定，不能挪给其他对象；换 KEK（keyID 变化）后旧包裹只能由
// 旧 KEK 解开。keyID 同时进线格式，Unwrap 先比对再解密。
func WrapDEK(kek *KEK, dek *DEK, objectID uint64) ([]byte, error) {
	if kek == nil {
		return nil, errors.New("contentcrypto: kek 为 nil")
	}
	if dek == nil {
		return nil, errors.New("contentcrypto: dek 为 nil")
	}
	if objectID == 0 {
		return nil, errors.New("contentcrypto: objectID 为 0（协议要求非零）")
	}
	// 兜底：KEK 只能经 NewKEK/NewKEKFromSecret 构造（已校验），这里再挡一次，
	// 防包内未来新增构造路径或测试直构 struct 造成“能包装、解不开”的包裹。
	if err := validateKeyID(kek.keyID); err != nil {
		return nil, err
	}
	aead, err := newGCM(&kek.key)
	if err != nil {
		return nil, err
	}
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	wrapped := aead.Seal(nil, nonce, dek[:], wrapAAD(kek.keyID, objectID))

	out := make([]byte, 0, wrapHeaderFixedLen+len(kek.keyID)+len(wrapped))
	out = append(out, wrapMagic[:]...)
	out = append(out, wrapFormatVersion)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(kek.keyID)))
	out = append(out, l[:]...)
	out = append(out, kek.keyID...)
	out = append(out, nonce...)
	out = append(out, wrapped...)
	return out, nil
}

// UnwrapDEK 解开包裹恢复 DEK。
//
// 拒绝条件（全部在返回任何密钥材料之前）：长度/magic/版本/keyID 长度非法、
// 包裹内 keyID 与传入 KEK 不匹配（即便密钥字节相同也拒绝——协议要求 keyID
// 一致）、GCM 校验失败（篡改、错误 KEK、objectID 不匹配）。
func UnwrapDEK(kek *KEK, objectID uint64, wrapped []byte) (*DEK, error) {
	if kek == nil {
		return nil, errors.New("contentcrypto: kek 为 nil")
	}
	if objectID == 0 {
		return nil, errors.New("contentcrypto: objectID 为 0（协议要求非零）")
	}
	if len(wrapped) < minWrapLen {
		return nil, fmt.Errorf("contentcrypto: 包裹长度 %d 低于最小值 %d（截断）", len(wrapped), minWrapLen)
	}
	if !bytes.Equal(wrapped[:4], wrapMagic[:]) {
		return nil, errors.New("contentcrypto: 包裹 magic 不符")
	}
	if v := wrapped[4]; v != wrapFormatVersion {
		return nil, fmt.Errorf("contentcrypto: 包裹格式版本 %d 不支持（本库为 %d）", v, wrapFormatVersion)
	}
	keyIDLen := int(binary.BigEndian.Uint16(wrapped[5:7]))
	// 精确长度检查（进 GCM 之前）：合法包裹的总长恰为
	// wrapHeaderFixedLen + keyIDLen + KeySize + TagSize。任何多余字节（哪怕
	// 1 字节 trailing）都直接拒绝——既防把巨量字节喂给 GCM 的内存/时间放大，
	// 也防 trailing 被并入密文后以“验证失败”之外的方式产生歧义。
	if keyIDLen > maxKeyIDLen {
		return nil, fmt.Errorf("contentcrypto: 包裹 keyID 长度 %d 超过上限 %d", keyIDLen, maxKeyIDLen)
	}
	if want := wrapHeaderFixedLen + keyIDLen + KeySize + TagSize; len(wrapped) != want {
		if len(wrapped) < want {
			return nil, fmt.Errorf("contentcrypto: 包裹长度 %d 低于期望 %d（截断）", len(wrapped), want)
		}
		return nil, fmt.Errorf("contentcrypto: 包裹长度 %d 超过期望 %d（含 trailing bytes）", len(wrapped), want)
	}
	embeddedKeyID := string(wrapped[7 : 7+keyIDLen])
	if subtle.ConstantTimeCompare([]byte(embeddedKeyID), []byte(kek.keyID)) != 1 {
		return nil, fmt.Errorf("contentcrypto: 包裹属于 keyID %q，与当前 KEK（keyID %q）不匹配",
			redactKeyID(embeddedKeyID), redactKeyID(kek.keyID))
	}

	offset := 7 + keyIDLen
	nonce := wrapped[offset : offset+NonceSize]
	ct := wrapped[offset+NonceSize:]

	aead, err := newGCM(&kek.key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ct, wrapAAD(kek.keyID, objectID))
	if err != nil {
		return nil, fmt.Errorf("contentcrypto: DEK 包裹验证失败（错误 KEK/篡改/objectID 不匹配）: %w", err)
	}
	if len(plaintext) != KeySize {
		return nil, fmt.Errorf("contentcrypto: 解出的 DEK 长度 %d 异常", len(plaintext))
	}
	dek := &DEK{}
	copy(dek[:], plaintext)
	return dek, nil
}

// wrapAAD 绑定域、格式版本、keyID 与对象身份。
func wrapAAD(keyID string, objectID uint64) []byte {
	var buf bytes.Buffer
	writeLP(&buf, []byte(ProtocolDomain))
	writeLP(&buf, []byte("dek-wrap"))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], wrapFormatVersion)
	buf.Write(b[:])
	writeLP(&buf, []byte(keyID))
	binary.BigEndian.PutUint64(b[:], objectID)
	buf.Write(b[:])
	return buf.Bytes()
}

// redactKeyID 错误消息里只保留 keyID 前缀，避免把内部标识整串打进日志。
func redactKeyID(keyID string) string {
	if len(keyID) <= 8 {
		return keyID
	}
	return keyID[:8] + "…"
}
