// Package contentcrypto 提供版本化的 AES-256-GCM 内容记录加密与 DEK 包装。
//
// 定位边界（不要过度外推）：
//   - 面向后续“对象内随机读取”的记录化加密设计，当前生产上传链路并未接入；
//     返回的记录字节仅用于持久保存与恢复演练。
//   - 每对象一把 32 字节随机 DEK（crypto/rand）；口令/密码绝不能直接当 DEK。
//   - 随机 96bit nonce 每次 Seal 独立生成，nonce 唯一性依赖调用次数上限约束
//     （每 DEK 记录数与重写次数预算见 README，不是无限的）。
//   - 记录格式不含明文长度字段：明文长度由密文长度（含 16B tag）推导并进 AAD，
//     trailing bytes 会因此进入密文导致 tag 校验失败而被拒绝。
//   - KEK 的生成/存储/轮换归调用方（本库不做账号、不做中心配置）；Go 无法承诺
//     内存零化，密钥字节不落盘、不进日志由调用方与本库共同遵守。
package contentcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

const (
	// ProtocolDomain 是内容加密的域分隔串，进所有 AAD，防跨协议/跨用途挪用密文。
	ProtocolDomain = "atoll-content-record-v1"

	// RecordVersion 是记录线格式版本（magic 之后的一个字节，同时进 AAD）。
	RecordVersion = 1

	// wrapFormatVersion 是 DEK 包裹线格式版本（magic 之后的一个字节，同时进 AAD）。
	wrapFormatVersion = 1

	// MaxRecordPlaintext 是单条记录明文上限（64KiB）。上限必须显式存在：
	// 它同时是 nonce/记录数预算与内存放大的界。
	MaxRecordPlaintext = 64 << 10

	// KeySize AES-256 密钥字节数（DEK 与 KEK 相同）。
	KeySize = 32
	// NonceSize GCM 标准随机 nonce 长度（96bit）。
	NonceSize = 12
	// TagSize GCM 认证标签长度。
	TagSize = 16
)

// recordWire 是记录线格式：magic(4) | version(1) | nonce(12) | ciphertext||tag。
// 密文段长度必须恰为 明文长度+TagSize；没有独立长度字段。
const (
	recordHeaderLen = 4 + 1 + NonceSize
	minRecordLen    = recordHeaderLen + TagSize
	maxRecordLen    = recordHeaderLen + MaxRecordPlaintext + TagSize
)

// wrapWire 是包装 DEK 的线格式：
// magic(4) | version(1) | keyIDLen(2,BE) | keyID | nonce(12) | wrapped(48)。
const (
	wrapHeaderFixedLen = 4 + 1 + 2 + NonceSize
	minWrapLen         = wrapHeaderFixedLen + KeySize + TagSize
	maxKeyIDLen        = 255
)

var (
	recordMagic = [4]byte{'A', 'T', 'C', 'R'}
	wrapMagic   = [4]byte{'A', 'T', 'W', 'K'}
)

// DEK 是每对象 32 字节内容加密密钥（data encryption key）。
// 必须由 NewDEK 生成（crypto/rand）；数组值类型避免调用方意外共享底层数组，
// 但 Go 无法阻止值拷贝，也无法承诺旧拷贝内存零化。
//
// 格式化安全：DEK 的 String/GoString/Format 一律只渲染 "DEK(...)" 占位，
// 不会把密钥字节打进 fmt 输出/日志；需要传输 DEK 用显式字节（dek[:]）。
type DEK [KeySize]byte

// String 返回不包含任何密钥材料的占位串。
func (d DEK) String() string { return "DEK(32B)" }

func (d DEK) GoString() string { return "contentcrypto.DEK(32B)" }

func (d DEK) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		fmt.Fprint(f, d.GoString())
		return
	}
	fmt.Fprint(f, d.String())
}

// NewDEK 生成新的随机 DEK。
func NewDEK() (*DEK, error) {
	var d DEK
	if _, err := rand.Read(d[:]); err != nil {
		return nil, fmt.Errorf("contentcrypto: 生成 DEK 失败: %w", err)
	}
	return &d, nil
}

// KEK 是包装 DEK 的主密钥（key encryption key），带稳定 keyID 供轮换与匹配。
// 密钥字节绝不导出；keyID 进 AAD 与线格式，换 KEK 必须换 keyID。
type KEK struct {
	keyID string
	key   [KeySize]byte
}

// NewKEK 生成随机 KEK。keyID 由调用方定义且必须非空（协议要求）。
// keyID 长度不得超 maxKeyIDLen（255）：包裹线格式用 2 字节长度字段虽可表达
// 至 65535，但解包端一律拒绝超 255 的 keyID 长度——两边不一致会造出
// “能包装、永远解不开”的不可恢复包裹，所以在生成端提前拒绝。
func NewKEK(keyID string) (*KEK, error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, err
	}
	k := &KEK{keyID: keyID}
	if _, err := rand.Read(k.key[:]); err != nil {
		return nil, fmt.Errorf("contentcrypto: 生成 KEK 失败: %w", err)
	}
	return k, nil
}

// NewKEKFromSecret 用调用方自持的 32 字节主密钥材料恢复 KEK。
// 用于“包存→恢复→解包”流程：主密钥如何存储、备份、轮换完全归调用方，
// 本库不实现账号体系或中心配置。keyID 约束与 NewKEK 相同（非空、≤255 字节）。
func NewKEKFromSecret(keyID string, secret []byte) (*KEK, error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, err
	}
	if len(secret) != KeySize {
		return nil, fmt.Errorf("contentcrypto: KEK 密钥材料必须为 %d 字节，得到 %d", KeySize, len(secret))
	}
	k := &KEK{keyID: keyID}
	copy(k.key[:], secret)
	return k, nil
}

// validateKeyID 是所有 KEK 构造入口共用的 keyID 校验：非空且 ≤ maxKeyIDLen。
// 在构造端拒绝超长 keyID，防止造出“能包装、解包端必拒”的不可恢复包裹。
func validateKeyID(keyID string) error {
	if keyID == "" {
		return errors.New("contentcrypto: keyID 不能为空")
	}
	if len(keyID) > maxKeyIDLen {
		return fmt.Errorf("contentcrypto: keyID 长度 %d 超过上限 %d", len(keyID), maxKeyIDLen)
	}
	return nil
}

// KeyID 返回 KEK 标识（不含任何密钥材料）。
func (k *KEK) KeyID() string {
	if k == nil {
		return ""
	}
	return k.keyID
}

// String 返回“keyID + 32B”占位描述，绝不渲染密钥字节。
func (k KEK) String() string { return "KEK(" + k.keyID + ",32B)" }

func (k KEK) GoString() string { return "contentcrypto.KEK(" + k.keyID + ",32B)" }

func (k KEK) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		fmt.Fprint(f, k.GoString())
		return
	}
	fmt.Fprint(f, k.String())
}

func newGCM(key *[KeySize]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block) // 标准随机 96bit nonce
}

func randomNonce() ([]byte, error) {
	n := make([]byte, NonceSize)
	if _, err := rand.Read(n); err != nil {
		return nil, fmt.Errorf("contentcrypto: 生成 nonce 失败: %w", err)
	}
	return n, nil
}
