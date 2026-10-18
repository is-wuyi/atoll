package edgeidentity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"time"
)

// sha256Sum 供 DeriveNodeID 使用（独立小包装，避免在多处散落 hash 调用）。
func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// Challenge 是一次待签名的挑战：所有字段由 caller 明确定义并通过传输层原样
// 送达验证方。本库不构造、不解析任何“通用 token”。
//
// 防重放边界：验证签名不等于防重放——同一 (Challenge, 签名) 可被验证任意多次。
// 一次性性由上层对 Nonce 做登记（已见即拒）实现，本库不做该登记。
type Challenge struct {
	// Nonce 是 caller 生成的挑战随机串（建议 ≥16 字节），必填，进签名。
	Nonce []byte
	// Audience 是证明的目标受众（如对端节点 ID、服务名），必填，防证明挪用。
	Audience string
	// ExpiresAt 是过期时刻，必填（零值在 Sign 即拒绝，防止签出永久有效证明）。
	ExpiresAt time.Time
	// NotBefore 可选生效时刻；零值表示立即生效。
	NotBefore time.Time
	// Purpose 可选用途上下文（如 "replica-lease"），进签名域分隔。
	Purpose string
	// Extras 可选附加绑定；键序规范化后进签名。
	Extras map[string]string
}

func validateChallenge(c Challenge) error {
	if len(c.Nonce) == 0 {
		return errors.New("edgeidentity: Challenge.Nonce 为空，拒绝签名空挑战")
	}
	if c.Audience == "" {
		return errors.New("edgeidentity: Challenge.Audience 为空，拒绝无受众证明")
	}
	if c.ExpiresAt.IsZero() {
		return errors.New("edgeidentity: Challenge.ExpiresAt 为零值，拒绝签出永久有效证明")
	}
	// UnixNano is undefined outside its representable range. Reject aliases
	// before signing or comparing expiry so a wrapped timestamp cannot extend a proof.
	for _, at := range []time.Time{c.ExpiresAt, c.NotBefore} {
		if !at.IsZero() && !time.Unix(0, at.UnixNano()).Equal(at) {
			return errors.New("edgeidentity: challenge time outside the supported range")
		}
	}
	if !c.NotBefore.IsZero() && !c.NotBefore.Before(c.ExpiresAt) {
		return errors.New("edgeidentity: challenge time window is empty")
	}
	return nil
}

// Sign 返回对 Challenge 规范编码的 detached Ed25519 签名。编码绑定
// IdentityProtocolVersion、签名者 NodeID 与全部字段。
func (id *Identity) Sign(c Challenge) ([]byte, error) {
	if id == nil || len(id.priv) != ed25519.PrivateKeySize {
		return nil, errors.New("edgeidentity: identity is not initialized")
	}
	if err := validateChallenge(c); err != nil {
		return nil, err
	}
	return ed25519.Sign(id.priv, encodeSignedChallenge(id.nodeID, c)), nil
}

// Verify 用当前时间、零时钟偏移校验。绝大多数调用应直接用它；
// 需要确定性测试或明确放宽时钟偏移时用 VerifyAt。
func Verify(pub ed25519.PublicKey, c Challenge, sig []byte) error {
	return VerifyAt(pub, c, sig, time.Now(), 0)
}

// VerifyAt 用显式 now 与显式 skew 校验签名与时间窗。
// skew 是 caller 显式选择的时钟容差：0 表示严格（不放宽有效期任何一边）；
// 传入正值等于接受过期后 skew 内 / 生效前 skew 内的证明，由 caller 自己负责。
func VerifyAt(pub ed25519.PublicKey, c Challenge, sig []byte, now time.Time, skew time.Duration) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("edgeidentity: 公钥长度 %d 不符（期望 %d）", len(pub), ed25519.PublicKeySize)
	}
	if skew < 0 {
		return errors.New("edgeidentity: skew 不能为负")
	}
	if err := validateChallenge(c); err != nil {
		return err
	}
	if !c.NotBefore.IsZero() && now.Add(skew).Before(c.NotBefore) {
		return fmt.Errorf("edgeidentity: 挑战尚未生效（notBefore=%s, now=%s）",
			c.NotBefore.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano))
	}
	if now.After(c.ExpiresAt.Add(skew)) {
		return fmt.Errorf("edgeidentity: 挑战已过期（expiresAt=%s, now=%s）",
			c.ExpiresAt.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano))
	}
	if !ed25519.Verify(pub, encodeSignedChallenge(DeriveNodeID(pub), c), sig) {
		return errors.New("edgeidentity: 签名验证失败")
	}
	return nil
}

// encodeSignedChallenge 产出确定性签名输入：全部字段长度前缀定界（防拼接歧义），
// extras 键排序（防 map 遍历顺序不确定性导致签名不一致）。
func encodeSignedChallenge(nodeID NodeID, c Challenge) []byte {
	var buf bytes.Buffer
	writeLP := func(b []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		buf.Write(l[:])
		buf.Write(b)
	}
	writeStr := func(s string) { writeLP([]byte(s)) }

	writeStr(IdentityProtocolVersion)
	writeStr(string(nodeID))
	writeStr(c.Purpose)
	writeStr(c.Audience)
	writeLP(c.Nonce)

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(c.NotBefore.UnixNano()))
	buf.Write(ts[:])
	binary.BigEndian.PutUint64(ts[:], uint64(c.ExpiresAt.UnixNano()))
	buf.Write(ts[:])

	keys := make([]string, 0, len(c.Extras))
	for k := range c.Extras {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var cnt [4]byte
	binary.BigEndian.PutUint32(cnt[:], uint32(len(keys)))
	buf.Write(cnt[:])
	for _, k := range keys {
		writeStr(k)
		writeStr(c.Extras[k])
	}
	return buf.Bytes()
}
