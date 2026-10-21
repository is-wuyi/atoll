package metacrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const ReaderHeader = "X-Atoll-Metadata-Reader"
const ReaderTTL = 2 * time.Minute
// ReaderClockSkew 是验签端允许的时钟偏移：签名方与验证方各自加 TTL/4 前后
// 容差（合计 TTL/2 余量），吸收分布式 NAS 的常态漂移； proofs 本身仍只活 TTL。
const ReaderClockSkew = ReaderTTL / 4

// ReaderInfo contains only the verification key, never the recovery signing key or KEK.
type ReaderInfo struct {
	Version int `json:"version"`
	Namespace string `json:"namespace"`
	PublicKey []byte `json:"public_key"`
}

func (c *Cipher) ReaderInfo() ReaderInfo {
	return ReaderInfo{Version: Version, Namespace: c.Namespace(), PublicKey: c.PublicKey()}
}

func (r ReaderInfo) Validate() error {
	if r.Version != Version || len(r.PublicKey) != ed25519.PublicKeySize {
		return errors.New("invalid metadata recovery reader")
	}
	digest := sha256.Sum256(r.PublicKey)
	if r.Namespace != hex.EncodeToString(digest[:]) {
		return errors.New("metadata recovery namespace does not match its public key")
	}
	return nil
}

type readProof struct {
	Version int `json:"version"`
	Namespace string `json:"namespace"`
	Audience string `json:"audience"`
	Expires int64 `json:"expires"`
	Nonce []byte `json:"nonce"`
	Signature []byte `json:"signature"`
}

func (c *Cipher) SignRead(req *http.Request, audience string, now time.Time) error {
	if c == nil || audience == "" || len(audience) > 255 || !metadataRead(req) {
		return errors.New("invalid metadata recovery read")
	}
	host := readerHost(req)
	if host == "" {
		return errors.New("metadata recovery read has no host")
	}
	proof := readProof{Version: Version, Namespace: c.Namespace(), Audience: audience, Expires: now.Add(ReaderTTL).Unix(), Nonce: make([]byte, 16)}
	if _, err := rand.Read(proof.Nonce); err != nil {
		return err
	}
	proof.Signature = ed25519.Sign(c.reader, readAAD(host, req, proof))
	raw, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	// 只允许恢复凭据头：Authorization 等其它凭据绝不随恢复请求外发。
	req.Header.Del("Authorization")
	req.Header.Set(ReaderHeader, base64.RawURLEncoding.EncodeToString(raw))
	return nil
}

func VerifyRead(info ReaderInfo, req *http.Request, audience string, now time.Time) error {
	if err := info.Validate(); err != nil {
		return err
	}
	if audience == "" || len(audience) > 255 {
		return errors.New("invalid metadata recovery audience")
	}
	values := req.Header.Values(ReaderHeader)
	if len(values) != 1 || len(values[0]) > 2048 || !metadataRead(req) {
		return errors.New("invalid metadata recovery read")
	}
	// 恢复读取只携带恢复凭据：混入 Authorization（票据/控制凭据）一律拒绝，
	// 防止签名后被注入其它凭据头或借恢复通道携带集群凭据。
	if len(req.Header.Values("Authorization")) != 0 {
		return errors.New("metadata recovery read must not carry other credentials")
	}
	host := readerHost(req)
	if host == "" {
		return errors.New("metadata recovery read has no host")
	}
	raw, err := base64.RawURLEncoding.DecodeString(values[0])
	if err != nil {
		return errors.New("invalid metadata recovery proof")
	}
	var proof readProof
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&proof) != nil || proof.Version != Version || proof.Namespace != info.Namespace || proof.Audience != audience || len(proof.Nonce) != 16 || len(proof.Signature) != ed25519.SignatureSize {
		return errors.New("invalid metadata recovery proof")
	}
	if proof.Expires <= now.Unix()-int64(ReaderClockSkew/time.Second) || proof.Expires > now.Add(ReaderTTL).Unix()+int64(ReaderClockSkew/time.Second) {
		return errors.New("metadata recovery proof expired or exceeds its lifetime")
	}
	if !ed25519.Verify(info.PublicKey, readAAD(host, req, proof), proof.Signature) {
		return errors.New("metadata recovery proof signature mismatch")
	}
	return nil
}

// readerHost 返回请求的目标主机（Host 头优先，URL host 兜底）。签名绑定它，
// 防止为节点 A 签的证明被拿到节点 B 重放。
func readerHost(req *http.Request) string {
	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(host, "."), ""))
}

func metadataRead(req *http.Request) bool {
	if req == nil || req.URL == nil || req.Method != http.MethodGet || req.URL.RawQuery != "" || req.URL.RawPath != "" || req.URL.ForceQuery {
		return false
	}
	if req.URL.Path == "/meta-backup" {
		return true
	}
	key, ok := strings.CutPrefix(req.URL.Path, "/meta-backup/")
	if !ok || len(key) == 0 || len(key) > MaxKeyLen || key == "." || key == ".." {
		return false
	}
	for _, ch := range key {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.') {
			return false
		}
	}
	return true
}

func readAAD(host string, req *http.Request, proof readProof) []byte {
	out := []byte("atoll-metadata-reader-v1\x00")
	for _, field := range []string{proof.Namespace, proof.Audience, host, req.Method, req.URL.Path, req.URL.RawQuery} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(field)))
		out = append(out, field...)
	}
	out = binary.BigEndian.AppendUint64(out, uint64(proof.Expires))
	return append(out, proof.Nonce...)
}

// IsZero 报告是否未设置（节点侧区分"未安装"与"已安装"）。
func (r ReaderInfo) IsZero() bool { return r.PublicKey == nil }
