package meta

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/edgeidentity"
	"atoll/pkg/types"

	bolt "go.etcd.io/bbolt"
)

var ErrDeviceAuth = errors.New("device authentication failed")

// ErrDeviceChallengeLimit 表示未过期挑战已达有界配额（或扫描触顶）。与 ErrDeviceAuth
// 区分以便日志可读；对外仍 fail-closed 拒绝签发。
var ErrDeviceChallengeLimit = errors.New("device challenge capacity reached")

// 有界未过期挑战上限：公开的 challenge 端点只需一个已知公钥即可匿名写库，
// 过期记录虽由 SweepSecurityState 每分钟回收，但在清扫窗口内仍需限制增长。
// 这两个常量只是"有界量"而非完备抗 DoS（攻击者可轮换公钥耗尽 global 配额，
// 届时新设备登录会短暂被拒，属可接受的可用性权衡，非授权绕过）。
const (
	maxOutstandingChallengesPerIdentity = 8
	maxOutstandingChallengesGlobal      = 512
	// securityChallengeScanLimit 限制单次 issue 扫描的 device-challenge key 数，
	// 避免在异常多的记录上做无界单事务扫描；超限即 fail-closed（拒绝新挑战）。
	securityChallengeScanLimit = 4096
)

type DeviceRecord struct {
	Identity       string `json:"identity"`
	PublicKey      []byte `json:"public_key"`
	NodeID         uint64 `json:"node_id"`
	Addr           string `json:"addr"`
	Revoked        bool   `json:"revoked"`
	SessionVersion uint64 `json:"session_version"`
}

type deviceInviteRecord struct {
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

type deviceChallengeRecord struct {
	Request    access.DeviceChallengeRequest `json:"request"`
	Challenge  edgeidentity.Challenge        `json:"challenge"`
	InviteHash string                        `json:"invite_hash"`
	Used       bool                          `json:"used"`
}

type deviceSessionRecord struct {
	Identity  string    `json:"identity"`
	Version   uint64    `json:"version"`
	ExpiresAt time.Time `json:"expires_at"`
}

func fmtUint(value uint64) string { return strconv.FormatUint(value, 10) }

func secOpaque(prefix string) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
func secHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func securityDataKey(kind, id string) []byte { return []byte(kind + "/" + id) }
func readSecurityData(tx *bolt.Tx, kind, id string, out any) error {
	raw := tx.Bucket(bucketSecurity).Get(securityDataKey(kind, id))
	if raw == nil {
		return ErrNotExist
	}
	return json.Unmarshal(raw, out)
}
func putSecurityData(w *txw, kind, id string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return w.put(bcSecurity, bucketSecurity, securityDataKey(kind, id), raw)
}

func (s *Store) CreateDeviceInvite(expiresAt, now time.Time) (string, error) {
	if !expiresAt.After(now) || expiresAt.After(now.Add(7*24*time.Hour)) {
		return "", errors.New("device invite lifetime must be within seven days")
	}
	token, err := secOpaque("di1_")
	if err != nil {
		return "", err
	}
	err = s.write(func(w *txw) error {
		return putSecurityData(w, "device-invite", secHash(token), deviceInviteRecord{ExpiresAt: expiresAt})
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return token, err
}

func validDeviceEndpoint(addr string) bool {
	if len(addr) > 253 || strings.ContainsAny(addr, "/\\?#@\x00") {
		return false
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	p, err := strconv.ParseUint(port, 10, 16)
	return err == nil && p > 0
}

// deviceChallengeUsageTx 在事务内按 device-challenge/ 前缀做一次有界扫描，统计
// 未过期（!Used 且 now < ExpiresAt）的挑战：返回全局计数、给定公钥的计数，以及
// 可复用的未过期挑战（同一公钥 + addr + total_bytes + inviteHash 且未使用，用于
// 同一请求复用、减少新记录）。只扫描 device-challenge/ 前缀，绝不扫描用户会话/票据等
// 其它前缀。扫描超过 securityChallengeScanLimit 即 fail-closed 报错（异常多记录下
// 不做无界单事务扫描）。
// inviteHash 必须进复用判据：完成登录时烧掉的是记录里的 InviteHash 对应邀请，
// 若跨邀请复用，换邀请的请求会拿到绑定别人邀请的挑战——一次登录烧不掉任何邀请，
// 邀请的"一次性"语义被旁路。
func deviceChallengeUsageTx(tx *bolt.Tx, pub ed25519.PublicKey, addr string, total int64, inviteHash string, now time.Time) (global, perIdentity int, reuse *deviceChallengeRecord, err error) {
	b := tx.Bucket(bucketSecurity)
	if b == nil {
		return 0, 0, nil, nil
	}
	c := b.Cursor()
	prefix := []byte("device-challenge/")
	examined := 0
	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		if examined >= securityChallengeScanLimit {
			return 0, 0, nil, ErrDeviceChallengeLimit
		}
		examined++
		var ch deviceChallengeRecord
		if json.Unmarshal(v, &ch) != nil {
			continue // 损坏记录不计入、不可复用（清扫保留并报告）
		}
		if ch.Used || !now.Before(ch.Challenge.ExpiresAt) {
			continue
		}
		global++
		if ed25519.PublicKey(ch.Request.PublicKey).Equal(pub) {
			perIdentity++
			// 同 request 复用：同一 endpoint + 同容量 + 同一邀请。签名域绑定 addr，
			// 复用不会让任何签名把设备切到别的 endpoint；邀请哈希相同则完成登录时
			// 烧掉的正是该请求所凭的那张邀请，语义不脱钩。
			if reuse == nil && ch.Request.Addr == addr && ch.Request.TotalBytes == total && ch.InviteHash == inviteHash {
				cp := ch
				reuse = &cp
			}
		}
	}
	return global, perIdentity, reuse, nil
}

func (s *Store) NewDeviceChallenge(req access.DeviceChallengeRequest, now time.Time) (access.DeviceChallenge, error) {
	var out access.DeviceChallenge
	if len(req.PublicKey) != ed25519.PublicKeySize || !validDeviceEndpoint(req.Addr) || req.TotalBytes <= 0 {
		return out, ErrDeviceAuth
	}
	id, err := secOpaque("dc1_")
	if err != nil {
		return out, err
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return out, err
	}
	identity := string(edgeidentity.DeriveNodeID(ed25519.PublicKey(req.PublicKey)))
	out = access.DeviceChallenge{ID: id, Challenge: edgeidentity.Challenge{Audience: "atoll-master-device-v1", Purpose: "node-session", Nonce: nonce,
		NotBefore: now, ExpiresAt: now.Add(2 * time.Minute), Extras: map[string]string{"challenge_id": id, "node_id": identity, "addr": req.Addr, "total_bytes": strconv.FormatInt(req.TotalBytes, 10)}}}
	inviteHash := secHash(req.Invite)
	req.Invite = ""
	err = s.write(func(w *txw) error {
		var existing DeviceRecord
		err := readSecurityData(w.tx, "device", identity, &existing)
		if err == nil {
			if existing.Revoked || !ed25519.PublicKey(existing.PublicKey).Equal(ed25519.PublicKey(req.PublicKey)) {
				return ErrDeviceAuth
			}
		} else if errors.Is(err, ErrNotExist) {
			var invite deviceInviteRecord
			if err := readSecurityData(w.tx, "device-invite", inviteHash, &invite); err != nil || invite.Used || !now.Before(invite.ExpiresAt) {
				return ErrDeviceAuth
			}
		} else {
			return err
		}
		global, perIdentity, reuse, err := deviceChallengeUsageTx(w.tx, ed25519.PublicKey(req.PublicKey), req.Addr, req.TotalBytes, inviteHash, now)
		if err != nil {
			return err
		}
		if reuse != nil {
			// 同一未过期请求：复用既有挑战，不新增记录（签名域绑定 addr，无 endpoint 切换风险）。
			out = access.DeviceChallenge{ID: reuse.Challenge.Extras["challenge_id"], Challenge: reuse.Challenge}
			return nil
		}
		if global >= maxOutstandingChallengesGlobal || perIdentity >= maxOutstandingChallengesPerIdentity {
			return ErrDeviceChallengeLimit
		}
		return putSecurityData(w, "device-challenge", secHash(id), deviceChallengeRecord{Request: req, Challenge: out.Challenge, InviteHash: inviteHash})
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return out, err
}

func (s *Store) CompleteDeviceChallenge(req access.DeviceLoginRequest, now time.Time) (access.DeviceSession, error) {
	var out access.DeviceSession
	if req.ChallengeID == "" || len(req.Signature) != ed25519.SignatureSize {
		return out, ErrDeviceAuth
	}
	token, err := secOpaque("nd1_")
	if err != nil {
		return out, err
	}
	err = s.write(func(w *txw) error {
		var ch deviceChallengeRecord
		if err := readSecurityData(w.tx, "device-challenge", secHash(req.ChallengeID), &ch); err != nil || ch.Used {
			return ErrDeviceAuth
		}
		if err := edgeidentity.VerifyAt(ed25519.PublicKey(ch.Request.PublicKey), ch.Challenge, req.Signature, now, 0); err != nil {
			return ErrDeviceAuth
		}
		identity := string(edgeidentity.DeriveNodeID(ed25519.PublicKey(ch.Request.PublicKey)))
		var device DeviceRecord
		err := readSecurityData(w.tx, "device", identity, &device)
		if err == nil {
			if device.Revoked {
				return ErrDeviceAuth
			}
		} else if errors.Is(err, ErrNotExist) {
			var invite deviceInviteRecord
			if err := readSecurityData(w.tx, "device-invite", ch.InviteHash, &invite); err != nil || invite.Used || !now.Before(invite.ExpiresAt) {
				return ErrDeviceAuth
			}
			invite.Used = true
			if err := putSecurityData(w, "device-invite", ch.InviteHash, invite); err != nil {
				return err
			}
			id, err := w.nextID(keyNextNode)
			if err != nil {
				return err
			}
			device = DeviceRecord{Identity: identity, PublicKey: append([]byte(nil), ch.Request.PublicKey...), NodeID: id}
		} else {
			return err
		}
		if err := w.tx.Bucket(bucketNodes).ForEach(func(_, raw []byte) error {
			var n types.NodeInfo
			if err := json.Unmarshal(raw, &n); err != nil {
				return err
			}
			if n.Addr == ch.Request.Addr && n.ID != device.NodeID {
				return ErrDeviceAuth
			}
			return nil
		}); err != nil {
			return err
		}
		device.Addr = ch.Request.Addr
		if device.SessionVersion == ^uint64(0) {
			return ErrDeviceAuth
		}
		device.SessionVersion++
		if err := putSecurityData(w, "device", identity, device); err != nil {
			return err
		}
		if err := putSecurityData(w, "device-node", strconv.FormatUint(device.NodeID, 10), identity); err != nil {
			return err
		}
		node := types.NodeInfo{ID: device.NodeID, Addr: device.Addr, TotalBytes: ch.Request.TotalBytes, LastHeartbeat: now}
		if old := w.tx.Bucket(bucketNodes).Get(u64be(device.NodeID)); old != nil {
			var prev types.NodeInfo
			if err := json.Unmarshal(old, &prev); err != nil {
				return err
			}
			node.UsedBytes = prev.UsedBytes
			node.Usage = prev.Usage
			node.UsageFloorBytes = prev.UsageFloorBytes
		}
		raw, err := json.Marshal(node)
		if err != nil {
			return err
		}
		if err := w.putNode(raw, node.ID); err != nil {
			return err
		}
		out = access.DeviceSession{NodeID: device.NodeID, Token: token, ExpiresAt: now.Add(30 * time.Minute)}
		if err := putSecurityData(w, "device-session", secHash(token), deviceSessionRecord{Identity: identity, Version: device.SessionVersion, ExpiresAt: out.ExpiresAt}); err != nil {
			return err
		}
		ch.Used = true
		return putSecurityData(w, "device-challenge", secHash(req.ChallengeID), ch)
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return out, err
}

func deviceForSessionTx(tx *bolt.Tx, token string, now time.Time) (DeviceRecord, error) {
	var session deviceSessionRecord
	var device DeviceRecord
	if !strings.HasPrefix(token, "nd1_") || readSecurityData(tx, "device-session", secHash(token), &session) != nil || !now.Before(session.ExpiresAt) {
		return device, ErrDeviceAuth
	}
	if err := readSecurityData(tx, "device", session.Identity, &device); err != nil || device.Revoked || session.Version != device.SessionVersion {
		return DeviceRecord{}, ErrDeviceAuth
	}
	return device, nil
}
func deviceByNodeTx(tx *bolt.Tx, nodeID uint64) (DeviceRecord, error) {
	var identity string
	var device DeviceRecord
	if err := readSecurityData(tx, "device-node", strconv.FormatUint(nodeID, 10), &identity); err != nil {
		return device, ErrDeviceAuth
	}
	if err := readSecurityData(tx, "device", identity, &device); err != nil || device.Revoked {
		return DeviceRecord{}, ErrDeviceAuth
	}
	return device, nil
}
func (s *Store) DeviceForSession(token string, now time.Time) (DeviceRecord, error) {
	var device DeviceRecord
	err := s.db.View(func(tx *bolt.Tx) error { var err error; device, err = deviceForSessionTx(tx, token, now); return err })
	return device, err
}
func (s *Store) DeviceByNode(nodeID uint64) (DeviceRecord, error) {
	var d DeviceRecord
	err := s.db.View(func(tx *bolt.Tx) error { var err error; d, err = deviceByNodeTx(tx, nodeID); return err })
	return d, err
}
func (s *Store) RevokeDevice(nodeID uint64) error {
	err := s.write(func(w *txw) error {
		var identity string
		var d DeviceRecord
		if err := readSecurityData(w.tx, "device-node", fmtUint(nodeID), &identity); err != nil {
			return ErrDeviceAuth
		}
		if err := readSecurityData(w.tx, "device", identity, &d); err != nil || d.NodeID != nodeID || d.Identity != identity {
			return ErrDeviceAuth
		}
		if d.Revoked {
			return nil
		}
		d.Revoked = true
		if err := putSecurityData(w, "device", d.Identity, d); err != nil {
			return err
		}
		stored := w.tx.Bucket(bucketNodes).Get(u64be(nodeID))
		if stored == nil {
			return nil
		}
		var node types.NodeInfo
		if err := json.Unmarshal(stored, &node); err != nil {
			return err
		}
		node.LastHeartbeat = time.Time{}
		raw, err := json.Marshal(node)
		if err != nil {
			return err
		}
		return w.putNode(raw, nodeID)
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return err
}
func (s *Store) ListDevices() ([]DeviceRecord, error) {
	var out []DeviceRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketSecurity).Cursor()
		prefix := []byte("device/")
		for k, v := c.Seek(prefix); k != nil && strings.HasPrefix(string(k), string(prefix)); k, v = c.Next() {
			var d DeviceRecord
			if err := json.Unmarshal(v, &d); err != nil {
				return err
			}
			out = append(out, d)
		}
		return nil
	})
	return out, err
}

func (d DeviceRecord) String() string {
	return fmt.Sprintf("device %s (node %d)", d.Identity, d.NodeID)
}
