// node/security.go 实现节点独立身份与在线访问票据（security 模式）。
//
// 与 legacy 集群单密钥（pkg/auth）的关系：EnableSecurity 未调用 → 一切保持
// legacy 行为（auth.Wrap / cluster token）。EnableSecurity 调用后（必须在
// Register/Handler 之前）：
//
//   - 节点以持久 Ed25519 身份（pkg/edgeidentity，LoadOrCreate）向 master 做
//     设备挑战注册（POST /security/devices/challenge + /security/devices/session），
//     换取仅存内存的设备会话 token；过期或 401 时用同一身份静默续期（无 invite）。
//     每次续期 master 递增会话版本并作废旧 token，因此 token 读取一律走互斥快照。
//   - 对 master 的出站请求只在精确的 master origin 上注入设备 Bearer（deviceTransport）；
//     其它 origin 一律拒绝发送，重定向不跟随。
//   - 对 peer 节点的出站数据面请求（仅 GET /objects/{id}、PUT /replicate/{id}）
//     先向 master /security/tickets 换取短时票据（绑定 method/path/query/plan/
//     bodyhash），原请求只携带该票据，不携带设备身份；对象 payload 永远不发给 master。
//   - 入站路由默认全拒（/healthz 除外）：解析票据 Bearer 后在线 POST
//     /security/check 裁决，不缓存——撤销/成员剔除对下一个请求立即生效。
//   - master 不可达一律 fail-closed（503/请求失败），绝不降级放行。
package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/auth"
	"atoll/pkg/edgeidentity"
	"atoll/pkg/metacrypto"
	"atoll/pkg/peerhttp"
	"atoll/pkg/types"
)

// 设备挑战签名绑定约定（与 master security_devices 侧一致）：
//   - Audience = deviceChallengeAudience，Purpose = deviceChallengePurpose
//   - Extras 恰好四键：challenge_id / node_id / addr / total_bytes
//     （invite 只在 master 侧持久绑定 Consume，不进 Extras，不回显明文）
const (
	deviceChallengeAudience = "atoll-master-device-v1"
	deviceChallengePurpose  = "node-session"

	// maxControlBody 控制面请求体上限：/pull 的 JSON 控制体（入站缓冲 + 出站
	// GetBody 哈希）。对象 payload 永远不走该路径（其 GetBody 为 nil 直接跳过）。
	maxControlBody = 64 << 10
	// maxControlResponse 控制面响应读取上限（challenge/session/ticket/check）。
	maxControlResponse = 1 << 20
	// controlTimeout 控制面请求（challenge/session/ticket/check）的整体上界。
	controlTimeout = 30 * time.Second
	// maxChallengeWindow master 签发的挑战有效期上界（签发时 now+2m，节点侧
	// 拒绝 >now+3m 的窗口，防签出长命挑战）。
	maxChallengeWindow = 3 * time.Minute
	// notBeforeSkew 挑战 NotBefore 允许的未来偏移（传输延迟余量）。
	notBeforeSkew = 30 * time.Second
	// minChallengeNonce 挑战 Nonce 最小字节数（master 用 32 字节随机）。
	minChallengeNonce = 16
	// sessionRenewMargin 会话到期前提前续期的余量（30min 会话 → 约 25min 续）。
	sessionRenewMargin = 5 * time.Minute
	// renewCheckInterval 续期巡检间隔。
	renewCheckInterval = 30 * time.Second
)

// errControlBodyTooLarge 表示控制面请求体超过 maxControlBody（fail-closed 拒绝）。
var errControlBodyTooLarge = errors.New("control body exceeds limit")

// errCheckDenied 表示 master 在线裁决明确拒绝（check 401/403：本节点会话失效或
// 票据无效/绑定不符）——入站映射本地 401；与「master 不可达 → 503」相区分。
var errCheckDenied = errors.New("security check denied")

// securityMarkerName 是 EnableSecurity 成功后写入 dataDir 的持久标记（0600，
// 内容只含版本/身份/主控地址，无任何机密）。防「重启忘带 --secure 静默退回
// legacy 模式暴露既有数据」：Handler 在 security 未启用但标记存在（或无法
// 读取）时 fail-closed（/healthz 豁免）。默认关闭且无标记 → 旧行为不变。
const securityMarkerName = ".security-enabled-v1"

// nodeSecurity 承载 security 模式状态。token 只存内存，绝不写日志。
type nodeSecurity struct {
	node     *Node
	identity *edgeidentity.Identity

	masterScheme string
	masterHost   string

	// base 是与 master 控制面共享的原始 TLS transport（可被 SetTLS 配置）。
	base       http.RoundTripper
	authClient *http.Client // 设备挑战/会话：公开端点，无 Bearer，不重定向

	mu       sync.Mutex // 保护以下会话字段（快照读，避免续期竞态反复作废）
	token    string     // 设备会话 token；空 = 尚未建立
	expires  time.Time
	hasSess  bool
	invite   string // 首次注册用；首次成功后清空，续期/重注册不再携带
	renewing atomic.Bool

	opMu          sync.Mutex    // 串行化 challenge→sign→session 全流程
	renewMargin   time.Duration // 测试可调小
	allowInsecure bool          // 显式放行明文 HTTP / TLS 跳过校验（仅本地测试）
	// readerPin：中心在线时经控制票据安装的元数据恢复公钥（nil = 未安装）。
	// 持私钥的恢复方在 master 全损后凭 Ed25519 签名读取 /meta-backup GET；
	// 节点只存公钥，写删不受它影响。
	readerPin metacrypto.ReaderInfo
}

// EnableSecurity 启用节点独立身份 + 在线访问票据模式。
//
// 必须在 Register()/Handler() 之前调用（重复调用或已注册后调用报错）。
// identityPath 为持久 Ed25519 身份文件（pkg/edgeidentity.LoadOrCreate：损坏绝不
// 重生成，宁可拒绝启动）。invite 为首次注册的邀请码，仅在第一次成功会话前使用，
// 续期与重注册一律不带。allowInsecure 仅用于本地测试放行明文 HTTP；生产必须
// HTTPS（TLS 具体配置由 caller 经 SetTLS 管理，本方法不设置也不跳过证书校验）。
func (n *Node) EnableSecurity(identityPath, invite string, allowInsecure bool) error {
	if n.sec != nil {
		return errors.New("node security already enabled")
	}
	if n.nodeID.Load() != 0 {
		return errors.New("node security must be enabled before Register")
	}
	u, err := url.Parse(n.masterURL)
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("node security: master URL %q must be scheme://host[:port] without path/query/userinfo", n.masterURL)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("node security: unsupported master URL scheme %q", u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("node security: master URL must not carry credentials")
	}
	if u.Scheme != "https" && !allowInsecure {
		return fmt.Errorf("node security: master %q is plain HTTP; allowInsecure is for local tests only", n.masterURL)
	}
	if cfg := currentTLSConfig(n); cfg != nil && cfg.InsecureSkipVerify && !allowInsecure {
		return fmt.Errorf("node security: TLS skip-verify requires allowInsecure")
	}
	id, err := edgeidentity.LoadOrCreate(identityPath)
	if err != nil {
		return fmt.Errorf("node security: load identity: %w", err)
	}
	// 全部校验通过后先落持久标记（0600，无机密），再装配传输：此后即使进程
	// 重启未带 --secure，Handler 也会因标记存在而 fail-closed，绝不退回 legacy。
	if err := writeSecurityMarker(n.dataDir, id, u); err != nil {
		return fmt.Errorf("node security: write marker: %w", err)
	}

	// 共享原始传输：master 控制面与 peer 数据面用同一底层连接池/TLS 配置；
	// 授权（设备注入 / 票据换取）在各自的包装层完成，互不递归。
	shared := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		TLSClientConfig:       currentTLSConfig(n),
	}
	sec := &nodeSecurity{
		node:          n,
		identity:      id,
		masterScheme:  u.Scheme,
		masterHost:    u.Host,
		base:          shared,
		invite:        invite,
		renewMargin:   sessionRenewMargin,
		allowInsecure: allowInsecure,
	}
	sec.authClient = &http.Client{
		Transport: shared,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	n.sec = sec
	n.httpClient.Transport = &deviceTransport{sec: sec, base: shared}
	n.bulkClient.Transport = &access.Transport{Base: shared, Authorize: sec.authorizePeer}
	// 拒绝跟随重定向：设备 Bearer 与票据绝不发往 3xx 指向的其它 origin。
	reject := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	n.httpClient.CheckRedirect = reject
	n.bulkClient.CheckRedirect = reject

	log.Printf("node security enabled: identity=%s master=%s://%s", id.NodeID(), u.Scheme, u.Host)
	return nil
}

// currentTLSConfig 摸底既有 transport 上的 TLS 配置（SetTLS 先于 EnableSecurity
// 调用时把配置带进共享传输；晚于调用则由扩展后的 setTLSOnTransport 覆盖共享层）。
func currentTLSConfig(n *Node) *tls.Config {
	for _, rt := range []http.RoundTripper{n.httpClient.Transport, n.bulkClient.Transport} {
		at, ok := rt.(*auth.Transport)
		if !ok {
			continue
		}
		if ht, ok := at.Fallback.(*http.Transport); ok && ht.TLSClientConfig != nil {
			return ht.TLSClientConfig.Clone()
		}
	}
	return nil
}

// writeSecurityMarker 保证 dataDir 的持久安全标记与本次启用完全绑定：
//   - 已有标记：Lstat 判形态（不跟随 symlink）——非 regular（symlink / dangling
//     symlink / 目录 / fifo…）一律 fail-closed；regular 则以 fd 读取并逐字段校验
//     （open 后 fstat + SameFile 复核同一 inode）：同 identity/master 放行且不重写
//     （fd + 目录 fsync 落定，inode 不变），不同 identity/master、损坏或不可读一律
//     拒绝，标记文件一字节不动（重新绑定须人工显式删除）。
//   - 无标记：首建走 temp(0600) → write → fsync → close → os.Link(tmp, final) 的
//     原子 no-replace 发布，再父目录 fsync。os.Link 是唯一发布手段：硬链接不支持
//     （EPERM/EOPNOTSUPP/ENOSYS…）→ fail-closed 拒绝启用，绝不回退 rename 覆盖
//     （并发首建会互相改写 dataDir 的属主凭证）；final 已存在（EEXIST，并发首建的
//     胜者先落盘）→ 读胜者内容校验，相同才放行，否则拒绝。
func writeSecurityMarker(dataDir string, id *edgeidentity.Identity, u *url.URL) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dataDir, securityMarkerName)
	wantIdentity := id.NodeID().String()
	wantMaster := u.Scheme + "://" + u.Host
	if st, err := os.Lstat(path); err == nil {
		if !st.Mode().IsRegular() {
			return fmt.Errorf("node security: marker %s is not a regular file (%s); refusing to enable on this data dir (delete it deliberately to re-bind)", path, st.Mode().Type())
		}
		return validateSecurityMarker(path, wantIdentity, wantMaster)
	} else if !errors.Is(err, fs.ErrNotExist) {
		// 无法判定存在性（权限/IO）→ fail-closed：拒绝启用，也绝不覆盖。
		return fmt.Errorf("node security: marker %s unreadable: %w", path, err)
	}
	body, err := json.Marshal(struct {
		Version  int    `json:"version"`
		Identity string `json:"identity"`
		Master   string `json:"master"`
	}{Version: 1, Identity: wantIdentity, Master: wantMaster})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dataDir, ".security-marker-tmp-*") // CreateTemp 固定 0600
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	// 原子 no-replace 发布：EEXIST = 并发首建的胜者已落盘（转校验胜者，相同才放行）；
	// 其它错误（含硬链接不支持）→ fail-closed，绝不回退 rename 覆盖。
	if err := os.Link(tmpName, path); err != nil {
		os.Remove(tmpName)
		if errors.Is(err, fs.ErrExist) {
			return validateSecurityMarker(path, wantIdentity, wantMaster)
		}
		return fmt.Errorf("node security: atomic publish of marker %s failed: %w (hard link may be unsupported on this volume; refusing to fall back to a non-atomic publish)", path, err)
	}
	// The final directory entry must be durable before secure mode is acknowledged.
	os.Remove(tmpName)
	return syncDir(dataDir)
}

// maxMarkerBytes 是标记文件读取上限：标记只含版本/identity/master，正常远小于
// 此值；超限一律按损坏拒绝（fail-closed，不做无界读取）。
const maxMarkerBytes = 1 << 20

// validateSecurityMarker 读取并校验已存在的 final 标记。Lstat 先判形态，open 后
// fstat + SameFile 复核（防 Lstat 与 open 之间被换成别的 inode），再逐字段与本次
// 启用比对：任何不符/损坏/不可读 → 拒绝，标记一字节不动；匹配则 fd + 目录 fsync
// 落定后放行（不重写内容，inode 不变）。
func validateSecurityMarker(path, wantIdentity, wantMaster string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("node security: marker %s unreadable: %w", path, err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("node security: marker %s is not a regular file (%s); refusing to enable", path, st.Mode().Type())
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("node security: marker %s unreadable: %w", path, err)
	}
	defer f.Close()
	fst, err := f.Stat()
	if err != nil {
		return fmt.Errorf("node security: marker %s unreadable: %w", path, err)
	}
	if !os.SameFile(st, fst) || !fst.Mode().IsRegular() {
		return fmt.Errorf("node security: marker %s changed while being read; refusing to enable", path)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxMarkerBytes+1))
	if err != nil {
		return fmt.Errorf("node security: marker %s unreadable: %w", path, err)
	}
	if len(raw) > maxMarkerBytes {
		return errors.New("node security: marker exceeds size limit")
	}
	var body struct {
		Version  int    `json:"version"`
		Identity string `json:"identity"`
		Master   string `json:"master"`
	}
	if jerr := json.Unmarshal(raw, &body); jerr != nil || body.Version != 1 || body.Identity == "" || body.Master == "" {
		return fmt.Errorf("node security: marker %s is corrupt; refusing to enable on this data dir (delete it deliberately to re-bind)", path)
	}
	if body.Identity != wantIdentity {
		return fmt.Errorf("node security: marker identity %s does not match this node identity %s; refusing to enable", body.Identity, wantIdentity)
	}
	if body.Master != wantMaster {
		return fmt.Errorf("node security: marker master %s does not match configured master %s; refusing to enable", body.Master, wantMaster)
	}
	// 匹配放行：既有标记的 fd 与目录项都 fsync 落定（内容不变）。
	if err := f.Sync(); err != nil {
		return fmt.Errorf("node security: marker %s sync: %w", path, err)
	}
	return syncDir(filepath.Dir(path))
}

// syncDir fsync 目录项（发布/删除的目录项持久化）。
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}

// securityMarkerPresent 报告 dataDir 是否带安全标记。除「明确不存在」外，任何
// 情况都按存在处理——包括 dangling symlink（os.Stat 会把它判成不存在而静默退回
// legacy，Lstat 不会）：宁可 fail-closed，也不静默退回 legacy。
func securityMarkerPresent(dataDir string) bool {
	if _, err := os.Lstat(filepath.Join(dataDir, securityMarkerName)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false
		}
		return true // 无法判定（权限/IO 等）→ fail-closed
	}
	return true
}

// securityRequiredHandler 是「标记存在但 security 未启用」的 fail-closed 兜底：
// 除 /healthz 外全部拒绝，防止忘带 --secure 的重启把既有数据暴露在 legacy 模式。
func securityRequiredHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		log.Printf("security marker present but node security is disabled; failing closed: %s %s", r.Method, r.URL.Path)
		httpError(w, http.StatusServiceUnavailable, "node security is required but disabled")
	})
}

// ---- 设备会话：challenge → sign → session ----

// establishSession 注册（首次，带 invite）或续期（同 key、无 invite）。
// force 表示强制重建（master 报 unknown node 时的重注册路径）；否则已有未临期
// 会话时为 no-op，避免多 goroutine 反复续期互相作废。401 条件重建走
// renewAfterRejection（被拒 token 快照判断在 opMu 内做，不在此短路）。
func (s *nodeSecurity) establishSession(ctx context.Context, force bool) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if !force {
		s.mu.Lock()
		tok, exp, has := s.token, s.expires, s.hasSess
		s.mu.Unlock()
		if has && tok != "" && time.Now().Before(exp.Add(-s.renewMargin)) {
			return nil
		}
	}
	return s.establishLocked(ctx)
}

// establishLocked 在已持 opMu 的前提下完成 challenge → 签名 → session 全流程；
// establishSession（主动注册/续期）与 renewAfterRejection（401 条件重建）汇合于此。
// first/invite 在此判定：仅首次注册携带 invite，续期与重注册一律不带。
func (s *nodeSecurity) establishLocked(ctx context.Context) error {
	s.mu.Lock()
	first, invite := !s.hasSess, ""
	if !s.hasSess {
		invite = s.invite
	}
	s.mu.Unlock()

	addr := s.node.advertise
	total := s.node.totalBytes
	var ch access.DeviceChallenge
	if _, err := s.postJSON(ctx, s.authClient, "/security/devices/challenge",
		access.DeviceChallengeRequest{
			PublicKey:  s.identity.PublicKey(),
			Addr:       addr,
			TotalBytes: total,
			Invite:     invite,
		}, &ch); err != nil {
		return fmt.Errorf("device challenge: %w", err)
	}
	// 不盲签：先校验挑战确实绑定了本请求的全部字段。
	if err := validateDeviceChallenge(ch.Challenge, ch.ID, string(s.identity.NodeID()), addr, total, time.Now()); err != nil {
		return fmt.Errorf("device challenge binding: %w", err)
	}
	sig, err := s.identity.Sign(ch.Challenge)
	if err != nil {
		return fmt.Errorf("sign device challenge: %w", err)
	}
	var sess access.DeviceSession
	if _, err := s.postJSON(ctx, s.authClient, "/security/devices/session",
		access.DeviceLoginRequest{ChallengeID: ch.ID, Signature: sig}, &sess); err != nil {
		return fmt.Errorf("device session: %w", err)
	}
	if sess.Token == "" {
		return errors.New("device session: empty token")
	}
	if sess.NodeID == 0 {
		return errors.New("device session: zero node id")
	}
	if !time.Now().Before(sess.ExpiresAt) {
		return errors.New("device session: zero or expired expiry")
	}
	s.mu.Lock()
	s.token, s.expires, s.hasSess = sess.Token, sess.ExpiresAt, true
	if first {
		s.invite = "" // 只在首次注册使用一次
	}
	s.mu.Unlock()
	s.node.nodeID.Store(int64(sess.NodeID))
	log.Printf("node registered (device %s): id=%d addr=%s", s.identity.NodeID(), sess.NodeID, addr)
	return nil
}

// validateDeviceChallenge 校验 master 签发挑战与本次请求的绑定：受众、用途、
// Nonce 长度、时间窗（未过期且 ≤maxChallengeWindow、NotBefore 不过分超前）、
// Extras 恰好等于预期四键（challenge_id/node_id/addr/total_bytes）。
func validateDeviceChallenge(c edgeidentity.Challenge, challengeID, nodeID, addr string, totalBytes int64, now time.Time) error {
	if c.Audience != deviceChallengeAudience {
		return fmt.Errorf("audience %q mismatch", c.Audience)
	}
	if c.Purpose != deviceChallengePurpose {
		return fmt.Errorf("purpose %q mismatch", c.Purpose)
	}
	if len(c.Nonce) < minChallengeNonce {
		return fmt.Errorf("nonce too short (%d bytes)", len(c.Nonce))
	}
	if !c.ExpiresAt.After(now) {
		return errors.New("challenge already expired")
	}
	if c.ExpiresAt.After(now.Add(maxChallengeWindow)) {
		return fmt.Errorf("challenge window too long (expires %s)", c.ExpiresAt.UTC().Format(time.RFC3339Nano))
	}
	if !c.NotBefore.IsZero() && c.NotBefore.After(now.Add(notBeforeSkew)) {
		return errors.New("challenge notBefore too far in the future")
	}
	want := map[string]string{
		"challenge_id": challengeID,
		"node_id":      nodeID,
		"addr":         addr,
		"total_bytes":  strconv.FormatInt(totalBytes, 10),
	}
	if len(c.Extras) != len(want) {
		return fmt.Errorf("challenge extras bind %d keys, want exactly %d", len(c.Extras), len(want))
	}
	for k, v := range want {
		got, ok := c.Extras[k]
		if !ok {
			return fmt.Errorf("challenge extras missing %q", k)
		}
		if got != v {
			return fmt.Errorf("challenge extras %q mismatch", k)
		}
	}
	return nil
}

// snapshot 互斥读取当前设备会话（续期原子换新，旧 token 读到也只会 401 一次）。
func (s *nodeSecurity) snapshot() (token string, expires time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.token, s.expires
}

// hasSession 报告是否已建立过设备会话（供 registerOnce 区分首次注册与强制重建）。
func (s *nodeSecurity) hasSession() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hasSess
}

// kickRenewFor 收到 master 401 时的异步续期（单飞：并发 401 只触发一次）。
// rejected 是 master 实际拒绝的那个设备 token；是否重建由 renewAfterRejection
// 按「被拒 token 是否仍是当前快照」裁决（见其注释）。
func (s *nodeSecurity) kickRenewFor(rejected string) {
	if rejected == "" {
		return
	}
	if !s.renewing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer s.renewing.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), controlTimeout)
		defer cancel()
		if err := s.renewAfterRejection(ctx, rejected); err != nil {
			log.Printf("device session renew after rejection: %v", err)
		}
	}()
}

// renewAfterRejection 是 401 三路径（deviceTransport 异步 / checkTicket、
// authorizePeer 同步）的统一条件重建入口：master 拒绝了设备会话时立即重建，使
// 「被作废/被轮换」的会话自愈，而不等本地到期余量（旧实现新鲜即短路，最长停摆
// 一个 renewMargin）。收敛语义：
//   - 仅当被拒 token 仍是当前快照才重建——迟到 401（快照已轮换到新 token）绝不
//     作废新会话；
//   - 判断在 opMu 内完成：并发触发时第一个重建、其余看到快照已变自然 no-op
//     （同步多请求与异步单飞混合亦然），无强制重登风暴；
//   - 重建失败原样返回错误：同步路径不重试（当前凭据确已失效），异步路径记日志，
//     后续 401 会再次触发；返回 nil（含已轮换 no-op）时调用方以当前快照重试。
func (s *nodeSecurity) renewAfterRejection(ctx context.Context, rejected string) error {
	if rejected == "" {
		return nil
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.Lock()
	cur, has := s.token, s.hasSess
	s.mu.Unlock()
	if !has || cur == "" || cur != rejected {
		return nil
	}
	return s.establishLocked(ctx)
}

// renewLoop 到期前主动续期（Register 成功后启动）。
func (s *nodeSecurity) renewLoop() {
	t := time.NewTicker(renewCheckInterval)
	defer t.Stop()
	for range t.C {
		tok, exp := s.snapshot()
		if tok != "" && time.Now().Before(exp.Add(-s.renewMargin)) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), controlTimeout)
		err := s.establishSession(ctx, false)
		cancel()
		if err != nil {
			log.Printf("device session renew: %v", err)
		}
	}
}

// ---- 出站：master 设备注入 / peer 票据 ----

// deviceTransport 是 master 控制面出站传输：仅在精确 master origin 上注入
// 设备 Bearer（互斥快照），剥离调用方自带凭据；非 master origin 直接拒绝。
type deviceTransport struct {
	sec  *nodeSecurity
	base http.RoundTripper
}

func (t *deviceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	dispatched := false
	defer func() {
		if !dispatched && req.Body != nil {
			req.Body.Close()
		}
	}()
	if !t.sec.isMasterOrigin(req.URL) {
		return nil, errors.New("node security: refusing to send device credentials outside the master origin")
	}
	if req.Host != "" && !strings.EqualFold(req.Host, req.URL.Host) {
		return nil, fmt.Errorf("node security: request Host %q does not match URL host %q", req.Host, req.URL.Host)
	}
	tok, _ := t.sec.snapshot()
	if tok == "" {
		return nil, errors.New("node security: no device session")
	}
	c := req.Clone(peerhttp.ControlContext(req.Context()))
	c.Header.Del("Authorization")
	c.Header.Set("Authorization", "Bearer "+tok)
	dispatched = true
	resp, err := t.base.RoundTrip(c)
	// 会话被作废（续期轮转/撤销）→ 按被拒 token 条件续期（单飞）；本请求按 401
	// 失败，由 caller 既有重试自然换新 token，不在这里无限重试。
	if err == nil && resp != nil && resp.StatusCode == http.StatusUnauthorized && !isDeviceAuthPath(req.URL.Path) {
		t.sec.kickRenewFor(tok)
	}
	return resp, err
}

func isDeviceAuthPath(path string) bool {
	return path == "/security/devices/challenge" || path == "/security/devices/session"
}

// isMasterOrigin 只在精确 master origin 上为真。带 userinfo/opaque/转义路径/
// fragment 的 URL 一律非 master origin：这些形态会让 origin 判定与实际发送目标
// 出现缝隙（http.Client 实际发送时也可能带上 userinfo/歧义目标），设备凭据
// 绝不因此发出。host 大小写不敏感（DNS 语义），scheme 与端口必须精确一致。
func (s *nodeSecurity) isMasterOrigin(u *url.URL) bool {
	if u == nil || u.Scheme != s.masterScheme || u.Host == "" {
		return false
	}
	if u.User != nil || u.Opaque != "" || u.RawPath != "" || u.Fragment != "" || u.RawFragment != "" {
		return false
	}
	return strings.EqualFold(u.Host, s.masterHost)
}

// authorizePeer 是 peer 数据面出站授权（access.Transport 回调）：先向 master
// 换取绑定 method/path/query/plan/bodyhash 的短时票据，再把票据放到原请求上。
// 对象 payload 不发给 master（哈希只经 GetBody 取小控制体，流式 body 一律空哈希）。
func (s *nodeSecurity) authorizePeer(req *http.Request) error {
	// scheme/URL 歧义加固（镜像 client.applyNodeAuth 的同款防线）：scheme 必须与
	// master 配置一致——https master 绝不换票降级把数据交付给明文 peer；userinfo/
	// opaque/转义路径/空 host 会让 origin/路径判定与实际发送目标出现缝隙，一律
	// fail-closed，任何情况下不为此触达 master 换票。
	if err := safePeerURL(req.URL, s.masterScheme); err != nil {
		return err
	}
	// Host 头与 URL host 不一致时，注入的票据会随请求发往与 origin 判定不同的
	// 虚拟主机（ticket 绑定的 NodeAddr 是 URL.Host）：拒绝以防歧义。大小写不敏感
	// 比较（DNS 语义），端口必须一致。
	if req.Host != "" && !strings.EqualFold(req.Host, req.URL.Host) {
		return fmt.Errorf("node security: peer request Host %q does not match URL host %q; refusing", req.Host, req.URL.Host)
	}
	if !peerTicketable(req.Method, req.URL.Path) {
		return fmt.Errorf("node security: peer request %s %s is not ticketable", req.Method, req.URL.Path)
	}
	planID := req.Header.Get(access.PlanHeader)
	if planID == "" {
		planID = req.URL.Query().Get("plan_id")
	}
	// 计划读取携带 attempt 序号：旧尝试的票据在 master 侧被拒（claim 已递增
	// Attempts）。仅在计划 GET /objects 时携带，其余请求保持空。
	planAttempt := uint32(0)
	planAttemptToken := ""
	if planID != "" && req.Method == http.MethodGet && strings.HasPrefix(req.URL.Path, "/objects/") {
		planAttemptToken = req.Header.Get(access.PlanAttemptTokenHeader)
		if raw := req.Header.Get(access.PlanAttemptHeader); raw != "" {
			if v, err := strconv.ParseUint(raw, 10, 32); err == nil {
				planAttempt = uint32(v)
			} else {
				return fmt.Errorf("node security: invalid plan attempt header %q", raw)
			}
		}
	}
	bodyHash, err := controlBodyHash(req)
	if err != nil {
		return fmt.Errorf("node security: control body hash: %w", err)
	}
	writeEpoch, resume, epochErr := requestWriteEpoch(req)
	if epochErr != nil {
		return fmt.Errorf("node security: %w", epochErr)
	}
	ticketReq := access.TicketRequest{
		NodeAddr:         req.URL.Host,
		Method:           req.Method,
		Path:             req.URL.Path,
		Query:            req.URL.RawQuery,
		PlanID:           planID,
		PlanAttempt:      planAttempt,
		PlanAttemptToken: planAttemptToken,
		BodyHash:         bodyHash,
		WriteEpoch:       writeEpoch,
		Resume:           resume,
	}
	var tk access.Ticket
	sent, _ := s.snapshot()
	status, err := s.postJSON(req.Context(), s.node.httpClient, "/security/tickets", ticketReq, &tk)
	if status == http.StatusUnauthorized {
		// 会话可能刚被轮转：按被拒 token 条件续期一次后最多重试一次。
		if rerr := s.renewAfterRejection(req.Context(), sent); rerr == nil {
			status, err = s.postJSON(req.Context(), s.node.httpClient, "/security/tickets", ticketReq, &tk)
		}
	}
	if err != nil {
		return fmt.Errorf("node security: ticket for %s %s: %w", req.Method, req.URL.Path, err)
	}
	if tk.Token == "" || !time.Now().Before(tk.ExpiresAt) {
		return errors.New("node security: master granted no usable ticket")
	}
	req.Header.Del("Authorization") // 不透传任何其它凭据（集群 token / 用户会话）
	req.Header.Set("Authorization", "Bearer "+tk.Token)
	return nil
}

// safePeerURL 校验 peer 数据面出站 URL：scheme 与 master 配置一致、host 非空、
// 无 userinfo/opaque/转义路径/fragment（与 client.secureTransport.safeRequestURL
// 同规）。这些歧义形态会让 origin/路径判定与实际发送目标出现缝隙，一律 fail-closed。
// peerTicketable 只约束 method+path，协议一致性由此处独立把关。
func safePeerURL(u *url.URL, masterScheme string) error {
	switch {
	case u == nil:
		return errors.New("node security: peer request has no URL")
	case u.Scheme != masterScheme:
		return fmt.Errorf("node security: peer %s scheme %q does not match master scheme %q; refusing", u.Host, u.Scheme, masterScheme)
	case u.Host == "":
		return errors.New("node security: peer request URL has no host")
	case u.User != nil:
		return errors.New("node security: peer request URL carries userinfo")
	case u.Opaque != "":
		return errors.New("node security: peer request URL is opaque")
	case u.RawPath != "":
		return errors.New("node security: peer request URL carries an escaped path")
	case u.Fragment != "" || u.RawFragment != "":
		return errors.New("node security: peer request URL carries a fragment")
	}
	return nil
}

// peerTicketable 限定节点可发起的 peer 数据面请求：仅 GET /objects/{id} 与
// PUT /replicate/{id}（数字 id，非零）。其它 URL 一律拒绝换票。
func peerTicketable(method, path string) bool {
	switch method {
	case http.MethodGet:
		return ticketableIDPath(path, "/objects/")
	case http.MethodPut:
		return ticketableIDPath(path, "/replicate/")
	default:
		return false
	}
}

func ticketableIDPath(path, prefix string) bool {
	rest, ok := strings.CutPrefix(path, prefix)
	if !ok || rest == "" {
		return false
	}
	id, err := strconv.ParseUint(rest, 10, 64)
	return err == nil && id != 0
}

// controlBodyHash 只对 POST /pull 的小控制体计算 SHA256 hex（与 master 侧
// validateControlTicket「/pull 必须带 BodyHash」、GET/PUT /objects 与
// PUT /replicate 必须为空的三方约定逐字节一致）。其它 method/path、流式 body
// （GetBody 为 nil，如对象 PUT）与空 body 一律返回空串——绝不读取对象 payload，
// body hash 也不是 payload 认证（对象完整性由 master 权威 CRC + staging 归属把关）。
func controlBodyHash(req *http.Request) (string, error) {
	if req.Method != http.MethodPost || req.URL == nil || req.URL.Path != "/pull" {
		return "", nil
	}
	if req.Body == nil || req.GetBody == nil {
		return "", nil
	}
	br, err := req.GetBody()
	if err != nil {
		return "", err
	}
	defer br.Close()
	data, err := io.ReadAll(io.LimitReader(br, maxControlBody+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxControlBody {
		return "", fmt.Errorf("%w: > %d bytes", errControlBodyTooLarge, maxControlBody)
	}
	if len(data) == 0 {
		return "", nil
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// postJSON 控制面 POST：30s 上界、响应 1MiB 封顶；返回状态码便于 401 重试决策。
func (s *nodeSecurity) postJSON(ctx context.Context, client *http.Client, path string, in any, out any) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	body, err := json.Marshal(in)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.node.masterURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return resp.StatusCode, fmt.Errorf("%s: status %d", path, resp.StatusCode)
	}
	if out == nil {
		return resp.StatusCode, nil
	}
	return resp.StatusCode, json.NewDecoder(io.LimitReader(resp.Body, maxControlResponse)).Decode(out)
}

// ---- 入站：默认全拒 + 在线 check 裁决 ----

// wrapHandler 包装 security 模式的对象路由：/healthz 公开，其余路由默认拒绝，
// 逐请求在线问 master /security/check（不缓存，撤销即时生效），master 不可达
// fail-closed。不接受集群 token 或用户会话——只把携带的票据转交 master 裁决。
// 例外：/meta-backup 的 GET 支持离线恢复凭据（SetMetadataReader pin 过公钥后，
// master 全损时凭 Ed25519 签名本地验签放行只读；写删仍需在线控制票据）。
func (s *nodeSecurity) wrapHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		// 非 allowInsecure（生产默认）：入站一律要求 TLS（/healthz 豁免）——
		// 覆盖绕过 CLI 直接使用 Handler 的用法，明文连接 fail-closed。
		if !s.allowInsecure && r.TLS == nil {
			httpError(w, http.StatusBadRequest, "plaintext connections are rejected")
			return
		}
		// 离线恢复读取：master 全损时管理员凭恢复签名读取备份。先于在线票据
		// 判定——此时不存在可用的在线票据；凭据头格式不同，绝不混淆。
		if !s.readerPin.IsZero() && len(r.Header.Values(metacrypto.ReaderHeader)) != 0 {
			if err := metacrypto.VerifyRead(s.readerPin, r, s.node.advertise, time.Now()); err != nil {
				httpError(w, http.StatusUnauthorized, "metadata recovery read denied")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		tok, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			httpError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		planID := r.Header.Get(access.PlanHeader)
		if planID == "" {
			planID = r.URL.Query().Get("plan_id") // query 只允许 plan_id 参与绑定
		}
		planAttempt := uint32(0)
		planAttemptToken := ""
		if planID != "" && r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/objects/") {
			planAttemptToken = r.Header.Get(access.PlanAttemptTokenHeader)
			if raw := r.Header.Get(access.PlanAttemptHeader); raw != "" {
				if v, perr := strconv.ParseUint(raw, 10, 32); perr == nil {
					planAttempt = uint32(v)
				}
			}
		}
		// WriteEpoch binds the request to one planned-write generation; Resume
		// marks a zero-length re-confirm that never carries new payload bytes.
		// Both are echoed to the master so the ticket binds them.
		writeEpoch, resume, epochErr := requestWriteEpoch(r)
		if epochErr != nil {
			httpError(w, http.StatusBadRequest, epochErr.Error())
			return
		}
		bodyHash := ""
		_, retirement := types.RetirementPathID(r.URL.Path)
		if r.Method == http.MethodPost && (r.URL.Path == "/pull" || retirement) {
			data, err := readControlBody(r.Body)
			if err != nil {
				if errors.Is(err, errControlBodyTooLarge) {
					httpError(w, http.StatusRequestEntityTooLarge, "control body too large")
				} else {
					httpError(w, http.StatusBadRequest, "read control body failed")
				}
				return
			}
			if len(data) > 0 {
				sum := sha256.Sum256(data)
				bodyHash = hex.EncodeToString(sum[:])
			}
			// 原样还原给 handler（含 GetBody），哈希绑定的是同一份原始字节。
			r.Body = io.NopCloser(bytes.NewReader(data))
			buf := data
			r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(buf)), nil }
		}
		// /verify 无 body（BodyHash 空）；GET/DELETE /objects、/replicate 等
		// payload 请求 BodyHash 一律空，由票据在 master 侧按成员关系核验。
		res, err := s.checkTicket(r.Context(), access.CheckRequest{
			Token:            tok,
			Method:           r.Method,
			Path:             r.URL.Path,
			Query:            r.URL.RawQuery,
			PlanID:           planID,
			PlanAttempt:      planAttempt,
			PlanAttemptToken: planAttemptToken,
			BodyHash:         bodyHash,
			WriteEpoch:       writeEpoch,
			Resume:           resume,
		})
		if err != nil {
			if errors.Is(err, errCheckDenied) {
				// master 明确拒绝（本节点会话失效 / 票据无效）：401，不是不可用。
				httpError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			// master 不可达/5xx/协议异常：fail-closed，绝不放行。
			log.Printf("security check unavailable (fail closed): %v", err)
			httpError(w, http.StatusServiceUnavailable, "authorization unavailable")
			return
		}
		if !res.Allowed || !time.Now().Before(res.ExpiresAt) {
			httpError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// checkTicket 在线裁决（逐请求、不缓存）。设备会话 401 时续期一次并重试一次；
// 仍 401（会话被撤销）或 403（票据无效/绑定不符）→ errCheckDenied（本地 401）；
// 网络/5xx → 上层 503 fail-closed。
func (s *nodeSecurity) checkTicket(ctx context.Context, cr access.CheckRequest) (access.CheckResult, error) {
	var res access.CheckResult
	sent, _ := s.snapshot()
	status, err := s.postJSON(ctx, s.node.httpClient, "/security/check", cr, &res)
	if status == http.StatusUnauthorized {
		// 设备会话可能被轮转/撤销：按被拒 token 条件续期一次后最多重试一次。
		if rerr := s.renewAfterRejection(ctx, sent); rerr == nil {
			status, err = s.postJSON(ctx, s.node.httpClient, "/security/check", cr, &res)
		}
	}
	if err != nil {
		if status == http.StatusForbidden || status == http.StatusUnauthorized {
			return res, errCheckDenied
		}
		return res, err
	}
	return res, nil
}

// readControlBody 读取 ≤64KiB 的控制体；超限报错（fail-closed）。
func readControlBody(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxControlBody+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxControlBody {
		return nil, fmt.Errorf("%w: > %d bytes", errControlBodyTooLarge, maxControlBody)
	}
	return data, nil
}

// bearerToken 严格解析 "Bearer <token>"（单 token、无内部空白）。
func bearerToken(h string) (string, bool) {
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	t := strings.TrimSpace(h[len(prefix):])
	if t == "" || strings.ContainsAny(t, " \t") {
		return "", false
	}
	return t, true
}

// SetMetadataReader 安装/更新元数据恢复公钥（master 经在线控制票据下发；测试
// 也可直接调用）。校验 namespace 与公钥自洽后原子替换；nil 清除（撤销恢复通道）。
func (s *nodeSecurity) SetMetadataReader(info metacrypto.ReaderInfo) error {
	if info.IsZero() {
		s.mu.Lock()
		s.readerPin = metacrypto.ReaderInfo{}
		s.mu.Unlock()
		return nil
	}
	if err := info.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readerPin = info
	return nil
}
