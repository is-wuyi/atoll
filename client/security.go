// 安全会话（用户登录 + space 选择 + 节点票据 transport）。
//
// 威胁模型与边界：
//   - 用户会话（Login 发的 Bearer）只允许出现在 master 源（精确 scheme+host 比较，
//     非字符串前缀——防 absolute URL 伪造前缀 trick）。
//   - 直连节点的请求绝不携带会话：先向 master POST /security/tickets 换取短期、
//     按 (节点,方法,路径,query,body哈希) 绑定的 opaque 票据，节点侧每次请求在线回
//     master 核验（无 TTL 缓存）。节点收到 30x 也不得把凭据带去别处（拒跨源重定向）。
//   - 旧 New*/NewWithToken/NewWithTLS（静态集群 token）行为不变；secure 模式下
//     c.HTTP 完全不经过 auth.Transport——静态 token 会无差别发往节点，正是要防的泄漏。
package client

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
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"atoll/pkg/access"
)

// errNotSecure：非 NewSecure 创建的客户端没有会话语义（旧构造函数保持兼容模式）。
var errNotSecure = errors.New("此客户端未启用安全会话（请用 NewSecure 创建）")

// ---- 账号 wire structs（与 master /auth/* 响应对齐；不依赖 meta 防环）----

// UserInfo 是 master 下发的用户公开字段。
type UserInfo struct {
	ID              uint64 `json:"id"`
	Username        string `json:"username"`
	PlatformAdmin   bool   `json:"platform_admin"`
	Disabled        bool   `json:"disabled"`
	PersonalSpaceID uint64 `json:"personal_space_id"`
}

// SpaceInfo 是 space 的公开字段（internal_path 服务端不下发，客户端不建模）。
type SpaceInfo struct {
	ID      uint64 `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"` // "personal" | "team"
	OwnerID uint64 `json:"owner_id"`
	RootID  uint64 `json:"root_id"`
}

// LoginResult 是 POST /auth/login 的响应。
type LoginResult struct {
	Token     string     `json:"token"`
	ExpiresAt time.Time  `json:"expires_at"`
	User      UserInfo   `json:"user"`
	Space     *SpaceInfo `json:"space,omitempty"` // 登录时的默认 space（可能为空）
}

// ---- 安全会话状态 ----

// secureSession 保存会话与 space 选择；读写都经锁（transport 每请求快照）。
type secureSession struct {
	mu       sync.Mutex
	token    string
	spaceID  uint64
	hasSpace bool
}

func (s *secureSession) snapshot() (token string, spaceID uint64, hasSpace bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.token, s.spaceID, s.hasSpace
}

// secureTransport 是 secure 模式的唯一出站 transport：
// master 源注入用户会话；其余源（节点）换票据。
type secureTransport struct {
	master *url.URL // 解析后的 master origin（scheme://host）
	base   http.RoundTripper
	s      *secureSession
}

// NewSecure 创建安全会话客户端。masterURL 无 scheme 默认 https；明文 http:// 仅在
// allowInsecure=true 时放行（测试/纯内网显式开）。tlsCfg 为节点/master 共用的 TLS 配置。
// 返回的 Client 对 master 注入会话、对节点自动换取短期票据；旧构造函数行为不受影响。
func NewSecure(masterURL string, tlsCfg *tls.Config, allowInsecure bool) (*Client, error) {
	raw := masterURL
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw // HTTPS 默认
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse master URL: %w", err)
	}
	if u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("master URL 需要形如 https://host[:port]: %q", masterURL)
	}
	if u.Scheme == "http" && !allowInsecure {
		return nil, fmt.Errorf("拒绝明文 http master %q（需要 allowInsecure 显式开启）", masterURL)
	}
	// InsecureSkipVerify 等价于放弃服务器身份校验（MITM 可见全部流量），与明文同级：
	// 必须同样显式 allowInsecure 才放行——防调用方在配置里"顺手"关掉校验。
	if tlsCfg != nil && tlsCfg.InsecureSkipVerify && !allowInsecure {
		return nil, errors.New("tlsCfg.InsecureSkipVerify=true 需要 allowInsecure 显式开启")
	}
	// NewSecure 只服务 origin：userinfo/query/fragment/ForceQuery/非 root path 一律
	// 拒绝而非静默丢弃，防调用方误以为这些部分在安全路径上生效。ForceQuery（尾随
	// "?"）在 url.Parse 后 RawQuery 为空串，只靠 RawQuery 检查会漏放行——显式拒绝。
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("master URL 必须是纯 origin（scheme://host），不得携带 userinfo/query/fragment/ForceQuery/非根路径: %q", masterURL)
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	if tlsCfg != nil {
		base.TLSClientConfig = tlsCfg.Clone()
	}
	s := &secureSession{}
	tr := &secureTransport{master: u, base: base, s: s}
	// MasterURL 归一为 origin（丢弃任何 path 后缀）：其余代码直接拼接路径，
	// 且 secureTransport 的 origin 比较必须与请求目标一致。
	return &Client{
		MasterURL:    u.Scheme + "://" + u.Host,
		HTTP:         &http.Client{Transport: tr, CheckRedirect: SecureRedirectPolicy},
		sec:          s,
		secTransport: tr,
	}, nil
}

// SetRequireEncryption 在 secure 会话下要求加密写入：探测 master content-key
// 服务因故障失败（非 409/404/405 的明确"无密钥服务"答复）时硬停上传，
// 不静默降级明文。老集群未配 KEK 的合规回退不受影响。
func (c *Client) SetRequireEncryption() { c.requireEncryption = true }

// RequireEncryption 报告当前是否要求加密写入。
func (c *Client) RequireEncryption() bool { return c.requireEncryption }

// ObjectTransport 返回 secure 模式下供直连节点的调用方（FUSE 读句柄等）复用的
// transport：节点请求自动换取票据，用户会话绝不外发。非 secure 模式返回 nil——
// 调用方保持原有 auth.HTTPTransport 行为。与 c.HTTP 的 Transport 是同一实例
// （NewSecure 填充），连接池一处复用。
func (c *Client) ObjectTransport() http.RoundTripper {
	if c.secTransport == nil {
		return nil
	}
	return c.secTransport
}

// SecureRedirectPolicy 拒绝跨源重定向：30x 不得把请求（连带 Authorization 与数据）
// 引到其它主机。同源跳转放行。
func SecureRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("secure client: 停止跟随重定向（超过 10 跳）")
	}
	if len(via) == 0 {
		return nil
	}
	prev := via[len(via)-1]
	if !sameOrigin(prev.URL, req.URL) {
		return fmt.Errorf("secure client: 拒绝跨源重定向 %s -> %s", prev.URL, req.URL)
	}
	return nil
}

func sameOrigin(a, b *url.URL) bool {
	return a != nil && b != nil &&
		a.Scheme == b.Scheme && strings.EqualFold(a.Host, b.Host)
}

// RoundTrip 按 URL origin 分流。克隆请求再改头：不改调用方的请求（与 pkg/access.Transport 同约定）。
func (t *secureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cp := req.Clone(req.Context())
	dispatched := false
	defer func() {
		if !dispatched && cp.Body != nil {
			cp.Body.Close()
		}
	}()
	// 歧义 URL 形态会让"origin 判定"与实际发送目标出现缝隙，一律 fail-closed。
	if err := safeRequestURL(cp.URL); err != nil {
		return nil, err
	}
	// req.Host 非空且与 URL.Host 不一致时，注入的会话可能发往与 origin 判定不同的
	// 虚拟主机——拒绝以防歧义。大小写不敏感比较（DNS 语义），端口必须一致。
	if cp.Host != "" && !strings.EqualFold(cp.Host, cp.URL.Host) {
		return nil, fmt.Errorf("secure transport: 请求 Host %q 与 URL host %q 不一致，拒绝发送", cp.Host, cp.URL.Host)
	}
	var err error
	if sameOrigin(cp.URL, t.master) {
		err = t.applyMasterAuth(cp)
	} else {
		err = t.applyNodeAuth(cp)
	}
	if err != nil {
		return nil, err
	}
	dispatched = true
	return t.base.RoundTrip(cp)
}

// safeRequestURL 拒绝歧义 URL：userinfo/opaque/转义 RawPath/ForceQuery/fragment 可能让
// 安全判定所依据的 origin 与节点实际看到的请求目标不一致。ForceQuery（尾随 "?"）
// 在 url.Parse 后 RawQuery 为空串，只查 RawQuery 会漏放行——显式拒绝。
func safeRequestURL(u *url.URL) error {
	switch {
	case u == nil || u.Host == "":
		return errors.New("secure transport: 请求缺少绝对 URL host")
	case u.User != nil:
		return errors.New("secure transport: 拒绝携带 userinfo 的请求 URL")
	case u.Opaque != "":
		return errors.New("secure transport: 拒绝 opaque 形态请求 URL")
	case u.RawPath != "":
		return errors.New("secure transport: 拒绝携带转义路径的请求 URL")
	case u.ForceQuery:
		return errors.New("secure transport: 拒绝携带 ForceQuery（尾随 ?）的请求 URL")
	case u.Fragment != "" || u.RawFragment != "":
		return errors.New("secure transport: 拒绝携带 fragment 的请求 URL")
	}
	return nil
}

// applyMasterAuth 注入用户会话与 space。token 为空（login/register 等免认证调用）
// 不注入任何头，认证由 master 裁决。
func (t *secureTransport) applyMasterAuth(req *http.Request) error {
	token, spaceID, hasSpace := t.s.snapshot()
	if token == "" {
		req.Header.Del("Authorization") // 防调用方预置头随请求外发
		req.Header.Del(access.SpaceHeader)
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if hasSpace {
		req.Header.Set(access.SpaceHeader, strconv.FormatUint(spaceID, 10))
	} else {
		req.Header.Del(access.SpaceHeader)
	}
	return nil
}

// applyNodeAuth 把节点请求换成短期票据：先向 master 换票（用户 Bearer+space 只出现在
// 这条 master 控制请求上），节点请求体只带票据。无会话/未选 space 直接本地拒绝。
func (t *secureTransport) applyNodeAuth(req *http.Request) error {
	// 非 master 目标：scheme 必须与 master 配置一致——https master 绝不允许客户端
	// 换票后降级把数据交付给明文 http 节点（scheme() 推导同一规则，双端一致）。
	if req.URL.Scheme != t.master.Scheme {
		return fmt.Errorf("secure client: 节点 %s scheme %q 与配置不符（want %q），拒绝连接",
			req.URL.Host, req.URL.Scheme, t.master.Scheme)
	}
	token, spaceID, hasSpace := t.s.snapshot()
	// 换票属于用户文件操作：master 对用户文件方法要求 X-Atoll-Space，
	// 未选 space 与未登录同样在本地拒绝（不发任何请求）。
	if token == "" || !hasSpace {
		return fmt.Errorf("secure client: 无会话或未选择 space，拒绝直连节点 %s", req.URL.Host)
	}
	tk, err := t.fetchTicket(req, token, spaceID)
	if err != nil {
		return err
	}
	// Del 再 Set：会话/space 头无论从哪条路径混进来都不得发往节点。
	req.Header.Del("Authorization")
	req.Header.Del(access.SpaceHeader)
	req.Header.Set("Authorization", "Bearer "+tk.Token)
	return nil
}

// maxTicketWait 是单次换票控制请求的 deadline 上限：调用方无 deadline 时补 30s，
// 有更短 deadline 时沿用调用方的——换票绝不该无界挂起。
const maxTicketWait = 30 * time.Second

// fetchTicket 向 master 申请绑定本次请求属性的短期票据。PlanID 用户侧通常无需填写
// （保护计划由 master 关联）；对象数据面 body 不绑定 hash（两端协议一致，master 裁决）。
func (t *secureTransport) fetchTicket(req *http.Request, token string, spaceID uint64) (access.Ticket, error) {
	tr := access.TicketRequest{
		NodeAddr: req.URL.Host,
		Method:   req.Method,
		Path:     req.URL.Path,
		Query:    req.URL.RawQuery,
		BodyHash: nodeBodyHash(req),
	}
	b, err := json.Marshal(tr)
	if err != nil {
		return access.Ticket{}, err
	}
	ctx, cancel := context.WithTimeout(req.Context(), maxTicketWait)
	defer cancel()
	treq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		t.master.Scheme+"://"+t.master.Host+"/security/tickets", bytes.NewReader(b))
	if err != nil {
		return access.Ticket{}, err
	}
	treq.Header.Set("Content-Type", "application/json")
	treq.Header.Set("Authorization", "Bearer "+token)
	treq.Header.Set(access.SpaceHeader, strconv.FormatUint(spaceID, 10))
	resp, err := t.base.RoundTrip(treq)
	if err != nil {
		return access.Ticket{}, fmt.Errorf("申请节点票据: %w", err)
	}
	defer resp.Body.Close()
	if err := statusError(resp); err != nil {
		return access.Ticket{}, fmt.Errorf("申请节点票据: %w", err)
	}
	var tk access.Ticket
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&tk); err != nil {
		return access.Ticket{}, fmt.Errorf("解析节点票据: %w", err)
	}
	if tk.Token == "" {
		return access.Ticket{}, errors.New("master 返回空票据")
	}
	// 过期/零值票据拒收：节点侧在线核验同样会拒，但客户端不应把注定失败的凭据发出去。
	if tk.ExpiresAt.IsZero() || !time.Now().Before(tk.ExpiresAt) {
		return access.Ticket{}, errors.New("master 返回过期或无效的节点票据")
	}
	return tk, nil
}

// maxBodyBind 是可绑定进票据的 body 上限：只覆盖小控制请求，绝不为此缓冲数据面 body。
const maxBodyBind = 64 << 10

// nodeBodyHash 按协议绑定票据 body：对象数据面 /objects/*（GET/PUT）恒空——票据绑定
// 物理 ObjectID + master 权威完整性/staging 归属/ACL，body hash 不是 payload 认证，
// 两端约定必须一致（节点/设备票据同样对对象 PUT 发空）。仅小控制 body（POST 等）
// 且 ≤maxBodyBind 才计算 hex(sha256)。
func nodeBodyHash(req *http.Request) string {
	if strings.HasPrefix(req.URL.Path, "/objects/") {
		return ""
	}
	return bindBodyHash(req)
}

// bindBodyHash 对小的内存 body（可回卷）计算 hex(sha256) 绑定进票据；其余返回空。
func bindBodyHash(req *http.Request) string {
	if req.Body == nil || req.ContentLength <= 0 || req.ContentLength > maxBodyBind {
		return ""
	}
	sr, ok := req.Body.(io.ReadSeeker)
	if !ok {
		return ""
	}
	h := sha256.New()
	if _, err := io.Copy(h, sr); err != nil {
		return ""
	}
	if _, err := sr.Seek(0, io.SeekStart); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---- 会话与账号操作 ----

// Login 用用户名/密码换取会话。凭据只发往 master（URL 固定 MasterURL；secure transport
// 亦只对 master 源注入），不写任何日志。成功后保存 token，并默认选择登录返回的 space
// （缺省时 user.personal_space_id）；之后仍可用 UseSpace 显式切换。
func (c *Client) Login(ctx context.Context, username, password string) (LoginResult, error) {
	if c.sec == nil {
		return LoginResult{}, errNotSecure
	}
	var out LoginResult
	err := c.postJSONCtx(ctx, "/auth/login", map[string]string{"username": username, "password": password}, &out)
	if err != nil {
		return LoginResult{}, err
	}
	if out.Token == "" || len(out.Token) > maxSessionTokenLen || strings.ContainsAny(out.Token, " \t\r\n") {
		return LoginResult{}, errors.New("Login: master 返回无效 token")
	}
	if out.ExpiresAt.IsZero() || !time.Now().Before(out.ExpiresAt) {
		return LoginResult{}, errors.New("Login: master 返回过期或无效 Expiry")
	}
	if out.User.ID == 0 || out.User.PersonalSpaceID == 0 || (out.Space != nil && out.Space.ID == 0) {
		return LoginResult{}, errors.New("Login: master 返回无效用户或空间")
	}
	c.sec.mu.Lock()
	c.sec.token = out.Token
	if out.Space != nil {
		c.sec.spaceID, c.sec.hasSpace = out.Space.ID, true
	} else if out.User.PersonalSpaceID != 0 {
		c.sec.spaceID, c.sec.hasSpace = out.User.PersonalSpaceID, true
	} else {
		c.sec.spaceID, c.sec.hasSpace = 0, false
	}
	c.sec.mu.Unlock()
	return out, nil
}

// maxSessionTokenLen 与服务端契约一致：master 的 bearer() 对 >512 字节或含
// " \t\r\n" 的 token 一律视为「无 token」（401）。客户端若放进更长的值，只会
// 得到注定 401 的请求——本地按同一上限拒绝，错误即刻、语义一致。
const maxSessionTokenLen = 512

// SetSession 手动注入会话 token（如从环境变量恢复登录态），不触网。space 另用 UseSpace。
// 空 token = 清会话（合法语义，如 CLI 登录前清空）；含非法空白/换行或超过服务端
// 512 上限的非空值拒绝。
func (c *Client) SetSession(token string) error {
	if c.sec == nil {
		return errNotSecure
	}
	if token != "" {
		if strings.ContainsAny(token, " \t\r\n") {
			return errors.New("SetSession: token 含非法空白字符")
		}
		if len(token) > maxSessionTokenLen {
			return fmt.Errorf("SetSession: token 长度 %d 超过服务端上限 %d", len(token), maxSessionTokenLen)
		}
	}
	c.sec.mu.Lock()
	c.sec.token = token
	c.sec.hasSpace = false
	c.sec.spaceID = 0
	c.sec.mu.Unlock()
	return nil
}

// UseSpace 选择后续请求的 X-Atoll-Space（十进制 ID）。0 = 清除选择（master 将拒绝
// 需要 space 的用户文件方法）。
func (c *Client) UseSpace(spaceID uint64) error {
	if c.sec == nil {
		return errNotSecure
	}
	c.sec.mu.Lock()
	c.sec.spaceID, c.sec.hasSpace = spaceID, spaceID != 0
	c.sec.mu.Unlock()
	return nil
}

// Logout 先在线注销（master 侧会话失效），随后无论成败都清除本地 token——master
// 不可达时保留本地 token 只会继续携带失效凭据打请求。
func (c *Client) Logout(ctx context.Context) error {
	if c.sec == nil {
		return errNotSecure
	}
	err := c.postJSONCtx(ctx, "/auth/logout", nil, nil)
	c.sec.mu.Lock()
	c.sec.token = ""
	c.sec.spaceID, c.sec.hasSpace = 0, false
	c.sec.mu.Unlock()
	return err
}

// ListSpaces 列出当前用户可见的 space。
func (c *Client) ListSpaces(ctx context.Context) ([]SpaceInfo, error) {
	if c.sec == nil {
		return nil, errNotSecure
	}
	var out []SpaceInfo
	if err := c.getJSONCtx(ctx, "/auth/spaces", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateTeam 创建团队 space，返回新 space。
func (c *Client) CreateTeam(ctx context.Context, name string) (SpaceInfo, error) {
	if c.sec == nil {
		return SpaceInfo{}, errNotSecure
	}
	var out SpaceInfo
	err := c.postJSONCtx(ctx, "/auth/teams", map[string]string{"name": name}, &out)
	return out, err
}

// AddMember 把用户加进 space（role 由 master 定义）。
func (c *Client) AddMember(ctx context.Context, spaceID, userID uint64, role string) error {
	if c.sec == nil {
		return errNotSecure
	}
	return c.postJSONCtx(ctx, "/auth/members", map[string]any{
		"space_id": spaceID, "user_id": userID, "role": role,
	}, nil)
}

// RemoveMember 把用户移出 space。
func (c *Client) RemoveMember(ctx context.Context, spaceID, userID uint64) error {
	if c.sec == nil {
		return errNotSecure
	}
	q := url.Values{}
	q.Set("space_id", strconv.FormatUint(spaceID, 10))
	q.Set("user_id", strconv.FormatUint(userID, 10))
	return c.doJSONCtx(ctx, http.MethodDelete, "/auth/members?"+q.Encode(), nil, nil)
}

// putEmptySecure 经 master 建空文件（服务端落盘）：secure 模式下 0 字节文件不走
// legacy 直写对象路径（客户端无需对 legacy mutable object 持直写票据）。
func (c *Client) putEmptySecure(remotePath string, replicas int, overwrite bool) error {
	return c.postJSON("/auth/files/empty", map[string]any{
		"path": remotePath, "overwrite": overwrite, "replicas": replicas,
	}, nil)
}

// ---- 带 ctx 的 JSON 请求工具（security.go 专用；与 client.go 的 postJSON/getJSON
// 同语义，仅 ctx 来源不同——Login/账号操作由调用方给 ctx）----

func (c *Client) postJSONCtx(ctx context.Context, path string, body any, out any) error {
	return c.doJSONCtx(ctx, http.MethodPost, path, body, out)
}

func (c *Client) getJSONCtx(ctx context.Context, path string, out any) error {
	return c.doJSONCtx(ctx, http.MethodGet, path, nil, out)
}

func (c *Client) doJSONCtx(ctx context.Context, method, path string, body any, out any) error {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), metadataTimeout)
		defer cancel()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.MasterURL+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method == http.MethodGet {
		// 与 getJSON 一致：meta 读依赖特性协商（secure 会话下同样经过 master）。
		req.Header.Set(featuresHeader, objectIDFeature)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := statusError(resp); err != nil {
		return err
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
