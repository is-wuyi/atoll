package master

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/access"
	"atoll/pkg/auth"
	"atoll/pkg/edgeidentity"
	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
	"atoll/pkg/peertransport"

	crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

type mPeerIdentity struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newMPeerIdentity(t *testing.T) mPeerIdentity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.UnmarshalEd25519PublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return mPeerIdentity{id: id.String(), pub: pub, priv: priv}
}

func mValidOp(t *testing.T) string {
	t.Helper()
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw[:])
}

// peerRuntimeStub 以固定正确身份实现 RuntimeAPI（不模拟真实网络拨号，
// 仅供 HTTP 路由/授权装配测试；SetDirectory/EnableRelay 为通过桩）。
type peerRuntimeStub struct {
	id   string
	pub  []byte
	dir  peerauth.Directory
	auth func(context.Context, string) bool
}

func (r *peerRuntimeStub) PeerID() string                                     { return r.id }
func (r *peerRuntimeStub) PublicKey() []byte                                  { return r.pub }
func (r *peerRuntimeStub) Sign([]byte) ([]byte, error)                        { return nil, errors.New("stub sign") }
func (r *peerRuntimeStub) Addresses() []string                                { return nil }
func (r *peerRuntimeStub) SetDirectory(d peerauth.Directory) error            { r.dir = d; return nil }
func (r *peerRuntimeStub) SetAuthorizer(f func(context.Context, string) bool) { r.auth = f }
func (r *peerRuntimeStub) AllowedPeer(id string) bool {
	return r.auth != nil && r.auth(context.Background(), id)
}
func (r *peerRuntimeStub) Listener() (net.Listener, error)                             { return nil, errors.New("stub listener") }
func (r *peerRuntimeStub) ConnContext(ctx context.Context, _ net.Conn) context.Context { return ctx }
func (r *peerRuntimeStub) ReserveRelay(context.Context, peerauth.Infrastructure) (time.Time, error) {
	return time.Time{}, errors.New("stub relay")
}
func (r *peerRuntimeStub) EnableRelay() error { return nil }
func (r *peerRuntimeStub) Dial(context.Context, peerauth.Endpoint, peerauth.Infrastructure, peerhttp.Path) peertransport.DialResult {
	return peertransport.DialResult{}
}
func (r *peerRuntimeStub) Close() error { return nil }

// mPeerFixture 装配一个安全 HTTPS + 写计划 + peer 目录已启用的 Server 与 store 状态。
type mPeerFixture struct {
	srv        *Server
	store      *meta.Store
	handler    http.Handler
	origin     string
	infra      mPeerIdentity
	now        time.Time
	deviceTok  string
	deviceID   uint64
	nodePeer   mPeerIdentity
	userTok    string
	userSpace  uint64
	clientPeer mPeerIdentity
	adminID    uint64
}

func newMPeerFixture(t *testing.T, runtime bool) *mPeerFixture {
	t.Helper()
	now := time.Now()
	s, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	admin, _, err := s.BootstrapSecurity("admin", "admin-password-123", now)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(s, time.Minute)
	// 安全模式（AllowInsecure=false）会设置 tlsCfg 与 https scheme。
	if err := srv.EnableSecurity(SecurityConfig{ControlToken: auth.Token(strings.Repeat("c", 32))}); err != nil {
		t.Fatalf("EnableSecurity: %v", err)
	}
	if err := srv.EnableWritePlanning(WritePlanningConfig{MaxReplicas: 2}); err != nil {
		t.Fatalf("EnableWritePlanning: %v", err)
	}
	infra := newMPeerIdentity(t)
	origin, err := peerauth.CanonicalOrigin("https://master.test")
	if err != nil {
		t.Fatal(err)
	}
	f := &mPeerFixture{srv: srv, store: s, origin: origin, infra: infra, now: now, adminID: admin.ID}
	cfg := PeerConfig{Origin: origin, Infrastructure: peerauth.Infrastructure{PeerID: infra.id, PublicKey: infra.pub, Addresses: []string{"/ip4/8.8.8.8/tcp/9400"}, Relay: true}}
	if err := srv.EnablePeerDirectory(cfg); err != nil {
		t.Fatalf("EnablePeerDirectory: %v", err)
	}
	// 设备（绑定 nodePeer）。
	f.deviceTok, f.deviceID, f.nodePeer = f.enrollDevice(t, "127.0.0.1:9443")
	// 用户会话 + 空间。
	_, space := f.makeUser(t, "peeruser")
	f.userTok = f.authenticate(t, "peeruser")
	f.userSpace = space.ID
	// 已注册的 client peer。
	f.clientPeer = newMPeerIdentity(t)
	if _, err := f.registerClient(t, f.userTok, f.userSpace, f.clientPeer, 0); err != nil {
		t.Fatalf("register client fixture: %v", err)
	}
	if runtime {
		stub := &peerRuntimeStub{id: infra.id, pub: infra.pub}
		if err := srv.SetPeerRuntime(stub); err != nil {
			t.Fatalf("SetPeerRuntime: %v", err)
		}
		if stub.dir.Protocol != peerauth.Feature {
			t.Fatalf("runtime 未收到目录: %+v", stub.dir)
		}
	}
	f.handler = srv.Handler()
	return f
}

func (f *mPeerFixture) enrollDevice(t *testing.T, addr string) (string, uint64, mPeerIdentity) {
	t.Helper()
	nodePeer := newMPeerIdentity(t)
	id, err := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), "dev.key"))
	if err != nil {
		t.Fatal(err)
	}
	invite, err := f.store.CreateDeviceInvite(f.now.Add(time.Hour), f.now)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := f.store.NewDeviceChallenge(access.DeviceChallengeRequest{
		PublicKey: id.PublicKey(), Addr: addr, TotalBytes: 1 << 20, Invite: invite,
		Peer: &peerauth.Enrollment{PeerID: nodePeer.id, PublicKey: nodePeer.pub, ExpectedRevision: 0},
	}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	deviceSig, _ := id.Sign(ch.Challenge)
	sess, err := f.store.CompleteDeviceChallenge(access.DeviceLoginRequest{
		ChallengeID: ch.ID, Signature: deviceSig,
		PeerSignature: ed25519.Sign(nodePeer.priv, peerauth.EnrollmentProof(ch.Challenge)),
	}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return sess.Token, sess.NodeID, nodePeer
}

func (f *mPeerFixture) makeUser(t *testing.T, name string) (meta.PublicUser, meta.Space) {
	t.Helper()
	code, err := f.store.CreateUserInvite(f.adminID, f.now.Add(time.Hour), f.now)
	if err != nil {
		t.Fatal(err)
	}
	user, space, err := f.store.RegisterInvitedUser(code, name, "invited-password-1", f.now)
	if err != nil {
		t.Fatal(err)
	}
	return user, space
}

func (f *mPeerFixture) authenticate(t *testing.T, name string) string {
	t.Helper()
	login, err := f.store.AuthenticateUser(name, "invited-password-1", f.now)
	if err != nil {
		t.Fatal(err)
	}
	return login.Token
}

func (f *mPeerFixture) registerClient(t *testing.T, session string, spaceID uint64, ident mPeerIdentity, expectedRev uint64) (peerauth.Endpoint, error) {
	t.Helper()
	req := peerauth.ClientRegistration{PeerID: ident.id, PublicKey: ident.pub, ExpectedRevision: expectedRev, OperationID: mValidOp(t), NotAfter: f.now.Add(time.Minute)}
	message, err := peerauth.ClientProof(f.origin, session, spaceID, req)
	if err != nil {
		t.Fatal(err)
	}
	req.Signature = ed25519.Sign(ident.priv, message)
	return f.store.RegisterClientPeer(session, spaceID, req, f.now)
}

func (f *mPeerFixture) do(t *testing.T, method, path, token string, spaceID uint64, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var space string
	if spaceID != 0 {
		space = strconv.FormatUint(spaceID, 10)
	}
	return f.request(t, method, path, token, space, true, body)
}

func (f *mPeerFixture) request(t *testing.T, method, path, token, spaceHeader string, secure bool, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if secure {
		req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS12}
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if spaceHeader != "" {
		req.Header.Set(access.SpaceHeader, spaceHeader)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// ---- HTTP 门：peer 目录未启用时路由必须 409 ----

func TestPeerHTTPRoutesDisabledWhenNotEnabled(t *testing.T) {
	s, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if _, _, err := s.BootstrapSecurity("admin", "admin-password-123", time.Now()); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(s, time.Minute)
	// AllowInsecure=true：无需 TLS 也能进入 securityHandler（EnablePeerDirectory 会拒绝它，
	// 但此处测试的是未启用 peer 目录的门）。
	if err := srv.EnableSecurity(SecurityConfig{ControlToken: auth.Token(strings.Repeat("c", 32)), AllowInsecure: true}); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	req := httptest.NewRequest(http.MethodGet, "/peers/directory", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("未启用 peer 目录应 409，got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "disabled") {
		t.Fatalf("409 信息不符: %s", rec.Body.String())
	}
}

// ---- 装配：peer 配置已启用但 runtime 未接线 → 503 ----

func TestPeerHTTPPeerConfigWithoutRuntimeIs503(t *testing.T) {
	f := newMPeerFixture(t, false) // 不调用 SetPeerRuntime
	rec := f.do(t, http.MethodGet, "/peers/directory", f.deviceTok, 0, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("config/runtime 不匹配应 503，got %d (%s)", rec.Code, rec.Body.String())
	}
}

// ---- 完整装配：目录/self/client-self/地址发布/客户端注册 ----

func TestPeerHTTPRoutesWithRuntime(t *testing.T) {
	f := newMPeerFixture(t, true)

	// GET /peers/directory（设备 token）：200，含基础设施与已注册 client。
	rec := f.do(t, http.MethodGet, "/peers/directory", f.deviceTok, 0, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("directory 应 200，got %d (%s)", rec.Code, rec.Body.String())
	}
	var dir peerauth.Directory
	if err := json.Unmarshal(rec.Body.Bytes(), &dir); err != nil {
		t.Fatalf("directory JSON: %v", err)
	}
	if dir.Protocol != peerauth.Feature || dir.Infrastructure.PeerID != f.infra.id {
		t.Fatalf("directory 内容不符: %+v", dir)
	}
	foundClient := false
	for _, ep := range dir.Endpoints {
		if ep.Role == peerauth.RoleClient && ep.PeerID == f.clientPeer.id {
			foundClient = true
		}
	}
	if !foundClient {
		t.Fatalf("directory 未列出已注册 client: %+v", dir.Endpoints)
	}

	// GET /peers/self（设备 token）：200，绑定已落。
	rec = f.do(t, http.MethodGet, "/peers/self", f.deviceTok, 0, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("self 应 200，got %d (%s)", rec.Code, rec.Body.String())
	}
	var state peerauth.NodeState
	if err := json.Unmarshal(rec.Body.Bytes(), &state); err != nil {
		t.Fatalf("self JSON: %v", err)
	}
	if state.Binding == nil || state.Binding.PeerID != f.nodePeer.id {
		t.Fatalf("self binding 不符: %+v", state)
	}

	// GET /peers/client-self（用户 token + space）：200。
	rec = f.do(t, http.MethodGet, "/peers/client-self?peer_id="+f.clientPeer.id, f.userTok, f.userSpace, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("client-self 应 200，got %d (%s)", rec.Code, rec.Body.String())
	}
	var cs peerauth.ClientState
	if err := json.Unmarshal(rec.Body.Bytes(), &cs); err != nil || cs.Revision == 0 {
		t.Fatalf("client-self JSON: %+v %v", cs, err)
	}

	// POST /peers/address（设备 token）：发布节点地址。
	addrReq := peerauth.AddressPublication{PeerID: f.nodePeer.id, BindingRevision: 1, ExpectedRevision: 0, OperationID: mValidOp(t), Addresses: []string{"/ip4/1.2.3.4/tcp/9400"}, NotAfter: f.now.Add(time.Minute)}
	msg, err := peerauth.PublicationProof(f.origin, f.deviceID, addrReq)
	if err != nil {
		t.Fatal(err)
	}
	addrReq.Signature = ed25519.Sign(f.nodePeer.priv, msg)
	addrBody, _ := json.Marshal(addrReq)
	rec = f.do(t, http.MethodPost, "/peers/address", f.deviceTok, 0, addrBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("address 应 200，got %d (%s)", rec.Code, rec.Body.String())
	}
	var pub peerauth.Endpoint
	if err := json.Unmarshal(rec.Body.Bytes(), &pub); err != nil || pub.Revision != 1 {
		t.Fatalf("address JSON: %+v %v", pub, err)
	}

	// POST /peers/client（用户 token + space）：注册新 client。
	nc := newMPeerIdentity(t)
	clientReq := peerauth.ClientRegistration{PeerID: nc.id, PublicKey: nc.pub, ExpectedRevision: 0, OperationID: mValidOp(t), NotAfter: f.now.Add(time.Minute)}
	cmsg, err := peerauth.ClientProof(f.origin, f.userTok, f.userSpace, clientReq)
	if err != nil {
		t.Fatal(err)
	}
	clientReq.Signature = ed25519.Sign(nc.priv, cmsg)
	clientBody, _ := json.Marshal(clientReq)
	rec = f.do(t, http.MethodPost, "/peers/client", f.userTok, f.userSpace, clientBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("client 应 200，got %d (%s)", rec.Code, rec.Body.String())
	}
	var creg peerauth.Endpoint
	if err := json.Unmarshal(rec.Body.Bytes(), &creg); err != nil || creg.Role != peerauth.RoleClient || creg.PeerID != nc.id {
		t.Fatalf("client JSON: %+v %v", creg, err)
	}

	// 未认证/错误 token：401。
	rec = f.do(t, http.MethodGet, "/peers/directory", "nd1_bad", 0, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("错误 token 应 401，got %d", rec.Code)
	}
}

// ---- 授权负向：会话缺失/伪造、空间缺失/非法/越权、设备/用户互访、控制凭据不得发现 ----

func TestPeerHTTPAuthNegative(t *testing.T) {
	f := newMPeerFixture(t, true)

	// 无 token：设备路由与用户路由都必须 401。
	if rec := f.do(t, http.MethodGet, "/peers/directory", "", 0, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("无 token directory 应 401，got %d", rec.Code)
	}
	if rec := f.do(t, http.MethodGet, "/peers/client-self", "", 0, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("无 token client-self 应 401，got %d", rec.Code)
	}

	// 伪造/非会话 token：401（不落入用户路径的越权）。
	for _, tok := range []string{"nd1_", "nd1_garbage", "user_garbage", "Bearer-with-space"} {
		if rec := f.do(t, http.MethodGet, "/peers/directory", tok, 0, nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("伪造 token %q 应 401，got %d", tok, rec.Code)
		}
	}

	// 控制凭据（ControlToken）不是设备也不是用户会话：不得发现 peer 目录。
	if rec := f.do(t, http.MethodGet, "/peers/directory", strings.Repeat("c", 32), 0, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("控制凭据不得发现目录，应 401，got %d", rec.Code)
	}

	// 设备访问 client 路由：403。
	if rec := f.do(t, http.MethodGet, "/peers/client-self", f.deviceTok, 0, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("设备访问 client-self 应 403，got %d", rec.Code)
	}
	if rec := f.do(t, http.MethodPost, "/peers/client", f.deviceTok, 0, []byte("{}")); rec.Code != http.StatusForbidden {
		t.Fatalf("设备访问 client 注册应 403，got %d", rec.Code)
	}

	// 用户访问 self/address（设备专属）：403。
	if rec := f.do(t, http.MethodGet, "/peers/self", f.userTok, f.userSpace, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("用户访问 self 应 403，got %d", rec.Code)
	}
	if rec := f.do(t, http.MethodPost, "/peers/address", f.userTok, f.userSpace, []byte("{}")); rec.Code != http.StatusForbidden {
		t.Fatalf("用户访问 address 应 403，got %d", rec.Code)
	}

	// 用户路径缺空间头：403（space required）。
	if rec := f.do(t, http.MethodGet, "/peers/client-self", f.userTok, 0, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("缺空间头应 403，got %d", rec.Code)
	}
	// 非法（非数字）与零空间头：403。
	if rec := f.request(t, http.MethodGet, "/peers/client-self", f.userTok, "not-a-number", true, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("非数字空间应 403，got %d", rec.Code)
	}
	if rec := f.request(t, http.MethodGet, "/peers/client-self", f.userTok, "0", true, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("零空间应 403，got %d", rec.Code)
	}
	// 越权空间（合法 ID，但用户非成员）：403（access denied）。
	_, foreignSpace := f.makeUser(t, "otheruser")
	if rec := f.do(t, http.MethodGet, "/peers/client-self", f.userTok, foreignSpace.ID, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("越权空间应 403，got %d", rec.Code)
	}
}

// ---- 查询参数与请求体负向：多余查询、非法 body、缺失证明、重复幂等 ----

func TestPeerHTTPQueryAndBodyNegative(t *testing.T) {
	f := newMPeerFixture(t, true)

	// 设备路由携带查询参数：400（client-self 除外，其查询为专用字段）。
	for _, p := range []string{"/peers/directory?x=1", "/peers/self?x=1"} {
		if rec := f.do(t, http.MethodGet, p, f.deviceTok, 0, nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s 带查询应 400，got %d", p, rec.Code)
		}
	}
	// client-self 专用查询字段非法/缺失/多余：400。
	for _, q := range []string{"/peers/client-self", "/peers/client-self?peer_id=not-valid", "/peers/client-self?peer_id=" + f.clientPeer.id + "&extra=1"} {
		if rec := f.do(t, http.MethodGet, q, f.userTok, f.userSpace, nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s 查询非法应 400，got %d", q, rec.Code)
		}
	}

	// 非法 JSON body：400。
	if rec := f.do(t, http.MethodPost, "/peers/address", f.deviceTok, 0, []byte("{bad")); rec.Code != http.StatusBadRequest {
		t.Fatalf("address 非法 JSON 应 400，got %d", rec.Code)
	}
	if rec := f.do(t, http.MethodPost, "/peers/client", f.userTok, f.userSpace, []byte("{bad")); rec.Code != http.StatusBadRequest {
		t.Fatalf("client 非法 JSON 应 400，got %d", rec.Code)
	}

	// 缺失证明字段（无 signature 键）：DecodeJSON 必填校验 → 400。
	noField := map[string]any{
		"peer_id": f.nodePeer.id, "binding_revision": 1, "expected_revision": 0,
		"operation_id": mValidOp(t), "addresses": []string{"/ip4/1.2.3.4/tcp/9400"},
		"not_after": f.now.Add(time.Minute),
	}
	noFieldBody, _ := json.Marshal(noField)
	if rec := f.do(t, http.MethodPost, "/peers/address", f.deviceTok, 0, noFieldBody); rec.Code != http.StatusBadRequest {
		t.Fatalf("缺失 signature 字段应 400，got %d (%s)", rec.Code, rec.Body.String())
	}

	// 无效证明（signature 为 64 个零字节，结构合法但验签失败）：409。
	wrongSig := peerauth.AddressPublication{PeerID: f.nodePeer.id, BindingRevision: 1, ExpectedRevision: 0, OperationID: mValidOp(t), Addresses: []string{"/ip4/1.2.3.4/tcp/9400"}, NotAfter: f.now.Add(time.Minute), Signature: make([]byte, 64)}
	wrongSigBody, _ := json.Marshal(wrongSig)
	if rec := f.do(t, http.MethodPost, "/peers/address", f.deviceTok, 0, wrongSigBody); rec.Code != http.StatusConflict {
		t.Fatalf("无效证明应 409，got %d (%s)", rec.Code, rec.Body.String())
	}

	// 重复同 op：幂等，第二次仍 200 且 rev 不变。
	addrReq := peerauth.AddressPublication{PeerID: f.nodePeer.id, BindingRevision: 1, ExpectedRevision: 0, OperationID: mValidOp(t), Addresses: []string{"/ip4/1.2.3.4/tcp/9400"}, NotAfter: f.now.Add(time.Minute)}
	msg, err := peerauth.PublicationProof(f.origin, f.deviceID, addrReq)
	if err != nil {
		t.Fatal(err)
	}
	addrReq.Signature = ed25519.Sign(f.nodePeer.priv, msg)
	addrBody, _ := json.Marshal(addrReq)
	rec1 := f.do(t, http.MethodPost, "/peers/address", f.deviceTok, 0, addrBody)
	if rec1.Code != http.StatusOK {
		t.Fatalf("首次发布应 200，got %d (%s)", rec1.Code, rec1.Body.String())
	}
	var ep1 peerauth.Endpoint
	if err := json.Unmarshal(rec1.Body.Bytes(), &ep1); err != nil {
		t.Fatalf("首次发布 JSON: %v", err)
	}
	rec2 := f.do(t, http.MethodPost, "/peers/address", f.deviceTok, 0, addrBody)
	if rec2.Code != http.StatusOK {
		t.Fatalf("重复同 op 应 200 幂等，got %d (%s)", rec2.Code, rec2.Body.String())
	}
	var ep2 peerauth.Endpoint
	if err := json.Unmarshal(rec2.Body.Bytes(), &ep2); err != nil {
		t.Fatalf("重复发布 JSON: %v", err)
	}
	if ep2.Revision != ep1.Revision {
		t.Fatalf("幂等不应提升 rev：first=%d second=%d", ep1.Revision, ep2.Revision)
	}
}

// ---- TLS 前置：明文 426，真实 TLS 200 ----

func TestPeerHTTPTLSFront(t *testing.T) {
	f := newMPeerFixture(t, true)

	// 明文请求（r.TLS==nil 且安全模式禁 AllowInsecure）：securityHandler 426。
	if rec := f.request(t, http.MethodGet, "/peers/directory", f.deviceTok, "", false, nil); rec.Code != http.StatusUpgradeRequired {
		t.Fatalf("明文应 426，got %d", rec.Code)
	}

	// 真实 TLS 服务器：握手成功即可访问。
	ts := httptest.NewTLSServer(f.handler)
	t.Cleanup(ts.Close)
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/peers/directory", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+f.deviceTok)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("TLS 请求: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("真实 TLS 应 200，got %d", resp.StatusCode)
	}
}

// ---- 设备撤销后 token 立即失效：401 ----

func TestPeerHTTPDeviceRevoked(t *testing.T) {
	f := newMPeerFixture(t, true)
	if err := f.store.RevokeDevice(f.deviceID); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	if rec := f.do(t, http.MethodGet, "/peers/directory", f.deviceTok, 0, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("撤销设备后应 401，got %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := f.do(t, http.MethodGet, "/peers/self", f.deviceTok, 0, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("撤销设备后 self 应 401，got %d", rec.Code)
	}
}
