package master

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"atoll/pkg/peerauth"
)

// ---- HTTP POST /peers/client/release：路由、门禁与释放后状态 ----

func TestPeerHTTPClientReleaseRoute(t *testing.T) {
	f := newMPeerFixture(t, true)
	relReq := peerauth.ClientRegistration{PeerID: f.clientPeer.id, PublicKey: f.clientPeer.pub, ExpectedRevision: 1, OperationID: mValidOp(t), NotAfter: f.now.Add(30 * time.Second)}
	msg, err := peerauth.ClientReleaseProof(f.origin, f.userTok, f.userSpace, relReq)
	if err != nil {
		t.Fatal(err)
	}
	relReq.Signature = ed25519.Sign(f.clientPeer.priv, msg)
	body, _ := json.Marshal(relReq)
	rec := f.do(t, http.MethodPost, "/peers/client/release", f.userTok, f.userSpace, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("release 应 200，got %d (%s)", rec.Code, rec.Body.String())
	}
	var st peerauth.ClientState
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || st.Revision != 2 {
		t.Fatalf("release 应返回 rev=2: %+v %v", st, err)
	}
	// 同 body 重放幂等。
	if rec := f.do(t, http.MethodPost, "/peers/client/release", f.userTok, f.userSpace, body); rec.Code != http.StatusOK {
		t.Fatalf("release 重放应 200 幂等，got %d (%s)", rec.Code, rec.Body.String())
	}
	// 释放后目录不再列出该 client。
	rec = f.do(t, http.MethodGet, "/peers/directory", f.deviceTok, 0, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("directory 应 200，got %d", rec.Code)
	}
	var dir peerauth.Directory
	if err := json.Unmarshal(rec.Body.Bytes(), &dir); err != nil {
		t.Fatal(err)
	}
	for _, ep := range dir.Endpoints {
		if ep.PeerID == f.clientPeer.id {
			t.Fatal("released client 不应列入目录")
		}
	}
	// owner 视角 client-self 仍可查，rev=2。
	rec = f.do(t, http.MethodGet, "/peers/client-self?peer_id="+f.clientPeer.id, f.userTok, f.userSpace, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("client-self 应 200，got %d (%s)", rec.Code, rec.Body.String())
	}
	var cs peerauth.ClientState
	if err := json.Unmarshal(rec.Body.Bytes(), &cs); err != nil || cs.Revision != 2 {
		t.Fatalf("client-self rev 应 2: %+v %v", cs, err)
	}
	// 门禁矩阵。
	if rec := f.do(t, http.MethodPost, "/peers/client/release", f.deviceTok, 0, body); rec.Code != http.StatusForbidden {
		t.Fatalf("设备 token release 应 403，got %d", rec.Code)
	}
	if rec := f.do(t, http.MethodPost, "/peers/client/release", "", 0, body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("无 token release 应 401，got %d", rec.Code)
	}
	if rec := f.do(t, http.MethodPost, "/peers/client/release", f.userTok, 0, body); rec.Code != http.StatusForbidden {
		t.Fatalf("缺 space release 应 403，got %d", rec.Code)
	}
	if rec := f.do(t, http.MethodPost, "/peers/client/release", f.userTok, f.userSpace, []byte("{bad")); rec.Code != http.StatusBadRequest {
		t.Fatalf("坏 JSON 应 400，got %d", rec.Code)
	}
	noSig := map[string]any{"peer_id": f.clientPeer.id, "public_key": f.clientPeer.pub, "expected_revision": 2, "operation_id": mValidOp(t), "not_after": f.now.Add(30 * time.Second)}
	noSigBody, _ := json.Marshal(noSig)
	if rec := f.do(t, http.MethodPost, "/peers/client/release", f.userTok, f.userSpace, noSigBody); rec.Code != http.StatusBadRequest {
		t.Fatalf("缺 signature 应 400，got %d (%s)", rec.Code, rec.Body.String())
	}
	// 注册域签名调 release：验签失败 → 409。
	regDom := peerauth.ClientRegistration{PeerID: f.clientPeer.id, PublicKey: f.clientPeer.pub, ExpectedRevision: 2, OperationID: mValidOp(t), NotAfter: f.now.Add(30 * time.Second)}
	msgReg, err := peerauth.ClientProof(f.origin, f.userTok, f.userSpace, regDom)
	if err != nil {
		t.Fatal(err)
	}
	regDom.Signature = ed25519.Sign(f.clientPeer.priv, msgReg)
	regDomBody, _ := json.Marshal(regDom)
	if rec := f.do(t, http.MethodPost, "/peers/client/release", f.userTok, f.userSpace, regDomBody); rec.Code != http.StatusConflict {
		t.Fatalf("注册域签名 release 应 409，got %d", rec.Code)
	}
	// 未知 peer release → 409。
	unk := newMPeerIdentity(t)
	unkReq := peerauth.ClientRegistration{PeerID: unk.id, PublicKey: unk.pub, ExpectedRevision: 1, OperationID: mValidOp(t), NotAfter: f.now.Add(30 * time.Second)}
	msgU, err := peerauth.ClientReleaseProof(f.origin, f.userTok, f.userSpace, unkReq)
	if err != nil {
		t.Fatal(err)
	}
	unkReq.Signature = ed25519.Sign(unk.priv, msgU)
	unkBody, _ := json.Marshal(unkReq)
	if rec := f.do(t, http.MethodPost, "/peers/client/release", f.userTok, f.userSpace, unkBody); rec.Code != http.StatusConflict {
		t.Fatalf("未知 peer release 应 409，got %d", rec.Code)
	}
	// 请求体 64KiB wire 上限：不因目录响应上限放大。
	huge := make([]byte, peerauth.MaxJSONBytes+1)
	for i := range huge {
		huge[i] = 'x'
	}
	if rec := f.do(t, http.MethodPost, "/peers/client/release", f.userTok, f.userSpace, huge); rec.Code != http.StatusBadRequest {
		t.Fatalf("超 64KiB 请求应 400，got %d", rec.Code)
	}
	t.Run("released-fresh-registration-advances-revision", func(t *testing.T) {
		f := newMPeerFixture(t, true)
		_, body := signedRelease(t, f, 1)
		if rec := f.do(t, http.MethodPost, "/peers/client/release", f.userTok, f.userSpace, body); rec.Code != http.StatusOK {
			t.Fatalf("release 应 200，got %d (%s)", rec.Code, rec.Body.String())
		}
		regReq := peerauth.ClientRegistration{PeerID: f.clientPeer.id, PublicKey: f.clientPeer.pub, ExpectedRevision: 2, OperationID: mValidOp(t), NotAfter: f.now.Add(time.Minute)}
		msg2, err := peerauth.ClientProof(f.origin, f.userTok, f.userSpace, regReq)
		if err != nil {
			t.Fatal(err)
		}
		regReq.Signature = ed25519.Sign(f.clientPeer.priv, msg2)
		regBody, _ := json.Marshal(regReq)
		rec := f.do(t, http.MethodPost, "/peers/client", f.userTok, f.userSpace, regBody)
		if rec.Code != http.StatusOK {
			t.Fatalf("new signed registration must succeed: %d (%s)", rec.Code, rec.Body.String())
		}
		var endpoint peerauth.Endpoint
		if err := json.Unmarshal(rec.Body.Bytes(), &endpoint); err != nil || endpoint.Revision != 3 {
			t.Fatalf("registration did not advance revision: %+v %v", endpoint, err)
		}
		if rec := f.do(t, http.MethodPost, "/peers/client/release", f.userTok, f.userSpace, body); rec.Code != http.StatusConflict {
			t.Fatalf("old release must not affect re-registration: %d", rec.Code)
		}
	})
	t.Run("released-second-release-must-conflict", func(t *testing.T) {
		f := newMPeerFixture(t, true)
		_, body := signedRelease(t, f, 1)
		if rec := f.do(t, http.MethodPost, "/peers/client/release", f.userTok, f.userSpace, body); rec.Code != http.StatusOK {
			t.Fatalf("release 应 200，got %d (%s)", rec.Code, rec.Body.String())
		}
		rel2 := peerauth.ClientRegistration{PeerID: f.clientPeer.id, PublicKey: f.clientPeer.pub, ExpectedRevision: 2, OperationID: mValidOp(t), NotAfter: f.now.Add(30 * time.Second)}
		msg3, err := peerauth.ClientReleaseProof(f.origin, f.userTok, f.userSpace, rel2)
		if err != nil {
			t.Fatal(err)
		}
		rel2.Signature = ed25519.Sign(f.clientPeer.priv, msg3)
		rel2Body, _ := json.Marshal(rel2)
		if rec := f.do(t, http.MethodPost, "/peers/client/release", f.userTok, f.userSpace, rel2Body); rec.Code != http.StatusConflict {
			t.Errorf("released 后不同 op 二次 release 必须 409，got %d (%s)", rec.Code, rec.Body.String())
		}
	})
}

// signedRelease 以当前 rev 签发一次 release 请求体。
func signedRelease(t *testing.T, f *mPeerFixture, expectedRev uint64) (peerauth.ClientRegistration, []byte) {
	t.Helper()
	relReq := peerauth.ClientRegistration{PeerID: f.clientPeer.id, PublicKey: f.clientPeer.pub, ExpectedRevision: expectedRev, OperationID: mValidOp(t), NotAfter: f.now.Add(30 * time.Second)}
	msg, err := peerauth.ClientReleaseProof(f.origin, f.userTok, f.userSpace, relReq)
	if err != nil {
		t.Fatal(err)
	}
	relReq.Signature = ed25519.Sign(f.clientPeer.priv, msg)
	body, _ := json.Marshal(relReq)
	return relReq, body
}

// ---- peer 路由任何错误响应不得回显凭据（token/签名/公钥） ----

func TestPeerHTTPPeerResponsesNeverEchoCredentials(t *testing.T) {
	f := newMPeerFixture(t, true)
	control := strings.Repeat("c", 32)
	secrets := []string{f.userTok, f.deviceTok, control}
	probe := func(label string, rec *httptest.ResponseRecorder) {
		t.Helper()
		for _, sec := range secrets {
			if sec != "" && strings.Contains(rec.Body.String(), sec) {
				t.Errorf("%s: %d 响应体回显凭据: %q", label, rec.Code, rec.Body.String())
			}
		}
	}
	probe("伪造设备 token", f.do(t, http.MethodGet, "/peers/directory", "nd1_garbage", 0, nil))
	probe("伪造用户 token", f.do(t, http.MethodGet, "/peers/client-self", "user_garbage", f.userSpace, nil))
	probe("控制凭据", f.do(t, http.MethodGet, "/peers/directory", control, 0, nil))
	probe("缺 space", f.do(t, http.MethodPost, "/peers/client", f.userTok, 0, []byte("{}")))
	probe("坏 JSON", f.do(t, http.MethodPost, "/peers/client/release", f.userTok, f.userSpace, []byte("{bad")))
	// 签名与公钥同样不得出现在错误响应体中。
	stale := peerauth.ClientRegistration{PeerID: f.clientPeer.id, PublicKey: f.clientPeer.pub, ExpectedRevision: 99, OperationID: mValidOp(t), NotAfter: f.now.Add(30 * time.Second)}
	msg, err := peerauth.ClientReleaseProof(f.origin, f.userTok, f.userSpace, stale)
	if err != nil {
		t.Fatal(err)
	}
	stale.Signature = ed25519.Sign(f.clientPeer.priv, msg)
	body, _ := json.Marshal(stale)
	rec := f.do(t, http.MethodPost, "/peers/client/release", f.userTok, f.userSpace, body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("陈旧 expected release 应 409，got %d", rec.Code)
	}
	probe("陈旧 release", rec)
	if strings.Contains(rec.Body.String(), hex.EncodeToString(stale.Signature)) {
		t.Error("release 409 响应体不得回显签名")
	}
}
