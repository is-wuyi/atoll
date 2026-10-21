package metacrypto

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"atoll/pkg/contentcrypto"
)

func readerCipher(t *testing.T) *Cipher {
	t.Helper()
	kek, err := contentcrypto.NewKEK("reader-test")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(kek)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// 恢复签名全链路：正常验证通过；过期拒绝；时钟容差内（±ReaderClockSkew）通过。
func TestReaderProofLifecycle(t *testing.T) {
	c := readerCipher(t)
	now := time.Now()
	req := httptest.NewRequest(http.MethodGet, "http://node-a:9421/meta-backup/manifest", nil)
	if err := c.SignRead(req, "node-a:9421", now); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRead(c.ReaderInfo(), req, "node-a:9421", now); err != nil {
		t.Fatalf("fresh proof rejected: %v", err)
	}
	// 验证方时钟落后/超前在容差内：接受。
	if err := VerifyRead(c.ReaderInfo(), req, "node-a:9421", now.Add(-ReaderClockSkew+time.Second)); err != nil {
		t.Fatalf("skew tolerance (behind) rejected: %v", err)
	}
	if err := VerifyRead(c.ReaderInfo(), req, "node-a:9421", now.Add(ReaderClockSkew-time.Second)); err != nil {
		t.Fatalf("skew tolerance (ahead) rejected: %v", err)
	}
	// 明确过期（超过容差）：拒绝。
	if err := VerifyRead(c.ReaderInfo(), req, "node-a:9421", now.Add(ReaderTTL+ReaderClockSkew+time.Second)); err == nil {
		t.Fatal("expired proof accepted")
	}
}

// 跨主机重放：为节点 A 签的证明在节点 B 必须拒绝（Host 绑定）。
func TestReaderProofBindsHost(t *testing.T) {
	c := readerCipher(t)
	now := time.Now()
	reqA := httptest.NewRequest(http.MethodGet, "http://node-a:9421/meta-backup/manifest", nil)
	if err := c.SignRead(reqA, "node-a:9421", now); err != nil {
		t.Fatal(err)
	}
	reqB := httptest.NewRequest(http.MethodGet, "http://node-b:9421/meta-backup/manifest", nil)
	reqB.Header.Set(ReaderHeader, reqA.Header.Get(ReaderHeader))
	if err := VerifyRead(c.ReaderInfo(), reqB, "node-b:9421", now); err == nil {
		t.Fatal("proof for host A verified on host B: Host not bound")
	}
	// Host 头与 URL host 不一致也拒绝（签名后的 Host 不能被改）。
	reqC := httptest.NewRequest(http.MethodGet, "http://node-a:9421/meta-backup/manifest", nil)
	reqC.Host = "node-b:9421"
	reqC.Header.Set(ReaderHeader, reqA.Header.Get(ReaderHeader))
	if err := VerifyRead(c.ReaderInfo(), reqC, "node-a:9421", now); err == nil {
		t.Fatal("mismatched Host header accepted")
	}
}

// 签名后注入 Authorization 等其它凭据：拒绝；写方法/带查询也拒绝。
func TestReaderProofRejectsInjectedCredentialsAndWrites(t *testing.T) {
	c := readerCipher(t)
	now := time.Now()
	req := httptest.NewRequest(http.MethodGet, "http://node-a:9421/meta-backup/wal-sync-7", nil)
	if err := c.SignRead(req, "node-a:9421", now); err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer forged")
	if err := VerifyRead(c.ReaderInfo(), req, "node-a:9421", now); err == nil {
		t.Fatal("credential header injected post-signature is invisible")
	}
	// 非 GET 拒绝（恢复只读，无写权限——写删走在线控制票据）。
	put := httptest.NewRequest(http.MethodPut, "http://node-a:9421/meta-backup/wal-sync-7", nil)
	if err := c.SignRead(put, "node-a:9421", now); err == nil {
		t.Fatal("write method accepted for signing")
	}
	// 证明换到不同 audience 拒绝。
	if err := VerifyRead(c.ReaderInfo(), req, "node-c:9421", now); err == nil {
		t.Fatal("proof replayed to a different audience")
	}
}
