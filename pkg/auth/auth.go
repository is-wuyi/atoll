// Package auth 实现组件间认证：静态 Bearer Token 校验中间件与请求注入。
//
// 设计约束（见 .trae/specs/stage5-ops-hardening/batch-b-auth-spec.md）：
//   - 单一集群密钥，所有角色共享（家庭集群，不做 per-principal 身份）
//   - 常数时间比较防时序侧信道
//   - token 为空 = 兼容模式（不校验，记 WARN），用于滚动升级窗口
//   - /healthz 永远豁免（探活无敏感信息，监控工具不需要钥匙）
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
)

// exemptPaths 永远免认证的路径（探活）。
var exemptPaths = map[string]bool{"/healthz": true}

// Token injects the Authorization header for outgoing requests.
type Token string

// Set 给请求注入 Bearer 头。空 token 不注入（兼容模式客户端）。
func (t Token) Set(r *http.Request) {
	if t == "" {
		return
	}
	r.Header.Set("Authorization", "Bearer "+string(t))
}

// Transport 在每次出站请求上自动注入 token。
type Transport struct {
	Token    Token
	Fallback http.RoundTripper // nil 时用 http.DefaultTransport
}

func (tr *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr.Token.Set(req)
	rt := tr.Fallback
	if rt == nil {
		rt = http.DefaultTransport
	}
	return rt.RoundTrip(req)
}

// ClientTLS 从 CA 文件（可空，空则用系统根）构建客户端 TLS 配置。
// skipVerify=true 跳过证书校验（仅用于自签名的可信内网，不校验主机名/链）。
func ClientTLS(caFile string, skipVerify bool) (*tls.Config, error) {
	cfg := &tls.Config{InsecureSkipVerify: skipVerify} //nolint:gosec // skipVerify 由运维显式开启
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA %s: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA %s: no valid certs", caFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// HTTPTransport 构建一个带 token 注入 + 可选 TLS 配置的出站 transport。
// tlsCfg 为空则为普通 HTTP（等价旧行为）。base 为空则克隆 http.DefaultTransport。
func HTTPTransport(token Token, tlsCfg *tls.Config, base *http.Transport) *Transport {
	if base == nil {
		base = http.DefaultTransport.(*http.Transport).Clone()
	}
	if tlsCfg != nil {
		base.TLSClientConfig = tlsCfg
	}
	return &Transport{Token: token, Fallback: base}
}

// Wrap 用 token 校验包装 handler（无独立管理 token，等价于读写管共用一把钥匙）。
func Wrap(next http.Handler, token Token) http.Handler {
	return WrapTokens(next, token, "", nil)
}

// WrapTokens 用集群 token + 可选管理 token 校验包装 handler：
//   - adminPaths 命中的路径需要 adminToken（破坏性操作，如 /admin/gc）；
//   - 其余路径需要 token（普通读写）；
//   - adminToken 为空 → 管理路径回退用 token 校验（向后兼容，读/管不分离）；
//   - token 也为空 → 兼容模式：不校验但敏感请求记一次 WARN。
//
// 读/管分离的价值：单一 token 泄露时不至于同时拿到 `gc --execute` 这类破坏性权限。
func WrapTokens(next http.Handler, token, adminToken Token, adminPaths map[string]bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exemptPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		required := token
		if adminPaths[r.URL.Path] && adminToken != "" {
			required = adminToken
		}
		if required == "" {
			log.Printf("WARN: auth 兼容模式（未配置 token）: %s %s", r.Method, r.URL.Path)
			next.ServeHTTP(w, r)
			return
		}
		want := []byte("Bearer " + string(required))
		got := r.Header.Get("Authorization")
		if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Generate 生成随机 32 字节 base64 token（43 字符）。
func Generate() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
