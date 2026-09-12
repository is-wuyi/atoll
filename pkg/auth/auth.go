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
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
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

// Wrap 用 token 校验包装 handler。token 为空时进入兼容模式：
// 不校验但每个敏感请求记一次 WARN（帮助运维确认升级窗口结束）。
func Wrap(next http.Handler, token Token) http.Handler {
	if token == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !exemptPaths[r.URL.Path] {
				log.Printf("WARN: auth 兼容模式（未配置 token）: %s %s", r.Method, r.URL.Path)
			}
			next.ServeHTTP(w, r)
		})
	}
	want := []byte("Bearer " + string(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exemptPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
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
