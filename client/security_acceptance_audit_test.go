package client

// security_acceptance_audit_test.go —— 独立验收审计回归（只读实现，仅新增本文件）。
//
// 与 security_test.go 既有覆盖不重叠，聚焦两个此前未钉死的验收点：
//  1. space 切换后票据逐请求重取并携带新 space：客户端绝不缓存节点票据（换票即
//     重新鉴权，权限/space 变更对下一次节点请求立即生效），同 space 连续两次节点
//     请求同样各换一次票；节点侧只见票据，永不见会话/space。
//  2. master 不可达时的 Logout：在线注销失败也必须清除本地会话——之后的节点请求
//     本地拒绝（零触达节点、零换票），不允许「注销失败 → 失效凭据继续可用」。

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"atoll/pkg/access"
)

// 1) space 变更/不变更都逐请求换票：票据是「一次一取」，无任何客户端侧缓存。
func TestAuditSpaceChangeReissuesTicketsPerRequest(t *testing.T) {
	c, spy, node := newSecureTestCluster(t, nil, nil)

	doGet := func(obj string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, node.URL+"/objects/"+obj, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			t.Fatalf("GET /objects/%s: %v", obj, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /objects/%s = %d, want 200", obj, resp.StatusCode)
		}
	}
	snapshot := func() (int, access.TicketRequest, string) {
		spy.mu.Lock()
		defer spy.mu.Unlock()
		return spy.ticketCnt, spy.ticketReq, spy.space["/security/tickets"]
	}

	// 基线：space 7 下第一次节点请求 → 换票 1 次，绑定该请求、space=7。
	doGet("11")
	cnt1, tr1, sp1 := snapshot()
	if cnt1 != 1 || tr1.Path != "/objects/11" || sp1 != testSpaceID {
		t.Fatalf("phase1: cnt=%d tr=%+v space=%q", cnt1, tr1, sp1)
	}

	// 切换 space → 下一笔节点请求必须以新 space 重取票（旧票不得复用）。
	if err := c.UseSpace(9); err != nil {
		t.Fatal(err)
	}
	doGet("22")
	cnt2, tr2, sp2 := snapshot()
	if cnt2 != 2 || tr2.Path != "/objects/22" {
		t.Fatalf("phase2: ticket must be re-fetched per request: cnt=%d tr=%+v", cnt2, tr2)
	}
	if sp2 != "9" {
		t.Fatalf("phase2: ticket request space = %q, want 9 (new space must take effect immediately)", sp2)
	}

	// space 不变：同空间第二笔请求仍逐请求换票（不缓存 allow/票据）。
	doGet("33")
	cnt3, tr3, sp3 := snapshot()
	if cnt3 != 3 || tr3.Path != "/objects/33" || sp3 != "9" {
		t.Fatalf("phase3: ticket re-fetch per request even without space change: cnt=%d tr=%+v space=%q", cnt3, tr3, sp3)
	}

	// 节点侧始终只见票据：会话/space 头零外发。
	spy.mu.Lock()
	nodeAuth, nodeSpace := spy.nodeAuth, spy.nodeSpace
	spy.mu.Unlock()
	if nodeAuth != "Bearer "+testTicket {
		t.Fatalf("node auth = %q, want ticket bearer", nodeAuth)
	}
	if nodeSpace != "" {
		t.Fatalf("space header must never reach node, got %q", nodeSpace)
	}
}

//  2. master 不可达：Logout 在线注销失败仍清除本地会话；此后节点请求本地拒绝，
//     零触达节点、零换票（失效凭据不得因注销失败而继续可用）。
func TestAuditLogoutClearsSessionEvenWhenMasterUnreachable(t *testing.T) {
	var nodeHits int32
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&nodeHits, 1)
		io.WriteString(w, "payload")
	}))
	defer node.Close()

	masterMux := http.NewServeMux()
	masterMux.HandleFunc("/security/tickets", func(w http.ResponseWriter, _ *http.Request) {
		// 仅服务对照阶段的换票；在线注销路由不存在（注销必须失败但仍清会话）。
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"audit-node-ticket","expires_at":"2099-01-01T00:00:00Z"}`)
	})
	master := httptest.NewServer(masterMux)
	defer master.Close()
	c, err := NewSecure(master.URL, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetSession("sess-audit-tok"); err != nil {
		t.Fatal(err)
	}
	if err := c.UseSpace(7); err != nil {
		t.Fatal(err)
	}

	// 对照：注销前同一客户端的节点请求正常走通（证明后面的拒绝来自会话清除）。
	req, err := http.NewRequest(http.MethodGet, node.URL+"/objects/1", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		t.Fatalf("control node GET before logout: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("control node GET = %d, want 200", resp.StatusCode)
	}
	if atomic.LoadInt32(&nodeHits) != 1 {
		t.Fatalf("control GET must reach node once, hits=%d", atomic.LoadInt32(&nodeHits))
	}

	// master 彻底不可达下注销：错误上抛，但本地会话必须清除。
	master.Close()
	if lerr := c.Logout(context.Background()); lerr == nil {
		t.Fatal("logout against unreachable master must surface the error")
	}

	// 节点请求在换票前本地拒绝，零网络触达。
	req2, err := http.NewRequest(http.MethodGet, node.URL+"/objects/1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.HTTP.Do(req2); err == nil {
		t.Fatal("node request after failed logout must be locally denied (session cleared)")
	}
	if hits := atomic.LoadInt32(&nodeHits); hits != 1 {
		t.Fatalf("node must not be contacted after failed logout: hits=%d", hits)
	}
}
