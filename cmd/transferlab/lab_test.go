package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/node"
	"atoll/pkg/auth"
)

// labNode 起一个未注册 ID 的生产 node（legacy 直写路径不依赖 master），外层包 lab。
func labNode(t *testing.T, token string) (*nodeLab, *httptest.Server) {
	t.Helper()
	n := node.New(t.TempDir(), "http://127.0.0.1:1", "127.0.0.1:1", 1<<30)
	n.SetToken(auth.Token(token))
	lab := newNodeLab("T", 64)
	ts := httptest.NewServer(lab.WrapNode(n, auth.Token(token)))
	t.Cleanup(ts.Close)
	return lab, ts
}

func labPutFault(t *testing.T, base, token string, f nodeFault) {
	t.Helper()
	if _, err := postFault(t, base, token, f); err != nil {
		t.Fatal(err)
	}
}

// postFault 设置故障并返回状态码（400 等 HTTP 语义测试用）。
func postFault(t *testing.T, base, token string, f nodeFault) (int, error) {
	t.Helper()
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, base+"/lab/fault", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != 200 {
		return resp.StatusCode, fmt.Errorf("设置故障: %d", resp.StatusCode)
	}
	return 200, nil
}

func TestRecorderCountsBytesAndGuardsPrivacy(t *testing.T) {
	const token = "test-token-transferlab-0123456789"
	lab, ts := labNode(t, token)
	payload := bytes.Repeat([]byte{7}, 4096)
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/objects/123456", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("PUT 状态 %d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/objects/123456", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("GET: %v %d", err, resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(got, payload) {
		t.Fatal("对象内容不一致")
	}
	if lab.activeGets.Load() != 0 || lab.gets.Load() != 1 || lab.puts.Load() != 1 {
		t.Fatalf("计数错误: gets=%d puts=%d active=%d", lab.gets.Load(), lab.puts.Load(), lab.activeGets.Load())
	}
	// 事件 NDJSON：有字节数与路由，绝无 Authorization/内容。
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/lab/events", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("lab/events: %v %d", err, resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	text := string(raw)
	if !strings.Contains(text, `"body_bytes":4096`) || !strings.Contains(text, `/objects/123456`) {
		t.Fatalf("事件缺计量或路由: %s", text)
	}
	if strings.Contains(text, "Authorization") || strings.Contains(text, string(payload[:32])) {
		t.Fatal("事件泄露了凭据或对象内容")
	}
	// 未带 token 的 lab 路由必须 401。
	resp, err = http.Get(ts.URL + "/lab/events")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无 token 访问 /lab/events 应 401，got %d", resp.StatusCode)
	}
}

func TestFaultReadDelayOnlyFullGets(t *testing.T) {
	const token = "test-token-transferlab-0123456789"
	lab, ts := labNode(t, token)
	payload := bytes.Repeat([]byte{1}, 2048)
	put(t, ts.URL+"/objects/777", token, payload)
	labPutFault(t, ts.URL, token, nodeFault{Kind: "read_delay", Target: "get", DelayMS: 250})
	started := time.Now()
	body := get(t, ts.URL+"/objects/777", token, 200)
	if time.Since(started) < 250*time.Millisecond {
		t.Fatal("完整 GET 未被延迟")
	}
	if !bytes.Equal(body, payload) {
		t.Fatal("延迟后内容不一致")
	}
	started = time.Now()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/objects/777", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Range", "bytes=0-0") // master 探测形态
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 206 {
		t.Fatalf("Range 探测应 206，got %d", resp.StatusCode)
	}
	if time.Since(started) > 250*time.Millisecond {
		t.Fatal("Range 探测不应被 read_delay 命中")
	}
	if lab.activeGets.Load() != 0 {
		t.Fatal("active GET 计数未归零")
	}
}

func TestFaultDropAbortsAndAckErrorKeepsObject(t *testing.T) {
	const token = "test-token-transferlab-0123456789"
	lab, ts := labNode(t, token)
	put(t, ts.URL+"/objects/888", token, []byte("hello-drop"))
	labPutFault(t, ts.URL, token, nodeFault{Kind: "drop", Target: "get", ObjectID: 888})
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/objects/888", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := http.DefaultClient.Do(req); err == nil {
		t.Fatal("drop 故障应中断连接")
	}
	dropped := false
	lab.mu.Lock()
	for _, ev := range lab.events {
		if ev.Fault == "drop" && ev.Path == "/objects/888" {
			dropped = true
		}
	}
	lab.mu.Unlock()
	if !dropped {
		t.Fatal("drop 未记录事件")
	}
	// ack_error：数据入库、201 翻 503，重试收敛（GET 可见对象）。
	labPutFault(t, ts.URL, token, nodeFault{Kind: "ack_error", Target: "all", ObjectID: 999})
	req, _ = http.NewRequest(http.MethodPut, ts.URL+"/objects/999", bytes.NewReader([]byte("keep-me")))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("ack_error 应返回 503，got %d", resp.StatusCode)
	}
	// 清除故障后重试收敛：GET 可见对象（数据已入库、201 翻 503 仅破确认）。
	req, _ = http.NewRequest(http.MethodDelete, ts.URL+"/lab/fault", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := get(t, ts.URL+"/objects/999", token, 200); string(got) != "keep-me" {
		t.Fatalf("清除故障后对象应可读，got %q", got)
	}
}

// 计数包装必须透传 ResponseController（计划写租约 SetReadDeadline 依赖 Unwrap）。
func TestCountWriterUnwrapSupportsResponseController(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			http.Error(w, "unwrap failed", 500)
			return
		}
		w.WriteHeader(200)
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner.ServeHTTP(&countWriter{ResponseWriter: w}, r)
	}))
	defer ts.Close()
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("ResponseController 透传失败: %d", resp.StatusCode)
	}
}

func TestMasterLabRoutes(t *testing.T) {
	store, err := meta.Open(t.TempDir() + "/lab.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const token = "test-token-transferlab-0123456789"
	lab := &masterLab{store: store, nodeMaxAge: time.Hour}
	ts := httptest.NewServer(auth.Wrap(lab.Routes(), auth.Token(token)))
	defer ts.Close()
	do := func(method, path, body string) (int, string) {
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}
	if code, _ := do(http.MethodGet, "/lab/status", ""); code != 200 {
		t.Fatalf("status 应 200，got %d", code)
	}
	if code, body := do(http.MethodPost, "/lab/reserve", `{"path":"/nope","target_id":1}`); code != 404 {
		t.Fatalf("未知路径 reserve 应 404，got %d: %s", code, body)
	}
	if code, _ := do(http.MethodPost, "/lab/profiles", `{"profiles":[{"node_id":999,"upload_bps":1}]}`); code != 200 {
		t.Fatalf("profiles 应 200+逐项错误，got %d", code)
	}
	if code, _ := do(http.MethodPost, "/lab/step", ""); code != 409 {
		t.Fatalf("autonomy 未装配时 step 应 409，got %d", code)
	}
	if code, _ := do(http.MethodGet, "/lab/status", ""); code != 200 {
		t.Fatalf("status second: %d", code)
	}
	// 无 token 一律 401。
	resp, err := http.Get(ts.URL + "/lab/status")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无 token 访问 master lab 应 401，got %d", resp.StatusCode)
	}
}

func TestClassifyObjectRoute(t *testing.T) {
	cases := []struct {
		method, path string
		id           uint64
		kind         string
	}{
		{"GET", "/objects/42", 42, "get"},
		{"PUT", "/objects/42", 42, "put"},
		{"PUT", "/replicate/42", 42, "replicate"},
		{"GET", "/healthz", 0, ""},
		{"POST", "/pull", 0, ""},
		{"GET", "/objects/notanumber", 0, ""},
		{"DELETE", "/objects/42", 0, ""},
	}
	for _, c := range cases {
		id, kind := classifyObjectRoute(c.method, c.path)
		if id != c.id || kind != c.kind {
			t.Fatalf("%s %s => (%d,%q), want (%d,%q)", c.method, c.path, id, kind, c.id, c.kind)
		}
	}
}

// ---- 并发 active GET 原子计数 ----

func TestActiveGetCountingConcurrent(t *testing.T) {
	const token = "test-token-transferlab-0123456789"
	lab, ts := labNode(t, token)
	put(t, ts.URL+"/objects/555", token, []byte("payload"))
	labPutFault(t, ts.URL, token, nodeFault{Kind: "read_delay", Target: "get", DelayMS: 300})
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, ts.URL+"/objects/555", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
	}
	time.Sleep(100 * time.Millisecond)
	if got := lab.activeGets.Load(); got != 3 {
		t.Fatalf("并发期间 active_gets=%d, want 3", got)
	}
	wg.Wait()
	if lab.activeGets.Load() != 0 {
		t.Fatalf("结束后 active_gets=%d", lab.activeGets.Load())
	}
}

// 回归：/lab/status 之后 /lab/events 必须仍能结束——handleStatus 曾漏 Unlock，
// 一次 poll 即永久锁死事件录制与导出（主线程 poll 阻塞根因）。
func TestStatusThenEventsNotDeadlocked(t *testing.T) {
	const token = "test-token-transferlab-0123456789"
	_, ts := labNode(t, token)
	get(t, ts.URL+"/objects/4242", token, 404) // 产生一条 404 事件
	done := make(chan struct{}, 1)
	go func() {
		get(t, ts.URL+"/lab/status", token, 200)
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("/lab/status 挂起")
	}
	evDone := make(chan string, 1)
	go func() { evDone <- string(get(t, ts.URL+"/lab/events", token, 200)) }()
	select {
	case body := <-evDone:
		if !strings.Contains(body, "/objects/4242") {
			t.Fatalf("events 缺事件: %s", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("status 之后 events 挂起：handleStatus 死锁回归")
	}
	for i := 0; i < 3; i++ { // 连续 poll 依旧正常
		get(t, ts.URL+"/lab/status", token, 200)
	}
	get(t, ts.URL+"/lab/events", token, 200)
}

// read_delay 上限 60s；客户端取消时 handler 随 ctx 提前结束，不硬睡满。
func TestFaultDelayCapAndContextCancel(t *testing.T) {
	const token = "test-token-transferlab-0123456789"
	_, ts := labNode(t, token)
	put(t, ts.URL+"/objects/4321", token, []byte("x"))
	code, _ := postFault(t, ts.URL, token, nodeFault{Kind: "read_delay", Target: "get", DelayMS: 61_000})
	if code != http.StatusBadRequest {
		t.Fatalf("delay_ms>60000 应 400，got %d", code)
	}
	if _, err := postFault(t, ts.URL, token, nodeFault{Kind: "read_delay", Target: "get", DelayMS: 60_000}); err != nil {
		t.Fatalf("60000 应可设置: %v", err)
	}
	started := time.Now()
	client := &http.Client{Timeout: 500 * time.Millisecond, Transport: &auth.Transport{Token: auth.Token(token)}}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/objects/4321", nil)
	resp, err := client.Do(req)
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		t.Fatal("客户端 500ms 超时应触发取消错误")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("取消后 handler 未随 ctx 结束，耗时 %v", elapsed)
	}
}

// ---- 小工具 ----

func put(t *testing.T, url, token string, body []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("PUT %s 状态 %d", url, resp.StatusCode)
	}
}

func get(t *testing.T, url, token string, wantCode int) []byte {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantCode {
		t.Fatalf("GET %s 状态 %d (want %d): %s", url, resp.StatusCode, wantCode, raw)
	}
	return raw
}
