package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"atoll/master/meta"
	"atoll/pkg/auth"
	"atoll/pkg/types"
)

// 确定性样本：同种子同字节、块表正确、落盘与纯哈希复算一致。
func TestSampleGeneratorDeterministic(t *testing.T) {
	cfg := &Config{SampleBytes: 64<<20 + 7}
	want := sampleExpect(cfg)
	path := filepath.Join(t.TempDir(), "s.bin")
	fileHash, chunkHashes, err := writeSampleFile(path, cfg.SampleBytes, sampleSeed(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if fileHash != want.file {
		t.Fatal("落盘与哈希复算的整文件 sha256 不一致")
	}
	if len(chunkHashes) != 2 || len(want.chunks) != 2 {
		t.Fatalf("64MiB+7 应为 2 块，got %d", len(chunkHashes))
	}
	for i := range chunkHashes {
		if chunkHashes[i] != want.chunks[i] {
			t.Fatalf("块 %d 哈希不一致", i)
		}
	}
	// 不同种子内容必须不同（随机样本，不是常量序列）。
	g1 := &chunkGen{state: seedState(sampleSeed(cfg))}
	g2 := &chunkGen{state: seedState("transferlab|other")}
	b1, b2 := make([]byte, 64), make([]byte, 64)
	_, _ = g1.Read(b1)
	_, _ = g2.Read(b2)
	if hex.EncodeToString(b1) == hex.EncodeToString(b2) {
		t.Fatal("不同种子的样本流不应相同")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestGateTransportDeniesNonIngress(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer ok.Close()
	host := ok.Listener.Addr().String()
	gate := &gateTransport{inner: &auth.Transport{Token: "test-token-transferlab-0123456789"}, deny: map[string]bool{host: true}}
	req, _ := http.NewRequest(http.MethodGet, "http://"+host+"/objects/1", nil)
	if _, err := gate.RoundTrip(req); err == nil {
		t.Fatal("被禁地址应被 client 策略拒绝")
	}
	inner := &auth.Transport{Token: "test-token-transferlab-0123456789"}
	resp, err := inner.RoundTrip(req)
	if err != nil {
		t.Fatalf("同一地址经普通传输应可达: %v", err)
	}
	resp.Body.Close()
}

// RoundTripper 契约：deny 错误路径也必须关闭请求 Body，别让缓冲滞留。
type trackingBody struct {
	io.Reader
	closed bool
}

func (b *trackingBody) Close() error { b.closed = true; return nil }

func TestGateTransportClosesBodyOnDeny(t *testing.T) {
	body := &trackingBody{Reader: strings.NewReader("payload")}
	gate := &gateTransport{inner: http.DefaultTransport, deny: map[string]bool{"blocked:1": true}}
	req, _ := http.NewRequest(http.MethodPut, "http://blocked:1/objects/1", body)
	if _, err := gate.RoundTrip(req); err == nil {
		t.Fatal("被禁地址应被拒绝")
	}
	if !body.closed {
		t.Fatal("deny 路径未关闭请求 Body")
	}
}

// applyProfiles 幂等：与 /lab/status 现值一致时不 POST（revision 不 bump，
// 既有 pending 计划不 stale）；仅差异节点进入 POST。
func TestApplyProfilesSkipsUnchanged(t *testing.T) {
	var mu sync.Mutex
	var posted [][]meta.NodePlacementProfile
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Profiles []meta.NodePlacementProfile `json:"profiles"`
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &in); err != nil {
			t.Errorf("profiles body 非法: %v", err)
		}
		mu.Lock()
		posted = append(posted, in.Profiles)
		mu.Unlock()
		writeJSONLab(w, 200, map[string]any{"results": []map[string]any{}})
	}))
	defer ts.Close()

	cfg := &Config{Nodes: []NodeRef{
		{Label: "A", Addr: "a:1", UploadBPS: 4 * MiB, DownloadBPS: 16 * MiB, MaxConcurrent: 4},
		{Label: "B", Addr: "b:1", UploadBPS: 2 * MiB, DownloadBPS: 16 * MiB, MaxConcurrent: 2},
	}}
	status := masterStatus{
		Nodes: []types.NodeInfo{{ID: 1, Addr: "a:1"}, {ID: 2, Addr: "b:1"}},
		Profiles: []meta.NodePlacementProfile{
			{NodeID: 1, FailureDomains: map[string]string{"site": "A"}, UploadBPS: 4 * MiB, DownloadBPS: 16 * MiB, MaxTransferConcurrency: 4},
			{NodeID: 2, FailureDomains: map[string]string{"site": "B"}, UploadBPS: 2 * MiB, DownloadBPS: 16 * MiB, MaxTransferConcurrency: 2},
		},
	}
	lab := &labClient{base: ts.URL,
		http: &http.Client{Transport: &auth.Transport{Token: "test-token-transferlab-0123456789"}}}
	if err := applyProfiles(lab, cfg, status, io.Discard); err != nil {
		t.Fatalf("applyProfiles: %v", err)
	}
	mu.Lock()
	if len(posted) != 0 {
		mu.Unlock()
		t.Fatalf("profile 全部一致时不应 POST（会 bump revision stale pending 计划），got %d 次", len(posted))
	}
	mu.Unlock()
	// B 的上行预算漂移 → 只 POST node 2。
	status.Profiles[1].UploadBPS = 9 * MiB
	if err := applyProfiles(lab, cfg, status, io.Discard); err != nil {
		t.Fatalf("applyProfiles: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(posted) != 1 || len(posted[0]) != 1 || posted[0][0].NodeID != 2 {
		t.Fatalf("只应 POST 变更节点(node 2)，got %+v", posted)
	}
}

// events 拉取遇非 200（如 401）必须带着状态码上浮，不许吞成 decode 错误。
func TestCollectNodeEventsSurfacesHTTPStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer ts.Close()
	cfg := &Config{Nodes: []NodeRef{{Label: "X", Addr: ts.Listener.Addr().String()}}}
	_, err := collectNodeEvents(cfg)
	if err == nil || !strings.Contains(err.Error(), "http 401") {
		t.Fatalf("401 应上浮且含状态码，got %v", err)
	}
}
