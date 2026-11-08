package node

// 定点回归：真实 201 + responseEOF 后的 WriteTransfer 应用层观测。
// 数据面使用本地 TLS 目标与 peerhttp fixture；控制端点捕获 Master 收到的 JSON。

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/peerhttp"
	"atoll/pkg/types"
)

type payloadObservationTestEnv struct {
	node    *Node
	master  *httptest.Server
	target  *httptest.Server
	reports chan types.TransferObservation
	data    []byte
	plan    types.ReplicationPlan
}

func payloadAckHandler(data []byte) http.HandlerFunc {
	want := types.CRC32C(data)
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) != len(data) || types.CRC32C(body) != want {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = io.WriteString(w, "{}")
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "{}")
	}
}

func newPayloadObservationTestEnv(t *testing.T, data []byte, targetHandler, masterHandler http.HandlerFunc) *payloadObservationTestEnv {
	t.Helper()
	var reports chan types.TransferObservation
	if masterHandler == nil {
		reports = make(chan types.TransferObservation, 16)
		masterHandler = func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/nodes/transfer-observation" {
				var observation types.TransferObservation
				if json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&observation) == nil {
					select {
					case reports <- observation:
					default:
					}
				}
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "{}")
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}
	}
	master := httptest.NewTLSServer(masterHandler)
	target := httptest.NewTLSServer(targetHandler)
	dataDir := t.TempDir()
	node := New(dataDir, master.URL, "", 1<<30)
	node.SetTLS(master.Client().Transport.(*http.Transport).TLSClientConfig.Clone())
	if err := node.ConfigureTransferBudget(types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 1 << 20, MaxConcurrent: 2}); err != nil {
		t.Fatal(err)
	}
	if err := node.EnableSecurity(filepath.Join(t.TempDir(), "identity.key"), "", false); err != nil {
		t.Fatal(err)
	}
	if err := node.SetPeerResolver(func(context.Context, string) (peerhttp.PeerDialer, error) {
		return func(ctx context.Context) peerhttp.PeerDial {
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", target.Listener.Addr().String())
			return peerhttp.PeerDial{Conn: conn, Err: err, Identity: "payload-test-target", Path: peerhttp.PathDirect}
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
	node.bulkClient.Transport = node.sec.base
	node.httpClient = master.Client()
	node.SetNodeIDForTest(1)
	const objectID = 4242
	objectPath := node.objectPathForTest(objectID)
	if err := os.MkdirAll(filepath.Dir(objectPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objectPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	env := &payloadObservationTestEnv{node: node, master: master, target: target, data: data, reports: reports}
	env.plan = types.ReplicationPlan{
		Object:  types.ObjectIntegrity{PlanID: "payload-plan", ObjectID: objectID, Size: int64(len(data)), Checksum: types.CRC32C(data), ChecksumKnown: true},
		Targets: []types.NodeInfo{{ID: 2, Addr: target.Listener.Addr().String()}},
		WriteTransfer: &types.WriteTransferPlan{UploadTargets: []uint64{2}, ExpiresAt: time.Now().Add(time.Minute),
			Legs: []types.WriteTransferLeg{{FromNodeID: 1, ToNodeID: 2, Path: string(peerhttp.PathDirect), BPS: 1 << 20}}},
	}
	t.Cleanup(func() {
		_ = node.CloseP2P()
		if tr, ok := node.sec.base.(*peerhttp.Transport); ok {
			tr.Close()
		}
		target.Close()
		master.Close()
	})
	return env
}

func TestPayloadObservationReportsApplicationGoodput(t *testing.T) {
	data := bytes.Repeat([]byte("application-confirmed-payload-"), 16*1024)
	env := newPayloadObservationTestEnv(t, data, payloadAckHandler(data), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var diagnostics atomic.Int32
	ctx = peerhttp.WithReporter(ctx, &peerhttp.Reporter{Observe: func(observation peerhttp.Observation) {
		if observation.Phase == peerhttp.PhaseResponse && !observation.Master {
			diagnostics.Add(1)
		}
	}})
	if err := env.node.pushWithPlan(ctx, env.plan.Targets[0].Addr, env.plan); err != nil {
		t.Fatal(err)
	}
	select {
	case observation := <-env.reports:
		if observation.FromNodeID != 1 || observation.ToNodeID != 2 || observation.Path != string(peerhttp.PathDirect) ||
			!observation.Available || observation.ThroughputBPS == 0 || observation.ObservedAt.IsZero() {
			t.Fatalf("bad payload observation: %+v", observation)
		}
		if diagnostics.Load() == 0 {
			t.Fatal("WithResponseReporter swallowed caller diagnostics")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("successful 201 payload produced no observation")
	}
}

func TestPayloadObservationDoesNotReportInvalidCRC(t *testing.T) {
	data := bytes.Repeat([]byte("invalid-crc-payload-"), 4096)
	env := newPayloadObservationTestEnv(t, data, func(w http.ResponseWriter, r *http.Request) {
		// Target reads the replica but rejects it as CRC-invalid.
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = io.WriteString(w, "{}")
	}, nil)
	if err := env.node.pushWithPlan(context.Background(), env.plan.Targets[0].Addr, env.plan); err == nil {
		t.Fatal("CRC-invalid replicate must fail")
	}
	select {
	case observation := <-env.reports:
		t.Fatalf("CRC-invalid target reported goodput: %+v", observation)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestPayloadObservationDoesNotReportOversizedBody(t *testing.T) {
	data := bytes.Repeat([]byte("oversized-response-payload-"), 4096)
	env := newPayloadObservationTestEnv(t, data, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(bytes.Repeat([]byte("x"), 4097))
	}, nil)
	if err := env.node.pushWithPlan(context.Background(), env.plan.Targets[0].Addr, env.plan); err != nil {
		t.Fatalf("201 with oversized body must preserve save-confirmation success: %v", err)
	}
	select {
	case observation := <-env.reports:
		t.Fatalf("oversized response body reported goodput: %+v", observation)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestPayloadObservationChunkedExactly4KiBDoesNotWaitOrMeasure(t *testing.T) {
	data := bytes.Repeat([]byte("exact-drain-payload-"), 512)
	release := make(chan struct{})
	flushed := make(chan struct{}, 1)
	env := newPayloadObservationTestEnv(t, data, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		// A trailer forces chunked transfer encoding, so the 201 body has no
		// Content-Length and only a real terminating chunk proves EOF.
		w.Header().Set("Trailer", "X-Payload-Test")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(bytes.Repeat([]byte("x"), 4096))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case flushed <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}, nil)
	t.Cleanup(func() { close(release) }) // release before env cleanup even on failure
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- env.node.pushWithPlan(ctx, env.plan.Targets[0].Addr, env.plan) }()
	select {
	case <-flushed:
	case <-time.After(2 * time.Second):
		t.Fatal("target did not emit the exact 4 KiB chunked body")
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("201 at the old drain limit must preserve save-confirmation success: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("push waited for an extra byte after the old 4 KiB drain limit")
	}
	select {
	case observation := <-env.reports:
		t.Fatalf("4 KiB chunked body without EOF reported goodput: %+v", observation)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestPayloadObservationDoesNotReportEarlyBodyError(t *testing.T) {
	data := bytes.Repeat([]byte("early-body-error-payload-"), 4096)
	env := newPayloadObservationTestEnv(t, data, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Length", "64")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "x")
	}, nil)
	if err := env.node.pushWithPlan(context.Background(), env.plan.Targets[0].Addr, env.plan); err != nil {
		t.Fatalf("201 with early body EOF must preserve save-confirmation success: %v", err)
	}
	select {
	case observation := <-env.reports:
		t.Fatalf("early body error reported goodput: %+v", observation)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestPayloadObservationDoesNotReportAfterContextClose(t *testing.T) {
	data := bytes.Repeat([]byte("ctx-close-payload-"), 4096)
	entered := make(chan struct{}, 1)
	env := newPayloadObservationTestEnv(t, data, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Length", "64")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "x")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case entered <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- env.node.pushWithPlan(ctx, env.plan.Targets[0].Addr, env.plan) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("target never reached response body")
	}
	cancel()
	select {
	case <-result:
	case <-time.After(3 * time.Second):
		t.Fatal("pushWithPlan did not return after context close")
	}
	select {
	case observation := <-env.reports:
		t.Fatalf("context close reported goodput: %+v", observation)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestPayloadObservationQueueBounded(t *testing.T) {
	data := bytes.Repeat([]byte("queue-bound-payload-"), 4096)
	var entered atomic.Int32
	release := make(chan struct{})
	masterHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/nodes/transfer-observation" {
			entered.Add(1)
			select {
			case <-r.Context().Done():
			case <-release:
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}
	env := newPayloadObservationTestEnv(t, data, payloadAckHandler(data), masterHandler)
	observation := types.TransferObservation{FromNodeID: 1, ToNodeID: 2, Path: string(peerhttp.PathDirect), Available: true, ThroughputBPS: 1, ObservedAt: time.Now()}
	for i := 0; i < 20; i++ {
		env.node.queuePayloadObservation(observation)
	}
	deadline := time.Now().Add(2 * time.Second)
	for entered.Load() < 8 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if got := entered.Load(); got != 8 {
		t.Fatalf("payload observation concurrency = %d, want 8", got)
	}
	close(release)
	if err := env.node.CloseP2P(); err != nil {
		t.Fatal(err)
	}
}

func TestPayloadObservationQueueRejectsInvalidSample(t *testing.T) {
	data := bytes.Repeat([]byte("queue-invalid-payload-"), 4096)
	var requests atomic.Int32
	masterHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/nodes/transfer-observation" {
			requests.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}
	env := newPayloadObservationTestEnv(t, data, payloadAckHandler(data), masterHandler)
	self := uint64(env.node.nodeID.Load())
	now := time.Now()
	base := types.TransferObservation{FromNodeID: self, ToNodeID: 2, Path: string(peerhttp.PathDirect), Available: true, ThroughputBPS: 1, ObservedAt: now}
	cases := map[string]types.TransferObservation{
		"from-other":      func() types.TransferObservation { o := base; o.FromNodeID = self + 1; return o }(),
		"to-self":         func() types.TransferObservation { o := base; o.ToNodeID = self; return o }(),
		"to-zero":         func() types.TransferObservation { o := base; o.ToNodeID = 0; return o }(),
		"over-limit":      func() types.TransferObservation { o := base; o.ThroughputBPS = 1 << 41; return o }(),
		"zero-throughput": func() types.TransferObservation { o := base; o.ThroughputBPS = 0; return o }(),
		"zero-time":       func() types.TransferObservation { o := base; o.ObservedAt = time.Time{}; return o }(),
		"future-time":     func() types.TransferObservation { o := base; o.ObservedAt = now.Add(time.Minute); return o }(),
		"unknown-path":    func() types.TransferObservation { o := base; o.Path = string(peerhttp.PathUnknown); return o }(),
		"empty-path":      func() types.TransferObservation { o := base; o.Path = ""; return o }(),
		"unavailable":     func() types.TransferObservation { o := base; o.Available = false; return o }(),
	}
	for name, observation := range cases {
		t.Run(name, func(t *testing.T) {
			before := len(env.node.payloadObsSlots)
			env.node.queuePayloadObservation(observation)
			if got := len(env.node.payloadObsSlots); got != before {
				t.Fatalf("invalid sample occupied a report slot: %d -> %d", before, got)
			}
		})
	}
	time.Sleep(100 * time.Millisecond)
	if got := requests.Load(); got != 0 {
		t.Fatalf("invalid samples reached master: %d", got)
	}
}

func TestPayloadObservationLifecycleCloseJoins(t *testing.T) {
	data := bytes.Repeat([]byte("lifecycle-payload-"), 4096)
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	defer close(release)
	masterHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/nodes/transfer-observation" {
			select {
			case entered <- struct{}{}:
			default:
			}
			select {
			case <-r.Context().Done():
			case <-release:
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}
	env := newPayloadObservationTestEnv(t, data, payloadAckHandler(data), masterHandler)
	if err := env.node.pushWithPlan(context.Background(), env.plan.Targets[0].Addr, env.plan); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("payload report never reached master")
	}
	closed := make(chan error, 1)
	go func() { closed <- env.node.CloseP2P() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("CloseP2P did not join the payload report worker")
	}
	// Lifecycle is closed: a queued report must be dropped, not start a new worker.
	env.node.queuePayloadObservation(types.TransferObservation{FromNodeID: 1, ToNodeID: 2, Path: string(peerhttp.PathDirect), Available: true, ThroughputBPS: 1, ObservedAt: time.Now()})
	select {
	case <-entered:
		t.Fatal("report worker started after CloseP2P")
	case <-time.After(100 * time.Millisecond):
	}
	if got := len(env.node.payloadObsSlots); got != 0 {
		t.Fatalf("closed node leaked payload slots: %d", got)
	}
}
