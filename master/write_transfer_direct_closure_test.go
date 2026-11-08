package master

// 定点回归：写转移观测的失败/离线节点隔离，以及 relay 观测后 direct 探测成功被新计划采用。
// 这里的 HTTP 探测、peerhttp Reporter 与 Master 观测端点/规划都是真实路径；
// 仅 dial 的 Path 事实是本地 fixture（master 包测试不启动 libp2p Runtime）。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"atoll/internal/scheduler"
	"atoll/master/meta"
	"atoll/pkg/peerhttp"
	"atoll/pkg/types"
)

type directClosureFixture struct {
	srv    *Server
	store  *meta.Store
	dbPath string
	a, b   uint64
	stale  uint64
	tlsA   *httptest.Server
	tlsB   *httptest.Server
}

func newDirectClosureFixture(t *testing.T, withStale bool) *directClosureFixture {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "meta.db")
	store, err := meta.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	srv := NewServer(store, time.Hour)
	if err := srv.EnableWritePlanning(WritePlanningConfig{MaxReplicas: 2, TransferPlanning: true}); err != nil {
		t.Fatal(err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})
	tlsA := httptest.NewTLSServer(ok)
	t.Cleanup(tlsA.Close)
	tlsB := httptest.NewTLSServer(ok)
	t.Cleanup(tlsB.Close)
	a, err := store.RegisterNode(tlsA.Listener.Addr().String(), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.RegisterNode(tlsB.Listener.Addr().String(), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	zones := []string{"a", "b"}
	for i, id := range []uint64{a.ID, b.ID} {
		if err := store.SetNodePlacementProfile(meta.NodePlacementProfile{NodeID: id, FailureDomains: map[string]string{"zone": zones[i]}, UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxTransferConcurrency: 4}); err != nil {
			t.Fatal(err)
		}
	}
	f := &directClosureFixture{srv: srv, store: store, dbPath: dbPath, a: a.ID, b: b.ID, tlsA: tlsA, tlsB: tlsB}
	if withStale {
		stale, err := store.RegisterNode("127.0.0.1:1", 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.SetNodeHeartbeatAt(stale.ID, time.Now().Add(-2*time.Hour)); err != nil {
			t.Fatal(err)
		}
		f.stale = stale.ID
	}
	return f
}

func directClosureProbe(t *testing.T, ts *httptest.Server, path peerhttp.Path) peerhttp.Path {
	t.Helper()
	base, ok := ts.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("test TLS client transport is not *http.Transport")
	}
	transport, err := peerhttp.NewTransport(base.Clone(), peerhttp.WithResolver(func(context.Context, string) (peerhttp.PeerDialer, error) {
		return func(ctx context.Context) peerhttp.PeerDial {
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", ts.Listener.Addr().String())
			if err != nil {
				return peerhttp.PeerDial{Err: err, Identity: "direct-closure-fixture", Path: path}
			}
			return peerhttp.PeerDial{Conn: conn, Identity: "direct-closure-fixture", Path: path}
		}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	var observed peerhttp.Path
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = peerhttp.WithReporter(ctx, &peerhttp.Reporter{Observe: func(o peerhttp.Observation) {
		if o.Phase == peerhttp.PhaseResponse && !o.Master {
			observed = o.Path
		}
	}})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+ts.Listener.Addr().String()+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("probe %s: %v", path, err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		resp.Body.Close()
		t.Fatalf("probe %s body: %v", path, err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("probe %s close: %v", path, err)
	}
	if observed != path {
		t.Fatalf("probe observed path %q, want %q", observed, path)
	}
	return observed
}

// directClosureFailedProbe 走真实 peerhttp 请求 + Reporter，得到失败探测实际报告的空/未知路径。
func directClosureFailedProbe(t *testing.T, ts *httptest.Server) peerhttp.Path {
	t.Helper()
	base, ok := ts.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("test TLS client transport is not *http.Transport")
	}
	transport, err := peerhttp.NewTransport(base.Clone(), peerhttp.WithResolver(func(context.Context, string) (peerhttp.PeerDialer, error) {
		return func(context.Context) peerhttp.PeerDial {
			return peerhttp.PeerDial{Err: errors.New("direct-closure fixture dial failure"), Identity: "direct-closure-fixture", Path: peerhttp.PathUnknown}
		}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	var observed peerhttp.Path
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = peerhttp.WithReporter(ctx, &peerhttp.Reporter{Observe: func(o peerhttp.Observation) {
		if o.Path != "" && o.Path != peerhttp.PathUnknown || o.ErrorKind != "" {
			observed = o.Path
		}
	}})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+ts.Listener.Addr().String()+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RoundTrip(req); err == nil {
		t.Fatal("expected fixture dial failure")
	}
	if observed == "" {
		t.Fatal("failed probe produced no observation path")
	}
	return observed
}

func directClosurePostObservationResponse(t *testing.T, srv *Server, observation types.TransferObservation) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/nodes/transfer-observation", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func directClosurePostObservation(t *testing.T, srv *Server, observation types.TransferObservation) {
	t.Helper()
	if rec := directClosurePostObservationResponse(t, srv, observation); rec.Code != http.StatusOK {
		t.Fatalf("observation status %d body %s", rec.Code, rec.Body.String())
	}
}

func directClosureClientLink(t *testing.T, nodeID uint64, path peerhttp.Path, at time.Time) types.TransferObservation {
	t.Helper()
	return types.TransferObservation{ToNodeID: nodeID, Path: string(path), Available: true, RTTMs: 1, ObservedAt: at}
}

func directClosurePlan(t *testing.T, f *directClosureFixture, client *types.WriteTransferObservation, now time.Time) (scheduler.WriteDecision, *scheduler.TransferNetwork) {
	t.Helper()
	snap, err := f.store.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	network, err := f.srv.writeTransferNetwork(client, snap, now)
	if err != nil {
		t.Fatalf("writeTransferNetwork: %v", err)
	}
	world, err := f.srv.newWriteSnapshot(context.Background(), snap, now)
	if err != nil {
		t.Fatal(err)
	}
	world.Network = network
	obj := scheduler.ObjectRequirement{ObjectID: "direct-closure", ContentVersion: 1, SizeBytes: 1024, Intent: scheduler.ProtectionIntent{Tier: string(types.ProtectionSecurity)}}
	decision, err := scheduler.PlanWriteAt(&world, obj, now)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Plan == nil || decision.Transfer == nil {
		t.Fatalf("no feasible transfer plan: %+v", decision)
	}
	return decision, network
}

func directClosureLegPath(t *testing.T, d scheduler.WriteDecision, from, to uint64) string {
	t.Helper()
	wantFrom, wantTo := strconv.FormatUint(from, 10), strconv.FormatUint(to, 10)
	for _, leg := range d.Transfer.Legs {
		if leg.From == wantFrom && leg.To == wantTo {
			return leg.Path
		}
	}
	t.Fatalf("missing leg %d->%d in %+v", from, to, d.Transfer.Legs)
	return ""
}

func TestDirectClosureUnknownFailedProbeDoesNotPoisonNetwork(t *testing.T) {
	f := newDirectClosureFixture(t, false)
	unknown := directClosureFailedProbe(t, f.tlsB)
	if unknown != peerhttp.PathUnknown {
		t.Fatalf("failed probe path %q, want unknown", unknown)
	}
	directA := directClosureProbe(t, f.tlsA, peerhttp.PathDirect)
	directAB := directClosureProbe(t, f.tlsB, peerhttp.PathDirect)
	at := time.Now()
	directClosurePostObservation(t, f.srv, types.TransferObservation{FromNodeID: f.a, ToNodeID: f.b, Path: string(directAB), Available: true, RTTMs: 1, ObservedAt: at})
	now := at.Add(time.Millisecond)
	for _, path := range []string{string(unknown), ""} {
		client := &types.WriteTransferObservation{Budget: types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 1},
			Links: []types.TransferObservation{directClosureClientLink(t, f.a, directA, at), {ToNodeID: f.b, Path: path, Available: false, ObservedAt: at}}}
		decision, network := directClosurePlan(t, f, client, now)
		if path := directClosureLegPath(t, decision, f.a, f.b); path != scheduler.TransferDirect {
			t.Fatalf("fan-out path %q, want direct", path)
		}
		if len(decision.Transfer.UploadTargets) != 1 || decision.Transfer.UploadTargets[0] != strconv.FormatUint(f.a, 10) {
			t.Fatalf("ingress set %+v", decision.Transfer.UploadTargets)
		}
		for _, link := range network.Links {
			if link.Path == "" || link.Path == string(peerhttp.PathUnknown) {
				t.Fatalf("failed probe was exposed as selectable link: %+v", link)
			}
		}
	}
}

func TestDirectClosureUnknownPathClaimsAreStillRejected(t *testing.T) {
	f := newDirectClosureFixture(t, false)
	directA := directClosureProbe(t, f.tlsA, peerhttp.PathDirect)
	at := time.Now()
	for name, link := range map[string]types.TransferObservation{
		"unknown-claims-available": {ToNodeID: f.b, Path: string(peerhttp.PathUnknown), Available: true, ObservedAt: at},
		"empty-claims-throughput":  {ToNodeID: f.b, Path: "", Available: false, ThroughputBPS: 1024, ObservedAt: at},
		"other-invalid-path":       {ToNodeID: f.b, Path: "guess", Available: false, ObservedAt: at},
	} {
		t.Run(name, func(t *testing.T) {
			client := &types.WriteTransferObservation{Budget: types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 1},
				Links: []types.TransferObservation{directClosureClientLink(t, f.a, directA, at), link}}
			snap, err := f.store.AutonomySnapshot()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.srv.writeTransferNetwork(client, snap, at.Add(time.Millisecond)); err == nil {
				t.Fatalf("accepted invalid failed probe %+v", link)
			}
		})
	}
}

func TestDirectClosureStaleNodeWithoutProfileDoesNotPoison(t *testing.T) {
	f := newDirectClosureFixture(t, true)
	directA := directClosureProbe(t, f.tlsA, peerhttp.PathDirect)
	directAB := directClosureProbe(t, f.tlsB, peerhttp.PathDirect)
	at := time.Now()
	directClosurePostObservation(t, f.srv, types.TransferObservation{FromNodeID: f.a, ToNodeID: f.b, Path: string(directAB), Available: true, RTTMs: 1, ObservedAt: at})
	directClosurePostObservation(t, f.srv, types.TransferObservation{FromNodeID: f.stale, ToNodeID: f.a, Path: scheduler.TransferHTTP, Available: true, RTTMs: 1, ObservedAt: at})
	client := &types.WriteTransferObservation{Budget: types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 1},
		Links: []types.TransferObservation{
			directClosureClientLink(t, f.a, directA, at),
			directClosureClientLink(t, f.stale, peerhttp.PathDirect, at),
		}}
	decision, network := directClosurePlan(t, f, client, at.Add(time.Millisecond))
	if path := directClosureLegPath(t, decision, f.a, f.b); path != scheduler.TransferDirect {
		t.Fatalf("fan-out path %q, want direct", path)
	}
	for _, endpoint := range network.Endpoints {
		if endpoint.ID == strconv.FormatUint(f.stale, 10) {
			t.Fatalf("stale node became an endpoint: %+v", network.Endpoints)
		}
	}
	for _, link := range network.Links {
		if link.From == strconv.FormatUint(f.stale, 10) || link.To == strconv.FormatUint(f.stale, 10) {
			t.Fatalf("stale node link leaked into network: %+v", link)
		}
	}
}

func TestDirectClosureFreshNodeWithoutBudgetStillRejected(t *testing.T) {
	f := newDirectClosureFixture(t, false)
	fresh, err := f.store.RegisterNode("127.0.0.1:2", 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	client := &types.WriteTransferObservation{Budget: types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 1},
		Links: []types.TransferObservation{directClosureClientLink(t, f.a, peerhttp.PathDirect, time.Now())}}
	snap, err := f.store.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.srv.writeTransferNetwork(client, snap, time.Now().Add(time.Millisecond)); err == nil {
		t.Fatalf("fresh node %d without transfer budget was accepted", fresh.ID)
	}
}

func directClosureStoredLink(t *testing.T, network *scheduler.TransferNetwork, from, to uint64, path string) scheduler.LinkObservation {
	t.Helper()
	wantFrom, wantTo := strconv.FormatUint(from, 10), strconv.FormatUint(to, 10)
	for _, link := range network.Links {
		if link.From == wantFrom && link.To == wantTo && link.Path == path {
			return link
		}
	}
	t.Fatalf("missing stored link %d->%d path %q in %+v", from, to, path, network.Links)
	return scheduler.LinkObservation{}
}

// 旧零吞吐失败（真实观测端点）必须能被更新后的同 path 成功探测替换，并使新计划可选。
func TestDirectClosureFailedObservationThenHealthSuccessSelectsPath(t *testing.T) {
	f := newDirectClosureFixture(t, false)
	directA := directClosureProbe(t, f.tlsA, peerhttp.PathDirect)
	at0 := time.Now()
	directClosurePostObservation(t, f.srv, types.TransferObservation{FromNodeID: f.a, ToNodeID: f.b, Path: scheduler.TransferDirect, Available: false, ObservedAt: at0})
	at1 := at0.Add(time.Second)
	directClosurePostObservation(t, f.srv, types.TransferObservation{FromNodeID: f.a, ToNodeID: f.b, Path: scheduler.TransferDirect, Available: true, ObservedAt: at1})
	client := &types.WriteTransferObservation{Budget: types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 1},
		Links: []types.TransferObservation{directClosureClientLink(t, f.a, directA, at1)}}
	decision, network := directClosurePlan(t, f, client, at1.Add(time.Millisecond))
	link := directClosureStoredLink(t, network, f.a, f.b, scheduler.TransferDirect)
	if !link.Available || !link.ObservedAt.Equal(at1) {
		t.Fatalf("old failed probe was not replaced: %+v", link)
	}
	if decision.RequiredConfirmations != 2 {
		t.Fatalf("security tier produced %d confirmations, want 2", decision.RequiredConfirmations)
	}
	if path := directClosureLegPath(t, decision, f.a, f.b); path != scheduler.TransferDirect {
		t.Fatalf("fan-out path %q, want direct", path)
	}
}

// 真正测得 payload 吞吐的 fresh result 仍必须压过零吞吐健康探测成功。
func TestDirectClosureMeasuredPayloadSurvivesHealthProbe(t *testing.T) {
	f := newDirectClosureFixture(t, false)
	directA := directClosureProbe(t, f.tlsA, peerhttp.PathDirect)
	at0 := time.Now()
	directClosurePostObservation(t, f.srv, types.TransferObservation{FromNodeID: f.a, ToNodeID: f.b, Path: scheduler.TransferDirect, Available: true, ThroughputBPS: 4096, ObservedAt: at0})
	at1 := at0.Add(time.Second)
	directClosurePostObservation(t, f.srv, types.TransferObservation{FromNodeID: f.a, ToNodeID: f.b, Path: scheduler.TransferDirect, Available: true, ObservedAt: at1})
	client := &types.WriteTransferObservation{Budget: types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 1},
		Links: []types.TransferObservation{directClosureClientLink(t, f.a, directA, at1)}}
	decision, network := directClosurePlan(t, f, client, at1.Add(time.Millisecond))
	link := directClosureStoredLink(t, network, f.a, f.b, scheduler.TransferDirect)
	if link.ThroughputBPS != 4096 || !link.ObservedAt.Equal(at0) {
		t.Fatalf("health probe erased measured payload result: %+v", link)
	}
	if path := directClosureLegPath(t, decision, f.a, f.b); path != scheduler.TransferDirect {
		t.Fatalf("fan-out path %q, want direct", path)
	}
}

func TestDirectClosureNodeUnknownFailureEndpointContract(t *testing.T) {
	f := newDirectClosureFixture(t, false)
	at0 := time.Now()
	directClosurePostObservation(t, f.srv, types.TransferObservation{FromNodeID: f.a, ToNodeID: f.b, Path: scheduler.TransferDirect, Available: true, ThroughputBPS: 4096, ObservedAt: at0})
	known := f.srv.transferObservationsAt(at0.Add(time.Millisecond))
	if len(known) != 1 || known[0].Path != scheduler.TransferDirect || !known[0].ObservedAt.Equal(at0) || known[0].ThroughputBPS != 4096 {
		t.Fatalf("known link before unknown failures: %+v", known)
	}
	knownValidUntil := known[0].ValidUntil
	at1 := at0.Add(time.Second)
	for _, path := range []string{string(peerhttp.PathUnknown), ""} {
		t.Run("legal-"+path, func(t *testing.T) {
			rec := directClosurePostObservationResponse(t, f.srv, types.TransferObservation{FromNodeID: f.a, ToNodeID: f.b, Path: path, Available: false, ThroughputBPS: 0, ObservedAt: at1})
			if rec.Code != http.StatusOK {
				t.Fatalf("legal missing-path failure status %d body %s", rec.Code, rec.Body.String())
			}
		})
	}
	after := f.srv.transferObservationsAt(at1.Add(time.Millisecond))
	if len(after) != 1 || after[0].Path != scheduler.TransferDirect || !after[0].ObservedAt.Equal(at0) || after[0].ThroughputBPS != 4096 || !after[0].Available || !after[0].ValidUntil.Equal(knownValidUntil) {
		t.Fatalf("unknown failed probe changed known link/TTL: %+v", after)
	}
	for _, link := range after {
		if link.Path == "" || link.Path == string(peerhttp.PathUnknown) {
			t.Fatalf("missing-path failure became a selectable link: %+v", link)
		}
	}
	directA := directClosureProbe(t, f.tlsA, peerhttp.PathDirect)
	client := &types.WriteTransferObservation{Budget: types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 1},
		Links: []types.TransferObservation{directClosureClientLink(t, f.a, directA, at1)}}
	decision, network := directClosurePlan(t, f, client, at1.Add(time.Millisecond))
	if path := directClosureLegPath(t, decision, f.a, f.b); path != scheduler.TransferDirect {
		t.Fatalf("fan-out path %q, want direct", path)
	}
	if link := directClosureStoredLink(t, network, f.a, f.b, scheduler.TransferDirect); link.ThroughputBPS != 4096 || !link.ObservedAt.Equal(at0) {
		t.Fatalf("plan input changed known link: %+v", link)
	}
}

func TestDirectClosureNodeUnknownFailureRejectsInvalidClaims(t *testing.T) {
	f := newDirectClosureFixture(t, false)
	at0 := time.Now()
	for name, observation := range map[string]types.TransferObservation{
		"unknown-claims-available":  {FromNodeID: f.a, ToNodeID: f.b, Path: string(peerhttp.PathUnknown), Available: true, ObservedAt: at0},
		"unknown-claims-throughput": {FromNodeID: f.a, ToNodeID: f.b, Path: string(peerhttp.PathUnknown), Available: false, ThroughputBPS: 1024, ObservedAt: at0},
		"empty-claims-available":    {FromNodeID: f.a, ToNodeID: f.b, Path: "", Available: true, ObservedAt: at0},
		"future":                    {FromNodeID: f.a, ToNodeID: f.b, Path: string(peerhttp.PathUnknown), Available: false, ObservedAt: at0.Add(time.Minute)},
		"stale":                     {FromNodeID: f.a, ToNodeID: f.b, Path: string(peerhttp.PathUnknown), Available: false, ObservedAt: at0.Add(-time.Minute)},
		"other-invalid-path":        {FromNodeID: f.a, ToNodeID: f.b, Path: "guess", Available: false, ObservedAt: at0},
		"same-endpoint":             {FromNodeID: f.a, ToNodeID: f.a, Path: string(peerhttp.PathUnknown), Available: false, ObservedAt: at0},
		"unknown-endpoint":          {FromNodeID: f.a, ToNodeID: 999999, Path: string(peerhttp.PathUnknown), Available: false, ObservedAt: at0},
		"zero-from":                 {FromNodeID: 0, ToNodeID: f.b, Path: string(peerhttp.PathUnknown), Available: false, ObservedAt: at0},
		"empty-to":                  {FromNodeID: f.a, ToNodeID: 0, Path: string(peerhttp.PathUnknown), Available: false, ObservedAt: at0},
	} {
		t.Run(name, func(t *testing.T) {
			rec := directClosurePostObservationResponse(t, f.srv, observation)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("invalid node observation status %d body %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestDirectClosurePrecedenceRejectsOldOrInvalidSample(t *testing.T) {
	f := newDirectClosureFixture(t, false)
	at0 := time.Now()
	directClosurePostObservation(t, f.srv, types.TransferObservation{FromNodeID: f.a, ToNodeID: f.b, Path: scheduler.TransferDirect, Available: false, ObservedAt: at0})
	for name, observation := range map[string]types.TransferObservation{
		"out-of-order": {FromNodeID: f.a, ToNodeID: f.b, Path: scheduler.TransferDirect, Available: true, ObservedAt: at0.Add(-time.Second)},
		"future":       {FromNodeID: f.a, ToNodeID: f.b, Path: scheduler.TransferDirect, Available: true, ObservedAt: at0.Add(time.Minute)},
		"over-goodput": {FromNodeID: f.a, ToNodeID: f.b, Path: scheduler.TransferDirect, Available: true, ThroughputBPS: 1 << 41, ObservedAt: at0.Add(time.Second)},
	} {
		t.Run(name, func(t *testing.T) {
			if rec := directClosurePostObservationResponse(t, f.srv, observation); rec.Code != http.StatusBadRequest {
				t.Fatalf("invalid precedence sample status %d body %s", rec.Code, rec.Body.String())
			}
		})
	}
	directClosurePostObservation(t, f.srv, types.TransferObservation{FromNodeID: f.a, ToNodeID: f.b, Path: scheduler.TransferDirect, Available: true, ObservedAt: at0.Add(time.Second)})
	directA := directClosureProbe(t, f.tlsA, peerhttp.PathDirect)
	client := &types.WriteTransferObservation{Budget: types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 1},
		Links: []types.TransferObservation{directClosureClientLink(t, f.a, directA, at0.Add(time.Second))}}
	decision, _ := directClosurePlan(t, f, client, at0.Add(time.Second+time.Millisecond))
	if path := directClosureLegPath(t, decision, f.a, f.b); path != scheduler.TransferDirect {
		t.Fatalf("fan-out path %q, want direct after valid success", path)
	}
}

func TestDirectClosureRelayObservationThenDirectProbeSelectsDirect(t *testing.T) {
	f := newDirectClosureFixture(t, false)
	relay := directClosureProbe(t, f.tlsB, peerhttp.PathRelay)
	directA := directClosureProbe(t, f.tlsA, peerhttp.PathDirect)
	at1 := time.Now()
	directClosurePostObservation(t, f.srv, types.TransferObservation{FromNodeID: f.a, ToNodeID: f.b, Path: string(relay), Available: true, RTTMs: 2, ObservedAt: at1})
	client := &types.WriteTransferObservation{Budget: types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 1},
		Links: []types.TransferObservation{directClosureClientLink(t, f.a, directA, at1)}}
	first, _ := directClosurePlan(t, f, client, at1.Add(time.Millisecond))
	if first.RequiredConfirmations != 2 {
		t.Fatalf("security tier produced %d confirmations, want 2", first.RequiredConfirmations)
	}
	if path := directClosureLegPath(t, first, f.a, f.b); path != scheduler.TransferRelay {
		t.Fatalf("first fan-out path %q, want circuit", path)
	}

	direct := directClosureProbe(t, f.tlsB, peerhttp.PathDirect)
	at2 := time.Now()
	directClosurePostObservation(t, f.srv, types.TransferObservation{FromNodeID: f.a, ToNodeID: f.b, Path: string(direct), Available: true, RTTMs: 1, ObservedAt: at2})
	client.Links[0].ObservedAt = at2
	second, _ := directClosurePlan(t, f, client, at2.Add(time.Millisecond))
	if second.RequiredConfirmations != 2 {
		t.Fatalf("security tier produced %d confirmations after direct probe, want 2", second.RequiredConfirmations)
	}
	if path := directClosureLegPath(t, second, f.a, f.b); path != scheduler.TransferDirect {
		t.Fatalf("second fan-out path %q, want direct", path)
	}
	choice, err := writeChunkChoice(types.PlanWriteChunkRequest{WriteBinding: types.WriteBinding{UploadID: 1, PlanID: "direct-closure", Revision: 1}, Index: 0, LogicalSize: 1024, StoredSize: 1024, Encoding: types.PlainEncoding, Checksum: types.CRC32C(make([]byte, 1024))}, 42, second)
	if err != nil {
		t.Fatal(err)
	}
	persisted := ""
	for _, leg := range choice.Transfer.Legs {
		if leg.FromNodeID == f.a && leg.ToNodeID == f.b {
			persisted = leg.Path
		}
	}
	if persisted != scheduler.TransferDirect {
		t.Fatalf("converted fan-out path %q, want direct", persisted)
	}

	// Real Store CAS + reopen: writeChunkChoice above is only DTO conversion.
	data := make([]byte, 1024)
	upload, err := f.store.BeginPlannedWrite(meta.WriteActor{}, meta.RootID, "direct-closure", types.BeginWriteRequest{Path: "/direct-closure", OpID: "direct-closure-begin", Size: int64(len(data))}, at2.Add(2*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	binding := types.WriteBinding{UploadID: upload.ID, PlanID: upload.PlanID, Revision: upload.Revision}
	chunkID := types.ChunkID(upload.ID, 0)
	request := types.PlanWriteChunkRequest{WriteBinding: binding, Index: 0, LogicalSize: int64(len(data)), StoredSize: int64(len(data)), Encoding: types.PlainEncoding, Checksum: types.CRC32C(data)}
	choice, err = writeChunkChoice(request, chunkID, second)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := f.store.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	reserved, chunk, err := f.store.ReserveWriteChunk(meta.WriteActor{}, request, choice, snap.ProfileRevision, time.Hour, at2.Add(3*time.Millisecond))
	if err != nil {
		t.Fatalf("ReserveWriteChunk: %v", err)
	}
	if reserved.Transfer == nil {
		t.Fatal("reserved plan lost transfer graph")
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := meta.Open(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	storedPlan, err := reopened.WriteTransferForObject(chunk.ID)
	if err != nil || storedPlan == nil {
		t.Fatalf("reopened store lost transfer plan: %+v %v", storedPlan, err)
	}
	reopenedPath := ""
	for _, leg := range storedPlan.Legs {
		if leg.FromNodeID == f.a && leg.ToNodeID == f.b {
			reopenedPath = leg.Path
		}
	}
	if reopenedPath != scheduler.TransferDirect {
		t.Fatalf("reopened fan-out path %q, want direct", reopenedPath)
	}
}
