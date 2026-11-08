package peer

// Real two-node path closure: circuit observation first, same NodeID/PeerID
// restarted direct, then persisted meta transfer plans drive object PUT/Done/
// readback; loopback direct means non-circuit only and never public reachability.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"

	"atoll/internal/scheduler"
	"atoll/master/meta"
	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
	"atoll/pkg/peertransport"
	"atoll/pkg/types"
)

type transferClosureFactsKey struct{}

type transferClosureConnFacts struct {
	transport    string
	remote       string
	local        string
	source       string
	connectionID string
	streamID     string
}

type transferClosureReceive struct {
	method        string
	path          string
	source        string
	transport     string
	remote        string
	local         string
	connectionID  string
	streamID      string
	checksum      string
	status        int
	contentLength int64
	responseBytes int64
}

type transferClosureReceiver struct {
	mu   sync.Mutex
	recs []transferClosureReceive
	err  error
}

func (r *transferClosureReceiver) addError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err == nil {
		r.err = err
	}
}

// connContext receives the actual accepted net.Conn of the node peer listener.
// The TLS wrapper is removed and the underlying stream is type-asserted to the
// real libp2p stream (not synthesized): net.Conn + Conn() + ID(), which is what
// peertransport.streamConn embeds.
func (r *transferClosureReceiver) connContext(ctx context.Context, conn net.Conn) context.Context {
	raw := conn
	if tc, ok := raw.(*tls.Conn); ok {
		raw = tc.NetConn()
	}
	sc, ok := raw.(interface {
		net.Conn
		Conn() network.Conn
		ID() string
	})
	if !ok {
		r.addError(fmt.Errorf("accepted conn %T is not a real libp2p stream", conn))
		return ctx
	}
	peerConn := sc.Conn()
	if peerConn == nil {
		r.addError(fmt.Errorf("real libp2p stream %T has no Conn", sc))
		return ctx
	}
	source := peerauth.SourcePeerID(ctx)
	if source == "" {
		r.addError(fmt.Errorf("ConnContext has no real source peer for %T", sc))
	}
	return context.WithValue(ctx, transferClosureFactsKey{}, &transferClosureConnFacts{
		transport:    peerConn.ConnState().Transport,
		remote:       peerConn.RemoteMultiaddr().String(),
		local:        peerConn.LocalMultiaddr().String(),
		source:       source,
		connectionID: peerConn.ID(),
		streamID:     sc.ID(),
	})
}

type transferClosureStatusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

// Unwrap is required: node planned replication uses http.ResponseController
// read deadlines, and without this the real /replicate handler returns 503.
func (w *transferClosureStatusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *transferClosureStatusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *transferClosureStatusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

func (r *transferClosureReceiver) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		isPut := req.Method == http.MethodPut &&
			(strings.HasPrefix(req.URL.Path, "/replicate/") || strings.HasPrefix(req.URL.Path, "/objects/"))
		if !isPut {
			next.ServeHTTP(w, req)
			return
		}
		rec := transferClosureReceive{
			method:        req.Method,
			path:          req.URL.Path,
			checksum:      req.Header.Get(types.ChecksumHeader),
			contentLength: req.ContentLength,
		}
		if facts, _ := req.Context().Value(transferClosureFactsKey{}).(*transferClosureConnFacts); facts != nil {
			rec.source = facts.source
			rec.transport = facts.transport
			rec.remote = facts.remote
			rec.local = facts.local
			rec.connectionID = facts.connectionID
			rec.streamID = facts.streamID
		}
		sw := &transferClosureStatusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, req)
		rec.status = sw.status
		rec.responseBytes = sw.bytes
		r.mu.Lock()
		r.recs = append(r.recs, rec)
		r.mu.Unlock()
	})
}

func (r *transferClosureReceiver) snapshot() ([]transferClosureReceive, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]transferClosureReceive(nil), r.recs...), r.err
}

func (r *transferClosureReceiver) recordsFor(objectID uint64) []transferClosureReceive {
	r.mu.Lock()
	defer r.mu.Unlock()
	want := "/replicate/" + strconv.FormatUint(objectID, 10)
	var out []transferClosureReceive
	for _, rec := range r.recs {
		if rec.method == http.MethodPut && rec.path == want {
			out = append(out, rec)
		}
	}
	return out
}

func transferClosureAssertReceive(t *testing.T, r *transferClosureReceiver, objectID uint64, payload []byte, sourcePeerID string, circuit bool) transferClosureReceive {
	t.Helper()
	if _, err := r.snapshot(); err != nil {
		t.Fatalf("receiver ConnContext failed to bind a real stream: %v", err)
	}
	recs := r.recordsFor(objectID)
	if len(recs) == 0 {
		t.Fatalf("target receiver has no /replicate/%d record", objectID)
	}
	rec := recs[len(recs)-1]
	if rec.status != http.StatusCreated {
		t.Fatalf("replicate %s status = %d, want 201", rec.path, rec.status)
	}
	if rec.source != sourcePeerID {
		t.Fatalf("replicate %s source = %q, want %q", rec.path, rec.source, sourcePeerID)
	}
	if rec.transport == "" {
		t.Fatalf("replicate %s has no actual transport fact: %+v", rec.path, rec)
	}
	if circuit {
		if !strings.Contains(rec.remote, "/p2p-circuit") {
			t.Fatalf("replicate %s remote = %q, want circuit component: %+v", rec.path, rec.remote, rec)
		}
	} else if strings.Contains(rec.remote, "/p2p-circuit") || !strings.Contains(rec.remote, "/tcp/") {
		t.Fatalf("replicate %s remote = %q, want direct TCP (loopback, not public): %+v", rec.path, rec.remote, rec)
	}
	if rec.connectionID == "" || rec.streamID == "" || rec.local == "" {
		t.Fatalf("replicate %s lacks actual conn/stream/local facts: %+v", rec.path, rec)
	}
	if rec.contentLength != int64(len(payload)) {
		t.Fatalf("replicate %s content length = %d, want %d", rec.path, rec.contentLength, len(payload))
	}
	wantChecksum := fmt.Sprintf("%08x", types.CRC32C(payload))
	if rec.checksum != wantChecksum {
		t.Fatalf("replicate %s checksum = %q, want %q", rec.path, rec.checksum, wantChecksum)
	}
	return rec
}

// transferClosureSetProfile declares the two-node placement/budget profile used
// by the real Master planner. B has a deliberately small upload budget so the
// planner keeps A as the client ingress and uses the A->B replication leg.
type transferClosureObservationRecord struct {
	observation types.TransferObservation
	status      int
}

type transferClosureObservationRecorder struct {
	mu   sync.Mutex
	recs []transferClosureObservationRecord
}

func (r *transferClosureObservationRecorder) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.URL.Path != "/nodes/transfer-observation" {
			next.ServeHTTP(w, req)
			return
		}
		// Copy only the non-secret TransferObservation body; restore it for the
		// real security handler. Never read or store Authorization/device tokens.
		var body []byte
		if req.Body != nil {
			body, _ = io.ReadAll(io.LimitReader(req.Body, 16<<10))
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
		var observation types.TransferObservation
		_ = json.Unmarshal(body, &observation)
		sw := &transferClosureStatusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, req)
		r.mu.Lock()
		r.recs = append(r.recs, transferClosureObservationRecord{observation: observation, status: sw.status})
		r.mu.Unlock()
	})
}

func (r *transferClosureObservationRecorder) snapshot() []transferClosureObservationRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]transferClosureObservationRecord(nil), r.recs...)
}

// transferClosureWaitAutoprobe waits for the real node heartbeat ->
// observeRegisteredTransferPeers -> n.httpClient POST chain. Only a 200 from
// the authenticated Master handler counts; the body source must be A.
func transferClosureWaitAutoprobe(t *testing.T, r *transferClosureObservationRecorder, from, to uint64, path string, window time.Duration) {
	t.Helper()
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		for _, rec := range r.snapshot() {
			o := rec.observation
			if rec.status == http.StatusOK && o.FromNodeID == from && o.ToNodeID == to && o.Path == path && o.Available {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no real authenticated transfer-observation POST %d->%d path=%s with status 200 within %s: %+v", from, to, path, window, r.snapshot())
}

func transferClosureSetProfile(t *testing.T, m *peerMaster, id uint64, upload, download uint64, zone string) {
	t.Helper()
	if err := m.store.SetNodePlacementProfile(meta.NodePlacementProfile{
		NodeID:                 id,
		FailureDomains:         map[string]string{"zone": zone},
		UploadBPS:              upload,
		DownloadBPS:            download,
		MaxTransferConcurrency: 4,
	}); err != nil {
		t.Fatalf("SetNodePlacementProfile(%d): %v", id, err)
	}
}

func transferClosureEndpoint(t *testing.T, m *peerMaster, addr string) (peerauth.Endpoint, peerauth.Infrastructure) {
	t.Helper()
	ep, err := m.store.PeerEndpointByAddr(addr, time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("PeerEndpointByAddr(%q): %v", addr, err)
	}
	dir, err := m.store.PeerDirectory(time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("PeerDirectory: %v", err)
	}
	return ep, dir.Infrastructure
}

func transferClosureWaitDirectEndpoint(t *testing.T, m *peerMaster, addr, peerID string) (peerauth.Endpoint, peerauth.Infrastructure) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		ep, err := m.store.PeerEndpointByAddr(addr, time.Now(), time.Hour)
		if err == nil && ep.PeerID == peerID && len(ep.Addresses) > 0 {
			dir, derr := m.store.PeerDirectory(time.Now(), time.Hour)
			if derr == nil {
				return ep, dir.Infrastructure
			}
			lastErr = derr
		} else if err != nil {
			lastErr = err
		} else if ep.PeerID != peerID {
			lastErr = errorString("endpoint peer id changed: " + ep.PeerID)
		} else {
			lastErr = errorString("endpoint still has no direct address")
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("node %q did not publish a direct endpoint: %v", addr, lastErr)
	return peerauth.Endpoint{}, peerauth.Infrastructure{}
}

type errorString string

func (e errorString) Error() string { return string(e) }

// transferClosureProbe performs one real Runtime Dial + peerhttp request to a
// node and returns the PhaseResponse observation of the serving connection.
// It retries only the real transport/response readiness, never a path guess.
func transferClosureProbe(t *testing.T, m *peerMaster, rt peertransport.RuntimeAPI, ep peerauth.Endpoint, infra peerauth.Infrastructure, path peerhttp.Path, window time.Duration) (peerhttp.Observation, float64) {
	t.Helper()
	deadline := time.Now().Add(window)
	var last error = errorString("probe not attempted")
	for time.Now().Before(deadline) {
		httpc := m.peerPathHTTPClient(rt, ep, infra, nil)
		var observed []peerhttp.Observation
		started := time.Now()
		resp, err := healthzWith(httpc, ep.Addr, path, &observed)
		if err == nil {
			if resp.StatusCode != http.StatusOK {
				err = errorString("unexpected /healthz status " + strconv.Itoa(resp.StatusCode))
			}
			resp.Body.Close()
		}
		if err == nil {
			for i := len(observed) - 1; i >= 0; i-- {
				o := observed[i]
				if o.Phase == peerhttp.PhaseResponse && !o.Master && o.ErrorKind == peerhttp.ErrorNone && o.Status == http.StatusOK {
					return o, float64(time.Since(started).Microseconds()) / 1000
				}
			}
			err = errorString("no serving PhaseResponse observation")
		}
		last = err
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("real %s probe to %q never produced a serving response: %v", path, ep.Addr, last)
	return peerhttp.Observation{}, 0
}

func transferClosureAssertObservedConn(t *testing.T, o peerhttp.Observation, peerID string, path peerhttp.Path, circuit bool) {
	t.Helper()
	if o.Identity != peerID {
		t.Fatalf("serving identity = %q, want real node PeerID %q: %+v", o.Identity, peerID, o)
	}
	if o.Path != path {
		t.Fatalf("actual path = %q, want %q: %+v", o.Path, path, o)
	}
	if o.RequestID == "" || o.ConnectionID == "" || o.StreamID == "" || o.LocalAddress == "" || o.RemoteAddress == "" {
		t.Fatalf("serving observation lacks request/conn/stream facts: %+v", o)
	}
	if circuit {
		if !strings.Contains(o.RemoteAddress, "/p2p-circuit") {
			t.Fatalf("circuit observation remote address = %q, want /p2p-circuit: %+v", o.RemoteAddress, o)
		}
	} else if strings.Contains(o.RemoteAddress, "/p2p-circuit") || !strings.Contains(o.RemoteAddress, "/tcp/") {
		t.Fatalf("direct observation remote address = %q, want non-circuit TCP (loopback direct, not public): %+v", o.RemoteAddress, o)
	}
}

func transferClosurePlan(t *testing.T, m *peerMaster, in types.Inode) *types.WriteTransferPlan {
	t.Helper()
	if len(in.Chunks) != 1 {
		t.Fatalf("planned small file has %d chunks, want 1: %+v", len(in.Chunks), in)
	}
	objectID := types.ChunkObjID(in.Chunks[0], in.ID)
	plan, err := m.store.WriteTransferForObject(objectID)
	if err != nil {
		t.Fatalf("meta WriteTransferForObject(%d): %v", objectID, err)
	}
	if plan == nil || len(plan.Legs) == 0 {
		t.Fatalf("meta has no persisted transfer plan for object %d: %+v", objectID, plan)
	}
	return plan
}

func transferClosureLeg(t *testing.T, plan *types.WriteTransferPlan, from, to uint64) types.WriteTransferLeg {
	t.Helper()
	for _, leg := range plan.Legs {
		if leg.FromNodeID == from && leg.ToNodeID == to {
			return leg
		}
	}
	t.Fatalf("transfer plan has no leg %d->%d: %+v", from, to, plan.Legs)
	return types.WriteTransferLeg{}
}

func transferClosureAssertObjectObservation(t *testing.T, observed []peerhttp.Observation, method string, objectID uint64, target, peerID string, wantPath peerhttp.Path) peerhttp.Observation {
	t.Helper()
	wantRequestPath := "/objects/" + strconv.FormatUint(objectID, 10)
	o := transferClosureFindObjectObservation(t, observed, method, wantRequestPath, map[string]string{target: peerID}, wantPath)
	return o
}

// transferClosureAssertAnyObjectObservation accepts a serving target among the
// provided addr->PeerID pairs. Readback may legitimately select either replica;
// the observation still names the exact serving PeerID/connection/stream.
func transferClosureAssertAnyObjectObservation(t *testing.T, observed []peerhttp.Observation, method string, objectID uint64, targets map[string]string) peerhttp.Observation {
	t.Helper()
	wantRequestPath := "/objects/" + strconv.FormatUint(objectID, 10)
	return transferClosureFindObjectObservation(t, observed, method, wantRequestPath, targets, "")
}

func transferClosureFindObjectObservation(t *testing.T, observed []peerhttp.Observation, method, requestPath string, targets map[string]string, wantPath peerhttp.Path) peerhttp.Observation {
	t.Helper()
	var found []peerhttp.Observation
	for _, o := range observed {
		if o.Master || o.Phase != peerhttp.PhaseResponse || o.ErrorKind != peerhttp.ErrorNone ||
			o.Status < http.StatusOK || o.Status >= http.StatusMultipleChoices {
			continue
		}
		if o.Method != method || o.RequestPath != requestPath {
			continue
		}
		if _, ok := targets[o.Target]; !ok {
			continue
		}
		if wantPath != "" && o.Path != wantPath {
			continue
		}
		found = append(found, o)
	}
	if len(found) == 0 {
		t.Fatalf("no serving %s %s observation for targets %v path %q: %+v", method, requestPath, targets, wantPath, observed)
	}
	o := found[len(found)-1]
	wantPeerID := targets[o.Target]
	if o.Identity != wantPeerID {
		t.Fatalf("object request serving identity = %q, want %q for target %q: %+v", o.Identity, wantPeerID, o.Target, o)
	}
	if o.RequestID == "" || o.ConnectionID == "" || o.StreamID == "" || o.LocalAddress == "" || o.RemoteAddress == "" {
		t.Fatalf("object request observation lacks request/conn/stream facts: %+v", o)
	}
	if o.Path != peerhttp.PathDirect && o.Path != peerhttp.PathRelay {
		t.Fatalf("object request path = %q, want direct or circuit: %+v", o.Path, o)
	}
	return o
}

func transferClosureAssertLedgerPut(t *testing.T, ledger *nodeLedger, objectID uint64, sourcePeerID string) {
	t.Helper()
	id := strconv.FormatUint(objectID, 10)
	// A client ingress uses /objects/<id>; a node-to-node replicate uses
	// /replicate/<id>. Both are real object-body requests on the serving stream.
	wantPaths := map[string]bool{"/objects/" + id: true, "/replicate/" + id: true}
	for _, rec := range ledger.snapshot() {
		if rec.method == http.MethodPut && wantPaths[rec.path] {
			if rec.source != sourcePeerID {
				t.Fatalf("replica PUT %s reached target from %q, want source node PeerID %q", rec.path, rec.source, sourcePeerID)
			}
			return
		}
	}
	t.Fatalf("target ledger has no real replica PUT object %s from %q: %+v", id, sourcePeerID, ledger.snapshot())
}

func transferClosureReadback(t *testing.T, cs *clientSecure, remote string, want []byte) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "readback.bin")
	if err := cs.c.Get(remote, out); err != nil {
		t.Fatalf("full readback %s: %v", remote, err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("readback file: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("readback mismatch for %s: got %d bytes want %d", remote, len(got), len(want))
	}
}

func TestPeerTransferPathClosureRelayObservationThenDirectSamePeer(t *testing.T) {
	pki := newTestPKI(t)
	obsRec := &transferClosureObservationRecorder{}
	m := newPeerMasterOpts(t, pki, masterOpts{transferPlanning: true, maxReplicas: 2, handlerWrapper: obsRec.wrap})
	m.createUser("alice")

	aBudget := &types.TransferBudget{UploadBPS: 4 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 4}
	bBudget := &types.TransferBudget{UploadBPS: 64 << 10, DownloadBPS: 4 << 20, MaxConcurrent: 4}
	a := m.startNodeOpts(filepath.Join(t.TempDir(), "a"), m.nodeInvite(),
		nodeOpts{transferBudget: aBudget})
	bDir := filepath.Join(t.TempDir(), "b")
	var bLedger nodeLedger
	receiver := &transferClosureReceiver{}
	b := m.startNodeOpts(bDir, m.nodeInvite(),
		nodeOpts{transferBudget: bBudget, hideTransportAddrs: true, ledger: &bLedger,
			handlerWrapper: receiver.wrap, receiverConnContext: receiver.connContext})
	aID, bID := a.node.NodeIDForTest(), b.node.NodeIDForTest()
	aPeer, bPeer := a.rt.PeerID(), b.rt.PeerID()
	if aID == 0 || bID == 0 || aID == bID || aPeer == "" || bPeer == "" || aPeer == bPeer {
		t.Fatalf("two distinct nodes not assigned real identities: a=%d/%q b=%d/%q", aID, aPeer, bID, bPeer)
	}
	// A is the fast ingress; B's upload budget is intentionally small so the
	// planner chooses A -> B rather than B -> A after the client/replication legs.
	transferClosureSetProfile(t, m, aID, 4<<20, 4<<20, "a")
	transferClosureSetProfile(t, m, bID, 64<<10, 4<<20, "b")
	// B must first be relay-only: its endpoint has no direct transport address,
	// but StartP2P has synchronously established its authorized circuit reservation.
	epB, infra := transferClosureEndpoint(t, m, b.nodeDataAddr())
	if epB.PeerID != bPeer || len(epB.Addresses) != 0 {
		t.Fatalf("hidden node endpoint = %+v, want %q with no direct address", epB, bPeer)
	}
	dir, err := m.store.PeerDirectory(time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("PeerDirectory: %v", err)
	}
	if err := a.rt.SetDirectory(dir); err != nil {
		t.Fatalf("A SetDirectory: %v", err)
	}

	cl, res := m.login("alice")
	cs := &clientSecure{c: cl, res: res}
	cs.rt = m.startClientPeer(cs)
	if err := cl.SetTransferBudget(types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 1}); err != nil {
		t.Fatalf("SetTransferBudget: %v", err)
	}
	if _, err := cl.SetProtection("/", types.ProtectionSecurity); err != nil {
		t.Fatalf("SetProtection(security): %v", err)
	}
	obs := &natObserver{}
	obs.wrap(cl, m.url)
	// Directional observation 1: real A runtime dials B over circuit; the real
	// peerhttp Reporter names the serving connection. Record it into Master.
	relayObs, _ := transferClosureProbe(t, m, a.rt, epB, infra, peerhttp.PathRelay, 25*time.Second)
	transferClosureAssertObservedConn(t, relayObs, bPeer, peerhttp.PathRelay, true)
	// Master receives the circuit link only through the node's real heartbeat
	// autoprobe -> /nodes/transfer-observation; no direct inject.
	transferClosureWaitAutoprobe(t, obsRec, aID, bID, scheduler.TransferRelay, 35*time.Second)

	payload1 := []byte("peer-transfer-path-closure-relay-payload-0123456789")
	in1, err := cl.PutSmall("/path-closure-relay.bin", payload1, 1, false)
	if err != nil {
		t.Fatalf("relay-observation planned PutSmall: %v", err)
	}
	plan1 := transferClosurePlan(t, m, in1)
	if len(plan1.UploadTargets) != 1 || plan1.UploadTargets[0] != aID {
		t.Fatalf("relay plan ingress = %v, want only fast node %d", plan1.UploadTargets, aID)
	}
	leg1 := transferClosureLeg(t, plan1, aID, bID)
	if leg1.Path != scheduler.TransferRelay {
		t.Fatalf("meta transfer leg %d->%d path = %q, want circuit after relay observation: %+v", aID, bID, leg1.Path, plan1.Legs)
	}
	if len(in1.Chunks) != 1 || len(in1.Chunks[0].Replicas) != 2 || len(in1.Chunks[0].Done) != 2 ||
		!types.ContainsUint64(in1.Chunks[0].Replicas, aID) || !types.ContainsUint64(in1.Chunks[0].Replicas, bID) ||
		!types.ContainsUint64(in1.Chunks[0].Done, aID) || !types.ContainsUint64(in1.Chunks[0].Done, bID) {
		t.Fatalf("security tier did not produce two real Done confirmations (MinFaultTolerance untouched): %+v", in1.Chunks)
	}
	obj1 := types.ChunkObjID(in1.Chunks[0], in1.ID)
	put1 := transferClosureAssertObjectObservation(t, obs.snapshot(), http.MethodPut, obj1, a.nodeDataAddr(), aPeer, peerhttp.PathDirect)
	if put1.Identity != aPeer || put1.Path != peerhttp.PathDirect {
		t.Fatalf("client ingress PUT facts = %+v", put1)
	}
	transferClosureReadback(t, cs, "/path-closure-relay.bin", payload1)
	transferClosureAssertAnyObjectObservation(t, obs.snapshot(), http.MethodGet, obj1,
		map[string]string{a.nodeDataAddr(): aPeer, b.nodeDataAddr(): bPeer})
	transferClosureAssertLedgerPut(t, &bLedger, obj1, aPeer)
	recv1 := transferClosureAssertReceive(t, receiver, obj1, payload1, aPeer, true)

	// Same logical data address + same data directory => same NodeID and same
	// peer identity; no direct addresses are hidden this time.
	m.closeNode(b)
	b2 := m.startNodeAddr(bDir, m.nodeInvite(), b.nodeDataAddr(),
		nodeOpts{transferBudget: bBudget, ledger: &bLedger,
			handlerWrapper: receiver.wrap, receiverConnContext: receiver.connContext})
	if b2.node.NodeIDForTest() != bID || b2.rt.PeerID() != bPeer || b2.nodeDataAddr() != b.nodeDataAddr() {
		t.Fatalf("restart changed identity/logical address: node %d->%d peer %q->%q addr %q->%q",
			bID, b2.node.NodeIDForTest(), bPeer, b2.rt.PeerID(), b.nodeDataAddr(), b2.nodeDataAddr())
	}
	epB2, infra2 := transferClosureWaitDirectEndpoint(t, m, b2.nodeDataAddr(), bPeer)
	dir2, err := m.store.PeerDirectory(time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("PeerDirectory after restart: %v", err)
	}
	if err := a.rt.SetDirectory(dir2); err != nil {
		t.Fatalf("A SetDirectory after restart: %v", err)
	}

	// Directional observation 2: same PeerID, same real Runtime/Reporter, now
	// direct (loopback non-circuit; not a public reachability claim).
	directObs, _ := transferClosureProbe(t, m, a.rt, epB2, infra2, peerhttp.PathDirect, 15*time.Second)
	transferClosureAssertObservedConn(t, directObs, bPeer, peerhttp.PathDirect, false)
	// Node autoprobe's peer throttle is 10s; wait for the real authenticated
	// direct POST rather than a fixed sleep or a hand-injected observation.
	transferClosureWaitAutoprobe(t, obsRec, aID, bID, scheduler.TransferDirect, 45*time.Second)

	// A fresh registered client in the same space with its own budget avoids the
	// first client's 10s transfer-observation cache without changing any TTL.
	cl2, res2 := m.login("alice")
	cs2 := &clientSecure{c: cl2, res: res2}
	cs2.rt = m.startClientPeer(cs2)
	if err := cl2.SetTransferBudget(types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 1}); err != nil {
		t.Fatalf("second client SetTransferBudget: %v", err)
	}
	obs2 := &natObserver{}
	obs2.wrap(cl2, m.url)
	// The second client registered after A's last directory snapshot; refresh A
	// so its real gate authorizes this client's ingress PUT.
	dir3, err := m.store.PeerDirectory(time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("PeerDirectory for second client: %v", err)
	}
	if err := a.rt.SetDirectory(dir3); err != nil {
		t.Fatalf("A SetDirectory for second client: %v", err)
	}
	payload2 := []byte("peer-transfer-path-closure-direct-payload-0123456789")
	in2, err := cl2.PutSmall("/path-closure-direct.bin", payload2, 1, false)
	if err != nil {
		t.Fatalf("direct-observation planned PutSmall: %v", err)
	}
	plan2 := transferClosurePlan(t, m, in2)
	if len(plan2.UploadTargets) != 1 || plan2.UploadTargets[0] != aID {
		t.Fatalf("direct plan ingress = %v, want only fast node %d", plan2.UploadTargets, aID)
	}
	leg2 := transferClosureLeg(t, plan2, aID, bID)
	if leg2.Path != scheduler.TransferDirect {
		t.Fatalf("meta transfer leg %d->%d path = %q, want direct after direct observation: %+v", aID, bID, leg2.Path, plan2.Legs)
	}
	if len(in2.Chunks) != 1 || len(in2.Chunks[0].Replicas) != 2 || len(in2.Chunks[0].Done) != 2 ||
		!types.ContainsUint64(in2.Chunks[0].Done, aID) || !types.ContainsUint64(in2.Chunks[0].Done, bID) {
		t.Fatalf("direct security tier did not produce two real Done confirmations: %+v", in2.Chunks)
	}
	obj2 := types.ChunkObjID(in2.Chunks[0], in2.ID)
	put2 := transferClosureAssertObjectObservation(t, obs2.snapshot(), http.MethodPut, obj2, a.nodeDataAddr(), aPeer, peerhttp.PathDirect)
	if put2.ConnectionID == put1.ConnectionID && put2.StreamID == put1.StreamID {
		t.Fatalf("two independent object PUTs reused the same serving stream facts: first=%+v second=%+v", put1, put2)
	}
	transferClosureReadback(t, cs2, "/path-closure-direct.bin", payload2)
	transferClosureAssertAnyObjectObservation(t, obs2.snapshot(), http.MethodGet, obj2,
		map[string]string{a.nodeDataAddr(): aPeer, b2.nodeDataAddr(): bPeer})
	transferClosureAssertLedgerPut(t, &bLedger, obj2, aPeer)
	recv2 := transferClosureAssertReceive(t, receiver, obj2, payload2, aPeer, false)
	if recv1.remote == recv2.remote || recv1.streamID == recv2.streamID {
		t.Fatalf("relay/direct replica payloads did not cross distinct actual stream facts: relay=%+v direct=%+v", recv1, recv2)
	}

	// The directional link in Master was replaced by the newer direct serving
	// path; the older relay link is still present as a separate path key, so the
	// planner selected direct by the real observation, not by dial ordering.
	if !strings.Contains(relayObs.RemoteAddress, "/p2p-circuit") ||
		strings.Contains(directObs.RemoteAddress, "/p2p-circuit") {
		t.Fatalf("directional observations are not the expected relay/direct pair: relay=%+v direct=%+v", relayObs, directObs)
	}
}
