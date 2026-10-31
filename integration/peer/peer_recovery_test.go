package peer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"atoll/pkg/contentcrypto"
	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
	"atoll/pkg/types"
)

type recoveryRoundTripper func(*http.Request) (*http.Response, error)

func (f recoveryRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type recoveryPayload struct {
	id       uint64
	host     string
	source   string
	epoch    uint64
	injected bool
	data     []byte
}

type recoveryCapture struct {
	mu           sync.Mutex
	badHost      string
	payloads     []*recoveryPayload
	begins       []types.BeginWriteResponse
	plans        []types.PlanWriteChunkResponse
	recoveries   []types.PlanWriteChunkResponse
	recoveryReqs []types.RecoverWriteChunkRequest
	paths        []peerhttp.Observation
	err          error
}

type recoveryReadBody struct {
	io.ReadCloser
	capture *recoveryCapture
	record  *recoveryPayload
}

func (b *recoveryReadBody) Read(p []byte) (int, error) {
	b.capture.mu.Lock()
	left := (32 << 10) - len(b.record.data)
	b.capture.mu.Unlock()
	if b.record.injected {
		if left <= 0 {
			return 0, io.ErrUnexpectedEOF
		}
		if len(p) > left {
			p = p[:left]
		}
	}
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.capture.mu.Lock()
		b.record.data = append(b.record.data, p[:n]...)
		b.capture.mu.Unlock()
	}
	return n, err
}

func (c *recoveryCapture) wrapNode(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || !strings.HasPrefix(r.URL.Path, "/objects/") {
			next.ServeHTTP(w, r)
			return
		}
		id, err := strconv.ParseUint(strings.TrimPrefix(r.URL.Path, "/objects/"), 10, 64)
		if err != nil {
			http.Error(w, "invalid test object", http.StatusBadRequest)
			return
		}
		_, index := types.ParseChunkID(id)
		epoch, _ := strconv.ParseUint(r.Header.Get(types.WriteEpochHeader), 10, 64)
		c.mu.Lock()
		if index == 1 && c.badHost == "" {
			c.badHost = r.Host
		}
		record := &recoveryPayload{id: id, host: r.Host, source: peerauth.SourcePeerID(r.Context()), epoch: epoch, injected: index == 1 && r.Host == c.badHost}
		c.payloads = append(c.payloads, record)
		c.mu.Unlock()
		// The real handler authorizes the request and reads these bytes itself.
		// No pre-read is allowed to masquerade as receiver progress.
		r.Body = &recoveryReadBody{ReadCloser: r.Body, capture: c, record: record}
		next.ServeHTTP(w, r)
	})
}

func (c *recoveryCapture) wrapClient(base http.RoundTripper, masterURL string) http.RoundTripper {
	return recoveryRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme+"://"+r.URL.Host != masterURL {
			ctx := peerhttp.WithPath(r.Context(), peerhttp.PathDirect)
			ctx = peerhttp.WithReporter(ctx, &peerhttp.Reporter{Observe: func(o peerhttp.Observation) {
				c.mu.Lock()
				c.paths = append(c.paths, o)
				c.mu.Unlock()
			}})
			return base.RoundTrip(r.Clone(ctx))
		}
		if r.URL.Path == "/writes/chunks/recover" && r.GetBody != nil {
			body, err := r.GetBody()
			if err != nil {
				return nil, err
			}
			var req types.RecoverWriteChunkRequest
			err = json.NewDecoder(body).Decode(&req)
			body.Close()
			if err != nil {
				return nil, err
			}
			c.mu.Lock()
			c.recoveryReqs = append(c.recoveryReqs, req)
			c.mu.Unlock()
		}
		resp, err := base.RoundTrip(r)
		if err != nil || resp.StatusCode >= 300 || r.Method != http.MethodPost {
			return resp, err
		}
		if r.URL.Path != "/writes" && r.URL.Path != "/writes/chunks" && r.URL.Path != "/writes/chunks/recover" {
			return resp, nil
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		c.mu.Lock()
		defer c.mu.Unlock()
		if r.URL.Path == "/writes" {
			var out types.BeginWriteResponse
			c.err = errors.Join(c.err, json.Unmarshal(raw, &out))
			c.begins = append(c.begins, out)
		} else {
			var out types.PlanWriteChunkResponse
			c.err = errors.Join(c.err, json.Unmarshal(raw, &out))
			if r.URL.Path == "/writes/chunks/recover" {
				c.recoveries = append(c.recoveries, out)
			} else {
				c.plans = append(c.plans, out)
			}
		}
		return resp, nil
	})
}

func TestPeerAEADRecoveryPreservesCiphertext(t *testing.T) {
	pki := newTestPKI(t)
	kek, err := contentcrypto.NewKEKFromSecret("peer-recovery-key", bytes.Repeat([]byte{0x39}, 32))
	if err != nil {
		t.Fatal(err)
	}
	m := newPeerMasterOpts(t, pki, masterOpts{contentKEK: kek, maxReplicas: 1})
	m.createUser("alice")
	capture := &recoveryCapture{}
	byID := map[uint64]*peerNode{}
	for i := 0; i < 3; i++ {
		n := m.startNodeOpts(filepath.Join(t.TempDir(), fmt.Sprintf("node%d", i)), m.nodeInvite(), nodeOpts{handlerWrapper: capture.wrapNode})
		byID[n.node.NodeIDForTest()] = n
	}
	cl, res := m.login("alice")
	cs := &clientSecure{c: cl, res: res}
	cs.rt = m.startClientPeer(cs)
	cl.HTTP.Transport = capture.wrapClient(cl.HTTP.Transport, m.url)

	oldChunkSize := types.ChunkSize
	types.ChunkSize = 128 << 10
	t.Cleanup(func() { types.ChunkSize = oldChunkSize })
	payload := bytes.Repeat([]byte("aead-recovery-byte-identity"), 11000)[:192<<10]
	if err := cl.PutChunkedReader("/recovered.bin", int64(len(payload)), bytes.NewReader(payload), 1); err != nil {
		t.Fatalf("recoverable peer upload: %v", err)
	}
	in := findFile(t, m.store, "recovered.bin")
	if len(in.Chunks) != 2 || in.Content == nil {
		t.Fatalf("missing two-block content manifest: %+v", in)
	}
	outPath := filepath.Join(t.TempDir(), "readback.bin")
	if err := cl.Get("/recovered.bin", outPath); err != nil {
		t.Fatalf("readback after recovery: %v", err)
	}
	readback, err := os.ReadFile(outPath)
	if err != nil || !bytes.Equal(readback, payload) {
		t.Fatalf("readback differs after recovery: %v", err)
	}

	capture.mu.Lock()
	defer capture.mu.Unlock()
	if capture.err != nil || len(capture.begins) != 1 || len(capture.plans) != 2 || len(capture.recoveries) != 1 {
		t.Fatalf("unexpected control transcript: begins=%d plans=%d recoveries=%d err=%v", len(capture.begins), len(capture.plans), len(capture.recoveries), capture.err)
	}
	upload := capture.begins[0].Upload
	if upload.ID != in.Content.ID || upload.Revision != 1 {
		t.Fatalf("recovery replaced the content identity: upload=%d content=%d revision=%d", upload.ID, in.Content.ID, upload.Revision)
	}
	if len(capture.recoveryReqs) != 1 || capture.recoveryReqs[0].UploadID != upload.ID || capture.recoveryReqs[0].PlanID != upload.PlanID || capture.recoveryReqs[0].Revision != upload.Revision {
		t.Fatalf("recovery changed the write binding: %+v", capture.recoveryReqs)
	}
	var initial types.WriteChunkPlan
	for _, p := range capture.plans {
		if p.Plan.Index == 1 {
			initial = p.Plan
		}
	}
	recovered := capture.recoveries[0].Plan
	if initial.Recovery == nil || recovered.Recovery == nil || recovered.Object != initial.Object || recovered.Recovery.Epoch != initial.Recovery.Epoch+1 || recovered.Recovery.Attempts != 1 || !recovered.Recovery.HardUntil.Equal(initial.Recovery.HardUntil) || recovered.RequiredConfirmations != initial.RequiredConfirmations || len(recovered.Layout.Nodes) != len(initial.Layout.Nodes) {
		t.Fatalf("recovery changed immutable contents or confirmation conditions: old=%+v new=%+v", initial, recovered)
	}
	if len(initial.Layout.Nodes) != 1 || len(recovered.Layout.Nodes) != 1 || recovered.Layout.Nodes[0] == initial.Layout.Nodes[0] || !types.ContainsUint64(recovered.Recovery.Excluded, initial.Layout.Nodes[0]) {
		t.Fatalf("failed target was not replaced: old=%+v new=%+v", initial.Layout, recovered.Layout)
	}
	if in.Chunks[0].WriteEpoch != 1 || in.Chunks[1].WriteEpoch != 2 {
		t.Fatalf("recovery affected the wrong chunk epochs: %+v", in.Chunks)
	}

	logicalOffset := 0
	for _, chunk := range in.Chunks {
		if len(chunk.Done) != 1 || len(chunk.Replicas) != 1 || chunk.Done[0] != chunk.Replicas[0] {
			t.Fatalf("chunk %d lacks its required complete receipt: %+v", chunk.Index, chunk)
		}
		node := byID[chunk.Done[0]]
		if node == nil {
			t.Fatalf("unknown completed node %d", chunk.Done[0])
		}
		verifyAEADChunk(t, m, kek, node, chunk, payload[logicalOffset:logicalOffset+int(chunk.LogicalSize)])
		logicalOffset += int(chunk.LogicalSize)
		ciphertext := nodeObjectBytes(t, node, chunk.ID)
		attempts, failures := 0, 0
		for _, p := range capture.payloads {
			if p.id != chunk.ID {
				continue
			}
			attempts++
			if p.source != cs.rt.PeerID() || len(p.data) == 0 || len(p.data) > len(ciphertext) || !bytes.Equal(p.data, ciphertext[:len(p.data)]) {
				t.Fatalf("chunk %d sent different ciphertext or source on retry: source=%q bytes=%d", chunk.Index, p.source, len(p.data))
			}
			if p.injected {
				failures++
				if len(p.data) != 32<<10 || p.epoch != 1 {
					t.Fatalf("failed receive did not stop at the intended byte/epoch: bytes=%d epoch=%d", len(p.data), p.epoch)
				}
			} else if len(p.data) != len(ciphertext) || p.epoch != chunk.WriteEpoch {
				t.Fatalf("completed payload length/epoch differs from the manifest: bytes=%d epoch=%d", len(p.data), p.epoch)
			}
		}
		if chunk.Index == 0 && (attempts != 1 || failures != 0) || chunk.Index == 1 && (attempts != 4 || failures != 3) {
			t.Fatalf("chunk %d unexpected retries: attempts=%d failures=%d", chunk.Index, attempts, failures)
		}
	}
	if len(capture.paths) == 0 {
		t.Fatal("no actual peer path observations")
	}
	for _, observation := range capture.paths {
		if observation.Master || observation.Path != peerhttp.PathDirect {
			t.Fatalf("data request bypassed the required peer path: %+v", observation)
		}
	}
}
