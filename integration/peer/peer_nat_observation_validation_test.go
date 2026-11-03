package peer

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"atoll/pkg/contentcrypto"
	"atoll/pkg/peerhttp"
)

func relayObservationPair(request, method, path string, status int, failure string) []peerhttp.Observation {
	dial := peerhttp.Observation{Scheme: "https", Target: "node.test:9421", Method: method, RequestPath: path,
		RequestID: request, Identity: "peer-node", ConnectionID: "conn-" + request, StreamID: "stream-" + request,
		LocalAddress: "/ip4/127.0.0.1/tcp/1", RemoteAddress: "/ip4/127.0.0.1/tcp/2/p2p/relay/p2p-circuit",
		Path: peerhttp.PathRelay, Fallback: true, Phase: peerhttp.PhaseDial,
	}
	response := dial
	response.Phase, response.Status, response.ErrorKind = peerhttp.PhaseResponse, status, failure
	return []peerhttp.Observation{dial, response}
}

func TestRelayObservationValidationKeepsRetriesAndRejectsFalseSuccess(t *testing.T) {
	path := "/objects/42"
	valid := append(relayObservationPair("failed", http.MethodPut, path, 0, peerhttp.ErrorRead), relayObservationPair("written", http.MethodPut, path, http.StatusCreated, "")...)
	valid = append(valid, relayObservationPair("read", http.MethodGet, path, http.StatusOK, "")...)
	if err := validateRelayOnlyObservations(valid, "node.test:9421", "peer-node", []uint64{42}); err != nil {
		t.Fatalf("bound failed attempt followed by verified success was rejected: %v", err)
	}
	// A read failure may follow a transport re-dial: the failed response still
	// proves it came from the authenticated target, while the final success must
	// match an accepted dial exactly.
	redialed := append([]peerhttp.Observation(nil), valid...)
	redialed[1].ConnectionID, redialed[1].StreamID, redialed[1].RemoteAddress = "conn-retried", "stream-retried", "/ip4/127.0.0.1/tcp/9/p2p/relay/p2p-circuit"
	if err := validateRelayOnlyObservations(redialed, "node.test:9421", "peer-node", []uint64{42}); err != nil {
		t.Fatalf("failed response after a transport re-dial was rejected: %v", err)
	}
	// A transport re-dial may produce a second accepted dial for the same
	// request; the completed response must match the later one.
	late := relayObservationPair("written", http.MethodPut, path, http.StatusCreated, "")
	late[0].ConnectionID, late[0].StreamID, late[0].RemoteAddress = "conn-late", "stream-late", "/ip4/127.0.0.1/tcp/11/p2p/relay/p2p-circuit"
	late[1].ConnectionID, late[1].StreamID, late[1].RemoteAddress = "conn-late", "stream-late", "/ip4/127.0.0.1/tcp/11/p2p/relay/p2p-circuit"
	redialSuccess := append([]peerhttp.Observation(nil), valid[:3]...)
	redialSuccess = append(redialSuccess, late...)
	redialSuccess = append(redialSuccess, valid[4:]...)
	if err := validateRelayOnlyObservations(redialSuccess, "node.test:9421", "peer-node", []uint64{42}); err != nil {
		t.Fatalf("re-dialed request with a matching completed response was rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func([]peerhttp.Observation) []peerhttp.Observation
	}{
		{"missing put success", func(in []peerhttp.Observation) []peerhttp.Observation { return append(in[:2], in[4:]...) }},
		{"missing get", func(in []peerhttp.Observation) []peerhttp.Observation { return in[:4] }},
		{"wrong response peer", func(in []peerhttp.Observation) []peerhttp.Observation { in[3].Identity = "other-peer"; return in }},
		{"wrong response connection", func(in []peerhttp.Observation) []peerhttp.Observation { in[3].ConnectionID = "other-conn"; return in }},
		{"wrong response request", func(in []peerhttp.Observation) []peerhttp.Observation {
			in[3].RequestID = "unrelated-request"
			return in
		}},
		{"direct accepted stream", func(in []peerhttp.Observation) []peerhttp.Observation { in[2].Path = peerhttp.PathDirect; return in }},
		{"wrong receipt", func(in []peerhttp.Observation) []peerhttp.Observation { in[3].Status = http.StatusOK; return in }},
		{"unrecovered last failure", func(in []peerhttp.Observation) []peerhttp.Observation {
			return append(in, relayObservationPair("last-failed", http.MethodPut, path, 0, peerhttp.ErrorRead)...)
		}},
		{"retries exceeded", func(in []peerhttp.Observation) []peerhttp.Observation {
			var out []peerhttp.Observation
			for i := 0; i < 3; i++ {
				out = append(out, relayObservationPair(fmt.Sprint(i), http.MethodPut, path, 0, peerhttp.ErrorRead)...)
			}
			return append(out, in[2:]...)
		}},
		{"authorization failure", func(in []peerhttp.Observation) []peerhttp.Observation {
			in[1].ErrorKind = peerhttp.ErrorRefused
			return in
		}},
		{"wrong object", func(in []peerhttp.Observation) []peerhttp.Observation { in[3].RequestPath = "/objects/43"; return in }},
		{"identical dial twice", func(in []peerhttp.Observation) []peerhttp.Observation {
			return append(append([]peerhttp.Observation(nil), in[:3]...), append([]peerhttp.Observation{in[2]}, in[3:]...)...)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := append([]peerhttp.Observation(nil), valid...)
			if err := validateRelayOnlyObservations(tc.change(input), "node.test:9421", "peer-node", []uint64{42}); err == nil {
				t.Fatal("invalid or incomplete relay evidence was accepted")
			}
		})
	}
}

func TestPeerNATRelayRetryPreservesCiphertextAndRequestEvidence(t *testing.T) {
	pki := newTestPKI(t)
	kek, err := contentcrypto.NewKEKFromSecret("relay-retry-test-key", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	m := newPeerMasterOpts(t, pki, masterOpts{contentKEK: kek})
	m.createUser("alice")
	var drop atomic.Bool
	var lostObject atomic.Uint64
	n := m.startNodeOpts(t.TempDir(), m.nodeInvite(), nodeOpts{hideTransportAddrs: true, handlerWrapper: func(inner http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/objects/") && drop.CompareAndSwap(false, true) {
				// Drop the connection only after the real handler stores and confirms.
				response := httptest.NewRecorder()
				inner.ServeHTTP(response, r)
				if response.Code == http.StatusCreated {
					id, _ := strconv.ParseUint(strings.TrimPrefix(r.URL.Path, "/objects/"), 10, 64)
					lostObject.Store(id)
					panic(http.ErrAbortHandler)
				}
				for key, values := range response.Header() {
					w.Header()[key] = values
				}
				w.WriteHeader(response.Code)
				_, _ = w.Write(response.Body.Bytes())
				return
			}
			inner.ServeHTTP(w, r)
		})
	}})
	c, res := m.login("alice")
	cs := &clientSecure{c: c, res: res}
	cs.rt = m.startClientPeer(cs)
	observed := &natObserver{}
	observed.wrap(c, m.url)
	data := bytes.Repeat([]byte("same-ciphertext-relay-retry-"), 3000)
	if err := c.PutChunkedReader("/relay-retry", int64(len(data)), bytes.NewReader(data), 1); err != nil {
		t.Fatal(err)
	}
	in := findFile(t, m.store, "relay-retry")
	if len(in.Chunks) != 1 || len(in.Chunks[0].Done) != 1 || in.Chunks[0].WriteEpoch != 1 || lostObject.Load() != in.Chunks[0].ID {
		t.Fatalf("lost-response fixture changed its immutable object or epoch: %+v", in)
	}
	verifyAEADChunk(t, m, kek, n, in.Chunks[0], data)
	out := filepath.Join(t.TempDir(), "readback")
	if err := c.Get("/relay-retry", out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("retry returned different content")
	}
	observations := observed.snapshot()
	failures, successes := 0, 0
	for _, o := range observations {
		if o.Method == http.MethodPut && o.Phase == peerhttp.PhaseResponse {
			if o.ErrorKind != peerhttp.ErrorNone {
				failures++
			} else {
				successes++
			}
		}
	}
	if failures != 1 || successes != 1 {
		t.Fatalf("retry lacks one real failed and one completed response: failures=%d successes=%d", failures, successes)
	}
	assertRelayOnlyObservations(t, observations, n, in)
}
