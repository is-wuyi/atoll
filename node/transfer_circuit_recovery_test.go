package node

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/peerhttp"
	"atoll/pkg/types"
)

func TestCircuitObservationGetsBoundedDirectRecheck(t *testing.T) {
	reported := make(chan types.TransferObservation, 4)
	master := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nodes/transfer-observation" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var observation types.TransferObservation
		if json.NewDecoder(r.Body).Decode(&observation) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		reported <- observation
		_, _ = w.Write([]byte("{}"))
	}))
	defer master.Close()
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer peer.Close()
	n := New(t.TempDir(), master.URL, "", 1<<30)
	n.SetTLS(master.Client().Transport.(*http.Transport).TLSClientConfig.Clone())
	if err := n.EnableSecurity(filepath.Join(t.TempDir(), "identity.key"), "", false); err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int64
	if err := n.SetPeerResolver(func(context.Context, string) (peerhttp.PeerDialer, error) {
		return func(ctx context.Context) peerhttp.PeerDial {
			attempt := dials.Add(1)
			conn, err := net.Dial("tcp", peer.Listener.Addr().String())
			path := peerhttp.PathRelay
			if attempt > 1 {
				path = peerhttp.PathDirect
			}
			return peerhttp.PeerDial{Conn: conn, Err: err, Path: path, Identity: "recovery-fixture"}
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
	transport := n.sec.base.(*peerhttp.Transport)
	defer transport.Close()
	n.httpClient = master.Client()
	if err := n.ConfigureTransferBudget(types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 1 << 20, MaxConcurrent: 1}); err != nil {
		t.Fatal(err)
	}
	n.SetNodeIDForTest(1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	plan := types.ReplicationPlan{Targets: []types.NodeInfo{{ID: 2, Addr: peer.Listener.Addr().String()}}}
	n.observeTransferPeers(ctx, plan)
	first := <-reported
	if first.Path != string(peerhttp.PathRelay) || !first.Available {
		t.Fatalf("first report = %+v", first)
	}
	n.observationMu.Lock()
	remaining := time.Until(n.observedPeers[2])
	n.observationMu.Unlock()
	if remaining <= 0 || remaining > 3*time.Second {
		t.Fatalf("circuit recheck delay = %v, want within 3s", remaining)
	}
	n.observeTransferPeers(ctx, plan)
	if dials.Load() != 1 {
		t.Fatalf("unexpired circuit observation bypassed throttle: dials=%d", dials.Load())
	}
	n.observationMu.Lock()
	n.observedPeers[2] = time.Now().Add(-time.Nanosecond)
	n.observationMu.Unlock()
	transport.CloseIdleConnections()
	n.observeTransferPeers(ctx, plan)
	second := <-reported
	if second.Path != string(peerhttp.PathDirect) || !second.Available {
		t.Fatalf("direct recovery report = %+v", second)
	}
	if dials.Load() != 2 {
		t.Fatalf("direct recovery did not re-probe: dials=%d", dials.Load())
	}
	n.observationMu.Lock()
	remaining = time.Until(n.observedPeers[2])
	n.observationMu.Unlock()
	if remaining <= 3*time.Second {
		t.Fatalf("direct recovery inherited the short circuit throttle: %v", remaining)
	}
}
