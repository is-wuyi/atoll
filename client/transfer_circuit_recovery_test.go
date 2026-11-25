package client

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/peerhttp"
	"atoll/pkg/types"
)

func TestCircuitObservationGetsBoundedDirectRecheck(t *testing.T) {
	node := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer node.Close()
	var discoveries atomic.Int64
	master := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/writes/transfer-nodes" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		discoveries.Add(1)
		_ = json.NewEncoder(w).Encode(types.WriteTransferNodes{Nodes: []types.NodeInfo{{ID: 2, Addr: node.Listener.Addr().String()}}, ObservationTTLSeconds: 30})
	}))
	defer master.Close()
	client, err := NewSecure(master.URL, master.Client().Transport.(*http.Transport).TLSClientConfig.Clone(), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetTransferBudget(types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 1 << 20, MaxConcurrent: 1}); err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int64
	if err := client.SetPeerResolver(func(context.Context, string) (peerhttp.PeerDialer, error) {
		return func(ctx context.Context) peerhttp.PeerDial {
			attempt := dials.Add(1)
			conn, err := net.Dial("tcp", node.Listener.Addr().String())
			path := peerhttp.PathRelay
			if attempt > 1 {
				path = peerhttp.PathDirect
			}
			return peerhttp.PeerDial{Conn: conn, Err: err, Path: path, Identity: "recovery-fixture"}
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
	transport := client.secTransport.base.(*peerhttp.Transport)
	defer transport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	upload := types.WriteUpload{ID: 1, PlanID: "recovery", Revision: 1}
	first, err := client.observeWriteTransfer(ctx, upload)
	if err != nil || len(first.Links) != 1 || first.Links[0].Path != string(peerhttp.PathRelay) || !first.Links[0].Available {
		t.Fatalf("first observation = %+v, %v", first, err)
	}
	if remaining := time.Until(client.transferValidUntil); remaining <= 0 || remaining > 3*time.Second {
		t.Fatalf("circuit cache lifetime = %v, want within 3s", remaining)
	}
	if _, err := client.observeWriteTransfer(ctx, upload); err != nil {
		t.Fatal(err)
	}
	if discoveries.Load() != 1 || dials.Load() != 1 {
		t.Fatalf("unexpired circuit observation bypassed cache: discoveries=%d dials=%d", discoveries.Load(), dials.Load())
	}
	client.transferMu.Lock()
	client.transferValidUntil = time.Now().Add(-time.Nanosecond)
	client.transferMu.Unlock()
	transport.CloseIdleConnections()
	second, err := client.observeWriteTransfer(ctx, upload)
	if err != nil || len(second.Links) != 1 || second.Links[0].Path != string(peerhttp.PathDirect) || !second.Links[0].Available {
		t.Fatalf("direct recovery observation = %+v, %v", second, err)
	}
	if discoveries.Load() != 2 || dials.Load() != 2 {
		t.Fatalf("direct recovery did not re-probe: discoveries=%d dials=%d", discoveries.Load(), dials.Load())
	}
	if remaining := time.Until(client.transferValidUntil); remaining <= 3*time.Second {
		t.Fatalf("direct recovery inherited the short circuit cache: %v", remaining)
	}
}
