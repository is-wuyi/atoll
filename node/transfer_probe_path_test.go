package node

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"atoll/pkg/peerhttp"
	"atoll/pkg/types"
)

func TestTransferFailedPeerProbeReportsUnknownPath(t *testing.T) {
	reported := make(chan types.TransferObservation, 1)
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
	node := New(t.TempDir(), master.URL, "", 1<<30)
	node.SetTLS(master.Client().Transport.(*http.Transport).TLSClientConfig.Clone())
	if err := node.EnableSecurity(filepath.Join(t.TempDir(), "identity.key"), "", false); err != nil {
		t.Fatal(err)
	}
	if err := node.SetPeerResolver(func(context.Context, string) (peerhttp.PeerDialer, error) {
		return func(context.Context) peerhttp.PeerDial {
			return peerhttp.PeerDial{Err: errors.New("fixture has no verified connection"), Path: peerhttp.PathUnknown}
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
	defer node.sec.base.(*peerhttp.Transport).Close()
	// This regression covers probe attribution, not device enrollment. Keep its
	// control request on the test server's verified TLS client.
	node.httpClient = master.Client()
	if err := node.ConfigureTransferBudget(types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 1 << 20, MaxConcurrent: 1}); err != nil {
		t.Fatal(err)
	}
	node.SetNodeIDForTest(1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	node.observeTransferPeers(ctx, types.ReplicationPlan{Targets: []types.NodeInfo{{ID: 2, Addr: "127.0.0.1:1"}}})
	select {
	case observation := <-reported:
		if observation.Path != string(peerhttp.PathUnknown) || observation.Available || observation.ThroughputBPS != 0 || observation.FromNodeID != 1 || observation.ToNodeID != 2 {
			t.Fatalf("failed peer probe invented an ordinary HTTPS path: %+v", observation)
		}
	case <-ctx.Done():
		t.Fatal("failed probe was not reported to the control endpoint")
	}
}
