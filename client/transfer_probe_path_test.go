package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"atoll/pkg/peerhttp"
	"atoll/pkg/types"
)

func TestWriteTransferFailedPeerProbeKeepsUnknownPath(t *testing.T) {
	master := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/writes/transfer-nodes" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(types.WriteTransferNodes{Nodes: []types.NodeInfo{{ID: 1, Addr: "127.0.0.1:1"}}})
	}))
	defer master.Close()
	client, err := NewSecure(master.URL, master.Client().Transport.(*http.Transport).TLSClientConfig.Clone(), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetTransferBudget(types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 1 << 20, MaxConcurrent: 1}); err != nil {
		t.Fatal(err)
	}
	if err := client.SetPeerResolver(func(context.Context, string) (peerhttp.PeerDialer, error) {
		return func(context.Context) peerhttp.PeerDial {
			return peerhttp.PeerDial{Err: errors.New("fixture has no verified connection"), Path: peerhttp.PathUnknown}
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
	defer client.secTransport.base.(*peerhttp.Transport).Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	observation, err := client.observeWriteTransfer(ctx, types.WriteUpload{ID: 1, PlanID: "probe", Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.Links) != 1 || observation.Links[0].Path != string(peerhttp.PathUnknown) || observation.Links[0].Available || observation.Links[0].ThroughputBPS != 0 {
		t.Fatalf("failed peer probe invented an ordinary HTTPS path: %+v", observation)
	}
}
