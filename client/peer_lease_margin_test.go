package client

// Regression for the isolated-cluster 409: the center validates every request
// against its own now+EndpointLease, so a peer with a slightly fast clock must
// not ask for the full window. Before the margin, a ~0.19s skew was enough to
// reject every registration and leave the peer unable to start.

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/peerauth"
)

func TestClientPeerRegistrationKeepsCenterLeaseMargin(t *testing.T) {
	peerID, pub := testPeerIdentity(t)
	// The observed real-world skew was about 0.19s; 200ms keeps this test
	// deterministic without waiting for the actual lease window.
	const skew = 200 * time.Millisecond
	var posts atomic.Int64
	rt := &stubRoundTripper{}
	rt.handler = func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/peers/client-self":
			return jsonResp(http.StatusOK, clientStateJSON(t, 0)), nil
		case req.Method == http.MethodPost && req.URL.Path == "/peers/client":
			posts.Add(1)
			reg := regFromBody(t, bodyOf(req))
			// Mirror the center's strict window check with a center clock that
			// lags the reporting peer.
			centerNow := time.Now().Add(-skew).UTC()
			if !centerNow.Before(reg.NotAfter) || reg.NotAfter.After(centerNow.Add(peerauth.EndpointLease)) {
				return jsonResp(http.StatusConflict, nil), nil
			}
			return jsonResp(http.StatusOK, clientEndpointJSON(t, peerID, pub, reg.ExpectedRevision+1)), nil
		}
		return jsonResp(http.StatusNotFound, []byte(`{}`)), nil
	}
	_, p := newRegClient(t, rt, &stubPeerRuntime{peerID: peerID, pubKey: pub}, "token-a", 1)
	if err := p.doRegistration(context.Background(), "token-a", 1, true); err != nil {
		t.Fatalf("registration must keep a lease margin for clock skew: %v", err)
	}
	if got := posts.Load(); got != 1 {
		t.Fatalf("registration POSTs = %d, want 1 (a 409 loop means the margin was lost)", got)
	}
}
