package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"atoll/pkg/types"
)

func TestWriteRecoveryFeatureIsOnlySentAfterNegotiation(t *testing.T) {
	for _, feature := range []string{"write-recovery-v1", types.WriteRecoveryFeature} {
		t.Run(feature, func(t *testing.T) {
			var upgraded atomic.Bool
			var announced atomic.Bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/capabilities" {
					current := feature
					if upgraded.Load() {
						current = types.WriteRecoveryFeature
					}
					json.NewEncoder(w).Encode(types.Capabilities{Features: []string{types.WritePlanFeature, current}, WritePlanning: true})
					return
				}
				announced.Store(strings.Contains(r.Header.Get(types.FeaturesHeader), types.WriteRecoveryFeature))
				json.NewEncoder(w).Encode(struct{}{})
			}))
			defer srv.Close()
			c := New(srv.URL)
			if enabled, err := c.WritePlanning(context.Background()); err != nil || !enabled {
				t.Fatalf("write planning negotiation: enabled=%t err=%v", enabled, err)
			}
			for _, upgrade := range []bool{false, true} {
				upgraded.Store(upgrade)
				if err := c.writeJSON(context.Background(), http.MethodPost, "/writes", struct{}{}, nil); err != nil {
					t.Fatal(err)
				}
				if want := feature == types.WriteRecoveryFeature; announced.Load() != want || c.writeRecovery != want {
					t.Fatalf("unnegotiated recovery was announced: upgrade=%t announced=%t negotiated=%t", upgrade, announced.Load(), c.writeRecovery)
				}
			}
		})
	}
}
