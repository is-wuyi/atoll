package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/types"
)

type recoveryStatusRetryTransport func(*http.Request) (*http.Response, error)

func (f recoveryStatusRetryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func recoveryStatusRetryFixture() (*Client, types.WriteUpload, types.WriteChunkPlan) {
	c := New("http://master")
	upload := types.WriteUpload{ID: types.StagingInodeBase + 31, PlanID: "wp1_status_retry_fixture", Revision: 1}
	plan := types.WriteChunkPlan{
		Index:         1,
		Object:        types.ContentObject{ID: 91, StoredSize: 8},
		Layout:        types.ReplicaLayout{ObjectID: 91, Epoch: 2, Nodes: []uint64{1, 2}},
		Confirmations: []uint64{1},
		Recovery:      &types.WriteRecovery{Epoch: 2, HardUntil: time.Now().Add(time.Minute)},
	}
	return c, upload, plan
}

func recoveryStatusResponse(r *http.Request, code int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: code,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    r,
	}
}

func recoveryStatusJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPlannedWriteRecoveryRetriesTransientStatus(t *testing.T) {
	withChunkSize(t, 1024)
	for _, tc := range []struct {
		name string
		kind string
	}{
		{name: "network-eof", kind: "eof"},
		{name: "temporary-503", kind: "503"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl := newPlannedClusterWithReplicas(t, 3, 1)
			base := cl.client.HTTP.Transport
			var mu sync.Mutex
			var badHost string
			chunkEpochs := map[int][]uint64{}
			var recoveryAccepted atomic.Bool
			var statusFaults atomic.Int32
			var recoveryPosts atomic.Int32
			var abortPosts atomic.Int32

			cl.client.HTTP.Transport = recoveryStatusRetryTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/objects/") && r.Header.Get(types.WriteEpochHeader) == "1" {
					var objectID uint64
					if _, err := fmt.Sscanf(r.URL.Path, "/objects/%d", &objectID); err == nil {
						_, index := types.ParseChunkID(objectID)
						if index == 1 {
							mu.Lock()
							if badHost == "" {
								badHost = r.URL.Host
							}
							fail := r.URL.Host == badHost
							mu.Unlock()
							if fail {
								_ = r.Body.Close()
								return nil, errors.New("injected original epoch target disconnect")
							}
						}
					}
				}

				if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/writes/status") && recoveryAccepted.Load() && statusFaults.CompareAndSwap(0, 1) {
					if tc.kind == "eof" {
						return nil, io.ErrUnexpectedEOF
					}
					return recoveryStatusResponse(r, http.StatusServiceUnavailable, []byte(`{"error":"injected one-shot master 503"}`)), nil
				}

				if r.URL.Path == "/writes/chunks/recover" {
					recoveryPosts.Add(1)
				}
				if r.URL.Path == "/writes/abort" {
					abortPosts.Add(1)
				}
				resp, err := base.RoundTrip(r)
				if err != nil || resp == nil {
					return resp, err
				}
				if (r.URL.Path == "/writes/chunks" || r.URL.Path == "/writes/chunks/recover") && resp.StatusCode == http.StatusOK {
					raw, readErr := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if readErr != nil {
						return nil, readErr
					}
					var out types.PlanWriteChunkResponse
					if err := json.Unmarshal(raw, &out); err != nil {
						return nil, err
					}
					mu.Lock()
					chunkEpochs[out.Plan.Index] = append(chunkEpochs[out.Plan.Index], out.Plan.Recovery.Epoch)
					mu.Unlock()
					if r.URL.Path == "/writes/chunks/recover" {
						recoveryAccepted.Store(true)
					}
					resp.Body = io.NopCloser(bytes.NewReader(raw))
				}
				return resp, nil
			})

			data := bytes.Repeat([]byte("Q"), 2048)
			remote := "/status-retry-" + tc.name
			if err := cl.client.PutChunkedReader(remote, int64(len(data)), bytes.NewReader(data), 1); err != nil {
				t.Fatalf("transient status failure should be retried: %v", err)
			}
			if statusFaults.Load() != 1 {
				t.Fatalf("status fault injection count=%d, want 1", statusFaults.Load())
			}
			if recoveryPosts.Load() != 1 {
				t.Fatalf("recovery posts=%d, want exactly one (no extra epoch)", recoveryPosts.Load())
			}
			if abortPosts.Load() != 0 {
				t.Fatalf("successful recovery must not abort; abort posts=%d", abortPosts.Load())
			}

			mu.Lock()
			chunk0Epochs := append([]uint64(nil), chunkEpochs[0]...)
			chunk1Epochs := append([]uint64(nil), chunkEpochs[1]...)
			mu.Unlock()
			if !reflect.DeepEqual(chunk0Epochs, []uint64{1}) {
				t.Fatalf("unaffected chunk epochs=%v, want [1]", chunk0Epochs)
			}
			if !reflect.DeepEqual(chunk1Epochs, []uint64{1, 2}) {
				t.Fatalf("failed chunk epochs=%v, want [1 2]", chunk1Epochs)
			}

			in, _, err := cl.client.Lookup(remote)
			if err != nil || len(in.Chunks) != 2 {
				t.Fatalf("recovered file lookup: chunks=%d err=%v", len(in.Chunks), err)
			}
			outPath := filepath.Join(t.TempDir(), "readback")
			if err := cl.client.Get(remote, outPath); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(outPath)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("recovered readback differs: err=%v", err)
			}
		})
	}
}

func TestCurrentRecoveryStatusRetriesTransientFailuresWithSameBinding(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first func(*http.Request) (*http.Response, error)
	}{
		{name: "network-eof", first: func(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF }},
		{name: "temporary-503", first: func(r *http.Request) (*http.Response, error) {
			return recoveryStatusResponse(r, http.StatusServiceUnavailable, []byte(`{"error":"temporary"}`)), nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, upload, plan := recoveryStatusRetryFixture()
			var calls atomic.Int32
			var queries []url.Values
			var mu sync.Mutex
			c.HTTP.Transport = recoveryStatusRetryTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				queries = append(queries, r.URL.Query())
				mu.Unlock()
				if calls.Add(1) == 1 {
					return tc.first(r)
				}
				body := recoveryStatusJSON(t, types.WriteStatus{UploadID: upload.ID, Chunks: []types.WriteChunkStatus{{Index: plan.Index, Epoch: plan.Recovery.Epoch}}})
				return recoveryStatusResponse(r, http.StatusOK, body), nil
			})

			status, err := c.currentRecoveryStatus(context.Background(), upload, plan)
			if err != nil || status.Index != plan.Index || status.Epoch != plan.Recovery.Epoch {
				t.Fatalf("status retry result=%+v err=%v", status, err)
			}
			if calls.Load() != 2 {
				t.Fatalf("calls=%d, want 2 (one retry)", calls.Load())
			}
			mu.Lock()
			defer mu.Unlock()
			if len(queries) != 2 || !reflect.DeepEqual(queries[0], queries[1]) {
				t.Fatalf("retry changed status binding: %v", queries)
			}
			if queries[0].Get("upload_id") != fmt.Sprint(upload.ID) || queries[0].Get("plan_id") != upload.PlanID || queries[0].Get("revision") != fmt.Sprint(upload.Revision) {
				t.Fatalf("unexpected binding query: %v", queries[0])
			}
		})
	}
}

func TestCurrentRecoveryStatusPersistentTransientFailuresAreBounded(t *testing.T) {
	for _, tc := range []struct {
		name string
		resp func(*http.Request) (*http.Response, error)
	}{
		{name: "network-eof", resp: func(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF }},
		{name: "temporary-503", resp: func(r *http.Request) (*http.Response, error) {
			return recoveryStatusResponse(r, http.StatusServiceUnavailable, []byte(`{"error":"still unavailable"}`)), nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, upload, plan := recoveryStatusRetryFixture()
			var calls atomic.Int32
			c.HTTP.Transport = recoveryStatusRetryTransport(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				return tc.resp(r)
			})
			if _, err := c.currentRecoveryStatus(context.Background(), upload, plan); err == nil {
				t.Fatal("persistent transient error unexpectedly succeeded")
			}
			if calls.Load() != 3 {
				t.Fatalf("calls=%d, want bounded maximum 3", calls.Load())
			}
		})
	}
}

func TestCurrentRecoveryStatusDoesNotRetryPermanentOrInvalidResponses(t *testing.T) {
	for _, tc := range []struct {
		name string
		resp func(types.WriteUpload, types.WriteChunkPlan, *http.Request) (*http.Response, error)
	}{
		{name: "http-409", resp: func(_ types.WriteUpload, _ types.WriteChunkPlan, r *http.Request) (*http.Response, error) {
			return recoveryStatusResponse(r, http.StatusConflict, []byte(`{"error":"conflict"}`)), nil
		}},
		{name: "http-403", resp: func(_ types.WriteUpload, _ types.WriteChunkPlan, r *http.Request) (*http.Response, error) {
			return recoveryStatusResponse(r, http.StatusForbidden, []byte(`{"error":"denied"}`)), nil
		}},
		{name: "invalid-binding", resp: func(u types.WriteUpload, p types.WriteChunkPlan, r *http.Request) (*http.Response, error) {
			body := recoveryStatusJSON(t, types.WriteStatus{UploadID: u.ID + 1, Chunks: []types.WriteChunkStatus{{Index: p.Index, Epoch: p.Recovery.Epoch}}})
			return recoveryStatusResponse(r, http.StatusOK, body), nil
		}},
		{name: "invalid-epoch", resp: func(u types.WriteUpload, p types.WriteChunkPlan, r *http.Request) (*http.Response, error) {
			body := recoveryStatusJSON(t, types.WriteStatus{UploadID: u.ID, Chunks: []types.WriteChunkStatus{{Index: p.Index, Epoch: p.Recovery.Epoch + 1}}})
			return recoveryStatusResponse(r, http.StatusOK, body), nil
		}},
		{name: "invalid-progress", resp: func(u types.WriteUpload, p types.WriteChunkPlan, r *http.Request) (*http.Response, error) {
			chunk := types.WriteChunkStatus{Index: p.Index, Epoch: p.Recovery.Epoch, Progress: []types.WriteNodeProgress{{NodeID: 99, Attempt: 1, Bytes: 1, UpdatedAt: time.Now()}}}
			body := recoveryStatusJSON(t, types.WriteStatus{UploadID: u.ID, Chunks: []types.WriteChunkStatus{chunk}})
			return recoveryStatusResponse(r, http.StatusOK, body), nil
		}},
		{name: "malformed-response", resp: func(_ types.WriteUpload, _ types.WriteChunkPlan, r *http.Request) (*http.Response, error) {
			return recoveryStatusResponse(r, http.StatusOK, []byte(`{"upload_id":`)), nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, upload, plan := recoveryStatusRetryFixture()
			var calls atomic.Int32
			c.HTTP.Transport = recoveryStatusRetryTransport(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				return tc.resp(upload, plan, r)
			})
			if _, err := c.currentRecoveryStatus(context.Background(), upload, plan); err == nil {
				t.Fatal("permanent or invalid response unexpectedly succeeded")
			}
			if calls.Load() != 1 {
				t.Fatalf("calls=%d, want immediate failure after one request", calls.Load())
			}
		})
	}
}

func TestCurrentRecoveryStatusCanceledContextDoesNotRetry(t *testing.T) {
	c, upload, plan := recoveryStatusRetryFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	c.HTTP.Transport = recoveryStatusRetryTransport(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		cancel()
		return nil, io.ErrUnexpectedEOF
	})
	if _, err := c.currentRecoveryStatus(ctx, upload, plan); err == nil {
		t.Fatal("canceled status query unexpectedly succeeded")
	}
	if calls.Load() != 1 {
		t.Fatalf("calls=%d, canceled request must not retry", calls.Load())
	}
}

func TestWaitRecoveryChunkDoesNotTreatFailedOrRepeatedStatusAsProgress(t *testing.T) {
	c, upload, plan := recoveryStatusRetryFixture()
	c.SetPutTimeout(80 * time.Millisecond)
	chunk := types.WriteChunkStatus{
		Index: plan.Index,
		Epoch: plan.Recovery.Epoch,
		Progress: []types.WriteNodeProgress{{
			NodeID: 1, Attempt: 1, Bytes: 4, UpdatedAt: time.Now(),
		}},
	}
	body := recoveryStatusJSON(t, types.WriteStatus{UploadID: upload.ID, Chunks: []types.WriteChunkStatus{chunk}})
	var calls atomic.Int32
	c.HTTP.Transport = recoveryStatusRetryTransport(func(r *http.Request) (*http.Response, error) {
		switch calls.Add(1) {
		case 1:
			return recoveryStatusResponse(r, http.StatusOK, body), nil
		case 2:
			return nil, io.ErrUnexpectedEOF
		default:
			return recoveryStatusResponse(r, http.StatusOK, body), nil
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	failed, err := c.waitRecoveryChunk(ctx, upload, plan)
	if err == nil || !reflect.DeepEqual(failed, []uint64{1}) {
		t.Fatalf("wait result failed=%v err=%v, want stalled node 1", failed, err)
	}
	if ctx.Err() != nil {
		t.Fatalf("wait consumed outer context instead of idle bound: %v", ctx.Err())
	}
	if calls.Load() != 3 {
		t.Fatalf("status calls=%d, want initial + transient failure + one retry; repeated progress must not renew idle", calls.Load())
	}
}
