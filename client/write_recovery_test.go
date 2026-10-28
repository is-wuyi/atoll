package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/types"
)

func TestPlannedWriteRecoveryReassignsOnlyFailedChunk(t *testing.T) {
	withChunkSize(t, 1024)
	cl := newPlannedClusterWithReplicas(t, 3, 1)
	if _, err := cl.client.SetProtection("/", types.ProtectionNormal); err != nil {
		t.Fatal(err)
	}
	base := cl.client.HTTP.Transport
	var badHost string
	var mu sync.Mutex
	writes := map[uint64]int{}
	var recovered atomic.Int32
	cl.client.HTTP.Transport = plannedTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/objects/") {
			var id uint64
			fmt.Sscanf(r.URL.Path, "/objects/%d", &id)
			_, index := types.ParseChunkID(id)
			mu.Lock()
			writes[id]++
			if index == 1 && badHost == "" {
				badHost = r.URL.Host
			}
			fail := index == 1 && r.URL.Host == badHost
			mu.Unlock()
			if fail {
				r.Body.Close()
				return nil, errors.New("injected target disconnect")
			}
		}
		resp, err := base.RoundTrip(r)
		if r.URL.Path == "/writes/chunks/recover" && err == nil && resp.StatusCode == http.StatusOK {
			recovered.Add(1)
		}
		return resp, err
	})
	data := bytes.Repeat([]byte("R"), 2048)
	if err := cl.client.PutChunkedReader("/recovered", int64(len(data)), bytes.NewReader(data), 1); err != nil {
		t.Fatal(err)
	}
	in, _, err := cl.client.Lookup("/recovered")
	if err != nil || len(in.Chunks) != 2 || recovered.Load() != 1 {
		t.Fatalf("incomplete recovered upload: %+v recovered=%d err=%v", in, recovered.Load(), err)
	}
	mu.Lock()
	if writes[in.Chunks[0].ID] != 1 {
		t.Errorf("completed first chunk resent: %d", writes[in.Chunks[0].ID])
	}
	mu.Unlock()
	out := filepath.Join(t.TempDir(), "out")
	if err := cl.client.Get("/recovered", out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("recovered content differs: %v", err)
	}
	cl.assertNoLegacyWrites(t)
}

func TestPlannedWriteRecoveryLostResponseIsIdempotent(t *testing.T) {
	cl := newPlannedClusterWithReplicas(t, 3, 1)
	base := cl.client.HTTP.Transport
	var badHost string
	var mu sync.Mutex
	var dropped atomic.Bool
	var epochs []uint64
	cl.client.HTTP.Transport = plannedTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/objects/") {
			mu.Lock()
			if badHost == "" {
				badHost = r.URL.Host
			}
			fail := badHost == r.URL.Host
			mu.Unlock()
			if fail {
				r.Body.Close()
				return nil, errors.New("injected unavailable ingress")
			}
		}
		resp, err := base.RoundTrip(r)
		if r.URL.Path == "/writes/chunks/recover" && err == nil && resp.StatusCode == http.StatusOK {
			raw, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				return nil, readErr
			}
			var out types.PlanWriteChunkResponse
			if err := json.Unmarshal(raw, &out); err != nil {
				return nil, err
			}
			epochs = append(epochs, out.Plan.Recovery.Epoch)
			if dropped.CompareAndSwap(false, true) {
				return nil, io.ErrUnexpectedEOF
			}
			resp.Body = io.NopCloser(bytes.NewReader(raw))
		}
		return resp, err
	})
	if _, err := cl.client.PutSmall("/response-lost", []byte("same operation"), 1, false); err != nil {
		t.Fatal(err)
	}
	if len(epochs) != 2 || epochs[0] != 2 || epochs[1] != 2 {
		t.Fatalf("lost recovery response consumed another epoch: %v", epochs)
	}
}

func TestPlannedWriteRecoverySlowProgressOutlivesLegacyTimeout(t *testing.T) {
	cl := newPlannedCluster(t, 1)
	cl.client.SetPutTimeout(80 * time.Millisecond)
	base := cl.client.HTTP.Transport
	cl.client.HTTP.Transport = plannedTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPut || !strings.HasPrefix(r.URL.Path, "/objects/") {
			return base.RoundTrip(r)
		}
		var collected bytes.Buffer
		buffer := make([]byte, 32)
		for {
			n, err := r.Body.Read(buffer)
			collected.Write(buffer[:n])
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			select {
			case <-time.After(15 * time.Millisecond):
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		r.Body.Close()
		copy := r.Clone(r.Context())
		copy.Body = io.NopCloser(bytes.NewReader(collected.Bytes()))
		return base.RoundTrip(copy)
	})
	started := time.Now()
	if err := cl.client.PutReaderOverwrite("/slow-progress", 512, bytes.NewReader(bytes.Repeat([]byte("s"), 512)), 1, false); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) <= 80*time.Millisecond {
		t.Fatal("fixture did not outlive the legacy total timeout")
	}
}

func TestPlannedWriteRecoveryNoProgressFailsBoundedly(t *testing.T) {
	cl := newPlannedCluster(t, 1)
	cl.client.SetPutTimeout(30 * time.Millisecond)
	base := cl.client.HTTP.Transport
	var attempts atomic.Int32
	cl.client.HTTP.Transport = plannedTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/objects/") {
			attempts.Add(1)
			defer r.Body.Close()
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		return base.RoundTrip(r)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := cl.client.WritePlanning(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.client.putPlannedReader(ctx, "/stalled", 3, bytes.NewReader([]byte("abc")), false); err == nil {
		t.Fatal("stalled upload succeeded")
	}
	if attempts.Load() != 3 || ctx.Err() != nil {
		t.Fatalf("unexpected retry bound attempts=%d ctx=%v", attempts.Load(), ctx.Err())
	}
	if _, _, err := cl.client.Lookup("/stalled"); err == nil {
		t.Fatal("stalled upload published")
	}
}
