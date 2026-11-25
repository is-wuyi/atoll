package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/types"
)

func TestPlannedUploadAdmissionQueuesFiles(t *testing.T) {
	cl := newPlannedCluster(t, 1)
	if err := cl.client.SetTransferBudget(types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 2}); err != nil {
		t.Fatal(err)
	}
	base := cl.client.HTTP.Transport
	gate := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(gate) }) }
	var planned, objectStarted atomic.Int64
	cl.client.HTTP.Transport = plannedTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost && r.URL.Path == "/writes/chunks" {
			planned.Add(1)
		}
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/objects/") {
			objectStarted.Add(1)
			<-gate
		}
		return base.RoundTrip(r)
	})
	const count = 8
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := cl.client.putPlannedReader(context.Background(), fmt.Sprintf("/admission-%d", i), 4, strings.NewReader("data"), false)
			errs <- err
		}(i)
	}
	defer func() {
		unblock()
		wg.Wait()
	}()
	deadline := time.Now().Add(5 * time.Second)
	for objectStarted.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := objectStarted.Load(); got != 2 {
		t.Fatalf("initial object PUTs = %d, want 2", got)
	}
	time.Sleep(100 * time.Millisecond)
	if got := planned.Load(); got != 2 {
		t.Fatalf("%d files reserved plans before admission released; want 2", got)
	}
	unblock()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("queued upload failed: %v", err)
		}
	}
	if got := planned.Load(); got != count {
		t.Fatalf("plan reservations after completion = %d, want %d", got, count)
	}
}

func TestPlannedUploadAdmissionReleasesOnTerminalOutcomes(t *testing.T) {
	cl := newPlannedCluster(t, 1)
	if err := cl.client.SetTransferBudget(types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 2}); err != nil {
		t.Fatal(err)
	}
	first, err := cl.client.BeginStreamUpload("/first", 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cl.client.BeginStreamUpload("/second", 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cl.client.putPlannedReader(ctx, "/cancelled", 4, strings.NewReader("data"), false); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled admission = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := cl.client.BeginStreamUpload("/third", 1)
	if err != nil {
		t.Fatalf("Close did not release admission: %v", err)
	}
	if err := third.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.client.putPlannedReader(context.Background(), "/short-reader", 5, strings.NewReader("data"), false); err == nil {
		t.Fatal("short reader unexpectedly succeeded")
	}
	fourth, err := cl.client.BeginStreamUpload("/fourth", 1)
	if err != nil {
		t.Fatalf("read failure did not release admission: %v", err)
	}
	if err := second.Finish([]byte("data"), 5); err == nil {
		t.Fatal("mismatched Finish unexpectedly succeeded")
	}
	fifth, err := cl.client.BeginStreamUpload("/fifth", 1)
	if err != nil {
		t.Fatalf("failed Finish did not release admission: %v", err)
	}
	for _, upload := range []*StreamUploader{fourth, fifth} {
		if err := upload.Close(); err != nil {
			t.Error(err)
		}
	}
}
