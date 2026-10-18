package client

import (
	"bytes"
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"atoll/pkg/types"
)

func TestPlannedCloseWaitsForFinishRequest(t *testing.T) {
	cl := newPlannedCluster(t, 1)
	c := cl.client
	base := c.HTTP.Transport
	started := make(chan struct{})
	cancelled := make(chan struct{})
	release := make(chan struct{})
	var startOnce, cancelOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	c.HTTP.Transport = plannedTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/writes/commit" {
			startOnce.Do(func() { close(started) })
			<-r.Context().Done()
			cancelOnce.Do(func() { close(cancelled) })
			<-release
			r.Body.Close()
			return nil, r.Context().Err()
		}
		return base.RoundTrip(r)
	})
	u, err := c.BeginStreamUpload("/closing", 1)
	if err != nil {
		t.Fatal(err)
	}
	finish := make(chan error, 1)
	go func() { finish <- u.Finish([]byte("data"), 4) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("commit request did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- u.Close() }()
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not cancel commit")
	}
	select {
	case <-closed:
		t.Error("Close returned while Finish was still executing its request")
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	select {
	case err := <-finish:
		if err == nil {
			t.Error("cancelled Finish succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Finish did not exit")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not join Finish")
	}
	if _, _, err := c.Lookup("/closing"); err == nil {
		t.Error("cancelled upload became visible")
	}
}

func TestPlannedConcurrentPushCloseJoinsUploads(t *testing.T) {
	withChunkSize(t, 1024)
	cl := newPlannedCluster(t, 1)
	base := cl.client.HTTP.Transport
	started := make(chan struct{})
	var once sync.Once
	cl.client.HTTP.Transport = plannedTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPut {
			once.Do(func() { close(started) })
			<-r.Context().Done()
			r.Body.Close()
			return nil, r.Context().Err()
		}
		return base.RoundTrip(r)
	})
	u, err := cl.client.BeginStreamUpload("/cancelled", 1)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("x"), 1024)
	if err := u.Push(data); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("node request not started")
	}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = u.Push(data) }()
	}
	closed := make(chan error, 1)
	go func() { closed <- u.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close stuck behind blocked Push")
	}
	wg.Wait()
	if err := u.Push(data); err == nil {
		t.Fatal("Push after Close accepted")
	}
	if err := u.Finish(nil, 0); err == nil {
		t.Fatal("Finish after Close accepted")
	}
	if u.planned.progress() != 0 {
		t.Fatal("cancelled data credited as uploaded")
	}
	if u.planned.ctx.Err() != context.Canceled {
		t.Fatal("upload context not cancelled")
	}
	if u.planned.next > types.MaxChunksPerFile {
		t.Fatal("invalid upload indices")
	}
}
