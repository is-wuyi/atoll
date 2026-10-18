package mount

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"atoll/client"
	"atoll/pkg/types"
)

func TestWholeReadTimeoutFallsBackToHealthyReplica(t *testing.T) {
	previous := chunkVerifyTimeoutFn
	chunkVerifyTimeoutFn = func(int64) time.Duration { return 40 * time.Millisecond }
	t.Cleanup(func() { chunkVerifyTimeoutFn = previous })

	for _, kind := range []string{"chunked", "whole"} {
		t.Run(kind, func(t *testing.T) {
			body := []byte("healthy content after a stalled replica")
			reports := newSuspectRecorder(t)
			slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write(body[:2])
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			t.Cleanup(slow.Close)
			fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write(body)
			}))
			t.Cleanup(fast.Close)
			ch := newUnitChunkHandle(t, reports.srv.URL, 7, 1, int64(len(body)),
				[]types.ChunkInfo{{Index: 0, ID: 960, Size: int64(len(body)), Checksum: types.CRC32C(body), Replicas: []uint64{1, 2}}},
				map[uint64]string{1: slow.Listener.Addr().String(), 2: fast.Listener.Addr().String()})
			var got []byte
			var errno syscall.Errno
			if kind == "chunked" {
				got, errno = readChunkBytes(context.Background(), ch, 0, len(body))
			} else {
				rh := &readHandle{ino: 7, objID: 960, size: int64(len(body)), checksum: types.CRC32C(body), m: ch.m,
					http: ch.http, scheme: "http", cands: []client.Replica{
						{ID: 1, Addr: slow.Listener.Addr().String()}, {ID: 2, Addr: fast.Listener.Addr().String()},
					}}
				buf := make([]byte, len(body))
				res, status := rh.Read(context.Background(), buf, 0)
				errno = status
				if errno == 0 {
					data, status := res.Bytes(buf)
					errno = syscall.Errno(status)
					got = append([]byte(nil), data...)
				}
			}
			if errno != 0 || !bytes.Equal(got, body) {
				t.Fatalf("stalled first replica prevented healthy fallback: errno=%v got=%q", errno, got)
			}
			assertNoSuspect(t, reports)
		})
	}
}
