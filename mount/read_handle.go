package mount

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"syscall"
	"time"

	"atoll/client"
	"atoll/pkg/types"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type readHandle struct {
	ino        uint64
	size       int64
	checksum   uint32
	generation uint64
	cands      []client.Replica
	http       *http.Client
	scheme     string
	m          *Mount

	mu       sync.Mutex
	next     int
	loading  chan struct{}
	loaded   bool
	cache    []byte
	reported map[uint64]bool
}

var _ fs.FileReader = (*readHandle)(nil)

func (rh *readHandle) candidateStart() int {
	rh.mu.Lock()
	defer rh.mu.Unlock()
	return rh.next
}

func (rh *readHandle) rememberCandidate(index int) {
	rh.mu.Lock()
	rh.next = (index + 1) % len(rh.cands)
	rh.mu.Unlock()
}

func (rh *readHandle) reportSuspect(nodeID uint64) {
	if rh.m == nil || nodeID == 0 {
		return
	}
	rh.mu.Lock()
	if rh.reported[nodeID] {
		rh.mu.Unlock()
		return
	}
	if rh.reported == nil {
		rh.reported = make(map[uint64]bool)
	}
	rh.reported[nodeID] = true
	rh.mu.Unlock()

	in := types.Inode{ID: rh.ino, Size: rh.size, Checksum: rh.checksum, Generation: rh.generation}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := rh.m.client.ReportSuspect(ctx, in, nodeID); err != nil {
			log.Printf("report suspect object %d node %d: %v", in.ID, nodeID, err)
		}
	}()
}

func (rh *readHandle) fetchWholeVerified(ctx context.Context) ([]byte, syscall.Errno) {
	start := rh.candidateStart()
	for i := range rh.cands {
		if ctx.Err() != nil {
			return nil, syscall.EINTR
		}
		index := (start + i) % len(rh.cands)
		r := rh.cands[index]
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			fmt.Sprintf("%s://%s/objects/%d", rh.scheme, r.Addr, rh.ino), nil)
		if err != nil {
			continue
		}
		resp, err := rh.http.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		// 多读一字节以检测超长响应，同时限制不可信节点的内存占用。
		data, err := io.ReadAll(io.LimitReader(resp.Body, rh.size+1))
		resp.Body.Close()
		if err != nil {
			continue
		}
		if int64(len(data)) != rh.size || types.CRC32C(data) != rh.checksum {
			rh.reportSuspect(r.ID)
			continue
		}
		rh.rememberCandidate(index)
		return data, 0
	}
	if ctx.Err() != nil {
		return nil, syscall.EINTR
	}
	return nil, syscall.EIO
}

// 同一句柄并发首次读取共用一次请求；失败不缓存，等待者可以取消。
func (rh *readHandle) loadSmall(ctx context.Context) ([]byte, syscall.Errno) {
	for {
		rh.mu.Lock()
		if rh.loaded {
			data := rh.cache
			rh.mu.Unlock()
			return data, 0
		}
		if pending := rh.loading; pending != nil {
			rh.mu.Unlock()
			select {
			case <-pending:
				continue
			case <-ctx.Done():
				return nil, syscall.EINTR
			}
		}
		pending := make(chan struct{})
		rh.loading = pending
		rh.mu.Unlock()

		data, errno := rh.fetchWholeVerified(ctx)
		rh.mu.Lock()
		if errno == 0 {
			rh.cache, rh.loaded = data, true
		}
		rh.loading = nil
		close(pending)
		rh.mu.Unlock()
		return data, errno
	}
}

func (rh *readHandle) readRange(ctx context.Context, start, end int64) ([]byte, syscall.Errno) {
	want := end - start + 1
	next := rh.candidateStart()
	for i := range rh.cands {
		if ctx.Err() != nil {
			return nil, syscall.EINTR
		}
		// 起点在本次请求内固定，其他并发读不能令本轮重复访问同一副本。
		index := (next + i) % len(rh.cands)
		r := rh.cands[index]
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			fmt.Sprintf("%s://%s/objects/%d", rh.scheme, r.Addr, rh.ino), nil)
		if err != nil {
			continue
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
		resp, err := rh.http.Do(req)
		if err != nil {
			continue
		}
		validRange := resp.StatusCode == http.StatusPartialContent &&
			resp.Header.Get("Content-Range") == fmt.Sprintf("bytes %d-%d/%d", start, end, rh.size)
		wholeObject := resp.StatusCode == http.StatusOK && start == 0 && want == rh.size
		if !validRange && !wholeObject {
			resp.Body.Close()
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, want+1))
		resp.Body.Close()
		if err != nil || int64(len(data)) != want {
			continue
		}
		rh.rememberCandidate(index)
		return data, 0
	}
	if ctx.Err() != nil {
		return nil, syscall.EINTR
	}
	return nil, syscall.EIO
}

func (rh *readHandle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if off < 0 || rh.size < 0 {
		return nil, syscall.EINVAL
	}
	if off >= rh.size || len(dest) == 0 {
		return fuse.ReadResultData(nil), 0
	}
	if ctx.Err() != nil {
		return nil, syscall.EINTR
	}
	count := min(int64(len(dest)), rh.size-off)
	if rh.size <= types.SmallFileMax && rh.checksum != 0 {
		data, errno := rh.loadSmall(ctx)
		if errno != 0 {
			return nil, errno
		}
		copy(dest, data[off:off+count])
		return fuse.ReadResultData(dest[:count]), 0
	}
	data, errno := rh.readRange(ctx, off, off+count-1)
	if errno != 0 {
		return nil, errno
	}
	return fuse.ReadResultData(data), 0
}
