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
	objID      uint64
	size       int64
	checksum   uint32
	generation uint64
	cands      []client.Replica // 健康副本段（轮转只在此段内进行）
	suspects   []client.Replica // master 标记待修的副本段：固定殿后兜底，不参与轮转
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

// objectID 返回本句柄物理读寻址的内容对象 ID：Open 时快照的显式 ObjID 优先；
// 0 兼容旧数据/直接构造句柄的测试——旧约定对象 ID = 文件 ID（ino）。
// 注意这与 reportSuspect 用的 ino（逻辑 FileID）刻意分离：物理寻址跟对象走，
// 版本比对跟文件身份走。
func (rh *readHandle) objectID() uint64 {
	if rh.objID != 0 {
		return rh.objID
	}
	return rh.ino
}

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

	// 上报用 ino（逻辑 FileID）+ 打开时的 generation/size/checksum：master 按
	// “当前 inode 的版本三元组是否仍匹配”决定是否撤销 Done——旧版本读者的上报
	// 不会撤销新版本的副本标记，也不会删除任何对象（新版本内容在另一个 ObjID 上）。
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
	if rh.size <= 0 || rh.size > types.ChunkSize {
		return nil, syscall.EIO // 坏元数据：make(rh.size+1) 前拒绝
	}
	// 整对象 GET 用无全程 Timeout 的共享 Transport 客户端，deadline 按字节数缩放；
	// 无 Mount 的测试句柄退回 rh.http。
	httpClient := rh.http
	if rh.m != nil && rh.m.verifyHTTP != nil {
		httpClient = rh.m.verifyHTTP
	}
	start := rh.candidateStart()
	buf := make([]byte, rh.size+1) // 多读 1 字节探测超长；复用于所有候选
	try := func(r client.Replica) ([]byte, bool) {
		attemptCtx, cancel := context.WithTimeout(ctx, chunkVerifyTimeoutFn(rh.size))
		defer cancel()
		req, err := http.NewRequestWithContext(attemptCtx, http.MethodGet,
			fmt.Sprintf("%s://%s/objects/%d", rh.scheme, r.Addr, rh.objectID()), nil)
		if err != nil {
			return nil, false
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, false
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, false
		}
		n, err := io.ReadFull(resp.Body, buf)
		resp.Body.Close()
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return nil, false // 传输中断不等于损坏：不误报
		}
		if int64(n) != rh.size || types.CRC32C(buf[:n]) != rh.checksum {
			rh.reportSuspect(r.ID)
			return nil, false
		}
		return buf[:n], true
	}
	for i := range rh.cands {
		if ctx.Err() != nil {
			return nil, syscall.EINTR
		}
		index := (start + i) % len(rh.cands)
		if data, ok := try(rh.cands[index]); ok {
			rh.rememberCandidate(index) // 轮转只记健康段；suspect 成功不改基准
			return data, 0
		}
	}
	for _, r := range rh.suspects { // 健康全败才试
		if ctx.Err() != nil {
			return nil, syscall.EINTR
		}
		if data, ok := try(r); ok {
			return data, 0
		}
	}
	if ctx.Err() != nil {
		return nil, syscall.EINTR
	}
	return nil, syscall.EIO
}

// loadVerified 返回整对象已校验数据：Mount 级共享缓存 + singleflight（跨句柄合并、
// 字节预算与在飞校验数有界）。release 必须在 copy-out 完成后调用：校验 permit 覆盖
// fetch 与 copy-out，已校验数据在被消费前始终计入在飞预算；命中缓存快路径的
// release 为 no-op。无 Mount（测试直接构造句柄）退化为句柄内缓存、permit no-op。
func (rh *readHandle) loadVerified(ctx context.Context) ([]byte, syscall.Errno, func()) {
	if rh.m == nil || rh.m.chunkCache == nil {
		data, errno := rh.loadSmall(ctx)
		return data, errno, func() {}
	}
	key := chunkCacheKey{obj: rh.objectID(), size: rh.size, crc: rh.checksum}
	if data, ok := rh.m.chunkCache.get(key); ok {
		return data, 0, func() {}
	}
	release, errno := rh.m.acquireVerify(ctx)
	if errno != 0 {
		return nil, errno, nil
	}
	data, errno := rh.m.chunkCache.load(ctx, key, func(ctx context.Context) ([]byte, syscall.Errno) {
		return rh.fetchWholeVerified(ctx)
	})
	if errno != 0 {
		release()
		return nil, errno, nil
	}
	return data, 0, release
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
	buf := make([]byte, want+1) // 多读 1 字节探测超长；复用于所有候选
	try := func(r client.Replica) ([]byte, bool) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			fmt.Sprintf("%s://%s/objects/%d", rh.scheme, r.Addr, rh.objectID()), nil)
		if err != nil {
			return nil, false
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
		resp, err := rh.http.Do(req)
		if err != nil {
			return nil, false
		}
		validRange := resp.StatusCode == http.StatusPartialContent &&
			resp.Header.Get("Content-Range") == fmt.Sprintf("bytes %d-%d/%d", start, end, rh.size)
		wholeObject := resp.StatusCode == http.StatusOK && start == 0 && want == rh.size
		if !validRange && !wholeObject {
			resp.Body.Close()
			return nil, false
		}
		n, err := io.ReadFull(resp.Body, buf)
		resp.Body.Close()
		if (err != nil && err != io.EOF && err != io.ErrUnexpectedEOF) || int64(n) != want {
			return nil, false
		}
		return buf[:want], true
	}
	// 起点在本次请求内固定；轮转只在健康段内，suspect 段固定殿后兜底。
	for i := range rh.cands {
		if ctx.Err() != nil {
			return nil, syscall.EINTR
		}
		index := (next + i) % len(rh.cands)
		if data, ok := try(rh.cands[index]); ok {
			rh.rememberCandidate(index)
			return data, 0
		}
	}
	for _, r := range rh.suspects {
		if ctx.Err() != nil {
			return nil, syscall.EINTR
		}
		if data, ok := try(r); ok {
			return data, 0
		}
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
	// 已知 checksum 且对象 ≤ ChunkSize：整对象校验读取（在飞内存界 chunkVerifyInFlight
	// × (ChunkSize+1)，Mount 共享缓存跨句柄复用）。已知判定：v2 显式对象（objID ≥
	// ObjectIDBase）的 CRC 恰为 0 也算已记录；v1 旧数据的 0 = 未记录。更大的 legacy
	// 整对象（v1 遗留，新写入全部 chunked）明确放弃内容校验走严格 Range——整块校验
	// 需缓冲整对象，超过 ChunkSize 会突破在飞内存界。
	known := rh.checksum != 0 || rh.objID >= types.ObjectIDBase
	if known && rh.size <= types.ChunkSize {
		data, errno, release := rh.loadVerified(ctx)
		if errno != 0 {
			return nil, errno
		}
		if int64(len(data)) != rh.size {
			release()
			return nil, syscall.EIO // 防御：整块校验路径保证长度
		}
		copy(dest, data[off:off+count])
		release() // copy-out 完成：校验 permit 归还
		return fuse.ReadResultData(dest[:count]), 0
	}
	data, errno := rh.readRange(ctx, off, off+count-1)
	if errno != 0 {
		return nil, errno
	}
	return fuse.ReadResultData(data), 0
}
