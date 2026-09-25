// 流式分块上传器（FUSE 写路径专用）：
// 边写边传，替代"攒满本地缓冲 + Flush 一口气同步传"的旧模式。
//
// 背景（400MB Finder 事故）：旧模式 close 时才开始上传，大文件在 1.2MB/s 隧道
// 上传 10+ 分钟，Finder 的 close 等待超时（~1-2 分钟）→ 弹"设备已消失"并放弃，
// staging 被 abort，整个上传作废。命令行能无限等所以成功——问题不在数据层，
// 在"close 前不传、close 时全传"的时序。
//
// 流式模式：Create/写打开时立即建 staging；WRITE 攒满一个块（64MB）就把它
// 投入后台上传（并发 ≤2）；close(Flush) 时最多只剩"不满一块的尾巴"要传，
// 秒级返回，Finder 不再超时。上传期间块对象以 staging 形态躺在节点上，
// master 的探测兜底/修复扫描对 staging 块同样生效（9a4831d 已打通）。
package client

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"atoll/pkg/types"
)

// StreamUploader 一次流式分块上传的会话。
type StreamUploader struct {
	c        *Client
	staging  uint64
	name     string
	replicas int
	minCopies int

	mu       sync.Mutex
	nextIdx  int   // 下一个待分配的块号
	uploaded int64 // 已完整落盘上传的字节数（进度可查询）
	err      error // 首个上传错误（置位后会话作废）
	closed   bool

	sem chan struct{}   // 并发 ≤2
	wg  sync.WaitGroup  // 等待所有在途块
}

// BeginStreamUpload 创建 staging 并返回流式上传会话。remotePath 的父目录必须存在。
// name 从 remotePath 提取，commit 时使用。
func (c *Client) BeginStreamUpload(remotePath string, replicas int) (*StreamUploader, error) {
	name := remotePath[strings.LastIndexByte(remotePath, '/')+1:]
	if name == "" || name == "." || name == ".." {
		return nil, fmt.Errorf("invalid remote path: %s", remotePath)
	}
	minCopies := replicas
	if minCopies > 2 {
		minCopies = 2 // 与旧 Flush 相同的持久性档位
	}
	var created struct {
		Inode types.Inode      `json:"inode"`
		Nodes []types.NodeInfo `json:"nodes"`
	}
	if err := c.postJSON("/files", map[string]any{
		"path": remotePath, "replicas": replicas, "overwrite": true, "chunked": true,
	}, &created); err != nil {
		return nil, fmt.Errorf("create staging: %w", err)
	}
	return &StreamUploader{
		c:         c,
		staging:   created.Inode.ID,
		name:      name,
		replicas:  replicas,
		minCopies: minCopies,
		sem:       make(chan struct{}, 2),
	}, nil
}

// Push 把"恰好一个完整块"的数据投入上传。调用方保证 data 为 64MB 整块
// （最后一块除外，最后一块走 Finish）。会话已出错时返回该错误、丢弃数据。
func (u *StreamUploader) Push(data []byte) error {
	u.mu.Lock()
	if u.err != nil {
		defer u.mu.Unlock()
		return u.err
	}
	idx := u.nextIdx
	u.nextIdx++
	u.mu.Unlock()

	u.sem <- struct{}{}
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		defer func() { <-u.sem }()
		if err := u.c.uploadChunkOnce(u.staging, idx, data, u.replicas); err != nil {
			u.mu.Lock()
			if u.err == nil {
				u.err = fmt.Errorf("chunk %d: %w", idx, err)
			}
			u.mu.Unlock()
			return
		}
		u.mu.Lock()
		u.uploaded += int64(len(data))
		u.mu.Unlock()
	}()
	return nil
}

// Finish 传入最后一块（可不满 64MB）并 commit。commit 语义与旧路径一致：
// minCopies 档位 409 由 master 侧细粒度等待（7e29046），这里 30s 兜底轮询。
// 成功后会话不可再用。失败会 abort staging 并返回错误。
func (u *StreamUploader) Finish(tail []byte, totalSize int64) error {
	u.mu.Lock()
	u.closed = true
	if u.err != nil {
		err := u.err
		u.mu.Unlock()
		u.abort()
		return err
	}
	u.mu.Unlock()

	if len(tail) > 0 {
		if err := u.c.uploadChunkOnce(u.staging, u.nextIdx, tail, u.replicas); err != nil {
			u.abort()
			return fmt.Errorf("chunk %d: %w", u.nextIdx, err)
		}
		u.mu.Lock()
		u.uploaded += int64(len(tail))
		u.mu.Unlock()
	}
	u.wg.Wait()
	u.mu.Lock()
	err := u.err
	u.mu.Unlock()
	if err != nil {
		u.abort()
		return err
	}

	chunkCount := int((totalSize + types.ChunkSize - 1) / types.ChunkSize)
	commitBody := map[string]any{
		"inode_id": u.staging, "name": u.name, "size": totalSize, "chunk_count": chunkCount,
	}
	if u.minCopies > 0 {
		commitBody["min_copies"] = u.minCopies
	}
	deadline := time.Now().Add(15 * time.Minute)
	for attempt := 0; ; attempt++ {
		err := u.c.postJSON("/files/commit", commitBody, nil)
		if err == nil {
			return nil
		}
		if u.minCopies <= 0 || attempt >= 30 || !strings.Contains(err.Error(), "http 409") || time.Now().After(deadline) {
			u.abort()
			return fmt.Errorf("commit: %w", err)
		}
		time.Sleep(30 * time.Second)
	}
}

// Progress 返回已上传字节数（供 FUSE 层报告文件大小做进度条）。
func (u *StreamUploader) Progress() int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.uploaded
}

// Err 返回会话首个错误（无错为 nil）。
func (u *StreamUploader) Err() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.err
}

// abort 尽力放弃 staging（失败只吞，主错误优先返回）。
func (u *StreamUploader) abort() {
	u.c.abortStaging(u.staging)
}

// ensure compile-time interface use
var _ io.Closer = (*StreamUploader)(nil)

// Close 满足 io.Closer：未 Finish 就关闭视为放弃（abort staging）。
func (u *StreamUploader) Close() error {
	u.mu.Lock()
	alreadyClosed := u.closed
	u.closed = true
	u.mu.Unlock()
	if alreadyClosed {
		return nil
	}
	u.abort()
	return nil
}
