package node

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"atoll/pkg/types"
)

// writeProgressInterval 是计划写入 payload 进度上报周期：足够密以支撑恢复
// 等待侧的续命判断，足够疏以免进度请求本身成为 master 负载。
var writeProgressInterval = 15 * time.Second
var writeProgressSequence atomic.Uint64

func nextWriteProgressAttempt() uint64 {
	for {
		previous := writeProgressSequence.Load()
		next := uint64(time.Now().UnixNano())
		if next <= previous {
			next = previous + 1
		}
		if writeProgressSequence.CompareAndSwap(previous, next) {
			return next
		}
	}
}

// writeProgressReporter 上报单个计划写入对象在本节点的 payload 进度。
//
// 进度只是 liveness 提示：它从不被当作 Done，也从不释放容量。master 侧按
// (object, node, epoch) 单调记录字节数；同世代的整块重试会从 0 重新计数，
// 因此本地上报只在字节确实前进时刷新，绝不用周期空报伪装进度。
//
// 世代为零表示 legacy 写入（没有 planned-write generation），master 侧不
// 接受这类进度，因此直接不发。
type writeProgressReporter struct {
	node     *Node
	objectID uint64
	epoch    uint64
	attempt  uint64

	bytes atomic.Int64
	// lastSent 是上一次成功上报的字节数；只有超过它才再次上报。
	lastSent atomic.Int64

	stop chan struct{}
	done chan struct{}
	once sync.Once
}

// newWriteProgressReporter 建立一个进度上报器；epoch 为 0 时返回 nil，
// 调用方据此跳过全部进度逻辑（legacy 写入路径零开销）。
func newWriteProgressReporter(n *Node, objectID uint64, epoch uint64) *writeProgressReporter {
	if epoch == 0 || n == nil {
		return nil
	}
	r := &writeProgressReporter{node: n, objectID: objectID, epoch: epoch, attempt: nextWriteProgressAttempt(),
		stop: make(chan struct{}), done: make(chan struct{})}
	go r.loop()
	return r
}

// Add 记录一次实际读到的 payload 字节数；n<=0 不计数（空读不刷新进度）。
func (r *writeProgressReporter) Add(n int) {
	if r == nil || n <= 0 {
		return
	}
	r.bytes.Add(int64(n))
}

// Finish 结束上报：先做一次收尾上报（若有新字节），再停止周期任务。
func (r *writeProgressReporter) Finish() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		close(r.stop)
		<-r.done
	})
}

// loop 周期上报；只有字节前进且上次上报成功时才刷新 lastSent，避免在 master
// 不可达时把“未确认”的字节数当成已上报。
func (r *writeProgressReporter) loop() {
	defer close(r.done)
	ticker := time.NewTicker(writeProgressInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			r.send()
			return
		case <-ticker.C:
			r.send()
		}
	}
}

// send 上报一次当前字节数。master 拒收（世代已推进/对象已提交）是正常的，
// 只记日志：进度是尽力而为的提示，不能影响写入结果。
func (r *writeProgressReporter) send() {
	current := r.bytes.Load()
	if current <= r.lastSent.Load() {
		// 没有新字节：不发空报。UpdatedAt 只能由实际前进刷新。
		return
	}
	if current > 0 {
		if err := r.node.reportWriteProgress(r.objectID, r.epoch, r.attempt, current); err != nil {
			log.Printf("write progress %d epoch %d: %v", r.objectID, r.epoch, err)
			return
		}
		r.lastSent.Store(current)
	}
}

// reportWriteProgress 向 master 上报一次 payload 进度。
func (n *Node) reportWriteProgress(objectID uint64, epoch uint64, attempt uint64, bytesDone int64) error {
	if epoch == 0 || bytesDone <= 0 {
		return nil
	}
	body, err := json.Marshal(types.WriteProgress{ObjectID: objectID, NodeID: uint64(n.nodeID.Load()), Epoch: epoch, Attempt: attempt, Bytes: bytesDone})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.masterURL+"/files/writes/progress", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return &writeProgressError{status: resp.StatusCode}
	}
	return nil
}

// writeProgressError 表示 master 拒绝了进度上报（世代推进、对象已提交等）。
// 这不是写入失败，只是提示失效。
type writeProgressError struct {
	status int
}

func (e *writeProgressError) Error() string {
	return "write progress rejected with status " + strconv.Itoa(e.status)
}

// progressCountingReader 统计流过的实际字节数，用于 payload 进度上报。
// 统计只发生在真正返回字节的 Read 上：空读不推进进度。
type progressCountingReader struct {
	src     io.Reader
	counter *writeProgressReporter
}

func (r *progressCountingReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	if n > 0 {
		r.counter.Add(n)
	}
	return n, err
}
