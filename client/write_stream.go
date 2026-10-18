package client

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"atoll/pkg/types"
)

type plannedStream struct {
	c          *Client
	upload     types.WriteUpload
	ctx        context.Context
	cancel     context.CancelFunc
	admission  sync.Mutex
	mu         sync.Mutex
	wg         sync.WaitGroup
	slots      chan struct{}
	next       int
	uploaded   int64
	err        error
	closed     bool
	finished   bool
	closing    bool
	finishDone chan struct{}
	result     types.Inode
	commitOp   string
}

func newPlannedStream(c *Client, u types.WriteUpload, ctx context.Context) *plannedStream {
	ctx, cancel := context.WithCancel(ctx)
	return &plannedStream{c: c, upload: u, ctx: ctx, cancel: cancel, slots: make(chan struct{}, 2), commitOp: newOpID()}
}

func (p *plannedStream) enqueue(data []byte) error {
	p.mu.Lock()
	err := p.err
	p.mu.Unlock()
	if err != nil {
		return err
	}
	if p.next >= types.MaxChunksPerFile {
		return errors.New("file exceeds planned chunk limit")
	}
	select {
	case p.slots <- struct{}{}:
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
	owned := append([]byte(nil), data...)
	index := p.next
	p.next++
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer func() { <-p.slots }()
		err := p.c.uploadPlannedChunk(p.ctx, p.upload, index, owned)
		p.mu.Lock()
		defer p.mu.Unlock()
		if err != nil {
			if p.closing && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
				return
			}
			if p.err == nil {
				p.err = fmt.Errorf("planned chunk %d: %w", index, err)
			}
			p.cancel()
			return
		}
		p.uploaded += int64(len(owned))
	}()
	return nil
}

func (p *plannedStream) push(data []byte) error {
	p.admission.Lock()
	defer p.admission.Unlock()
	if p.closed {
		return plannedError(errors.New("planned stream is closed"))
	}
	if int64(len(data)) != types.ChunkSize {
		return plannedError(errors.New("Push requires one full chunk"))
	}
	return plannedError(p.enqueue(data))
}

func (p *plannedStream) finish(tail []byte, total int64) (types.Inode, error) {
	p.admission.Lock()
	if p.closed {
		p.admission.Unlock()
		return types.Inode{}, plannedError(errors.New("planned stream is closed"))
	}
	p.closed = true
	p.finishDone = make(chan struct{})
	defer close(p.finishDone)
	var err error
	if total < 0 || int64(len(tail)) >= types.ChunkSize || total != int64(p.next)*types.ChunkSize+int64(len(tail)) {
		err = errors.New("planned stream size does not match supplied chunks")
	}
	if err == nil && len(tail) > 0 {
		err = p.enqueue(tail)
	}
	count := p.next
	p.admission.Unlock()
	if err != nil {
		p.cancel()
	}
	p.wg.Wait()
	p.mu.Lock()
	if err == nil {
		err = p.err
	}
	p.mu.Unlock()
	var out types.Inode
	if err == nil {
		out, err = p.c.commitPlannedWrite(p.ctx, p.upload, total, count, p.commitOp)
	}
	if err != nil {
		p.mu.Lock()
		if p.err == nil {
			p.err = err
		}
		p.mu.Unlock()
		p.cancel()
		p.c.abortPlannedWrite(p.upload)
		return out, plannedError(err)
	}
	p.mu.Lock()
	p.result = out
	p.finished = true
	p.mu.Unlock()
	p.cancel()
	return out, nil
}

func (p *plannedStream) close() error {
	p.mu.Lock()
	p.closing = true
	p.mu.Unlock()
	p.cancel()
	p.admission.Lock()
	p.closed = true
	finishDone := p.finishDone
	p.admission.Unlock()
	if finishDone != nil {
		<-finishDone
		return nil
	}
	p.wg.Wait()
	p.mu.Lock()
	finished := p.finished
	p.mu.Unlock()
	if !finished {
		p.c.abortPlannedWrite(p.upload)
	}
	return nil
}
func (p *plannedStream) progress() int64 { p.mu.Lock(); defer p.mu.Unlock(); return p.uploaded }
func (p *plannedStream) failure() error  { p.mu.Lock(); defer p.mu.Unlock(); return plannedError(p.err) }
