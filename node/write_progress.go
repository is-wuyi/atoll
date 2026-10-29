package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/types"
)

const writeProgressInterval = 15 * time.Second

// SetWriteProgressIntervalForTest must be called before the node serves requests.
func (n *Node) SetWriteProgressIntervalForTest(d time.Duration) {
	n.writeProgressInterval = d
}

func (n *Node) writeReportInterval() time.Duration {
	if n.writeProgressInterval > 0 {
		return n.writeProgressInterval
	}
	return writeProgressInterval
}

func newWriteRequestID() string {
	var id [16]byte
	_, _ = rand.Read(id[:])
	return hex.EncodeToString(id[:])
}

type writeProgressReporter struct {
	node     *Node
	objectID uint64
	epoch    uint64
	attempt  uint64
	token    string
	interval time.Duration
	bytes    atomic.Int64
	lastSent atomic.Int64
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
}

func (n *Node) beginWriteProgress(ctx context.Context, plan types.ReplicationPlan, requestID string) (*writeProgressReporter, error) {
	if plan.Object.WriteEpoch == 0 || plan.WriteProgress == nil {
		return nil, nil
	}
	if requestID == "" {
		requestID = newWriteRequestID()
	}
	if !access.ValidWriteAttemptID(requestID) {
		return nil, errors.New("invalid write attempt id")
	}
	var expected uint64
	if plan.WriteProgress != nil {
		expected = plan.WriteProgress.Attempt
	}
	req := types.BeginWriteProgressRequest{ObjectID: plan.Object.ObjectID, NodeID: uint64(n.nodeID.Load()), Epoch: plan.Object.WriteEpoch, ExpectedAttempt: expected, RequestID: requestID}
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	var result types.BeginWriteProgressResponse
	for retry := 0; retry < 3; retry++ {
		attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		request, requestErr := http.NewRequestWithContext(attemptCtx, http.MethodPost, n.masterURL+"/files/writes/progress/begin", bytes.NewReader(raw))
		if requestErr != nil {
			cancel()
			return nil, requestErr
		}
		request.Header.Set("Content-Type", "application/json")
		resp, requestErr := n.httpClient.Do(request)
		status := 0
		if requestErr == nil {
			status = resp.StatusCode
			if status == http.StatusOK {
				requestErr = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&result)
			} else {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				requestErr = fmt.Errorf("write attempt registration: status %d", status)
			}
			resp.Body.Close()
		}
		cancel()
		if requestErr == nil {
			if result.Attempt != expected+1 || !types.ValidRetirementToken(result.AttemptToken) {
				return nil, errors.New("invalid registered write attempt")
			}
			r := &writeProgressReporter{node: n, objectID: req.ObjectID, epoch: req.Epoch, attempt: result.Attempt, token: result.AttemptToken, interval: n.writeReportInterval(), stop: make(chan struct{}), done: make(chan struct{})}
			go r.loop()
			return r, nil
		}
		err = requestErr
		if ctx.Err() != nil || status >= 400 && status < 500 {
			break
		}
	}
	return nil, err
}

func (r *writeProgressReporter) Add(n int) {
	if r != nil && n > 0 {
		r.bytes.Add(int64(n))
	}
}

func (r *writeProgressReporter) Finish() {
	if r != nil {
		r.once.Do(func() {
			close(r.stop)
			<-r.done
		})
	}
}

func (r *writeProgressReporter) loop() {
	defer close(r.done)
	ticker := time.NewTicker(r.interval)
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

func (r *writeProgressReporter) send() {
	current := r.bytes.Load()
	if current <= r.lastSent.Load() {
		return
	}
	report := types.WriteProgress{ObjectID: r.objectID, NodeID: uint64(r.node.nodeID.Load()), Epoch: r.epoch, Attempt: r.attempt, AttemptToken: r.token, Bytes: current}
	raw, err := json.Marshal(report)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.node.masterURL+"/files/writes/progress", bytes.NewReader(raw))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.node.httpClient.Do(req)
	if err != nil {
		log.Printf("write progress %d epoch %d: %v", r.objectID, r.epoch, err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusOK {
		r.lastSent.Store(current)
	}
}

type progressCountingReader struct {
	src     io.Reader
	counter *writeProgressReporter
}

func (r *progressCountingReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	r.counter.Add(n)
	return n, err
}
