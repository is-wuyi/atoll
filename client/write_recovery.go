package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/peerhttp"
	"atoll/pkg/types"
)

func (c *Client) recoveryIdleTimeout() time.Duration {
	if c.putTimeout > 0 {
		return c.putTimeout
	}
	return time.Minute
}

func (c *Client) putRecoveryObject(ctx context.Context, upload types.WriteUpload, nodeID uint64, addr string, plan types.WriteChunkPlan, data []byte, rate uint64) error {
	if path, required := peerhttp.RequiredPath(ctx); required && (path == peerhttp.PathDirect || path == peerhttp.PathRelay) {
		if c.secTransport == nil {
			return errors.New("P2P write plan requires a configured secure peer transport")
		}
		if _, ok := c.secTransport.base.(*peerhttp.Transport); !ok {
			return errors.New("P2P write plan requires a configured peer resolver")
		}
	}
	c.transferMu.Lock()
	limiter := c.transferUpload
	c.transferMu.Unlock()
	if limiter != nil {
		release, err := limiter.Acquire(ctx)
		if err != nil {
			return err
		}
		defer release()
	}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		remaining := time.Until(plan.Recovery.HardUntil)
		if remaining <= 0 {
			return context.DeadlineExceeded
		}
		putCtx, progress, cancel := newWriteProgressContext(ctx, remaining, c.recoveryIdleTimeout())
		requestID := newOpID()
		stopProgress := c.observeActiveWrite(putCtx, progress, upload, plan, nodeID, requestID)
		var body io.Reader = bytes.NewReader(data)
		if limiter != nil {
			body = limiter.Reader(putCtx, body, rate)
		}
		body = progress.Reader(body)
		req, err := http.NewRequestWithContext(putCtx, http.MethodPut, fmt.Sprintf("%s://%s/objects/%d", c.scheme(), addr, plan.Object.ID), body)
		if err == nil {
			req.ContentLength = int64(len(data))
			req.Header.Set(types.ChecksumHeader, fmt.Sprintf("%08x", plan.Object.Checksum))
			req.Header.Set(types.WriteEpochHeader, strconv.FormatUint(plan.Recovery.Epoch, 10))
			req.Header.Set(types.WriteAttemptHeader, requestID)
			var resp *http.Response
			resp, err = c.HTTP.Do(req)
			if err == nil {
				err = statusError(resp)
				if err == nil {
					var result struct {
						Size *int64 `json:"size"`
					}
					err = decodePlannedResponse(resp.Body, &result)
					if err == nil && (result.Size == nil || *result.Size != int64(len(data))) {
						err = errors.New("node acknowledged incorrect stored length")
					}
				}
				resp.Body.Close()
			}
		}
		cancel()
		stopProgress()
		if err == nil {
			return nil
		}
		last = err
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var he *HTTPError
		if errors.As(err, &he) && he.StatusCode < 500 {
			return err
		}
		if attempt < 2 {
			if err := waitWriteRetry(ctx, 100*time.Millisecond); err != nil {
				return err
			}
		}
	}
	return last
}

func (c *Client) observeActiveWrite(ctx context.Context, progress *writeProgress, upload types.WriteUpload, plan types.WriteChunkPlan, nodeID uint64, requestID string) func() {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		interval := min(time.Second, max(time.Millisecond, c.recoveryIdleTimeout()/5))
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		var observedAttempt uint64
		var observedBytes int64
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			started := time.Now()
			queryCtx, queryCancel := context.WithTimeout(peerhttp.ControlContext(ctx), metadataTimeout)
			status, err := c.currentRecoveryStatus(queryCtx, upload, plan)
			queryCancel()
			if err != nil {
				continue
			}
			for _, state := range status.Progress {
				if state.NodeID != nodeID || state.RequestID != requestID || state.Attempt < observedAttempt || state.Bytes <= 0 {
					continue
				}
				if state.Attempt > observedAttempt || state.Bytes > observedBytes {
					observedAttempt, observedBytes = state.Attempt, state.Bytes
					progress.progressedAt(started)
				}
			}
		}
	}()
	return func() { cancel(); <-done }
}

func (c *Client) resumeRecoveryObject(ctx context.Context, addr string, plan types.WriteChunkPlan) error {
	ctx, cancel := context.WithTimeout(ctx, c.recoveryIdleTimeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, fmt.Sprintf("%s://%s/objects/%d", c.scheme(), addr, plan.Object.ID), nil)
	if err != nil {
		return err
	}
	req.Header.Set(types.WriteEpochHeader, strconv.FormatUint(plan.Recovery.Epoch, 10))
	req.Header.Set(types.WriteResumeHeader, "true")
	req.Header.Set(types.ChecksumHeader, fmt.Sprintf("%08x", plan.Object.Checksum))
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := statusError(resp); err != nil {
		return err
	}
	var result struct {
		Size *int64 `json:"size"`
	}
	if err := decodePlannedResponse(resp.Body, &result); err != nil {
		return err
	}
	if result.Size == nil || *result.Size != plan.Object.StoredSize {
		return errors.New("node resume acknowledged incorrect stored length")
	}
	return nil
}

func (c *Client) currentRecoveryStatus(ctx context.Context, upload types.WriteUpload, plan types.WriteChunkPlan) (types.WriteChunkStatus, error) {
	q := url.Values{}
	q.Set("upload_id", strconv.FormatUint(upload.ID, 10))
	q.Set("plan_id", upload.PlanID)
	q.Set("revision", strconv.FormatUint(upload.Revision, 10))
	var status types.WriteStatus
	if err := c.writeJSON(ctx, http.MethodGet, "/writes/status?"+q.Encode(), nil, &status); err != nil {
		return types.WriteChunkStatus{}, err
	}
	if status.UploadID != upload.ID {
		return types.WriteChunkStatus{}, errors.New("write status differs from upload")
	}
	for _, chunk := range status.Chunks {
		if chunk.Index != plan.Index {
			continue
		}
		if chunk.Epoch != plan.Recovery.Epoch {
			return chunk, errors.New("write status recovery epoch changed")
		}
		seen := map[uint64]bool{}
		for _, id := range chunk.Done {
			if seen[id] || !types.ContainsUint64(plan.Layout.Nodes, id) {
				return chunk, errors.New("write status contains invalid confirmations")
			}
			seen[id] = true
		}
		progressNodes := map[uint64]bool{}
		for _, progress := range chunk.Progress {
			if progressNodes[progress.NodeID] || progress.Attempt == 0 || progress.RequestID != "" && !access.ValidWriteAttemptID(progress.RequestID) || !types.ContainsUint64(plan.Layout.Nodes, progress.NodeID) || progress.Bytes < 0 || progress.Bytes > plan.Object.StoredSize || progress.UpdatedAt.IsZero() {
				return chunk, errors.New("write status contains invalid progress")
			}
			progressNodes[progress.NodeID] = true
		}
		if chunk.Ready {
			for _, id := range plan.Confirmations {
				if !seen[id] {
					return chunk, errors.New("ready write omitted required confirmation")
				}
			}
		}
		return chunk, nil
	}
	return types.WriteChunkStatus{}, errors.New("write status omitted chunk")
}

func (c *Client) waitRecoveryChunk(ctx context.Context, upload types.WriteUpload, plan types.WriteChunkPlan) ([]uint64, error) {
	began := time.Now()
	lastProgress := map[uint64]time.Time{}
	bytesDone := map[uint64]int64{}
	attempts := map[uint64]uint64{}
	for _, id := range plan.Confirmations {
		lastProgress[id] = began
	}
	for {
		status, err := c.currentRecoveryStatus(ctx, upload, plan)
		if err != nil {
			return nil, err
		}
		if status.Ready {
			return nil, nil
		}
		now := time.Now()
		for _, progress := range status.Progress {
			if progress.Bytes > 0 && (progress.Attempt > attempts[progress.NodeID] || progress.Attempt == attempts[progress.NodeID] && progress.Bytes > bytesDone[progress.NodeID]) {
				attempts[progress.NodeID] = progress.Attempt
				bytesDone[progress.NodeID] = progress.Bytes
				lastProgress[progress.NodeID] = now
			}
		}
		var stalled []uint64
		for _, id := range plan.Confirmations {
			if !types.ContainsUint64(status.Done, id) && now.Sub(lastProgress[id]) >= c.recoveryIdleTimeout() {
				stalled = append(stalled, id)
			}
		}
		if len(stalled) > 0 {
			return stalled, errors.New("required write replicas made no payload progress")
		}
		if err := waitWriteRetry(ctx, min(100*time.Millisecond, c.recoveryIdleTimeout()/4)); err != nil {
			return nil, err
		}
	}
}

func (c *Client) uploadRecoveryTargets(ctx context.Context, upload types.WriteUpload, out types.PlanWriteChunkResponse, data []byte) ([]uint64, error) {
	plan := out.Plan
	addresses := map[uint64]string{}
	for _, n := range out.Nodes {
		addresses[n.ID] = n.Addr
	}
	targets := plan.Confirmations
	if plan.Transfer != nil {
		targets = plan.Transfer.UploadTargets
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failed []uint64
	var firstErr error
	slots := make(chan struct{}, 2)
	for _, id := range targets {
		if types.ContainsUint64(out.Chunk.Done, id) && !types.ContainsUint64(out.Chunk.Suspect, id) && plan.Transfer == nil {
			continue
		}
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return nil, ctx.Err()
		}
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			defer func() { <-slots }()
			putCtx := ctx
			var rate uint64
			if plan.Transfer != nil {
				for _, leg := range plan.Transfer.Legs {
					if leg.FromNodeID == 0 && leg.ToNodeID == id {
						putCtx = peerhttp.WithPath(putCtx, peerhttp.Path(leg.Path))
						rate = leg.BPS
					}
				}
			}
			var err error
			if types.ContainsUint64(out.Chunk.Done, id) && !types.ContainsUint64(out.Chunk.Suspect, id) {
				err = c.resumeRecoveryObject(putCtx, addresses[id], plan)
				var he *HTTPError
				if errors.As(err, &he) && he.StatusCode == http.StatusNotFound {
					err = c.putRecoveryObject(putCtx, upload, id, addresses[id], plan, data, rate)
				}
			} else {
				err = c.putRecoveryObject(putCtx, upload, id, addresses[id], plan, data, rate)
			}
			if err != nil {
				mu.Lock()
				failed = append(failed, id)
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(id)
	}
	wg.Wait()
	sort.Slice(failed, func(i, j int) bool { return failed[i] < failed[j] })
	return failed, firstErr
}

func (c *Client) recoverWritePlan(ctx context.Context, req types.RecoverWriteChunkRequest, out *types.PlanWriteChunkResponse) error {
	var err error
	for retry := 0; retry < 3; retry++ {
		err = c.writeJSONRetry(ctx, "/writes/chunks/recover", req, out)
		var status *HTTPError
		if !errors.As(err, &status) || status.StatusCode != http.StatusConflict || WriteCode(err) != types.WriteRecoveryRetry || ctx.Err() != nil {
			return err
		}
		if retry < 2 {
			if waitErr := waitWriteRetry(ctx, time.Duration(retry+1)*100*time.Millisecond); waitErr != nil {
				return waitErr
			}
		}
	}
	return err
}

func (c *Client) uploadRecoverableChunk(ctx context.Context, upload types.WriteUpload, geometry types.PlanWriteChunkRequest, out types.PlanWriteChunkResponse, data []byte) error {
	if out.Plan.Recovery == nil || !time.Now().Before(out.Plan.Recovery.HardUntil) {
		return errors.New("write recovery deadline expired")
	}
	ctx, cancel := context.WithDeadline(ctx, out.Plan.Recovery.HardUntil)
	defer cancel()
	for {
		failed, transferErr := c.uploadRecoveryTargets(ctx, upload, out, data)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		status, statusErr := c.currentRecoveryStatus(ctx, upload, out.Plan)
		if statusErr != nil {
			return statusErr
		}
		if status.Ready {
			return nil
		}
		var pending []uint64
		for _, id := range failed {
			if !types.ContainsUint64(status.Done, id) {
				pending = append(pending, id)
			}
		}
		failed = pending
		if len(failed) == 0 {
			var err error
			failed, err = c.waitRecoveryChunk(ctx, upload, out.Plan)
			if err == nil {
				return nil
			}
			if len(failed) == 0 {
				return err
			}
			transferErr = err
		}
		if out.Plan.Recovery.Attempts >= types.MaxWriteRecoveries {
			return fmt.Errorf("write recovery attempts exhausted: %w", transferErr)
		}
		req := types.RecoverWriteChunkRequest{WriteBinding: plannedBinding(upload), Index: out.Plan.Index, ExpectedEpoch: out.Plan.Recovery.Epoch, OpID: newOpID(), FailedNodes: failed}
		if c.transferEnabled {
			c.transferMu.Lock()
			c.transferObservation = nil
			c.transferMu.Unlock()
			observation, err := c.observeWriteTransfer(ctx, upload)
			if err != nil {
				return err
			}
			req.Network = observation
		}
		var next types.PlanWriteChunkResponse
		if err := c.recoverWritePlan(ctx, req, &next); err != nil {
			return fmt.Errorf("recover chunk %d: %w", req.Index, err)
		}
		if err := validatePlannedChunk(geometry, next); err != nil {
			return err
		}
		if next.Plan.Recovery == nil || next.Plan.Recovery.Epoch != out.Plan.Recovery.Epoch+1 || next.Plan.Recovery.OperationID != req.OpID || next.Plan.Recovery.Attempts != out.Plan.Recovery.Attempts+1 || !next.Plan.Recovery.HardUntil.Equal(out.Plan.Recovery.HardUntil) || next.Plan.RequiredConfirmations < out.Plan.RequiredConfirmations || len(next.Plan.Layout.Nodes) < len(out.Plan.Layout.Nodes) || (next.Plan.Transfer == nil) != (out.Plan.Transfer == nil) {
			return errors.New("master returned inconsistent recovery plan")
		}
		for _, id := range failed {
			if types.ContainsUint64(next.Plan.Layout.Nodes, id) || !types.ContainsUint64(next.Plan.Recovery.Excluded, id) {
				return errors.New("master did not exclude failed upload node")
			}
		}
		out = next
	}
}
