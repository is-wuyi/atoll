package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"atoll/pkg/peerhttp"
	"atoll/pkg/transferbudget"
	"atoll/pkg/types"
)

func (c *Client) SetTransferBudget(budget types.TransferBudget) error {
	if budget.UploadBPS == 0 || budget.UploadBPS > transferbudget.MaxRate || budget.DownloadBPS == 0 || budget.DownloadBPS > transferbudget.MaxRate || budget.MaxConcurrent < 1 || budget.MaxConcurrent > 4 {
		return errors.New("invalid client transfer budgets")
	}
	limiter, err := transferbudget.New(budget.UploadBPS, budget.MaxConcurrent)
	if err != nil {
		return err
	}
	c.transferMu.Lock()
	defer c.transferMu.Unlock()
	if c.transferUpload != nil {
		return errors.New("client transfer budgets must be configured once before requests")
	}
	c.transferBudget = &budget
	c.transferUpload = limiter
	c.transferObservation = nil
	return nil
}

func (c *Client) observeWriteTransfer(ctx context.Context, upload types.WriteUpload) (*types.WriteTransferObservation, error) {
	c.transferMu.Lock()
	defer c.transferMu.Unlock()
	if c.transferBudget == nil {
		return nil, errors.New("write transfer planning requires configured client upload and download budgets")
	}
	if c.transferObservation != nil && time.Since(c.transferObservedAt) < 10*time.Second {
		return c.transferObservation, nil
	}
	q := url.Values{}
	q.Set("upload_id", strconv.FormatUint(upload.ID, 10))
	q.Set("plan_id", upload.PlanID)
	q.Set("revision", strconv.FormatUint(upload.Revision, 10))
	var out types.WriteTransferNodes
	if err := c.writeJSON(ctx, http.MethodGet, "/writes/transfer-nodes?"+q.Encode(), nil, &out); err != nil {
		return nil, err
	}
	if len(out.Nodes) > 256 {
		return nil, errors.New("transfer discovery exceeded node limit")
	}
	observation := &types.WriteTransferObservation{Budget: *c.transferBudget, Links: make([]types.TransferObservation, len(out.Nodes))}
	var wg sync.WaitGroup
	slots := make(chan struct{}, 8)
	for i, node := range out.Nodes {
		wg.Add(1)
		go func(i int, node types.NodeInfo) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				return
			}
			probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			link := types.TransferObservation{ToNodeID: node.ID, Path: c.scheme(), ObservedAt: time.Now()}
			var path atomic.Value
			path.Store(c.scheme())
			probeCtx = peerhttp.WithReporter(probeCtx, &peerhttp.Reporter{Observe: func(observation peerhttp.Observation) { path.Store(string(observation.Path)) }})
			req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, c.scheme()+"://"+node.Addr+"/healthz", nil)
			if err == nil {
				base := c.transferProbeTransport()
				started := time.Now()
				resp, probeErr := base.RoundTrip(req)
				link.RTTMs = float64(time.Since(started).Microseconds()) / 1000
				if probeErr == nil {
					_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
					resp.Body.Close()
					link.Available = resp.StatusCode == http.StatusOK && readErr == nil
				}
			}
			link.Path = path.Load().(string)
			observation.Links[i] = link
		}(i, node)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.transferObservation, c.transferObservedAt = observation, time.Now()
	return observation, nil
}
