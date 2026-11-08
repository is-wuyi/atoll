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

type transferSubmissionKey struct{}

type transferMeasurementKey struct {
	addr string
	path string
}

type transferMeasurement struct {
	types.TransferObservation
	generation uint64
	started    time.Time
}

func (c *Client) transferGeneration() uint64 {
	if c.sec == nil {
		return 0
	}
	c.sec.mu.Lock()
	defer c.sec.mu.Unlock()
	return c.sec.generation
}

func (c *Client) withTransferGeneration(generation uint64, apply func()) bool {
	if c.sec == nil {
		apply()
		return true
	}
	c.sec.mu.Lock()
	defer c.sec.mu.Unlock()
	if c.sec.generation != generation {
		return false
	}
	apply()
	return true
}

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
	generation := c.transferGeneration()
	if c.transferObservation != nil && c.transferObservationGen == generation && time.Now().Before(c.transferValidUntil) {
		return c.measuredWriteTransfer(c.transferObservation, generation)
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
	ttl := 30 * time.Second
	if out.ObservationTTLSeconds != 0 {
		if out.ObservationTTLSeconds > 300 {
			return nil, errors.New("invalid transfer observation TTL")
		}
		ttl = time.Duration(out.ObservationTTLSeconds) * time.Second
	}
	nodeIDs := make(map[string]uint64, len(out.Nodes))
	seenIDs := make(map[uint64]bool, len(out.Nodes))
	for _, node := range out.Nodes {
		if node.ID == 0 || node.Addr == "" || nodeIDs[node.Addr] != 0 || seenIDs[node.ID] {
			return nil, errors.New("invalid transfer discovery node")
		}
		nodeIDs[node.Addr], seenIDs[node.ID] = node.ID, true
	}
	if !c.withTransferGeneration(generation, func() {
		c.transferMeasurementMu.Lock()
		defer c.transferMeasurementMu.Unlock()
		if c.transferMeasurementGen != generation {
			c.transferMeasurements = nil
		}
		c.transferNodeIDs, c.transferMeasurementTTL = nodeIDs, ttl
		c.transferMeasurementGen = generation
	}) {
		return nil, errors.New("write transfer session changed during discovery")
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
			probeCtx, cancel := context.WithTimeout(ctx, min(3*time.Second, ttl/2))
			defer cancel()
			link := types.TransferObservation{ToNodeID: node.ID, Path: c.scheme(), ObservedAt: time.Now()}
			base := c.transferProbeTransport()
			if _, peer := base.(*peerhttp.Transport); peer {
				link.Path = string(peerhttp.PathUnknown)
			}
			var path atomic.Value
			path.Store(link.Path)
			probeCtx = peerhttp.WithResponseReporter(probeCtx, func(observation peerhttp.Observation) {
				path.Store(string(observation.Path))
			})
			req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, c.scheme()+"://"+node.Addr+"/healthz", nil)
			if err == nil {
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
			if link.Path == "" || link.Path == string(peerhttp.PathUnknown) {
				link.Available = false
			}
			observation.Links[i] = link
		}(i, node)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Reserve half the lease for publication and clock/network delay. Probes
	// completed early in a large fan-out may already be too old to submit.
	now := time.Now()
	validUntil := now.Add(min(10*time.Second, ttl/2))
	fresh := observation.Links[:0]
	for _, link := range observation.Links {
		until := link.ObservedAt.Add(ttl / 2)
		if link.ObservedAt.IsZero() || !now.Before(until) {
			continue
		}
		fresh = append(fresh, link)
		if until.Before(validUntil) {
			validUntil = until
		}
	}
	observation.Links = fresh
	if !c.withTransferGeneration(generation, func() {
		c.transferObservation, c.transferObservedAt = observation, now
		c.transferValidUntil, c.transferObservationGen = validUntil, generation
	}) {
		return nil, errors.New("write transfer session changed during observation")
	}
	return c.measuredWriteTransfer(observation, generation)
}

func (c *Client) planWriteChunk(ctx context.Context, upload types.WriteUpload, request *types.PlanWriteChunkRequest, out *types.PlanWriteChunkResponse) error {
	if !c.transferEnabled {
		return c.writeJSONRetry(ctx, "/writes/chunks", request, out)
	}
	ctx, cancel := context.WithTimeout(ctx, metadataTimeout)
	defer cancel()
	generation := c.transferGeneration()
	planCtx := context.WithValue(ctx, transferSubmissionKey{}, generation)
	for attempt := 0; attempt < 2; attempt++ {
		observation, err := c.observeWriteTransfer(ctx, upload)
		if err != nil {
			return err
		}
		request.Network = observation
		err = c.writeJSONRetry(planCtx, "/writes/chunks", request, out)
		if err == nil || attempt != 0 || !retryMissingTransferIngress(err, observation) || ctx.Err() != nil {
			return err
		}
		if deadline, bounded := ctx.Deadline(); bounded && time.Until(deadline) < 3*time.Second {
			return err
		}
		c.transferMu.Lock()
		if c.transferGeneration() != generation {
			c.transferMu.Unlock()
			return errors.New("write transfer session changed before ingress rediscovery")
		}
		// A cold path can finish preparing after its first bounded probe. Retry
		// real observation once; old payload evidence must not revive that failure.
		c.transferObservation = nil
		c.transferValidUntil = time.Time{}
		c.transferMu.Unlock()
	}
	return errors.New("write transfer planning attempts exhausted")
}

func retryMissingTransferIngress(err error, observation *types.WriteTransferObservation) bool {
	var rejected *HTTPError
	if !errors.As(err, &rejected) || rejected.StatusCode != http.StatusUnprocessableEntity || rejected.Code != types.WriteNoFeasible || observation == nil || len(observation.Links) == 0 {
		return false
	}
	for _, link := range observation.Links {
		if link.Available {
			return false
		}
	}
	return true
}

func (c *Client) measuredWriteTransfer(probes *types.WriteTransferObservation, generation uint64) (*types.WriteTransferObservation, error) {
	out := &types.WriteTransferObservation{Budget: probes.Budget, Links: append([]types.TransferObservation(nil), probes.Links...)}
	if !c.withTransferGeneration(generation, func() {
		c.transferMeasurementMu.Lock()
		defer c.transferMeasurementMu.Unlock()
		now := time.Now()
		for key, measured := range c.transferMeasurements {
			if measured.generation != generation || !now.Before(measured.ObservedAt.Add(c.transferMeasurementTTL/2)) || c.transferNodeIDs[key.addr] != measured.ToNodeID {
				delete(c.transferMeasurements, key)
			}
		}
		// Payload measurements neither revive failed probes nor invent a new
		// usable path. Their timestamps are never renewed by health checks.
		for i, probe := range out.Links {
			if !probe.Available {
				continue
			}
			for _, measured := range c.transferMeasurements {
				if measured.ToNodeID == probe.ToNodeID && measured.Path == probe.Path {
					out.Links[i] = measured.TransferObservation
					out.Links[i].RTTMs = probe.RTTMs
					break
				}
			}
		}
	}) {
		return nil, errors.New("write transfer session changed before submission")
	}
	return out, nil
}

func (c *Client) recordTransferMeasurement(addr, path string, expectedNodeID, generation uint64, size int64, started time.Time, elapsed time.Duration) {
	if expectedNodeID == 0 || size <= 0 || elapsed <= 0 || started.IsZero() || path != string(peerhttp.PathDirect) && path != string(peerhttp.PathRelay) && path != string(peerhttp.PathHTTP) && path != string(peerhttp.PathHTTPS) {
		return
	}
	measured := float64(size) / elapsed.Seconds()
	if measured <= 0 || measured > float64(transferbudget.MaxRate) {
		return
	}
	rate := uint64(measured)
	if rate == 0 {
		return
	}
	c.withTransferGeneration(generation, func() {
		c.transferMeasurementMu.Lock()
		defer c.transferMeasurementMu.Unlock()
		if c.transferMeasurementGen != generation || c.transferNodeIDs[addr] != expectedNodeID {
			return
		}
		if c.transferMeasurements == nil {
			c.transferMeasurements = make(map[transferMeasurementKey]transferMeasurement)
		}
		key := transferMeasurementKey{addr: addr, path: path}
		now := time.Now()
		for oldKey, previous := range c.transferMeasurements {
			if previous.generation != generation || c.transferNodeIDs[oldKey.addr] != previous.ToNodeID || !now.Before(previous.ObservedAt.Add(c.transferMeasurementTTL/2)) {
				delete(c.transferMeasurements, oldKey)
			}
		}
		if old, exists := c.transferMeasurements[key]; exists && old.started.After(started) {
			return
		}
		if _, exists := c.transferMeasurements[key]; !exists && len(c.transferMeasurements) >= 1024 {
			return
		}
		c.transferMeasurements[key] = transferMeasurement{TransferObservation: types.TransferObservation{ToNodeID: expectedNodeID, Path: path, Available: true, ThroughputBPS: rate, ObservedAt: now}, generation: generation, started: started}
	})
}

type transferUploadObservation struct {
	mu         sync.Mutex
	response   peerhttp.Observation
	ordinary   string
	nodeID     uint64
	generation uint64
	ctx        context.Context
}

func (c *Client) observeTransferUpload(ctx context.Context, addr string, objectID uint64) (context.Context, *transferUploadObservation) {
	generation := c.transferGeneration()
	var nodeID uint64
	c.withTransferGeneration(generation, func() {
		c.transferMeasurementMu.Lock()
		defer c.transferMeasurementMu.Unlock()
		if c.transferMeasurementGen == generation {
			nodeID = c.transferNodeIDs[addr]
		}
	})
	if nodeID == 0 {
		return ctx, nil
	}
	observed := &transferUploadObservation{ordinary: c.scheme(), nodeID: nodeID, generation: generation, ctx: ctx}
	if _, peer := c.transferProbeTransport().(*peerhttp.Transport); peer {
		observed.ordinary = ""
	}
	path := "/objects/" + strconv.FormatUint(objectID, 10)
	ctx = peerhttp.WithResponseReporter(ctx, func(response peerhttp.Observation) {
		if response.Target == addr && response.Method == http.MethodPut && response.RequestPath == path {
			observed.mu.Lock()
			observed.response = response
			observed.mu.Unlock()
		}
	})
	return ctx, observed
}

// Called only after the node's complete stored-size acknowledgement. This is
// application-confirmed goodput, including request overhead and budget pacing.
func (c *Client) finishTransferUpload(observed *transferUploadObservation, addr string, size int64, started time.Time, status int) {
	if observed == nil || status != http.StatusCreated || observed.ctx != nil && observed.ctx.Err() != nil {
		return
	}
	observed.mu.Lock()
	response, path := observed.response, observed.ordinary
	observed.mu.Unlock()
	if response.Phase == peerhttp.PhaseResponse {
		if response.Master || response.ErrorKind != "" || response.Status != http.StatusCreated {
			return
		}
		path = string(response.Path)
	} else if path == "" {
		return
	}
	c.recordTransferMeasurement(addr, path, observed.nodeID, observed.generation, size, started, time.Since(started))
}
