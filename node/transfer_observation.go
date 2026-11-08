package node

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"atoll/pkg/peerhttp"
	"atoll/pkg/types"
)

func (n *Node) scheduleTransferObservation() {
	if n.uploadBudget == nil || !n.observationBusy.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer n.observationBusy.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		n.observeRegisteredTransferPeers(ctx)
	}()
}

func (n *Node) observeRegisteredTransferPeers(ctx context.Context) {
	if n.uploadBudget == nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.masterURL+"/nodes/transfer-peers", nil)
	if err != nil {
		return
	}
	resp, err := n.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var out types.WriteTransferNodes
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out) != nil || len(out.Nodes) > 256 {
		return
	}
	n.observeTransferPeers(ctx, types.ReplicationPlan{Sources: out.Nodes})
}

func (n *Node) observeTransferPeers(ctx context.Context, plan types.ReplicationPlan) {
	if n.uploadBudget == nil {
		return
	}
	peers := append(append([]types.NodeInfo(nil), plan.Targets...), plan.Sources...)
	var wg sync.WaitGroup
	slots := make(chan struct{}, 8)
	for _, peer := range peers {
		if peer.ID == uint64(n.nodeID.Load()) {
			continue
		}
		n.observationMu.Lock()
		if n.observedPeers == nil {
			n.observedPeers = map[uint64]time.Time{}
		}
		if time.Since(n.observedPeers[peer.ID]) < 10*time.Second {
			n.observationMu.Unlock()
			continue
		}
		n.observedPeers[peer.ID] = time.Now()
		n.observationMu.Unlock()
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return
		}
		wg.Add(1)
		go func(peer types.NodeInfo) {
			defer wg.Done()
			defer func() { <-slots }()
			probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			started := time.Now()
			link := types.TransferObservation{FromNodeID: uint64(n.nodeID.Load()), ToNodeID: peer.ID, Path: n.scheme(), ObservedAt: started}
			base := n.bulkClient.Transport
			if n.sec != nil {
				base = n.sec.base
			}
			if _, peer := base.(*peerhttp.Transport); peer {
				link.Path = string(peerhttp.PathUnknown)
			}
			var path atomic.Value
			path.Store(link.Path)
			probeCtx = peerhttp.WithReporter(probeCtx, &peerhttp.Reporter{Observe: func(observation peerhttp.Observation) {
				if observation.Phase == peerhttp.PhaseResponse && !observation.Master {
					path.Store(string(observation.Path))
				}
			}})
			req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, n.scheme()+"://"+peer.Addr+"/healthz", nil)
			if err == nil {
				resp, probeErr := base.RoundTrip(req)
				link.RTTMs = float64(time.Since(started).Microseconds()) / 1000
				if probeErr == nil {
					_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
					resp.Body.Close()
					link.Available = resp.StatusCode == http.StatusOK && readErr == nil
				}
			}
			cancel()
			link.Path = path.Load().(string)
			body, _ := json.Marshal(link)
			reportCtx, reportCancel := context.WithTimeout(ctx, 3*time.Second)
			req, err = http.NewRequestWithContext(reportCtx, http.MethodPost, n.masterURL+"/nodes/transfer-observation", bytes.NewReader(body))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
				resp, reportErr := n.httpClient.Do(req)
				if reportErr == nil {
					io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
					resp.Body.Close()
				}
			}
			reportCancel()
		}(peer)
	}
	wg.Wait()
}

func (n *Node) transferBase() http.RoundTripper {
	if n.sec != nil {
		return n.sec.base
	}
	return n.bulkClient.Transport
}

func payloadObservationPath(path string) bool {
	switch peerhttp.Path(path) {
	case peerhttp.PathHTTP, peerhttp.PathHTTPS, peerhttp.PathDirect, peerhttp.PathRelay:
		return true
	}
	return false
}

func payloadGoodput(size int64, elapsed time.Duration) uint64 {
	if size <= 0 || elapsed <= 0 {
		return 0
	}
	bps := float64(size) / elapsed.Seconds()
	if bps <= 0 || bps > 1<<40 {
		return 0 // beyond the observation protocol ceiling; never overclaim
	}
	return uint64(bps)
}

// queuePayloadObservation is best-effort and non-blocking: the data path must
// not wait for the control report. At most eight reports are outstanding.
func (n *Node) queuePayloadObservation(observation types.TransferObservation) {
	self := uint64(n.nodeID.Load())
	now := time.Now()
	if n.payloadObsSlots == nil || self == 0 || observation.FromNodeID != self || observation.ToNodeID == 0 ||
		observation.ToNodeID == self || !observation.Available || observation.ThroughputBPS == 0 ||
		observation.ThroughputBPS > 1<<40 || observation.ObservedAt.IsZero() ||
		observation.ObservedAt.After(now.Add(time.Second)) || !payloadObservationPath(observation.Path) {
		return
	}
	select {
	case n.payloadObsSlots <- struct{}{}:
	default:
		return // bounded queue full: drop this report
	}
	if !n.goLife(func(ctx context.Context) {
		defer func() { <-n.payloadObsSlots }()
		n.reportPayloadObservation(ctx, observation)
	}) {
		<-n.payloadObsSlots
	}
}

func (n *Node) reportPayloadObservation(ctx context.Context, observation types.TransferObservation) {
	body, err := json.Marshal(observation)
	if err != nil {
		return
	}
	reportCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reportCtx, http.MethodPost, n.masterURL+"/nodes/transfer-observation", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.httpClient.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	resp.Body.Close()
}
