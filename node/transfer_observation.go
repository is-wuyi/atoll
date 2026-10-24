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
			var path atomic.Value
			path.Store(n.scheme())
			probeCtx = peerhttp.WithReporter(probeCtx, &peerhttp.Reporter{Observe: func(observation peerhttp.Observation) { path.Store(string(observation.Path)) }})
			req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, n.scheme()+"://"+peer.Addr+"/healthz", nil)
			if err == nil {
				base := n.bulkClient.Transport
				if n.sec != nil {
					base = n.sec.base
				}
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
