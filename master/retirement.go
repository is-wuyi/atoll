package master

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"atoll/master/meta"
	"atoll/pkg/access"
	"atoll/pkg/types"
)

const retirementBatch = 64

func (s *Scanner) wakeRetirements() {
	select {
	case s.retirementWake <- struct{}{}:
	default:
	}
}

func (s *Scanner) runRetirementLoop(ctx context.Context) {
	interval := 15 * time.Second
	if s.gcIntv > 0 && s.gcIntv < interval {
		interval = s.gcIntv
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := s.RunRetirements(ctx); err != nil && ctx.Err() == nil {
			log.Printf("object retirement: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.retirementWake:
		}
	}
}

// RunRetirements executes only journaled, unreferenced objects; inventory absence is not authority.
func (s *Scanner) RunRetirements(ctx context.Context) (int, error) {
	s.retirementMu.Lock()
	defer s.retirementMu.Unlock()
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	enabled, err := s.store.WritePlanningEnabled()
	if err != nil || !enabled {
		return 0, err
	}
	if _, err := s.store.ExpirePlannedWrites(time.Now()); err != nil {
		return 0, err
	}
	if _, err := s.store.SweepExpiredObjects(); err != nil {
		return 0, err
	}
	if err := s.store.ReconcileRetirements(time.Now()); err != nil {
		return 0, err
	}
	records, err := s.store.ListRetirements()
	if err != nil {
		return 0, err
	}
	completed, attempted := 0, 0
	for _, rec := range records {
		if rec.State == meta.RetirementHeld || rec.State == meta.RetirementConfirmed {
			continue
		}
		if err := ctx.Err(); err != nil {
			return completed, err
		}
		if attempted == retirementBatch {
			break
		}
		req, claimed, err := s.store.ClaimRetirement(rec.ObjectID, rec.NodeID, time.Now(), 15*time.Second, s.nodeMaxAge)
		if err != nil || !claimed {
			continue
		}
		attempted++
		node, err := s.store.GetNode(rec.NodeID)
		if err != nil {
			continue
		}
		raw, err := json.Marshal(req)
		if err != nil {
			return completed, err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost,
			fmt.Sprintf("%s://%s%s", s.scheme, node.Addr, types.RetirementPath(req.ObjectID)), bytes.NewReader(raw))
		if err != nil {
			continue
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set(access.PlanHeader, req.FenceID)
		response, err := s.httpClient.Do(request)
		if err != nil {
			log.Printf("retire object %d node %d: %v", rec.ObjectID, rec.NodeID, err)
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK {
			continue
		}
		var receipt types.ObjectRetirementReceipt
		if types.DecodeRetirementJSON(body, &receipt) != nil || receipt.Validate() != nil || receipt.ObjectRetirement != req {
			log.Printf("retire object %d node %d: invalid receipt", rec.ObjectID, rec.NodeID)
			continue
		}
		ok, err := s.store.ConfirmRetirement(receipt, time.Now(), s.nodeMaxAge)
		if err != nil {
			log.Printf("retire object %d node %d confirmation: %v", rec.ObjectID, rec.NodeID, err)
			continue
		}
		if ok {
			completed++
		}
	}
	return completed, nil
}
