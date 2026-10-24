package node

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"atoll/pkg/transferbudget"
	"atoll/pkg/types"
)

func receiveDeadline(w http.ResponseWriter, r *http.Request, deadline time.Time) (context.Context, context.CancelFunc, error) {
	if deadline.IsZero() || !time.Now().Before(deadline) {
		return nil, nil, errLeaseExpired
	}
	if err := http.NewResponseController(w).SetReadDeadline(deadline); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	return ctx, cancel, nil
}

func (n *Node) ConfigureTransferBudget(budget types.TransferBudget) error {
	if n.nodeID.Load() != 0 || n.uploadBudget != nil || n.downloadBudget != nil {
		return errors.New("transfer budgets must be configured once before registration")
	}
	up, err := transferbudget.New(budget.UploadBPS, budget.MaxConcurrent)
	if err != nil {
		return err
	}
	down, err := transferbudget.New(budget.DownloadBPS, budget.MaxConcurrent)
	if err != nil {
		return err
	}
	n.uploadBudget, n.downloadBudget = up, down
	return nil
}

func budgetReader(ctx context.Context, source io.Reader, limiter *transferbudget.Limiter, rate uint64) (io.Reader, func(), error) {
	if limiter == nil {
		if rate != 0 {
			return nil, nil, errors.New("persisted transfer rate requires a configured local budget")
		}
		return source, func() {}, nil
	}
	release, err := limiter.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	return limiter.Reader(ctx, source, rate), release, nil
}

func (n *Node) receiveWithBudget(ctx context.Context, source io.Reader, rate uint64) (io.Reader, func(), error) {
	return budgetReader(ctx, source, n.downloadBudget, rate)
}

func (n *Node) sendWithBudget(ctx context.Context, source io.Reader, rate uint64) (io.Reader, func(), error) {
	return budgetReader(ctx, source, n.uploadBudget, rate)
}

func (n *Node) writeTransferLeg(plan *types.WriteTransferPlan, from, to uint64) (types.WriteTransferLeg, error) {
	if plan == nil || !time.Now().Before(plan.ExpiresAt) {
		return types.WriteTransferLeg{}, errors.New("write transfer lease expired")
	}
	for _, leg := range plan.Legs {
		if leg.FromNodeID == from && leg.ToNodeID == to && leg.BPS != 0 {
			return leg, nil
		}
	}
	return types.WriteTransferLeg{}, errors.New("transfer source and target are not assigned")
}

func (n *Node) incomingWriteLeg(plan *types.WriteTransferPlan, to uint64) (types.WriteTransferLeg, error) {
	for _, leg := range plan.Legs {
		if leg.ToNodeID == to && leg.FromNodeID != 0 {
			return n.writeTransferLeg(plan, leg.FromNodeID, to)
		}
	}
	return types.WriteTransferLeg{}, errors.New("target is not assigned a node replication ingress")
}
