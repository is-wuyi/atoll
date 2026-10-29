package meta

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"atoll/pkg/types"
)

func TestWriteProgressConcurrentRegistrationCAS(t *testing.T) {
	for _, replay := range []bool{false, true} {
		t.Run(fmt.Sprintf("same_request_%t", replay), func(t *testing.T) {
			s, nodes := writeTestStore(t)
			u, plan := recoveryFixture(t, s, nodes)
			now := time.Now()
			type result struct {
				request  types.BeginWriteProgressRequest
				response types.BeginWriteProgressResponse
				err      error
			}
			const workers = 8
			start := make(chan struct{})
			results := make(chan result, workers)
			var wg sync.WaitGroup
			for i := 0; i < workers; i++ {
				requestID := "same-request"
				if !replay {
					requestID = fmt.Sprintf("request-%d", i)
				}
				req := types.BeginWriteProgressRequest{ObjectID: plan.Object.ID, NodeID: nodes[0], Epoch: plan.Recovery.Epoch, RequestID: requestID}
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					response, err := s.BeginWriteProgress(req, now)
					results <- result{request: req, response: response, err: err}
				}()
			}
			close(start)
			wg.Wait()
			close(results)
			var winner result
			successful := 0
			for r := range results {
				if r.err != nil {
					if !errors.Is(r.err, ErrWritePlanConflict) {
						t.Fatal(r.err)
					}
					continue
				}
				if successful > 0 && r.response != winner.response {
					t.Fatal("concurrent replay returned different attempts or tokens")
				}
				winner = r
				successful++
			}
			want := 1
			if replay {
				want = workers
			}
			if successful != want || winner.response.Attempt != 1 {
				t.Fatalf("registration winners=%d want=%d attempt=%d", successful, want, winner.response.Attempt)
			}
			state, err := s.WriteProgressState(plan.Object.ID, nodes[0], plan.Recovery.Epoch, now)
			if err != nil || state == nil || state.Attempt != 1 {
				t.Fatalf("CAS consumed multiple attempts: %+v %v", state, err)
			}
			status, err := s.PlannedWriteStatus(WriteActor{}, writeBinding(u), time.Hour, now)
			if err != nil || len(status.Chunks[0].Progress) != 0 || status.Chunks[0].Ready || len(status.Chunks[0].Done) != 0 {
				t.Fatalf("concurrent registration created progress or Done: %+v %v", status, err)
			}
			next := winner.request
			next.RequestID, next.ExpectedAttempt = "next-request", 1
			second, err := s.BeginWriteProgress(next, now)
			if err != nil || second.Attempt != 2 || second.AttemptToken == winner.response.AttemptToken {
				t.Fatalf("new registration did not advance: %+v %v", second, err)
			}
			if _, err := s.BeginWriteProgress(winner.request, now); !errors.Is(err, ErrWritePlanConflict) {
				t.Fatalf("delayed winning request replaced its successor: %v", err)
			}
		})
	}
}
