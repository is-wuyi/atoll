package meta

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/types"
)

func TestWriteRecoveryTicketBindsEpochAndResume(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	admin, _ := bootstrapAdmin(t, s)
	_, bobSpace := inviteAndRegister(t, s, admin.ID, "recoveryticket", time.Now())
	if err := s.EnableWritePlanning(); err != nil {
		t.Fatal(err)
	}
	dev := auditLoginDevice(t, s, "127.0.0.1:59888", "")
	actor := WriteActor{UserID: 2, SpaceID: bobSpace.ID}
	// Use the invited user's real id; it is intentionally not derived from ordering.
	login, err := s.AuthenticateUser("recoveryticket", "invited-password-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	user, err := s.UserForSession(login.Token, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	actor.UserID = user.ID
	u, err := s.BeginPlannedWrite(actor, bobSpace.RootID, "file", types.BeginWriteRequest{Path: "/file", OpID: "begin", Size: 3}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req, plan := writeChoice(u, 0, []byte("abc"), []uint64{dev.NodeID}, []uint64{dev.NodeID})
	plan.Recovery = &types.WriteRecovery{Epoch: 1, HardUntil: time.Now().Add(time.Minute)}
	if _, _, err := s.ReserveWriteChunk(actor, req, plan, 0, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/objects/%d", plan.Object.ID)
	for _, tc := range []struct {
		name    string
		epoch   uint64
		resume  bool
		attempt string
		ok      bool
	}{
		{"missing", 0, false, "", false},
		{"wrong", 2, false, "", false},
		{"resume-missing", 0, true, "", false},
		{"put", 1, false, "", true},
		{"resume", 1, true, "", true},
		{"put-attempt", 1, false, "00000000000000000000000000000001", true},
		{"attempt-without-epoch", 0, false, "00000000000000000000000000000001", false},
		{"attempt-with-resume", 1, true, "00000000000000000000000000000001", false},
		{"malformed-attempt", 1, false, "invalid", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := access.TicketRequest{NodeAddr: "127.0.0.1:59888", Method: "PUT", Path: path, WriteEpoch: tc.epoch, Resume: tc.resume, WriteAttemptID: tc.attempt}
			ticket, err := s.IssueUserTicket(login.Token, bobSpace.ID, r, time.Now())
			if !tc.ok {
				if !errors.Is(err, ErrAccessTicket) {
					t.Fatalf("invalid epoch ticket: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			check := access.CheckRequest{Token: ticket.Token, Method: r.Method, Path: r.Path, WriteEpoch: r.WriteEpoch, Resume: r.Resume, WriteAttemptID: r.WriteAttemptID}
			if _, err := s.CheckAccessTicket(dev.Token, check, time.Now()); err != nil {
				t.Fatal(err)
			}
			for _, other := range []string{"", "00000000000000000000000000000001", "00000000000000000000000000000002"} {
				if other == r.WriteAttemptID {
					continue
				}
				check.WriteAttemptID = other
				if _, err := s.CheckAccessTicket(dev.Token, check, time.Now()); !errors.Is(err, ErrAccessTicket) {
					t.Fatalf("changed attempt id accepted: %v", err)
				}
			}
			check.WriteAttemptID = r.WriteAttemptID
			check.WriteEpoch++
			if _, err := s.CheckAccessTicket(dev.Token, check, time.Now()); !errors.Is(err, ErrAccessTicket) {
				t.Fatalf("changed checked epoch accepted: %v", err)
			}
		})
	}
}
