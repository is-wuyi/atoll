package master

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/access"
	"atoll/pkg/types"
)

func TestProtectionFeedbackDeviceTicketAttemptAndTokenFence(t *testing.T) {
	cluster := newAccCluster(t)
	_, _, space := cluster.accUser("flight-user")
	sourceToken, sourceID := cluster.accDevice("127.0.0.1:51301")
	targetToken, targetID := cluster.accDevice("127.0.0.1:51302")
	if err := cluster.store.EnableProtectionFeedback(); err != nil {
		t.Fatal(err)
	}
	obj, _, err := cluster.store.PrepareSmallFile(meta.SmallFileTarget{ParentID: space.RootID, Name: "ticket-flight", Size: 100, Checksum: 7, Replicas: []uint64{sourceID}, PrimaryID: sourceID, Mtime: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := cluster.store.CommitSmallFile(obj.ID); err != nil {
		t.Fatal(err)
	}
	d, err := cluster.store.ObjectIntegrity(obj.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := cluster.store.MarkVerifiedObjectDone(d, sourceID); err != nil || !ok {
		t.Fatalf("source receipt: %v %v", ok, err)
	}
	d, _ = cluster.store.ObjectIntegrity(obj.ID)
	snapshot, _ := cluster.store.AutonomySnapshot()
	plan, err := cluster.store.ReserveProtection(meta.ProtectionRequest{ID: "ticket-flight", Expected: d, Targets: []uint64{targetID}, MaxBytes: d.Size, NodeMaxAge: time.Hour, ProfileRevision: snapshot.ProfileRevision}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	_, first, err := cluster.store.ClaimProtectionTarget(plan.ID, now, 30*time.Second)
	if err != nil || first == nil {
		t.Fatal(err)
	}
	path := "/objects/" + strconv.FormatUint(obj.ID, 10)
	req := access.TicketRequest{NodeAddr: "127.0.0.1:51301", Method: http.MethodGet, Path: path, PlanID: plan.ID, PlanAttempt: first.Attempts, PlanAttemptToken: first.AttemptToken}
	ticket, err := cluster.store.IssueDeviceTicket(targetToken, req, now)
	if err != nil {
		t.Fatalf("current attempt ticket: %v", err)
	}
	check := access.CheckRequest{Token: ticket.Token, Method: http.MethodGet, Path: path, PlanID: plan.ID, PlanAttempt: first.Attempts, PlanAttemptToken: first.AttemptToken}
	if _, err := cluster.store.CheckAccessTicket(sourceToken, check, now); err != nil {
		t.Fatalf("current attempt check: %v", err)
	}
	for _, token := range []string{"", "forged"} {
		bad := check
		bad.PlanAttemptToken = token
		if _, err := cluster.store.CheckAccessTicket(sourceToken, bad, now); err == nil {
			t.Fatalf("wrong token accepted: %q", token)
		}
	}
	_, second, err := cluster.store.ClaimProtectionTarget(plan.ID, now.Add(31*time.Second), 30*time.Second)
	if err != nil || second == nil {
		t.Fatal(err)
	}
	if _, err := cluster.store.CheckAccessTicket(sourceToken, check, now.Add(31*time.Second)); err == nil {
		t.Fatal("superseded ticket still authorized")
	}
	req.PlanAttempt, req.PlanAttemptToken = second.Attempts, second.AttemptToken
	if _, err := cluster.store.IssueDeviceTicket(targetToken, req, now.Add(31*time.Second)); err != nil {
		t.Fatalf("new attempt could not get ticket: %v", err)
	}
	wrongDeviceBody := types.ProtectionProgress{PlanID: plan.ID, ObjectID: obj.ID, Generation: d.Generation, IntegrityEpoch: d.IntegrityEpoch, NodeID: targetID, Attempt: second.Attempts, AttemptToken: second.AttemptToken, BytesDone: 1}
	status, _, _ := cluster.accDo(http.MethodPost, "/files/protection/progress", sourceToken, 0, wrongDeviceBody)
	if status != http.StatusForbidden {
		t.Fatalf("source device impersonated target feedback: %d", status)
	}
}
