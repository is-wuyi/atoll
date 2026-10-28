package types

import (
	"testing"
	"time"
)

func recoveryPlanFixture() (PlanWriteChunkRequest, WriteChunkPlan) {
	id := StagingInodeBase + 7
	req := PlanWriteChunkRequest{WriteBinding: WriteBinding{UploadID: id, PlanID: "write-plan", Revision: 1}, Index: 0, LogicalSize: 8, StoredSize: 8, Encoding: PlainEncoding, Checksum: 100}
	plan := WriteChunkPlan{Index: 0, Object: ContentObject{ID: ChunkID(id, 0), Version: 1, LogicalSize: 8, StoredSize: 8, Encoding: PlainEncoding, Checksum: 100, ChecksumKnown: true}, Layout: ReplicaLayout{ObjectID: ChunkID(id, 0), Epoch: 1, Scheme: "replicate", Nodes: []uint64{1, 2}}, Confirmations: []uint64{1, 2}, RequiredConfirmations: 2, Recovery: &WriteRecovery{Epoch: 1, HardUntil: time.Now().Add(time.Minute)}}
	return req, plan
}

func TestWriteRecoveryValidation(t *testing.T) {
	req, original := recoveryPlanFixture()
	if err := ValidateWriteChunkPlan(req, original); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*WriteChunkPlan)
	}{
		{"missing-state", func(p *WriteChunkPlan) { p.Layout.Epoch = 2; p.Recovery = nil }},
		{"epoch-mismatch", func(p *WriteChunkPlan) { p.Recovery.Epoch = 2 }},
		{"exhausted", func(p *WriteChunkPlan) { p.Recovery.Attempts = MaxWriteRecoveries + 1 }},
		{"deadline-missing", func(p *WriteChunkPlan) { p.Recovery.HardUntil = time.Time{} }},
		{"excluded-target", func(p *WriteChunkPlan) { p.Recovery.Excluded = []uint64{1} }},
		{"duplicate-exclusion", func(p *WriteChunkPlan) { p.Recovery.Excluded = []uint64{3, 3} }},
		{"initial-operation", func(p *WriteChunkPlan) { p.Recovery.OperationID = "not-initial" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := original
			r := *original.Recovery
			plan.Recovery = &r
			test.edit(&plan)
			if err := ValidateWriteChunkPlan(req, plan); err == nil {
				t.Fatal("invalid recovery plan accepted")
			}
		})
	}
	valid := original
	valid.Layout.Epoch = 2
	valid.Recovery = &WriteRecovery{Epoch: 2, Attempts: 1, HardUntil: original.Recovery.HardUntil, Excluded: []uint64{3}, FailedNodes: []uint64{3}, OperationID: "recover", RequestHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	if err := ValidateWriteChunkPlan(req, valid); err != nil {
		t.Fatal(err)
	}
}
