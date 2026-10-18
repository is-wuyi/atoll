package scheduler

import (
	"fmt"
	"testing"
	"time"
)

func TestReadabilityGateRetainsZeroProbabilityShards(t *testing.T) {
	policy := Policy{MinFaultTolerance: 1, MinPredictedReadability: 0.5,
		MinConfidence: 0.5, PredictionHorizonSeconds: 3600, MaxReplicaCount: 3,
		CodecLimits: CodecLimits{MaxK: -1}}
	obj := ObjectRequirement{ObjectID: "zero-forecast", SizeBytes: 1, ContentVersion: 1}
	layout := Layout{ObjectID: obj.ObjectID, ContentVersion: 1, LayoutEpoch: 1, Scheme: SchemeReplicate}
	snapshot := Snapshot{SchemaVersion: SchemaVersion, Policy: policy, Objects: []ObjectRequirement{obj}}
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("node-%d", i)
		snapshot.Nodes = append(snapshot.Nodes, Node{ID: id, Online: true, HardCapacityBytes: 1024,
			FailureDomains: map[string]string{"zone": id},
			Availability:   []AvailabilityWindow{{HorizonSeconds: 3600, ProbabilityOnline: 0, Confidence: 1}}})
		layout.Replicas = append(layout.Replicas, FragmentPlacement{NodeID: id, FragmentIndex: i, Bytes: 1, Origin: OriginExisting})
	}
	probs := shardProbabilities(layout, nodeIndex(&snapshot), time.Unix(0, 0), 3600, 0.5)
	if len(probs) != 3 {
		t.Errorf("zero-probability shards disappeared: %v", probs)
	}
	if floor := readabilityFloor(probs); floor != 0 {
		t.Errorf("all-zero forecast floor = %v, want 0", floor)
	}
	report := ValidateLayout(&snapshot, obj, layout, policy)
	if report.Passed || !hasViolation(report, VHorizonGate) {
		t.Errorf("all-zero forecast passed readability gate: %+v", report)
	}
	decisions, err := RunAt(&snapshot, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 1 || decisions[0].Status != StatusNoFeasible || decisions[0].Plan != nil {
		t.Fatalf("all-zero forecasts produced a plan: %+v", decisions)
	}
}

func TestSupportedECRejectsIntegerOverflow(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	if supportedEC(&ECParams{K: maxInt, M: maxInt}) {
		t.Fatal("overflowing EC geometry accepted")
	}
	if !supportedEC(&ECParams{K: 254, M: 1}) {
		t.Fatal("supported boundary geometry rejected")
	}
}
