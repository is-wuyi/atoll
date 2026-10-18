package master

import (
	"context"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/types"
)

func TestAutonomyPlanningCursorAdvancesAcrossRestart(t *testing.T) {
	s := ieNewStack(t)
	input := meta.AutonomySnapshot{}
	for i := 0; i < 300; i++ {
		input.Objects = append(input.Objects, types.ObjectIntegrity{ObjectID: types.ObjectIDBase + uint64(i), InodeID: uint64(i + 2), Size: 1, Checksum: 1, ChecksumKnown: true})
	}
	makeController := func() *Autonomy {
		a, err := NewAutonomy(s.store, time.Hour, AutonomyConfig{Mode: AutonomyShadow})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	first, err := makeController().plan(context.Background(), input, time.Now())
	if err != nil || len(first) != 256 {
		t.Fatalf("first page: %d %v", len(first), err)
	}
	snapshot, err := s.store.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ScanAfter != input.Objects[255].ObjectID {
		t.Fatalf("cursor not persisted: %d", snapshot.ScanAfter)
	}
	input.ScanAfter = snapshot.ScanAfter
	second, err := makeController().plan(context.Background(), input, time.Now())
	if err != nil || len(second) == 0 || second[0].ObjectID != input.Objects[256].ObjectID {
		t.Fatalf("new controller restarted at the first objects: %v %v", second, err)
	}
}
