package master

import (
	"path/filepath"
	"testing"
	"time"

	"atoll/master/meta"
)

func TestProtectionFeedbackCapabilityRequiresExplicitRestartFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "feedback-restart.db")
	store, err := meta.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := AutonomyConfig{Mode: AutonomyAdd, ProtectionFeedback: true}
	if _, err := NewAutonomy(store, time.Hour, cfg); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = meta.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := NewAutonomy(store, time.Hour, AutonomyConfig{Mode: AutonomyAdd}); err == nil {
		t.Fatal("restart silently downgraded feedback capability")
	}
	if _, err := NewAutonomy(store, time.Hour, cfg); err != nil {
		t.Fatalf("explicit restart rejected: %v", err)
	}
}
