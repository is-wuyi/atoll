package main

import (
	"testing"

	"atoll/pkg/auth"
)

func TestConfiguredClientDoesNotDropSpaceWithoutSession(t *testing.T) {
	if _, err := configuredClient("http://127.0.0.1:1", auth.Token("legacy-token"), nil, "", 7, true); err == nil {
		t.Fatal("space selection silently fell back to the legacy root")
	}
	legacy, err := configuredClient("http://127.0.0.1:1", "", nil, "", 0, false)
	if err != nil || legacy.ObjectTransport() != nil {
		t.Fatalf("legacy client changed: %v", err)
	}
	secure, err := configuredClient("https://127.0.0.1:1", "", nil, "test-session", 7, false)
	if err != nil || secure.ObjectTransport() == nil {
		t.Fatalf("session client not enabled: %v", err)
	}
}
