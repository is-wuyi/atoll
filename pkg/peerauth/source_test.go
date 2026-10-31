package peerauth

import (
	"context"
	"testing"
)

func TestSourcePeerIdentityOnlyComesFromConnectionContext(t *testing.T) {
	base := context.Background()
	if SourcePeerID(base) != "" {
		t.Fatal("unbound context supplied a source identity")
	}
	bound := WithSourcePeerID(base, "connection-peer")
	if SourcePeerID(bound) != "connection-peer" || SourcePeerID(base) != "" {
		t.Fatal("source identity context was not isolated")
	}
	cleared := WithSourcePeerID(bound, "")
	if SourcePeerID(cleared) != "" {
		t.Fatal("cleared connection identity survived")
	}
}
