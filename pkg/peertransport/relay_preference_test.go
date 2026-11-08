package peertransport

import (
	"strings"
	"testing"

	"atoll/pkg/peerauth"
	"crypto/rand"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

func relayTargetIdentity(t *testing.T) (peer.ID, []byte) {
	t.Helper()
	_, key, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := key.Raw()
	if err != nil {
		t.Fatal(err)
	}
	return id, raw
}

func TestPreferTCPKeepsTCPAndFallsBackToQUIC(t *testing.T) {
	tcp := ma.StringCast("/ip4/203.0.113.10/tcp/29602")
	quic := ma.StringCast("/ip4/203.0.113.10/udp/29603/quic-v1")
	got := preferTCP([]ma.Multiaddr{quic, tcp})
	if len(got) != 1 || !got[0].Equal(tcp) {
		t.Fatalf("mixed relay addresses = %v, want only the TCP address", got)
	}
	got = preferTCP([]ma.Multiaddr{quic})
	if len(got) != 1 || !got[0].Equal(quic) {
		t.Fatalf("QUIC-only relay addresses = %v, want the QUIC fallback", got)
	}
}

func TestCircuitAddrInfoPrefersTCPRelayHop(t *testing.T) {
	target, public := relayTargetIdentity(t)
	infra := peerauth.Infrastructure{
		PeerID:    target.String(),
		PublicKey: public,
		Addresses: []string{
			"/ip4/203.0.113.10/udp/29603/quic-v1",
			"/ip4/203.0.113.10/tcp/29602",
		},
		Relay: true,
	}
	ai, err := circuitAddrInfo(infra, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(ai.Addrs) != 1 || !strings.Contains(ai.Addrs[0].String(), "/tcp/29602") || strings.Contains(ai.Addrs[0].String(), "/quic-") {
		t.Fatalf("circuit addresses = %v, want the TCP relay hop only", ai.Addrs)
	}
}
