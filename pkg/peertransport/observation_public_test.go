package peertransport

import (
	"testing"

	"atoll/pkg/peerauth"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

func TestObservationHostAdmitsUnknownPublicQUICCandidate(t *testing.T) {
	center, edge, infra := mixedInfrastructure(t)
	if err := edge.SetDirectory(peerauth.Directory{Protocol: peerauth.Feature, Infrastructure: infra}); err != nil {
		t.Fatal(err)
	}
	h, err := edge.observationHostFor()
	if err != nil {
		t.Fatal(err)
	}
	checker, ok := h.Network().(interface {
		CanDial(peer.ID, ma.Multiaddr) bool
	})
	if !ok {
		t.Fatal("observation host has no public swarm CanDial interface")
	}
	gate := &observationGate{auth: edge.auth, publicOnly: true}
	for _, raw := range []string{"/ip4/1.1.1.1/udp/443/quic-v1", "/ip6/2606:4700:4700::1111/udp/443/quic-v1"} {
		address, err := ma.NewMultiaddr(raw)
		if err != nil || !manet.IsPublicAddr(address) {
			t.Fatalf("fixture address is not public QUIC: %s, %v", raw, err)
		}
		if !gate.InterceptAddrDial(center.id, address) {
			t.Fatalf("authorized center candidate rejected by the observation gate: %s", raw)
		}
		// CanDial runs the real swarm filters but sends no packets to this address.
		if !checker.CanDial(center.id, address) {
			t.Fatalf("new observation host blocked unmeasured public QUIC: %s", raw)
		}
	}
	private, err := ma.NewMultiaddr("/ip4/127.0.0.1/udp/443/quic-v1")
	if err != nil {
		t.Fatal(err)
	}
	if gate.InterceptAddrDial(center.id, private) {
		t.Fatal("public observation policy accepted a private UDP candidate")
	}
	unknown := testPeerID(t)
	if gate.InterceptPeerDial(unknown) {
		t.Fatal("candidate admission bypassed the current infrastructure identity")
	}
}
