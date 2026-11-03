package peertransport

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
)

func TestCallbackDoesNotOverwriteLiveInfrastructureProtocols(t *testing.T) {
	center, edge := nativeProbePair(t)
	if err := center.EnableRelay(); err != nil {
		t.Fatal(err)
	}
	const sentinel protocol.ID = "/atoll/live-control/1"
	center.mainHost.SetStreamHandler(sentinel, func(stream network.Stream) { _ = stream.Close() })
	if err := edge.mainHost.Peerstore().AddProtocols(center.id, sentinel); err != nil {
		t.Fatal(err)
	}
	_, err := nativeProbe(t, edge)
	if err != nil {
		t.Fatal(err)
	}
	protocols, err := edge.mainHost.Peerstore().SupportsProtocols(center.id, sentinel)
	if err != nil || len(protocols) != 1 {
		t.Fatalf("probe Identify overwrote live infrastructure protocols: %v %v", protocols, err)
	}
	if len(edge.mainHost.Network().ConnsToPeer(center.id)) == 0 {
		t.Fatal("probe cleanup removed the live infrastructure connection")
	}
}
