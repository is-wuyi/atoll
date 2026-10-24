package peertransport

import (
	"net"
	"testing"
)

func TestPublicGateRejectsReservedIPv6ProofAddresses(t *testing.T) {
	for _, address := range []string{"fec0::1", "2001:db8::1", "100::1", "64:ff9b::a7e:7e03"} {
		if isPublicIP(net.ParseIP(address)) {
			t.Fatalf("reserved or translated IPv6 address accepted as public proof: %s", address)
		}
	}
}
