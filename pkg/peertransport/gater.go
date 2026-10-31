package peertransport

import (
	"net"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// mainGate is the connection gate for the main host. Beyond the public-only
// endpoint class it performs bounded authorization at the security handshake
// (Secured) and after muxing (Upgraded), so an unauthorized peer cannot consume
// AutoNAT, identify or hole-punch resources. The decision comes from the shared
// protocolGate (authoritative authorizer when installed, allow-set otherwise)
// and is bounded and lock-free by construction. The gate never closes other
// active connections or clears the peerstore.
type mainGate struct {
	publicOnly bool
	auth       *protocolGate
}

func (g *mainGate) InterceptPeerDial(peer.ID) bool { return true }

func (g *mainGate) InterceptAddrDial(_ peer.ID, addr ma.Multiaddr) bool {
	if !g.publicOnly || publicOnlyRemote(addr) {
		return true
	}
	return false
}

func (g *mainGate) InterceptAccept(cm network.ConnMultiaddrs) bool {
	if !g.publicOnly {
		return true
	}
	return publicOnlyRemote(cm.RemoteMultiaddr()) && publicOnlyLocal(cm.LocalMultiaddr())
}

func (g *mainGate) InterceptSecured(_ network.Direction, p peer.ID, cm network.ConnMultiaddrs) bool {
	if g.auth != nil && !g.auth.authorize(g.auth.ctx, p.String()) {
		return false
	}
	if !g.publicOnly {
		return true
	}
	return publicOnlyRemote(cm.RemoteMultiaddr()) && publicOnlyLocal(cm.LocalMultiaddr())
}

func (g *mainGate) InterceptUpgraded(c network.Conn) (bool, control.DisconnectReason) {
	if g.auth != nil && !g.auth.authorize(g.auth.ctx, c.RemotePeer().String()) {
		return false, 0
	}
	if !g.publicOnly {
		return true, 0
	}
	if publicOnlyRemote(c.RemoteMultiaddr()) && publicOnlyLocal(c.LocalMultiaddr()) {
		return true, 0
	}
	return false, 0
}

// relayGate is the gate for the lazy relay-dial host, which is strictly
// dial-only and carries exactly one purpose: reach an authorized target node
// through a CircuitRelay v2 hop without ever reusing a direct connection to
// that node. Outbound dials are limited to an authorized target's circuit
// address and the relay's direct addresses; inbound connections are refused.
// Authorization is the same authoritative protocolGate decision as the main
// gate, so a forced-relay dial cannot reuse a direct connection and cannot
// reach a peer the authorizer rejects.
type relayGate struct {
	auth       *protocolGate
	relay      peer.ID
	publicOnly bool
}

func (g *relayGate) InterceptPeerDial(p peer.ID) bool {
	if p == g.relay {
		return true
	}
	return g.auth != nil && g.auth.authorize(g.auth.ctx, p.String())
}

func (g *relayGate) InterceptAddrDial(p peer.ID, addr ma.Multiaddr) bool {
	if p == g.relay {
		return !g.publicOnly || publicOnlyRemote(addr)
	}
	if g.auth == nil || !g.auth.authorize(g.auth.ctx, p.String()) {
		return false
	}
	if !hasCircuitComponent(addr) {
		return false
	}
	return !g.publicOnly || publicOnlyRemote(addr)
}

func (g *relayGate) InterceptAccept(network.ConnMultiaddrs) bool { return false }

func (g *relayGate) InterceptSecured(dir network.Direction, p peer.ID, cm network.ConnMultiaddrs) bool {
	if dir == network.DirInbound {
		return false
	}
	if g.auth == nil || !g.auth.authorize(g.auth.ctx, p.String()) {
		return false
	}
	if p == g.relay {
		return !g.publicOnly || (publicOnlyRemote(cm.RemoteMultiaddr()) && publicOnlyLocal(cm.LocalMultiaddr()))
	}
	if !hasCircuitComponent(cm.RemoteMultiaddr()) {
		return false
	}
	return !g.publicOnly || (publicOnlyRemote(cm.RemoteMultiaddr()) && publicOnlyLocal(cm.LocalMultiaddr()))
}

func (g *relayGate) InterceptUpgraded(c network.Conn) (bool, control.DisconnectReason) {
	if c.Stat().Direction == network.DirInbound {
		return false, 0
	}
	p := c.RemotePeer()
	if g.auth == nil || !g.auth.authorize(g.auth.ctx, p.String()) {
		return false, 0
	}
	if p == g.relay {
		if g.publicOnly && !(publicOnlyRemote(c.RemoteMultiaddr()) && publicOnlyLocal(c.LocalMultiaddr())) {
			return false, 0
		}
		return true, 0
	}
	if !hasCircuitComponent(c.RemoteMultiaddr()) {
		return false, 0
	}
	if g.publicOnly && !(publicOnlyRemote(c.RemoteMultiaddr()) && publicOnlyLocal(c.LocalMultiaddr())) {
		return false, 0
	}
	return true, 0
}

// ---- endpoint classification ----

type endpointKind int

const (
	endpointNone endpointKind = iota
	endpointIP
	endpointDNS
)

func transportEndpoint(a ma.Multiaddr) (net.IP, endpointKind) {
	if a == nil {
		return nil, endpointNone
	}
	var (
		ip   net.IP
		kind = endpointNone
	)
	for _, p := range a.Protocols() {
		switch p.Code {
		case ma.P_IP4, ma.P_IP6:
			if ip != nil {
				continue
			}
			v, err := a.ValueForProtocol(p.Code)
			if err != nil {
				return nil, endpointNone
			}
			parsed := net.ParseIP(v)
			if parsed == nil {
				return nil, endpointNone
			}
			ip, kind = parsed, endpointIP
		case ma.P_DNS, ma.P_DNS4, ma.P_DNS6, ma.P_DNSADDR:
			if kind == endpointNone {
				kind = endpointDNS
			}
		}
	}
	return ip, kind
}

func isPublicIP(ip net.IP) bool {
	if ip == nil ||
		ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return false
		}
		if v4[0] == 0 || v4[0] >= 240 {
			return false
		}
	} else {
		v6 := ip.To16()
		if v6 == nil || v6[0] == 0xfe && v6[1]&0xc0 == 0xc0 ||
			v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x0d && v6[3] == 0xb8 ||
			v6[0] == 0x01 && v6[1] == 0 && v6[2] == 0 && v6[3] == 0 && v6[4] == 0 && v6[5] == 0 && v6[6] == 0 && v6[7] == 0 ||
			v6[0] == 0 && v6[1] == 0x64 && v6[2] == 0xff && v6[3] == 0x9b {
			return false
		}
	}
	return true
}

func publicOnlyRemote(a ma.Multiaddr) bool {
	ip, kind := transportEndpoint(a)
	if kind != endpointIP {
		return false
	}
	return isPublicIP(ip)
}

func publicOnlyLocal(a ma.Multiaddr) bool {
	ip, kind := transportEndpoint(a)
	switch kind {
	case endpointIP:
		return !ip.IsLoopback() && !ip.IsUnspecified()
	case endpointNone:
		return hasCircuitComponent(a)
	default:
		return false
	}
}

func hasCircuitComponent(m ma.Multiaddr) bool {
	if m == nil {
		return false
	}
	for _, p := range m.Protocols() {
		if p.Code == ma.P_CIRCUIT {
			return true
		}
	}
	return false
}

var _ connmgr.ConnectionGater = (*mainGate)(nil)
var _ connmgr.ConnectionGater = (*relayGate)(nil)
