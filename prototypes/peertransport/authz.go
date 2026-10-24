package peertransport

import (
	"net"
	"sync"

	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	ma "github.com/multiformats/go-multiaddr"
)

// Allowlist is the shared authorization set of PeerIDs. The same set is used
// for connection gating (both dialer and listener side), for stream-level
// end-to-end checks, and for relay ACLs. Unknown peers are always rejected.
type Allowlist struct {
	mu      sync.RWMutex
	allowed map[peer.ID]struct{}
}

// NewAllowlist builds an Allowlist from the given PeerIDs.
func NewAllowlist(ids ...peer.ID) *Allowlist {
	a := &Allowlist{allowed: make(map[peer.ID]struct{}, len(ids))}
	for _, id := range ids {
		a.allowed[id] = struct{}{}
	}
	return a
}

// Add inserts a PeerID.
func (a *Allowlist) Add(id peer.ID) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.allowed[id] = struct{}{}
}

// Contains reports whether the PeerID is authorized.
func (a *Allowlist) Contains(id peer.ID) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, ok := a.allowed[id]
	return ok
}

// IDs returns a snapshot of authorized PeerIDs.
func (a *Allowlist) IDs() []peer.ID {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]peer.ID, 0, len(a.allowed))
	for id := range a.allowed {
		out = append(out, id)
	}
	return out
}

// Clone returns a copy that can be extended without affecting the original.
func (a *Allowlist) Clone() *Allowlist {
	a.mu.RLock()
	defer a.mu.RUnlock()
	c := &Allowlist{allowed: make(map[peer.ID]struct{}, len(a.allowed))}
	for id := range a.allowed {
		c.allowed[id] = struct{}{}
	}
	return c
}

// With returns a new Allowlist containing a plus the given IDs.
func (a *Allowlist) With(ids ...peer.ID) *Allowlist {
	c := a.Clone()
	for _, id := range ids {
		c.Add(id)
	}
	return c
}

// ConnGater implements connmgr.ConnectionGater on top of an Allowlist.
// It gates both outgoing dials and incoming secured connections, so an
// unauthorized peer can neither connect to us nor make us connect to it.
//
// The optional PublicOnly flag adds an address-class gate on top of the
// PeerID allowlist: only REAL public transport endpoints may be dialed or
// accepted. Rejected classes: loopback (127/8, ::1), RFC1918 private,
// CGNAT 100.64.0.0/10, IPv4/IPv6 link-local, IPv6 ULA (fc00::/7), multicast,
// unspecified, and DNS names (the prototype dials explicitly configured
// addresses only and must not resolve names implicitly). CircuitRelay v2
// addresses are judged by their FIRST transport component — the relay hop —
// so a public relay (including the /p2p-circuit dial address) keeps working
// while a loopback/private relay is refused. PublicOnly is off by default;
// the historical loopback behavior is unchanged.
type ConnGater struct {
	allow *Allowlist // nil = allow all (only used by the control role)
	log   interface {
		Printf(format string, args ...any)
	}

	// PublicOnly rejects every non-public transport endpoint in ALL five
	// intercept hooks. It is set by newHost from HostOptions.PublicOnly (the
	// flag flows PeerConfig -> HostOptions -> ConnGater) and must be in place
	// before the host serves traffic.
	PublicOnly bool
}

// NewConnGater builds a ConnectionGater. If allow is nil all connections are
// accepted at the transport level (used by the control role which enforces
// authorization at the HTTP layer so unauthorized peers receive an explicit
// 403 instead of a transport-level rejection).
func NewConnGater(allow *Allowlist) *ConnGater { return &ConnGater{allow: allow} }

// Allow authorizes p at this gater after construction, in both directions
// (outbound dials and inbound secured connections). Intended for
// infrastructure peers — e.g. an additional CircuitRelay v2 relay — that must
// be dialable or may terminate connections here. It grants no service rights:
// the stream-level allowlist is separate.
func (g *ConnGater) Allow(p peer.ID) {
	if g.allow != nil {
		g.allow.Add(p)
	}
}

func (g *ConnGater) permitted(id peer.ID) bool {
	if g.allow == nil {
		return true
	}
	return g.allow.Contains(id)
}

// endpointKind classifies what a multiaddr's transport component is.
type endpointKind int

const (
	endpointNone endpointKind = iota // no transport endpoint at all
	endpointIP                       // a /ip4/ or /ip6/ transport endpoint
	endpointDNS                      // a /dns, /dns4, /dns6 or /dnsaddr name
)

// transportEndpoint returns the FIRST transport component of a. For a
// CircuitRelay v2 address that first component is the RELAY HOP, so judging it
// judges the whole circuit path without mistaking the /p2p-circuit virtual
// part (which carries no IP) for a private endpoint.
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
				continue // the first transport endpoint wins
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

// isPublicIP reports whether ip is a real WAN-routable address: not loopback,
// not RFC1918/ULA private (net.IP.IsPrivate covers both), not CGNAT
// 100.64.0.0/10 (RFC 6598 — Tailscale and carrier-grade NAT live there while
// net.IP still calls it global unicast), not link-local, not multicast, not
// unspecified, and not the reserved 0/8 and 240/4 blocks.
func isPublicIP(ip net.IP) bool {
	if ip == nil ||
		ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 { // CGNAT 100.64.0.0/10
			return false
		}
		if v4[0] == 0 || v4[0] >= 240 { // "this network" / reserved + broadcast
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

// publicOnlyRemote judges a DIAL target or the remote side of a connection:
// the address must carry a real public transport endpoint. DNS names are
// refused outright (they would need an implicit external resolution to be
// judged), and so is any address without a transport component — there is
// nothing to enforce a class on.
func publicOnlyRemote(a ma.Multiaddr) bool {
	ip, kind := transportEndpoint(a)
	if kind != endpointIP {
		return false
	}
	return isPublicIP(ip)
}

// publicOnlyLocal judges the LOCAL side of an accepted/upgraded connection. A
// port-forwarded WAN host legitimately shows a PRIVATE local address (the
// NAT'd LAN interface the packet arrived on), so only loopback and unspecified
// are refused — those mean the connection never left the machine. A circuit
// virtual local endpoint with no transport component is passed through: its
// real endpoints were already judged at dial/accept time, and reading the
// virtual /p2p-circuit form as "local-private" would break every relayed
// connection.
func publicOnlyLocal(a ma.Multiaddr) bool {
	ip, kind := transportEndpoint(a)
	switch kind {
	case endpointIP:
		return !ip.IsLoopback() && !ip.IsUnspecified()
	case endpointNone:
		// Circuit virtual endpoint shape (no IP): the class lives on the
		// transport endpoints inside the circuit path.
		return hasCircuitComponent(a)
	default: // DNS on the local side: not a real interface, refuse
		return false
	}
}

func (g *ConnGater) logReject(format string, args ...any) {
	if g.log != nil {
		g.log.Printf(format, args...)
	}
}

// InterceptPeerDial gates outbound dials by PeerID.
func (g *ConnGater) InterceptPeerDial(p peer.ID) bool { return g.permitted(p) }

// InterceptAddrDial gates outbound dials by PeerID and target address. This is
// the choke point for EVERY dial the swarm makes (libp2p v0.50 filters each
// resolved address here), so endpoints re-learned into the peerstore by
// identify or dialed speculatively by the DCUtR hole-punch service cannot
// materialize as private connections either: PublicOnly is enforced on the
// connection, not on the probe's initial address list.
func (g *ConnGater) InterceptAddrDial(p peer.ID, addr ma.Multiaddr) bool {
	if !g.permitted(p) {
		return false
	}
	if !g.PublicOnly || publicOnlyRemote(addr) {
		return true
	}
	g.logReject("conn-gater: public-only 拒绝拨号 peer=%s addr=%s（非公网端点：loopback/私网/CGNAT/链路本地/DNS 一律禁止）", p, addr)
	return false
}

// InterceptAccept sees an inbound connection BEFORE the security handshake, so
// no PeerID is known yet and only the endpoint classes can be judged: the
// remote must be a real public endpoint (for a relayed connection the actual
// transport peer is the relay hop), the local must not be loopback.
func (g *ConnGater) InterceptAccept(cm network.ConnMultiaddrs) bool {
	if !g.PublicOnly {
		return true
	}
	if publicOnlyRemote(cm.RemoteMultiaddr()) && publicOnlyLocal(cm.LocalMultiaddr()) {
		return true
	}
	g.logReject("conn-gater: public-only 拒绝入站连接 remote=%s local=%s（握手前仅按端点类别判定）",
		cm.RemoteMultiaddr(), cm.LocalMultiaddr())
	return false
}

// InterceptSecured gates a connection once the remote PeerID is
// cryptographically verified: the allowlist applies in both directions and, in
// PublicOnly mode, the connection's ACTUAL endpoints are judged again. For an
// outbound CircuitRelay v2 connection the remote is the circuit address over
// the public relay hop and the local is the real transport source address —
// the virtual circuit form is never misread as local-private here.
func (g *ConnGater) InterceptSecured(dir network.Direction, p peer.ID, cm network.ConnMultiaddrs) bool {
	ok := g.permitted(p)
	if ok && g.PublicOnly {
		ok = publicOnlyRemote(cm.RemoteMultiaddr()) && publicOnlyLocal(cm.LocalMultiaddr())
	}
	if !ok {
		if g.PublicOnly {
			g.logReject("conn-gater: 拒绝 %s 连接 peer=%s remote=%s local=%s（allowlist 或 public-only 端点检查未通过）",
				dir, p, cm.RemoteMultiaddr(), cm.LocalMultiaddr())
		} else {
			g.logReject("conn-gater: rejected inbound connection from unauthorized peer %s", p)
		}
	}
	return ok
}

// InterceptUpgraded is the final check after muxer negotiation: allowlist by
// PeerID plus, in PublicOnly mode, the actual endpoints of the connection —
// the same rules as InterceptSecured. In libp2p v0.50 every fully upgraded
// connection (inbound and outbound, direct and relayed) passes through here.
func (g *ConnGater) InterceptUpgraded(c network.Conn) (bool, control.DisconnectReason) {
	if !g.permitted(c.RemotePeer()) {
		return false, 0
	}
	if g.PublicOnly && !(publicOnlyRemote(c.RemoteMultiaddr()) && publicOnlyLocal(c.LocalMultiaddr())) {
		g.logReject("conn-gater: public-only 拒绝已升级连接 peer=%s remote=%s local=%s",
			c.RemotePeer(), c.RemoteMultiaddr(), c.LocalMultiaddr())
		return false, 0
	}
	return true, 0
}

// RelayACL implements the circuit relay v2 relay.ACLFilter on top of an
// Allowlist: only peers of this experiment may reserve on or traverse the
// relay, and only toward other authorized peers.
type RelayACL struct {
	allow *Allowlist
}

// NewRelayACL builds a relay ACL from an Allowlist.
func NewRelayACL(allow *Allowlist) RelayACL { return RelayACL{allow: allow} }

// AllowReserve accepts a reservation request from p only if p is authorized.
func (a RelayACL) AllowReserve(p peer.ID, _ ma.Multiaddr) bool { return a.allow.Contains(p) }

// AllowConnect accepts a relayed connection only if both source and
// destination are authorized peers of this experiment.
func (a RelayACL) AllowConnect(src peer.ID, _ ma.Multiaddr, dest peer.ID) bool {
	return a.allow.Contains(src) && a.allow.Contains(dest)
}
