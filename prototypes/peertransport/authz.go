package peertransport

import (
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
type ConnGater struct {
	allow *Allowlist // nil = allow all (only used by the control role)
	log   interface{ Printf(format string, args ...any) }
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

// InterceptPeerDial gates outbound dials by PeerID.
func (g *ConnGater) InterceptPeerDial(p peer.ID) bool { return g.permitted(p) }

// InterceptAddrDial gates outbound dials by PeerID and target address.
func (g *ConnGater) InterceptAddrDial(p peer.ID, _ ma.Multiaddr) bool { return g.permitted(p) }

// InterceptAccept cannot see the PeerID before the security handshake, so it
// always passes; the decision is made in InterceptSecured.
func (g *ConnGater) InterceptAccept(_ network.ConnMultiaddrs) bool { return true }

// InterceptSecured gates inbound connections once the remote PeerID is
// cryptographically verified by the security handshake.
func (g *ConnGater) InterceptSecured(_ network.Direction, p peer.ID, _ network.ConnMultiaddrs) bool {
	ok := g.permitted(p)
	if !ok && g.log != nil {
		g.log.Printf("conn-gater: rejected inbound connection from unauthorized peer %s", p)
	}
	return ok
}

// InterceptUpgraded is the final check after muxer negotiation.
func (g *ConnGater) InterceptUpgraded(c network.Conn) (bool, control.DisconnectReason) {
	return g.permitted(c.RemotePeer()), 0
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
