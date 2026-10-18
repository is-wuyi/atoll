package peertransport

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	ma "github.com/multiformats/go-multiaddr"
)

// TransferStats describes one transport path used by the prototype. `Path` is
// the requested policy, `Effective` is the path actually used ("direct" or
// "circuit"), so a silent fallback can never happen unnoticed.
type TransferStats struct {
	Path                string `json:"path"`
	Effective           string `json:"effective"`
	RemotePeer          string `json:"remote_peer"`
	RemoteMultiaddr     string `json:"remote_multiaddr"`
	Limited             bool   `json:"limited"`   // true for CircuitRelay v2 connections
	Secure              bool   `json:"secure"`    // identity-locked secure handshake verified (not at-rest encryption)
	FallbackUsed        bool   `json:"fallback_used"`
	PayloadBytesWritten int64  `json:"payload_bytes_written"`
	PayloadBytesRead    int64  `json:"payload_bytes_read"`
}

const (
	pathDirect     = "direct"
	pathCircuit    = "circuit"
	maCircuitProto = "/p2p-circuit"
)

// countingConn wraps a libp2p stream as a net.Conn and counts payload bytes
// traversing it. For circuit-relayed connections these bytes are, by
// construction, the bytes carried by the relay circuit.
type countingConn struct {
	network.Stream
	peerID  peer.ID
	written atomic.Int64
	read    atomic.Int64
	circuit bool
	stats   *TransferStats
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Stream.Read(p)
	c.read.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Stream.Write(p)
	c.written.Add(int64(n))
	return n, err
}

func (c *countingConn) LocalAddr() net.Addr  { return maNetAddr{c.Stream.Conn().LocalMultiaddr()} }
func (c *countingConn) RemoteAddr() net.Addr { return maNetAddr{c.Stream.Conn().RemoteMultiaddr()} }

// maNetAddr adapts a multiaddr to net.Addr for net/http bookkeeping.
type maNetAddr struct{ ma.Multiaddr }

func (a maNetAddr) Network() string { return "libp2p" }
func (a maNetAddr) String() string  { return a.Multiaddr.String() }

// PeerID returns the cryptographically verified end-to-end remote peer.
func (c *countingConn) PeerID() peer.ID { return c.peerID }

// Snapshot transfers current counters into the bound TransferStats.
func (c *countingConn) Snapshot() {
	if c.stats != nil {
		c.stats.PayloadBytesWritten = c.written.Load()
		c.stats.PayloadBytesRead = c.read.Load()
	}
}

// PeerRegistry maps an active connection's RemoteAddr string to the
// cryptographically verified PeerID of the remote end. net/http handlers use
// it to learn which authorized peer issued a request (r.RemoteAddr lookup),
// without trusting any client-supplied header.
type PeerRegistry struct {
	mu sync.RWMutex
	m  map[string]peer.ID
}

// NewPeerRegistry creates an empty registry.
func NewPeerRegistry() *PeerRegistry { return &PeerRegistry{m: map[string]peer.ID{}} }

// Observe records the connection (call from http.Server ConnState on
// StateNew/StateActive).
func (r *PeerRegistry) Observe(c net.Conn) {
	if pc, ok := c.(*countingConn); ok {
		r.mu.Lock()
		r.m[c.RemoteAddr().String()] = pc.peerID
		r.mu.Unlock()
	}
}

// Forget drops the connection entry (call from ConnState on StateClosed).
func (r *PeerRegistry) Forget(c net.Conn) {
	r.mu.Lock()
	delete(r.m, c.RemoteAddr().String())
	r.mu.Unlock()
}

// FromRemoteAddr returns the verified PeerID for a request RemoteAddr.
func (r *PeerRegistry) FromRemoteAddr(addr string) (peer.ID, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.m[addr]
	return id, ok
}
