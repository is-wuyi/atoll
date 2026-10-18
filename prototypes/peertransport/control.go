package peertransport

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	ma "github.com/multiformats/go-multiaddr"
)

// ControlConfig configures the bootstrap / control role.
type ControlConfig struct {
	DataDir string
	// Authorized is the set of storage peers allowed to register. Peers not
	// in this set receive an explicit 403 (the control host accepts
	// connections from anyone precisely so unauthorized peers can be told
	// they are unauthorized instead of just failing to connect).
	Authorized *Allowlist
	// RelayAddrInfo is advertised to registering peers.
	RelayAddrInfo *peer.AddrInfo
	Logger        *log.Logger
}

// RegisteredPeer is one entry of the endpoint registry: a stable PeerID
// mapped to its CURRENT mutable endpoints. Endpoints change every run; the
// PeerID never does (identity survives restarts).
type RegisteredPeer struct {
	PeerID      string   `json:"peer_id"`
	Addrs       []string `json:"addrs"`
	LastSeenRFC string   `json:"last_seen"`
}

// ControlNode is the bootstrap/control role: it hands out the peer registry
// (PeerID -> current endpoints), the authorization allowlist and the relay
// endpoint to authorized storage peers.
type ControlNode struct {
	Host  host.Host
	cfg   ControlConfig
	reg   *PeerRegistry
	mu    sync.RWMutex
	peers map[peer.ID]RegisteredPeer
	srv   *http.Server
	lis   net.Listener
	log   *log.Logger
}

// NewControlNode starts the control host and its HTTP service over libp2p.
func NewControlNode(ctx context.Context, cfg ControlConfig) (*ControlNode, error) {
	id, err := LoadOrCreateIdentity(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	// No connection gater: control accepts connections from anyone so that
	// unauthorized peers get an explicit HTTP 403. Service-level
	// authorization is enforced in the register handler.
	h, err := newHost(ctx, HostOptions{
		Priv:       id.Priv,
		ListenTCP:  true,
		ListenQUIC: true,
		Logger:     cfg.Logger,
	})
	if err != nil {
		return nil, err
	}
	lis, reg, err := NewHTTPListener(ctx, h, nil)
	if err != nil {
		h.Close()
		return nil, err
	}
	c := &ControlNode{
		Host:  h,
		cfg:   cfg,
		reg:   reg,
		peers: map[peer.ID]RegisteredPeer{},
		lis:   lis,
		log:   cfg.Logger,
	}
	if c.log == nil {
		c.log = log.Default()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", c.handleRegister)
	mux.HandleFunc("GET /peers", c.handlePeers)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	c.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ConnState: func(conn net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				reg.Observe(conn)
			case http.StateClosed:
				reg.Forget(conn)
			}
		},
	}
	go func() { _ = c.srv.Serve(lis) }()
	if c.log != nil {
		c.log.Printf("control node started id=%s addrs=%v", h.ID(), h.Addrs())
	}
	return c, nil
}

// AddrInfo returns the control node's current endpoints.
func (c *ControlNode) AddrInfo() peer.AddrInfo {
	return peer.AddrInfo{ID: c.Host.ID(), Addrs: c.Host.Addrs()}
}

// maxRegisterBodyBytes bounds a registration announce. A legitimate announce
// is a handful of multiaddr strings; the cap keeps even an authorized peer
// from streaming unbounded bytes into the control plane.
const maxRegisterBodyBytes = 64 << 10

// handleRegister authenticates the caller from the connection's verified
// PeerID (never from a header) and stores its mutable endpoints.
func (c *ControlNode) handleRegister(w http.ResponseWriter, r *http.Request) {
	caller, ok := c.reg.FromRemoteAddr(r.RemoteAddr)
	if !ok {
		httpError(w, http.StatusUnauthorized, "caller identity unavailable")
		return
	}
	if !c.cfg.Authorized.Contains(caller) {
		c.log.Printf("control: registration DENIED for unauthorized peer %s", caller)
		httpError(w, http.StatusForbidden, "peer not authorized to join: "+caller.String())
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRegisterBodyBytes)
	var body struct {
		Addrs []string `json:"addrs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			httpError(w, http.StatusRequestEntityTooLarge, "register body too large")
			return
		}
		httpError(w, http.StatusBadRequest, "bad body: "+err.Error())
		return
	}
	addrs := make([]ma.Multiaddr, 0, len(body.Addrs))
	for _, s := range body.Addrs {
		a, err := ma.NewMultiaddr(s)
		if err != nil {
			httpError(w, http.StatusBadRequest, "bad addr "+s+": "+err.Error())
			return
		}
		addrs = append(addrs, a)
	}
	c.mu.Lock()
	c.peers[caller] = RegisteredPeer{
		PeerID:      caller.String(),
		Addrs:       body.Addrs,
		LastSeenRFC: time.Now().UTC().Format(time.RFC3339),
	}
	c.mu.Unlock()
	c.log.Printf("control: registered peer %s endpoints=%v", caller, body.Addrs)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"registered": true, "peer_id": caller.String()})
}

func (c *ControlNode) handlePeers(w http.ResponseWriter, r *http.Request) {
	caller, ok := c.reg.FromRemoteAddr(r.RemoteAddr)
	if !ok {
		httpError(w, http.StatusUnauthorized, "caller identity unavailable")
		return
	}
	if !c.cfg.Authorized.Contains(caller) {
		httpError(w, http.StatusForbidden, "peer not authorized")
		return
	}
	c.mu.RLock()
	peers := make([]RegisteredPeer, 0, len(c.peers))
	for _, p := range c.peers {
		peers = append(peers, p)
	}
	c.mu.RUnlock()
	auth := make([]string, 0)
	for _, id := range c.cfg.Authorized.IDs() {
		auth = append(auth, id.String())
	}
	resp := map[string]any{"peers": peers, "authorized": auth}
	if c.cfg.RelayAddrInfo != nil {
		resp["relay"] = NewAddrInfoJSON(*c.cfg.RelayAddrInfo)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// AddrInfoJSON is a JSON-friendly AddrInfo.
type AddrInfoJSON struct {
	ID    string   `json:"id"`
	Addrs []string `json:"addrs"`
}

// NewAddrInfoJSON converts a peer.AddrInfo to its JSON form.
func NewAddrInfoJSON(ai peer.AddrInfo) AddrInfoJSON {
	addrs := make([]string, 0, len(ai.Addrs))
	for _, a := range ai.Addrs {
		addrs = append(addrs, a.String())
	}
	return AddrInfoJSON{ID: ai.ID.String(), Addrs: addrs}
}

// Close shuts the control service down.
func (c *ControlNode) Close() error {
	_ = c.srv.Close()
	_ = c.lis.Close()
	return c.Host.Close()
}
