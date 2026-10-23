package peertransport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	relayclient "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"

	ma "github.com/multiformats/go-multiaddr"
)

// PeerConfig configures a storage peer.
type PeerConfig struct {
	DataDir string // identity + object store live here
	// EnableQUIC additionally listens on QUIC (TCP is always on).
	EnableQUIC bool
	// Peers is the end-to-end service allowlist (storage peers that may call
	// us). The relay and control IDs are added to the connection gater only.
	Peers            *Allowlist
	Control          *peer.AddrInfo
	Relay            *peer.AddrInfo
	MaxObjectBytes   int64
	TransferDeadline time.Duration
	// DirectTimeout bounds each direct dial attempt in DirectThenRelay.
	DirectTimeout time.Duration
	// SkipRelayReservation skips the startup relay reservation (used for
	// unauthorized test peers whose reservation would be denied anyway).
	SkipRelayReservation bool
	Logger               *log.Logger
	// WAN mode (zero values = historical loopback behavior):
	ListenIP     string        // listen IP, e.g. "0.0.0.0" for cross-machine runs
	AnnounceAddrs []ma.Multiaddr // force-announced public endpoint(s) behind NAT
	ListenPort   int
}

// StoragePeer is one storage node of the prototype: a persistent Ed25519
// identity, a libp2p host (TCP + optional QUIC, Noise, circuit v2 client,
// hole punching), an allowlist-gated object service served by an unmodified
// net/http server over libp2p streams, and an HTTP client factory with
// explicit direct / forced-relay / direct-then-relay policies.
type StoragePeer struct {
	Host  host.Host
	ID    peer.ID
	Store *ObjectStore
	lis   net.Listener
	reg   *PeerRegistry
	srv   *http.Server
	log   *log.Logger
	// gater is the peer's connection-level allowlist gate.
	gater *ConnGater
	// control/relay identity ids allowed at the connection-gater level only.
	cfg PeerConfig
}

// NewStoragePeer starts the peer's host and object service.
func NewStoragePeer(ctx context.Context, cfg PeerConfig) (*StoragePeer, error) {
	id, err := LoadOrCreateIdentity(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	if cfg.Peers == nil {
		cfg.Peers = NewAllowlist()
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	store, err := NewObjectStore(cfg.DataDir+"/objects", cfg.MaxObjectBytes, cfg.TransferDeadline)
	if err != nil {
		return nil, err
	}
	p := &StoragePeer{ID: id.ID, Store: store, log: cfg.Logger, cfg: cfg}

	// Connection-level allowlist: service peers + the relay/control
	// identities (a CircuitRelay v2 connection physically arrives from the
	// relay; the end-to-end peer check happens again at the listener).
	gaterAllow := cfg.Peers.Clone()
	var controlID, relayID peer.ID
	if cfg.Control != nil {
		controlID = cfg.Control.ID
		gaterAllow.Add(controlID)
	}
	if cfg.Relay != nil {
		relayID = cfg.Relay.ID
		gaterAllow.Add(relayID)
	}
	gater := NewConnGater(gaterAllow)
	p.gater = gater

	h, err := newHost(ctx, HostOptions{
		Priv:          id.Priv,
		ListenTCP:     true,
		ListenQUIC:    cfg.EnableQUIC,
		Gater:         gater,
		HolePunch:     true,
		Logger:        cfg.Logger,
		ListenIP:      cfg.ListenIP,
		ListenPort:    cfg.ListenPort,
		AnnounceAddrs: cfg.AnnounceAddrs,
	})
	if err != nil {
		return nil, err
	}
	p.Host = h

	lis, reg, err := NewHTTPListener(ctx, h, cfg.Peers)
	if err != nil {
		h.Close()
		return nil, err
	}
	p.lis = lis
	p.reg = reg

	// Hold a reservation on the relay so other peers can reach us via
	// CircuitRelay v2. This is the standard circuit v2 flow: destinations
	// keep a live reservation at the hop; the hop then relays connections
	// over it (no discovery, no DHT — the relay endpoint is configured
	// explicitly).
	//
	// The first attempt still gates startup (an unreachable relay is an
	// operator-visible failure, matching the historical contract), but a
	// transient miss no longer kills the peer forever: a background loop
	// retries every 30s until the reservation lands. Real WAN runs showed
	// one-shot startup reservations failing on transient dial loss, leaving
	// the peer without a relay path until a manual restart.
	if cfg.Relay != nil && !cfg.SkipRelayReservation {
		rctx, rcancel := context.WithTimeout(ctx, 20*time.Second)
		_, resErr := relayclient.Reserve(rctx, h, *cfg.Relay)
		rcancel()
		if resErr != nil {
			p.log.Printf("relay reservation at %s failed (%v); retrying in background", cfg.Relay.ID, resErr)
			go p.renewReservationLoop(ctx, *cfg.Relay)
		} else {
			p.log.Printf("relay reservation held at %s", cfg.Relay.ID)
			go p.renewReservationLoop(ctx, *cfg.Relay)
		}
	}
	if !cfg.SkipRelayReservation && cfg.Relay == nil {
		p.log.Printf("no relay configured; peer is direct-reachable only")
	}

	p.srv = &http.Server{
		Handler:           store.Handler(),
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
	go func() { _ = p.srv.Serve(lis) }()
	return p, nil
}

// renewReservationLoop keeps a CircuitRelay v2 reservation alive: every 30s it
// (re)issues a Reserve call — idempotent at the hop for holders, the only path
// to a reservation after a transient startup failure. Stops when the peer
// context ends; errors are logged, never fatal (direct transport keeps
// working without a relay path).
func (p *StoragePeer) renewReservationLoop(ctx context.Context, relay peer.AddrInfo) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			_, err := relayclient.Reserve(rctx, p.Host, relay)
			cancel()
			if err != nil {
				p.log.Printf("relay reservation refresh at %s failed: %v", relay.ID, err)
				continue
			}
			p.log.Printf("relay reservation held at %s", relay.ID)
		}
	}
}

// AllowInfraPeer authorizes an infrastructure peer (e.g., an additional
// CircuitRelay v2 relay) at this peer's connection gater so the peer may dial
// it and accept connections it terminates, in both directions. It does NOT
// grant service rights: the stream-level allowlist is unchanged.
func (p *StoragePeer) AllowInfraPeer(id peer.ID) {
	if p.gater != nil {
		p.gater.Allow(id)
	}
}

// AddrInfo returns the peer's current (mutable) direct endpoints together
// with its stable PeerID.
func (p *StoragePeer) AddrInfo() peer.AddrInfo {
	return peer.AddrInfo{ID: p.ID, Addrs: p.Host.Addrs()}
}

// Endpoints returns the current endpoints as strings (mutable; the PeerID is
// the stable half of the pair).
func (p *StoragePeer) Endpoints() []string {
	out := make([]string, 0, 4)
	for _, a := range p.Host.Addrs() {
		out = append(out, a.String())
	}
	return out
}

// Dial prepares an HTTP client toward the expected peer with an explicit
// transport policy. directAddrs are the mutable endpoints of the target as
// last announced to the control node (may be stale or empty).
func (p *StoragePeer) Dial(expected peer.ID, policy DialPolicy, directAddrs []ma.Multiaddr) (*http.Client, *DialConfig) {
	d := &DialConfig{
		Host:          p.Host,
		Expected:      expected,
		DirectAddrs:   directAddrs,
		Relay:         p.cfg.Relay,
		Policy:        policy,
		DirectTimeout: p.cfg.DirectTimeout,
		logf:          p.log.Printf,
	}
	return d.NewHTTPClient(), d
}

// RegisterWithControl dials the control node and announces the peer's current
// endpoints. The control plane is the explicitly configured bootstrap endpoint
// (production: the master's public address) — direct by definition; a relay
// fallback applies only when one is configured.
func (p *StoragePeer) RegisterWithControl(ctx context.Context, control peer.AddrInfo) error {
	policy := PolicyDirect
	if p.cfg.Relay != nil {
		policy = PolicyDirectThenRelay
	}
	d := &DialConfig{
		Host:          p.Host,
		Expected:      control.ID,
		DirectAddrs:   control.Addrs,
		Relay:         p.cfg.Relay,
		Policy:        policy,
		DirectTimeout: p.cfg.DirectTimeout,
		logf:          p.log.Printf,
	}
	client := d.NewHTTPClient()
	body, _ := json.Marshal(map[string]any{"addrs": p.Endpoints()})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://control/register", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("peertransport: register with control: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("peertransport: control register: HTTP %d: %s", resp.StatusCode, string(b))
	}
	p.log.Printf("registered with control %s; endpoints=%v", control.ID, p.Endpoints())
	return nil
}

// FetchControlState retrieves the control registry (authorized list, peers,
// relay endpoint) over the control connection.
func (p *StoragePeer) FetchControlState(ctx context.Context, control peer.AddrInfo) (map[string]any, error) {
	policy := PolicyDirect
	if p.cfg.Relay != nil {
		policy = PolicyDirectThenRelay
	}
	d := &DialConfig{
		Host:          p.Host,
		Expected:      control.ID,
		DirectAddrs:   control.Addrs,
		Relay:         p.cfg.Relay,
		Policy:        policy,
		DirectTimeout: p.cfg.DirectTimeout,
		logf:          p.log.Printf,
	}
	client := d.NewHTTPClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://control/peers", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("peertransport: control state: HTTP %d: %s", resp.StatusCode, string(b))
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// Close shuts the object service and the host down cleanly.
func (p *StoragePeer) Close() error {
	_ = p.srv.Close()
	_ = p.lis.Close()
	return p.Host.Close()
}
