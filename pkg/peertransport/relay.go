package peertransport

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	relayclient "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	relaypb "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/pb"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	ma "github.com/multiformats/go-multiaddr"

	"atoll/pkg/peerauth"
)

const (
	relayReservationTTL  = 30 * time.Minute
	relayDuration        = 30 * time.Minute
	relayDataLimit       = 256 << 20 // 256 MiB per direction, >= 64 MiB requirement
	relayMaxReservations = 64
	relayMaxCircuits     = 8
	relayReserveTimeout  = 20 * time.Second
)

// Relay endpoints require TCP independently of the direct candidate set.
func preferTCP(addrs []ma.Multiaddr) []ma.Multiaddr {
	tcp := make([]ma.Multiaddr, 0, len(addrs))
	for _, address := range addrs {
		if tcpAddress(address) {
			tcp = append(tcp, address)
		}
	}
	return tcp
}

// ReserveRelay holds (or refreshes) a CircuitRelay v2 reservation on the main
// host for the given infrastructure relay, and returns the reservation expiry.
// The caller (node/client) manages TTL renewal and retry; this only issues one
// reservation.
func (r *Runtime) ReserveRelay(ctx context.Context, infra peerauth.Infrastructure) (time.Time, error) {
	operation, finish, err := r.operationContext(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer finish()
	ctx = operation
	ai, err := infraAddrInfo(infra)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %v", ErrInfrastructureInvalid, err)
	}
	if !r.auth.authorize(ctx, infra.PeerID) {
		return time.Time{}, ErrPeerUnauthorized
	}
	rctx, cancel := context.WithTimeout(ctx, relayReserveTimeout)
	defer cancel()
	conn, err := r.prepareTCPInfrastructure(rctx, infra)
	if err != nil {
		return time.Time{}, err
	}
	selected := &connectionHost{Host: r.mainHost, observe: r.cfg.Observe, connection: func(ctx context.Context, remote peer.ID) (network.Conn, error) {
		if remote != ai.ID || !r.auth.authorize(ctx, remote.String()) {
			return nil, ErrPeerUnauthorized
		}
		if err := verifyStreamPeer(conn, ai.ID, infra.PublicKey); err != nil {
			return nil, ErrInfrastructureInvalid
		}
		return conn, nil
	}}
	bounded := &reservationHost{Host: selected}
	defer bounded.finish()
	ai.Addrs = preferTCP(ai.Addrs)
	res, err := relayclient.Reserve(rctx, bounded, ai)
	if err != nil {
		if rctx.Err() != nil {
			return time.Time{}, rctx.Err()
		}
		var reservation relayclient.ReservationError
		if errors.As(err, &reservation) {
			switch reservation.Status {
			case relaypb.Status_PERMISSION_DENIED:
				return time.Time{}, fmt.Errorf("%w: relay denied reservation", ErrPeerUnauthorized)
			case relaypb.Status_MALFORMED_MESSAGE:
				return time.Time{}, fmt.Errorf("%w: malformed relay reservation", ErrInfrastructureInvalid)
			}
		}
		return time.Time{}, fmt.Errorf("peertransport: relay reservation: %w", err)
	}
	return res.Expiration, nil
}

// EnableRelay starts the finite CircuitRelay v2 hop service on the main host.
// Only the center role calls this; ordinary nodes only call ReserveRelay. The
// ACL admits a peer through the authoritative protocol gate, so a newly
// registered (but not yet published) node or client can reserve, and a revoked
// peer is rejected immediately, without depending on a stale directory
// snapshot. Limits are finite: reservation cap, per-peer circuit cap, a
// per-circuit duration and a per-direction data cap, backed by the host's
// finite resource manager.
func (r *Runtime) EnableRelay() error {
	r.lifeMu.Lock()
	defer r.lifeMu.Unlock()
	if r.closed {
		return errRuntimeClosed
	}
	if r.relaySvc != nil {
		return nil
	}
	res := relay.DefaultResources()
	res.Limit = &relay.RelayLimit{Duration: relayDuration, Data: relayDataLimit}
	res.ReservationTTL = relayReservationTTL
	res.MaxReservations = relayMaxReservations
	res.MaxCircuits = relayMaxCircuits
	selected := &connectionHost{Host: r.mainHost, observe: r.cfg.Observe, connection: func(ctx context.Context, remote peer.ID) (network.Conn, error) {
		return selectedTCP(ctx, r.mainHost, r.auth, remote)
	}}
	svc, err := relay.New(selected,
		relay.WithACL(&runtimeRelayACL{auth: r.auth}),
		relay.WithResources(res),
	)
	if err != nil {
		return fmt.Errorf("peertransport: enable relay: %w", err)
	}
	r.relaySvc = svc
	return nil
}

// runtimeRelayACL admits relay reservations and traversal through the
// authoritative protocol gate (online authorizer when installed, allow-set
// otherwise), so relay rights follow the current authorization state rather
// than the last directory snapshot.
type runtimeRelayACL struct {
	auth *protocolGate
}

func (a *runtimeRelayACL) AllowReserve(p peer.ID, address ma.Multiaddr) bool {
	return tcpAddress(address) && a.auth.authorize(a.auth.ctx, p.String())
}

func (a *runtimeRelayACL) AllowConnect(src peer.ID, address ma.Multiaddr, dest peer.ID) bool {
	return tcpAddress(address) && a.auth.authorize(a.auth.ctx, src.String()) && a.auth.authorize(a.auth.ctx, dest.String())
}

// infraAddrInfo validates an infrastructure descriptor and returns a libp2p
// AddrInfo for dialing the relay.
func infraAddrInfo(infra peerauth.Infrastructure) (peer.AddrInfo, error) {
	if err := peerauth.ValidateIdentity(infra.PeerID, infra.PublicKey); err != nil {
		return peer.AddrInfo{}, errors.New("peertransport: invalid relay identity")
	}
	id, err := peer.Decode(infra.PeerID)
	if err != nil {
		return peer.AddrInfo{}, fmt.Errorf("peertransport: invalid relay PeerID: %w", err)
	}
	normalized, err := peerauth.NormalizeAddresses(infra.Addresses, false)
	if err != nil {
		return peer.AddrInfo{}, fmt.Errorf("peertransport: invalid relay addresses: %w", err)
	}
	addrs := make([]ma.Multiaddr, 0, len(normalized))
	for _, s := range normalized {
		a, err := ma.NewMultiaddr(s)
		if err != nil {
			return peer.AddrInfo{}, fmt.Errorf("peertransport: invalid relay address %s: %w", s, err)
		}
		addrs = append(addrs, a)
	}
	return peer.AddrInfo{ID: id, Addrs: addrs}, nil
}

// circuitAddrInfo builds the CircuitRelay v2 dial address for target via the
// given relay infrastructure:
// <relayAddr>/p2p/<relayID>/p2p-circuit/p2p/<targetID>.
func circuitAddrInfo(infra peerauth.Infrastructure, target peer.ID) (peer.AddrInfo, error) {
	relayAI, err := infraAddrInfo(infra)
	if err != nil {
		return peer.AddrInfo{}, err
	}
	bases := preferTCP(relayAI.Addrs)
	if len(bases) == 0 {
		return peer.AddrInfo{}, fmt.Errorf("%w: relay needs a TCP endpoint", ErrInfrastructureInvalid)
	}
	addrs := make([]ma.Multiaddr, 0, len(bases))
	for _, base := range bases {
		if _, err := base.ValueForProtocol(ma.P_P2P); err != nil {
			base = ma.Join(base, ma.StringCast("/p2p/"+relayAI.ID.String()))
		}
		full := ma.Join(base, ma.StringCast("/p2p-circuit"), ma.StringCast("/p2p/"+target.String()))
		addrs = append(addrs, full)
	}
	return peer.AddrInfo{ID: target, Addrs: addrs}, nil
}
