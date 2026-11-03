package peertransport

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/p2p/protocol/autonatv2"
	"github.com/libp2p/go-libp2p/p2p/protocol/autonatv2/pb"
	"github.com/libp2p/go-libp2p/p2p/protocol/holepunch"
	ma "github.com/multiformats/go-multiaddr"
)

func runtimeErrorKind(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, ErrPeerUnauthorized):
		return "unauthorized"
	case errors.Is(err, ErrInfrastructureInvalid):
		return "invalid_infrastructure"
	case errors.Is(err, errRuntimeClosed):
		return "closed"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "network_timeout"
	}
	return "transport_error"
}

type probeEvents struct{ observe func(RuntimeEvent) }

func (p *probeEvents) CompletedRequest(result autonatv2.EventDialRequestCompleted) {
	if p.observe == nil {
		return
	}
	event := RuntimeEvent{Time: time.Now().UTC(), Kind: "autonat_server", Success: result.ResponseStatus == pb.DialResponse_OK && result.DialStatus == pb.DialStatus_OK, ErrorKind: runtimeErrorKind(result.Error), ProbeStatus: result.ResponseStatus.String() + ":" + result.DialStatus.String()}
	if result.DialedAddr != nil {
		event.Candidates = []string{result.DialedAddr.String()}
	}
	if !event.Success && event.ErrorKind == "" {
		event.ErrorKind = "probe_unsuccessful"
	}
	p.observe(event)
}
func (p *probeEvents) ClientCompletedRequest(requests []autonatv2.Request, result autonatv2.Result, err error) {
	if p.observe == nil {
		return
	}
	event := RuntimeEvent{Time: time.Now().UTC(), Kind: "autonat_client", Success: err == nil && result.Reachability == network.ReachabilityPublic, ErrorKind: runtimeErrorKind(err), Reachability: result.Reachability.String()}
	for _, request := range requests {
		event.Candidates = append(event.Candidates, request.Addr.String())
	}
	if !event.Success && event.ErrorKind == "" {
		event.ErrorKind = "probe_not_public"
	}
	p.observe(event)
}

type traversalEvents struct {
	observe func(RuntimeEvent)
	metrics holepunch.MetricsTracer
}

// This callback supplies the actual connection used by the DCUtR attempt;
// picking an arbitrary concurrently connected peer would misattribute success.
func (t *traversalEvents) HolePunchFinished(side string, attempt int, remote, local []ma.Multiaddr, direct network.ConnMultiaddrs) {
	if t.metrics != nil {
		t.metrics.HolePunchFinished(side, attempt, remote, local, direct)
	}
	if t.observe == nil {
		return
	}
	event := RuntimeEvent{Time: time.Now().UTC(), Kind: "holepunch_finished", Success: direct != nil, Side: side, Attempt: attempt}
	if direct != nil {
		event.LocalAddress = direct.LocalMultiaddr().String()
		event.RemoteAddress = direct.RemoteMultiaddr().String()
		if conn, ok := direct.(network.Conn); ok {
			event.ConnectionID = conn.ID()
			event.LocalPeerID = conn.LocalPeer().String()
			event.RemotePeerID = conn.RemotePeer().String()
		}
	} else {
		event.ErrorKind = "holepunch_failed"
	}
	for _, address := range remote {
		if len(event.Candidates) >= maxAdvertisedAddresses {
			break
		}
		event.Candidates = append(event.Candidates, address.String())
	}
	t.observe(event)
}

func (t *traversalEvents) DirectDialFinished(success bool) {
	if t.metrics != nil {
		t.metrics.DirectDialFinished(success)
	}
}

func (t *traversalEvents) Trace(source *holepunch.Event) {
	if t.observe == nil || source == nil {
		return
	}
	event := RuntimeEvent{Time: time.Unix(0, source.Timestamp).UTC(), Kind: source.Type, LocalPeerID: source.Peer.String(), RemotePeerID: source.Remote.String()}
	switch value := source.Evt.(type) {
	case *holepunch.StartHolePunchEvt:
		event.Candidates = append([]string(nil), value.RemoteAddrs...)
		event.Elapsed = value.RTT
	case *holepunch.EndHolePunchEvt:
		event.Success = value.Success
		event.Elapsed = value.EllapsedTime
		if !value.Success {
			event.ErrorKind = "holepunch_failed"
		}
	case *holepunch.DirectDialEvt:
		event.Success = value.Success
		event.Elapsed = value.EllapsedTime
		if !value.Success {
			event.ErrorKind = "direct_dial_failed"
		}
	case *holepunch.ProtocolErrorEvt:
		event.ErrorKind = "holepunch_protocol_error"
	case *holepunch.HolePunchAttemptEvt:
	}
	t.observe(event)
}
