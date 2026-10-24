package node

import (
	"errors"
	"net/http"

	"atoll/pkg/access"
	"atoll/pkg/peerhttp"
)

func (n *Node) SetPeerResolver(resolver peerhttp.Resolver) error {
	if n.sec == nil || n.sec.masterScheme != "https" || n.nodeID.Load() != 0 {
		return errors.New("peer transport requires a secure HTTPS node before registration")
	}
	base, ok := n.sec.base.(*http.Transport)
	if !ok {
		return errors.New("peer resolver must be configured once")
	}
	transport, err := peerhttp.NewTransport(base, peerhttp.WithMaster(n.masterURL), peerhttp.WithResolver(resolver))
	if err != nil {
		return err
	}
	n.sec.base = transport
	n.sec.authClient.Transport = transport
	if t, ok := n.httpClient.Transport.(*deviceTransport); ok {
		t.base = transport
	}
	if t, ok := n.bulkClient.Transport.(*access.Transport); ok {
		t.Base = transport
	}
	return nil
}
