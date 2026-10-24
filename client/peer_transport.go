package client

import (
	"errors"
	"net/http"

	"atoll/pkg/auth"
	"atoll/pkg/peerhttp"
)

func (c *Client) SetPeerResolver(resolver peerhttp.Resolver) error {
	if c.secTransport == nil || c.scheme() != "https" {
		return errors.New("peer transport requires a secure HTTPS client")
	}
	base, ok := c.secTransport.base.(*http.Transport)
	if !ok {
		return errors.New("peer transport must be configured once before requests")
	}
	transport, err := peerhttp.NewTransport(base, peerhttp.WithMaster(c.MasterURL), peerhttp.WithResolver(resolver))
	if err != nil {
		return err
	}
	c.secTransport.base = transport
	return nil
}

func (c *Client) transferProbeTransport() http.RoundTripper {
	if c.secTransport != nil {
		return c.secTransport.base
	}
	if transport, ok := c.HTTP.Transport.(*auth.Transport); ok && transport.Fallback != nil {
		return transport.Fallback
	}
	if c.HTTP.Transport != nil {
		return c.HTTP.Transport
	}
	return http.DefaultTransport
}
