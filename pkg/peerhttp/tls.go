package peerhttp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
)

// SecureListener wraps lis so that every connection it accepts is a TLS
// connection, which is what gives an https request a genuine handshake over a
// peer transport's stream:
//
//	lis, err := peerhttp.SecureListener(peerStreams, cfg)
//	srv := &http.Server{Handler: h}
//	err = srv.Serve(lis)
//
// A peer transport's accepted stream is an authenticated channel but not a TLS
// connection, so tls.NewListener is what produces the handshake on the server
// side and a populated r.TLS, keeping an existing gate such as node.security's
// "reject when r.TLS == nil" working unchanged.
//
// A raw listener with ServeTLS is equally correct: ServeTLS performs the
// handshake itself. Do not mix the two: SecureListener already wraps, so its
// result is served with Serve, and a raw listener goes to ServeTLS. Serving an
// already-wrapped listener with ServeTLS would start a second handshake that a
// normal single-layer TLS client does not send.
//
// cfg is copied so later mutation does not change the listener in place.
// cfg.MinVersion defaults to TLS 1.2 when zero; cfg.NextProtos is left alone,
// so an empty list means HTTP/1.1 only. No private key leaves cfg.
func SecureListener(lis net.Listener, cfg *tls.Config) (net.Listener, error) {
	if lis == nil {
		return nil, errors.New("peerhttp: listener is required")
	}
	if cfg == nil {
		return nil, errors.New("peerhttp: TLS config is required")
	}
	if err := checkServerConfig(cfg); err != nil {
		return nil, err
	}
	c := cfg.Clone()
	if c.MinVersion == 0 {
		c.MinVersion = tls.VersionTLS12
	}
	return tls.NewListener(lis, c), nil
}

// checkServerConfig enforces that the config can hand out a certificate with a
// private key, so a broken certificate shows up at wiring time.
func checkServerConfig(c *tls.Config) error {
	if len(c.Certificates) == 0 {
		switch {
		case c.GetConfigForClient != nil:
			return nil
		case c.GetCertificate != nil:
			cert, err := c.GetCertificate(nil)
			if err != nil {
				return fmt.Errorf("peerhttp: GetCertificate: %w", err)
			}
			return usableCert(cert)
		default:
			return errors.New("peerhttp: TLS config needs a certificate")
		}
	}
	for i := range c.Certificates {
		if err := usableCert(&c.Certificates[i]); err != nil {
			return fmt.Errorf("peerhttp: certificate %d: %w", i, err)
		}
	}
	return nil
}

// usableCert reports whether a certificate can complete a handshake.
func usableCert(cert *tls.Certificate) error {
	if cert == nil || len(cert.Certificate) == 0 {
		return errors.New("certificate is empty")
	}
	if cert.PrivateKey == nil {
		return errors.New("certificate has no private key")
	}
	return nil
}
