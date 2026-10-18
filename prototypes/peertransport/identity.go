// Package peertransport is an isolated, application-layer prototype for the
// Atoll edge "phase B network prototype" work. It builds a runnable libp2p
// transport carrying the existing net/http object-processing model over
// libp2p streams, with explicit direct / forced-relay (CircuitRelay v2)
// paths, per-peer persistent Ed25519 identities and allowlist based
// authorization.
//
// This prototype is standalone: it does NOT import the production `atoll`
// module and must not be wired into production cmd/master/node/client/mount.
package peertransport

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// IdentityFileName is the on-disk name of the per-peer private key inside the
// identity directory.
const IdentityFileName = "identity.key"

// Identity is a persistent per-peer Ed25519 identity. The PeerID is derived
// from the key and is stable across restarts; endpoints (listen addresses)
// are intentionally NOT part of the identity and may change every run.
type Identity struct {
	Priv crypto.PrivKey
	ID   peer.ID
	Path string
}

// LoadOrCreateIdentity loads the identity from dir/identity.key, creating the
// key with O_CREATE|O_EXCL and mode 0600 if absent. An existing file is never
// overwritten, and a corrupt existing file is an error (never regenerated),
// so a peer's PeerID cannot silently change.
func LoadOrCreateIdentity(dir string) (*Identity, error) {
	if dir == "" {
		return nil, errors.New("peertransport: identity dir must not be empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("peertransport: create identity dir: %w", err)
	}
	path := filepath.Join(dir, IdentityFileName)

	// Fast path: load the existing key. Never rewrite it, even if it is
	// unreadable/corrupt — surface the error instead.
	if _, err := os.Stat(path); err == nil {
		return loadIdentity(path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("peertransport: stat identity %s: %w", path, err)
	}

	// Create exclusively: O_EXCL guarantees we never clobber an identity
	// that appears concurrently.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadIdentity(path)
		}
		return nil, fmt.Errorf("peertransport: create identity %s: %w", path, err)
	}
	defer f.Close()

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, 0)
	if err != nil {
		return nil, fmt.Errorf("peertransport: generate ed25519 key: %w", err)
	}
	b, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("peertransport: marshal private key: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		return nil, fmt.Errorf("peertransport: write identity %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return nil, fmt.Errorf("peertransport: sync identity %s: %w", path, err)
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("peertransport: derive peer id: %w", err)
	}
	return &Identity{Priv: priv, ID: id, Path: path}, nil
}

func loadIdentity(path string) (*Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("peertransport: read identity %s: %w", path, err)
	}
	priv, err := crypto.UnmarshalPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("peertransport: corrupt identity %s (refusing to overwrite): %w", path, err)
	}
	if priv.Type() != crypto.Ed25519 {
		return nil, fmt.Errorf("peertransport: identity %s is not ed25519", path)
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("peertransport: derive peer id from %s: %w", path, err)
	}
	return &Identity{Priv: priv, ID: id, Path: path}, nil
}

// RawEd25519 exposes the raw ed25519 private key bytes (used by tests).
func (id *Identity) RawEd25519() (ed25519.PrivateKey, error) {
	raw, err := id.Priv.Raw()
	if err != nil {
		return nil, err
	}
	k := ed25519.PrivateKey(raw)
	if len(k) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("peertransport: identity %s is not ed25519", id.Path)
	}
	return k, nil
}
