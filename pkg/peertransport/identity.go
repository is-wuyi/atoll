package peertransport

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	maxIdentityFileSize = 4096
	identityFileMode    = 0o600
)

// runtimeIdentity keeps the private key private to this package. It is never
// an edgeidentity.Identity and is never backed by the device/node key file.
type runtimeIdentity struct {
	priv crypto.PrivKey
	pub  []byte
	id   peer.ID
}

// String never exposes the private key material.
func (i *runtimeIdentity) String() string { return "runtimeIdentity(" + i.id.String() + ")" }

func newEphemeralIdentity() (*runtimeIdentity, error) {
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("peertransport: generate ephemeral identity: %w", err)
	}
	return makeRuntimeIdentity(priv)
}

func loadOrCreateRuntimeIdentity(path string) (*runtimeIdentity, error) {
	if path == "" {
		return newEphemeralIdentity()
	}
	if err := ensureIdentityParent(path); err != nil {
		return nil, err
	}

	li, err := os.Lstat(path)
	if err == nil {
		if li.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("peertransport: identity %s is a symlink", path)
		}
		return readRuntimeIdentity(path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("peertransport: stat identity %s: %w", path, err)
	}

	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("peertransport: generate identity: %w", err)
	}
	blob, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("peertransport: marshal identity: %w", err)
	}
	if len(blob) == 0 || len(blob) > maxIdentityFileSize {
		return nil, errors.New("peertransport: generated identity has an invalid size")
	}

	// Write and fsync a private temporary file, then publish with link(2).
	// link never replaces an existing path, so concurrent creators converge on
	// the first complete key instead of silently changing the PeerID.
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".peertransport-identity-*")
	if err != nil {
		return nil, fmt.Errorf("peertransport: create identity temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(identityFileMode); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("peertransport: chmod identity temp: %w", err)
	}
	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("peertransport: write identity temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("peertransport: fsync identity temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("peertransport: close identity temp: %w", err)
	}
	if err := os.Link(tmpName, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return readRuntimeIdentity(path)
		}
		return nil, fmt.Errorf("peertransport: publish identity: %w", err)
	}
	cleanup = false
	_ = os.Remove(tmpName)
	if err := syncDirectory(dir); err != nil {
		return nil, fmt.Errorf("peertransport: fsync identity directory: %w", err)
	}
	return makeRuntimeIdentity(priv)
}

func ensureIdentityParent(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("peertransport: create identity directory: %w", err)
	}
	return nil
}

// openRuntimeIdentity opens path without following a symlink and without
// blocking on a FIFO. The Lstat/Open/SameFile sequence rejects a path that was
// swapped for a symlink between the two calls.
func openRuntimeIdentity(path string) (*os.File, os.FileInfo, error) {
	li, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("peertransport: identity %s is a symlink", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|identityOpenFlags, 0)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !os.SameFile(li, fi) {
		f.Close()
		return nil, nil, fmt.Errorf("peertransport: identity %s changed while opening", path)
	}
	return f, fi, nil
}

func readRuntimeIdentity(path string) (*runtimeIdentity, error) {
	f, fi, err := openRuntimeIdentity(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("peertransport: identity %s is not a regular file", path)
	}
	if fi.Size() <= 0 || fi.Size() > maxIdentityFileSize {
		return nil, fmt.Errorf("peertransport: identity %s has invalid size %d", path, fi.Size())
	}
	if fi.Mode().Perm() != identityFileMode {
		return nil, fmt.Errorf("peertransport: identity %s must have mode 0600", path)
	}
	blob, err := io.ReadAll(io.LimitReader(f, maxIdentityFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("peertransport: read identity %s: %w", path, err)
	}
	if len(blob) > maxIdentityFileSize {
		return nil, fmt.Errorf("peertransport: identity %s is too large", path)
	}
	priv, err := crypto.UnmarshalPrivateKey(blob)
	if err != nil {
		return nil, fmt.Errorf("peertransport: invalid identity %s: %w", path, err)
	}
	if priv.Type() != crypto.Ed25519 {
		return nil, fmt.Errorf("peertransport: identity %s is not Ed25519", path)
	}
	// Require the canonical libp2p private-key encoding so corruption and
	// ambiguous encodings fail closed instead of silently producing a new ID.
	canonical, err := crypto.MarshalPrivateKey(priv)
	if err != nil || !bytes.Equal(canonical, blob) {
		return nil, fmt.Errorf("peertransport: identity %s is not canonical", path)
	}
	// A concurrent creator may have linked the file but not yet fsynced its
	// directory; mirror its durability before acknowledging the load.
	if err := f.Sync(); err != nil {
		return nil, fmt.Errorf("peertransport: sync identity %s: %w", path, err)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("peertransport: sync identity directory: %w", err)
	}
	return makeRuntimeIdentity(priv)
}

func makeRuntimeIdentity(priv crypto.PrivKey) (*runtimeIdentity, error) {
	if priv == nil || priv.Type() != crypto.Ed25519 {
		return nil, errors.New("peertransport: identity must be Ed25519")
	}
	raw, err := priv.GetPublic().Raw()
	if err != nil || len(raw) != 32 {
		return nil, errors.New("peertransport: invalid Ed25519 public key")
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("peertransport: derive PeerID: %w", err)
	}
	return &runtimeIdentity{priv: priv, pub: append([]byte(nil), raw...), id: id}, nil
}

func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
