// Package keyfile loads a stable master KEK from a dedicated local file.
// The file is intentionally separate from bbolt/WAL and never returns key bytes in errors.
package keyfile

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"atoll/pkg/contentcrypto"
)

var magic = [4]byte{'A', 'T', 'K', 'F'}

const version byte = 1

func Load(path string) (*contentcrypto.KEK, error) {
	if path == "" {
		return nil, errors.New("keyfile path is required")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("keyfile parent must be a private directory")
	}
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("keyfile must be a private regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) < 4+1+2+contentcrypto.KeySize || !bytes.Equal(raw[:4], magic[:]) || raw[4] != version {
		return nil, errors.New("invalid keyfile format")
	}
	keyLen := int(binary.BigEndian.Uint16(raw[5:7]))
	if keyLen == 0 || keyLen > 255 || len(raw) != 4+1+2+keyLen+contentcrypto.KeySize {
		return nil, errors.New("invalid keyfile length")
	}
	keyID := string(raw[7 : 7+keyLen])
	if strings.ContainsAny(keyID, "\x00\r\n") {
		return nil, errors.New("invalid keyfile key id")
	}
	return contentcrypto.NewKEKFromSecret(keyID, raw[7+keyLen:])
}

// Create creates a new keyfile atomically and refuses to overwrite an existing path.
func Create(path, keyID string) (*contentcrypto.KEK, error) {
	if path == "" || keyID == "" || strings.ContainsAny(keyID, "\x00\r\n") {
		return nil, errors.New("invalid keyfile arguments")
	}
	if len(keyID) > 255 {
		return nil, errors.New("keyfile key id is too long")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, err
	}
	if st, err := os.Stat(parent); err != nil || !st.IsDir() || st.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("keyfile parent must be a private directory")
	}
	var secret [contentcrypto.KeySize]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, err
	}
	if _, err := contentcrypto.NewKEKFromSecret(keyID, secret[:]); err != nil {
		return nil, err
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(keyID)))
	raw := append(append(append(append([]byte{}, magic[:]...), version), length[:]...), []byte(keyID)...)
	raw = append(raw, secret[:]...)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	// Link is no-replace publication: an existing key file is never overwritten.
	if err := os.Link(tmp, path); err != nil {
		return nil, err
	}
	if err := os.Remove(tmp); err != nil {
		return nil, err
	}
	if err := syncDir(parent); err != nil {
		return nil, err
	}
	keep = true
	return Load(path)
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
