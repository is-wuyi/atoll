package contentcrypto

import (
	"crypto/sha256"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// Derive separates auxiliary keys from the content-wrapping key without exporting it.
func (k *KEK) Derive(domain string) (*DEK, error) {
	if k == nil || domain == "" || len(domain) > 256 || strings.ContainsRune(domain, '\x00') {
		return nil, errors.New("contentcrypto: invalid key derivation domain")
	}
	r := hkdf.New(sha256.New, k.key[:], []byte("atoll-key-derivation-v1"), []byte(domain+"\x00"+k.keyID))
	out := new(DEK)
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return nil, err
	}
	return out, nil
}
