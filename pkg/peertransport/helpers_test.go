package peertransport

import (
	"crypto/rand"

	crypto "github.com/libp2p/go-libp2p/core/crypto"
)

// testRSAKey returns a fresh RSA private key for the wrong-key-type test.
func testRSAKey() (crypto.PrivKey, crypto.PubKey, error) {
	return crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, rand.Reader)
}

func marshalRSA(priv crypto.PrivKey) ([]byte, error) {
	return crypto.MarshalPrivateKey(priv)
}
