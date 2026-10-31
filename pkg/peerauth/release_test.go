package peerauth

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

func TestClientReleaseProofSeparatesRegistrationAndRelease(t *testing.T) {
	id, pub, priv := proofIdentity(t)
	req := ClientRegistration{PeerID: id, PublicKey: pub, ExpectedRevision: 7, OperationID: "0123456789abcdef0123456789abcdef", NotAfter: time.Now().UTC().Add(time.Minute)}
	registration, err := ClientProof("https://master.test", "session", 1, req)
	if err != nil {
		t.Fatal(err)
	}
	release, err := ClientReleaseProof("https://master.test", "session", 1, req)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(priv, release)
	if bytes.Equal(registration, release) || Verify(pub, registration, signature) || !Verify(pub, release, signature) {
		t.Fatal("registration and release signatures share an authority domain")
	}
	for _, mutate := range []func(*ClientRegistration){
		func(r *ClientRegistration) { r.ExpectedRevision++ },
		func(r *ClientRegistration) { r.OperationID = "1123456789abcdef0123456789abcdef" },
		func(r *ClientRegistration) { r.NotAfter = r.NotAfter.Add(time.Second) },
	} {
		changed := req
		mutate(&changed)
		message, err := ClientReleaseProof("https://master.test", "session", 1, changed)
		if err != nil {
			t.Fatal(err)
		}
		if Verify(pub, message, signature) {
			t.Fatal("changed release binding accepted")
		}
	}
}
