package edgeidentity

import (
	"bytes"
	"testing"
	"time"
)

func TestChallengeRejectsTimeEncodingAlias(t *testing.T) {
	_, id := validKeyBlob(t, t.TempDir())
	now := time.Unix(1_700_000_000, 0)
	c := Challenge{Nonce: []byte("0123456789abcdef"), Audience: "master", ExpiresAt: now.Add(-time.Hour)}
	sig, err := id.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	alias := c
	alias.ExpiresAt = time.Unix(c.ExpiresAt.Unix()+18_446_744_073, int64(c.ExpiresAt.Nanosecond())+709_551_616)
	if !bytes.Equal(encodeSignedChallenge(id.NodeID(), c), encodeSignedChallenge(id.NodeID(), alias)) {
		t.Fatal("fixture no longer exercises the timestamp alias")
	}
	if err := VerifyAt(id.PublicKey(), alias, sig, now, 0); err == nil {
		t.Fatal("expired challenge accepted after timestamp wrapped by 2^64 nanoseconds")
	}
}

func TestZeroValueIdentityCannotSign(t *testing.T) {
	var id Identity
	defer func() {
		if recover() != nil {
			t.Fatal("zero-value identity panicked instead of returning an error")
		}
	}()
	_, err := id.Sign(Challenge{Nonce: []byte("nonce"), Audience: "master", ExpiresAt: time.Now().Add(time.Minute)})
	if err == nil {
		t.Fatal("zero-value identity signed a challenge")
	}
}
