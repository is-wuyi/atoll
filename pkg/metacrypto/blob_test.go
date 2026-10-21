package metacrypto

import (
	"bytes"
	"encoding/binary"
	"testing"

	"atoll/pkg/contentcrypto"
)

func testCipher(t *testing.T) *Cipher {
	t.Helper()
	kek, err := contentcrypto.NewKEK("metadata-test")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(kek)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBlobRoundTrip(t *testing.T) {
	c := testCipher(t)
	for _, size := range []int{0, 1, RecordSize - 1, RecordSize, RecordSize + 1, 3*RecordSize + 9} {
		t.Run(string(rune('a'+size%23)), func(t *testing.T) {
			plain := bytes.Repeat([]byte{0x6a}, size)
			sealed, err := c.Seal("snapshot-7-10", plain)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateEnvelope(sealed, c.Namespace()); err != nil {
				t.Fatal(err)
			}
			opened, err := c.Open("snapshot-7-10", sealed)
			if err != nil || !bytes.Equal(opened, plain) {
				t.Fatalf("size=%d: opened=%d err=%v", size, len(opened), err)
			}
			other, err := c.Seal("snapshot-7-10", plain)
			if err != nil || bytes.Equal(sealed, other) {
				t.Fatalf("repeated seal reused ciphertext: %v", err)
			}
			if size > 128 && bytes.Contains(sealed, plain[:128]) {
				t.Fatal("metadata contains its plaintext sample")
			}
		})
	}
}

func TestBlobAuthenticationRejectsSubstitution(t *testing.T) {
	c := testCipher(t)
	sealed, err := c.Seal("wal-7-11-12", bytes.Repeat([]byte("private metadata"), RecordSize/4))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"wal-8-11-12", "wal-7-11-13", "snapshot-7-0", "manifest"} {
		if plain, err := c.Open(key, sealed); err == nil || plain != nil {
			t.Fatalf("blob substitution %s accepted", key)
		}
	}
	for _, index := range []int{4, 5, 37, 45, 47, fixedHeader, fixedHeader + len(c.KeyID()), len(sealed) - 1} {
		bad := append([]byte(nil), sealed...)
		bad[index] ^= 0x80
		if plain, err := c.Open("wal-7-11-12", bad); err == nil || plain != nil {
			t.Fatalf("header or ciphertext mutation at %d accepted", index)
		}
	}
	other := testCipher(t) // same public keyID, different secret
	if plain, err := other.Open("wal-7-11-12", sealed); err == nil || plain != nil {
		t.Fatal("different KEK with the same keyID opened metadata")
	}
}

func TestBlobRejectsTruncationReorderingAndOversize(t *testing.T) {
	c := testCipher(t)
	plain := bytes.Repeat([]byte{0x73}, 2*RecordSize)
	sealed, err := c.Seal("snapshot-3-0", plain)
	if err != nil {
		t.Fatal(err)
	}
	header, _, _, _, err := parseEnvelope(sealed)
	if err != nil {
		t.Fatal(err)
	}
	mutations := [][]byte{
		append(append([]byte(nil), sealed...), 0),
		append([]byte(nil), sealed[:len(sealed)-1]...),
		append([]byte(nil), sealed[:len(header)]...),
		append([]byte(nil), sealed[:len(sealed)-RecordSize-recordOverhead]...),
	}
	first := sealed[len(header) : len(header)+RecordSize+recordOverhead]
	second := sealed[len(header)+RecordSize+recordOverhead:]
	reordered := append([]byte(nil), header...)
	reordered = append(reordered, second...)
	reordered = append(reordered, first...)
	mutations = append(mutations, reordered)
	for _, raw := range mutations {
		if opened, err := c.Open("snapshot-3-0", raw); err == nil || opened != nil {
			t.Fatal("truncated, extended or reordered metadata accepted")
		}
	}
	bad := append([]byte(nil), sealed...)
	binary.BigEndian.PutUint64(bad[37:45], ^uint64(0))
	if _, err := c.Open("snapshot-3-0", bad); err == nil {
		t.Fatal("unbounded plaintext size accepted")
	}
	if _, err := New(nil); err == nil {
		t.Fatal("missing KEK accepted")
	}
}

func FuzzEnvelopeOpen(f *testing.F) {
	kek, _ := contentcrypto.NewKEKFromSecret("fuzz", bytes.Repeat([]byte{0x4a}, contentcrypto.KeySize))
	c, _ := New(kek)
	sealed, _ := c.Seal("manifest", []byte("fuzz manifest"))
	f.Add(sealed)
	f.Add([]byte("ATMB"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = c.Open("manifest", raw)
		_ = ValidateEnvelope(raw, c.Namespace())
	})
}
