package metacrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"atoll/pkg/contentcrypto"
)

const (
	Version = 1
	MaxPlainSize = 64 << 20
	RecordSize = 64 << 10
	MaxKeyLen = 256
	fixedHeader = 4 + 1 + 32 + 8 + 2 + 2
	recordOverhead = 12 + 16
)

var magic = [4]byte{'A', 'T', 'M', 'B'}

// Cipher also derives the public-only recovery identity installed on storage nodes.
type Cipher struct {
	wrapping *contentcrypto.KEK
	reader ed25519.PrivateKey
	namespace [32]byte
}

func New(kek *contentcrypto.KEK) (*Cipher, error) {
	if kek == nil {
		return nil, errors.New("metadata encryption requires a KEK")
	}
	wrapSecret, err := kek.Derive("metadata-backup-wrapping-v1")
	if err != nil {
		return nil, err
	}
	wrapping, err := contentcrypto.NewKEKFromSecret(kek.KeyID(), wrapSecret[:])
	if err != nil {
		return nil, err
	}
	readerSecret, err := kek.Derive("metadata-backup-reader-v1")
	if err != nil {
		return nil, err
	}
	reader := ed25519.NewKeyFromSeed(readerSecret[:])
	namespace := sha256.Sum256(reader.Public().(ed25519.PublicKey))
	return &Cipher{wrapping: wrapping, reader: reader, namespace: namespace}, nil
}

func (c *Cipher) Namespace() string { return hex.EncodeToString(c.namespace[:]) }
func (c *Cipher) KeyID() string { return c.wrapping.KeyID() }
func (c *Cipher) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), c.reader.Public().(ed25519.PublicKey)...)
}

// Each blob has a fresh DEK; recovery never depends on a live batch-key cache.
func (c *Cipher) Seal(key string, plain []byte) ([]byte, error) {
	if c == nil || key == "" || len(key) > MaxKeyLen || len(plain) > MaxPlainSize {
		return nil, errors.New("invalid metadata blob")
	}
	dek, err := contentcrypto.NewDEK()
	if err != nil {
		return nil, err
	}
	wrapped, err := contentcrypto.WrapDEK(c.wrapping, dek, wrapObjectID(key))
	if err != nil {
		return nil, err
	}
	keyID := c.KeyID()
	header := make([]byte, 0, fixedHeader+len(keyID)+len(wrapped))
	header = append(header, magic[:]...)
	header = append(header, Version)
	header = append(header, c.namespace[:]...)
	header = binary.BigEndian.AppendUint64(header, uint64(len(plain)))
	header = binary.BigEndian.AppendUint16(header, uint16(len(keyID)))
	header = binary.BigEndian.AppendUint16(header, uint16(len(wrapped)))
	header = append(header, keyID...)
	header = append(header, wrapped...)
	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	count := recordCount(len(plain))
	out := make([]byte, 0, len(header)+len(plain)+count*recordOverhead)
	out = append(out, header...)
	for i := 0; i < count; i++ {
		start := i * RecordSize
		end := min(start+RecordSize, len(plain))
		nonce := make([]byte, aead.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}
		out = append(out, nonce...)
		out = aead.Seal(out, nonce, plain[start:end], recordAAD(header, key, uint64(i)))
	}
	return out, nil
}

func IsEncrypted(raw []byte) bool {
	return len(raw) >= len(magic) && bytes.Equal(raw[:len(magic)], magic[:])
}

// ValidateEnvelope is structural only; storage nodes cannot authenticate or decrypt it.
func ValidateEnvelope(raw []byte, namespace string) error {
	_, ns, _, _, err := parseEnvelope(raw)
	if err != nil {
		return err
	}
	if namespace != hex.EncodeToString(ns) {
		return errors.New("metadata blob namespace mismatch")
	}
	return nil
}

func (c *Cipher) Open(key string, raw []byte) ([]byte, error) {
	if c == nil || key == "" || len(key) > MaxKeyLen {
		return nil, errors.New("metadata decryption requires a key and KEK")
	}
	header, ns, keyID, wrapped, err := parseEnvelope(raw)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(ns, c.namespace[:]) || keyID != c.KeyID() {
		return nil, errors.New("metadata encryption identity mismatch")
	}
	dek, err := contentcrypto.UnwrapDEK(c.wrapping, wrapObjectID(key), wrapped)
	if err != nil {
		return nil, errors.New("metadata DEK cannot be opened")
	}
	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint64(header[37:45]))
	plain := make([]byte, 0, length)
	off := len(header)
	for i := 0; i < recordCount(length); i++ {
		want := min(RecordSize, length-i*RecordSize)
		nonce := raw[off:off+aead.NonceSize()]
		off += aead.NonceSize()
		opened, err := aead.Open(nil, nonce, raw[off:off+want+aead.Overhead()], recordAAD(header, key, uint64(i)))
		if err != nil {
			return nil, fmt.Errorf("metadata record %d authentication failed", i)
		}
		plain = append(plain, opened...)
		off += want + aead.Overhead()
	}
	return plain, nil
}

func parseEnvelope(raw []byte) (header, namespace []byte, keyID string, wrapped []byte, err error) {
	if len(raw) < fixedHeader || !IsEncrypted(raw) || raw[4] != Version {
		err = errors.New("unsupported metadata encryption envelope")
		return
	}
	length := binary.BigEndian.Uint64(raw[37:45])
	keyLen := int(binary.BigEndian.Uint16(raw[45:47]))
	wrapLen := int(binary.BigEndian.Uint16(raw[47:49]))
	if length > MaxPlainSize || keyLen < 1 || keyLen > 255 || wrapLen != 19+keyLen+contentcrypto.KeySize+contentcrypto.TagSize {
		err = errors.New("invalid metadata encryption geometry")
		return
	}
	headerLen := fixedHeader + keyLen + wrapLen
	want := uint64(headerLen) + length + uint64(recordCount(int(length))*recordOverhead)
	if uint64(len(raw)) != want {
		err = errors.New("metadata blob truncated or has trailing data")
		return
	}
	header, namespace = raw[:headerLen], raw[5:37]
	keyID = string(raw[fixedHeader:fixedHeader+keyLen])
	wrapped = raw[fixedHeader+keyLen:headerLen]
	return
}

func newGCM(dek *contentcrypto.DEK) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func recordCount(size int) int { return max(1, (size+RecordSize-1)/RecordSize) }

func wrapObjectID(key string) uint64 {
	digest := sha256.Sum256([]byte("atoll-metadata-wrap-v1\x00"+key))
	return binary.BigEndian.Uint64(digest[:8]) | 1<<63
}

func recordAAD(header []byte, key string, index uint64) []byte {
	out := []byte("atoll-metadata-record-v1\x00")
	out = binary.BigEndian.AppendUint32(out, uint32(len(header)))
	out = append(out, header...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(key)))
	out = append(out, key...)
	return binary.BigEndian.AppendUint64(out, index)
}
