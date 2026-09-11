package stream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// subkeyInfo domain-separates the segment subkey from every other key derived
// from a DEK.
const subkeyInfo = "blindbucket/v1/segment"

// deriveSubkey derives a segment's encryption key from the DEK and the segment's
// salt.
//
// The fresh salt per segment is what keeps (key, nonce) pairs unique across
// segments, including across retried uploads of the same part number: a retry
// draws a new salt, hence a new key, so reusing the chunk counter is harmless.
func deriveSubkey(dek []byte, salt [SaltSize]byte) ([]byte, error) {
	if len(dek) != KeySize {
		return nil, fmt.Errorf("stream: DEK is %d bytes, want %d", len(dek), KeySize)
	}
	return hkdf.Key(sha256.New, dek, salt[:], subkeyInfo, KeySize)
}

// chunkNonce builds the nonce for chunk i as a value.
//
// The hot path uses sealer.setNonce instead, to avoid an allocation per chunk;
// this function is the readable statement of the layout and is what the tests
// and the known-answer vectors check against.
//
// The layout is uint88_be(i) || f, where f is 1 for the final chunk of the
// segment and 0 otherwise. Putting the position in the nonce makes reordering
// detectable; putting the final flag there makes truncation and extension
// detectable, because the chunk that becomes last would have to verify under a
// flag it was not sealed with.
func chunkNonce(i uint64, final bool) [NonceSize]byte {
	var n [NonceSize]byte
	binary.BigEndian.PutUint64(n[NonceSize-9:NonceSize-1], i)
	if final {
		n[NonceSize-1] = 1
	}
	return n
}

// sealer seals and opens the chunks of exactly one segment.
//
// It is not safe for concurrent use: the nonce buffer is reused across calls, so
// that passing it to the AEAD does not send a fresh slice to the heap on every
// chunk. That single allocation is small but it sits in the hot path, where the
// target is none at all.
type sealer struct {
	aead cipher.AEAD
	aad  []byte
	// chunkSize is the plaintext size of every chunk but the last.
	chunkSize int
	// nonce is rebuilt per chunk in place. Its leading three bytes are always
	// zero -- the counter is 88 bits but never exceeds 64 -- and are never
	// written, so only the counter and the final flag need setting.
	nonce [NonceSize]byte
}

// newSealer derives the segment subkey from dek and prepares the AEAD.
func newSealer(dek []byte, h header) (*sealer, error) {
	subkey, err := deriveSubkey(dek, h.salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if aead.NonceSize() != NonceSize || aead.Overhead() != TagSize {
		return nil, fmt.Errorf("stream: unexpected AEAD geometry: nonce %d, tag %d",
			aead.NonceSize(), aead.Overhead())
	}
	return &sealer{aead: aead, aad: h.aad(), chunkSize: h.chunkSize()}, nil
}

// setNonce rebuilds the nonce for chunk i in place.
func (s *sealer) setNonce(i uint64, final bool) {
	binary.BigEndian.PutUint64(s.nonce[NonceSize-9:NonceSize-1], i)
	s.nonce[NonceSize-1] = 0
	if final {
		s.nonce[NonceSize-1] = 1
	}
}

// seal encrypts one chunk of plaintext, appending the result to dst.
//
// Callers pass dst = buf[:0] and plain = buf[:n] to encrypt in place, which is
// what keeps the hot path free of per-chunk allocations.
func (s *sealer) seal(dst, plain []byte, i uint64, final bool) []byte {
	s.setNonce(i, final)
	return s.aead.Seal(dst, s.nonce[:], plain, s.aad)
}

// open decrypts and verifies one chunk, appending the plaintext to dst.
//
// It returns an *IntegrityError on any failure. No plaintext is produced unless
// the tag verified, so a caller may forward the result to a client directly.
func (s *sealer) open(dst, sealed []byte, i uint64, final bool) ([]byte, error) {
	s.setNonce(i, final)
	out, err := s.aead.Open(dst, s.nonce[:], sealed, s.aad)
	if err != nil {
		return nil, chunkErrorf(i, "authentication failed (final=%t)", final)
	}
	return out, nil
}
