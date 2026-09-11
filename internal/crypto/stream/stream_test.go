package stream

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"testing"
)

// testDEK is a fixed key: tests must be reproducible, and nothing here is secret.
var testDEK = bytes.Repeat([]byte{0x2a}, KeySize)

func singlePart(log2C uint8) SegmentParams {
	return SegmentParams{Log2ChunkSize: log2C}
}

// sealSegment encrypts plain as one segment and returns the ciphertext.
func sealSegment(t *testing.T, dek []byte, p SegmentParams, plain []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := NewEncryptWriter(&out, dek, p)
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return out.Bytes()
}

// openSegment decrypts a segment and returns the plaintext or the failure.
func openSegment(dek []byte, p SegmentParams, sealed []byte) ([]byte, error) {
	r, err := NewDecryptReader(bytes.NewReader(sealed), dek, p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return io.ReadAll(r)
}

// requireIntegrityError fails the test unless err is an *IntegrityError. An
// ordinary error would mean the failure was noticed by accident rather than by
// the format's own checks.
func requireIntegrityError(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected an integrity failure, got plaintext", what)
	}
	var ie *IntegrityError
	if !errors.As(err, &ie) {
		t.Fatalf("%s: got %T (%v), want *IntegrityError", what, err, err)
	}
}

func TestRoundTripAtBoundaries(t *testing.T) {
	t.Parallel()

	for _, log2C := range []uint8{12, 16, 20} {
		t.Run(fmt.Sprintf("log2C=%d", log2C), func(t *testing.T) {
			t.Parallel()
			c := int64(1) << log2C

			sizes := []int64{0, 1, 2, c - 1, c, c + 1, 2*c - 1, 2 * c, 2*c + 1, 3*c + 7}
			for _, size := range sizes {
				plain := make([]byte, size)
				if _, err := rand.Read(plain); err != nil {
					t.Fatalf("rand: %v", err)
				}

				sealed := sealSegment(t, testDEK, singlePart(log2C), plain)

				want, err := SealedSize(size, log2C)
				if err != nil {
					t.Fatalf("SealedSize(%d): %v", size, err)
				}
				if int64(len(sealed)) != want {
					t.Errorf("size %d: ciphertext is %d bytes, SealedSize says %d", size, len(sealed), want)
				}

				got, err := openSegment(testDEK, singlePart(log2C), sealed)
				if err != nil {
					t.Fatalf("size %d: decrypt: %v", size, err)
				}
				if !bytes.Equal(got, plain) {
					t.Errorf("size %d: plaintext differs after round trip", size)
				}
			}
		})
	}
}

// TestRoundTripAcrossWriteSplits checks that the result does not depend on how
// the caller chunks its writes. The encoder buffers across calls, so a segment
// written in many small pieces must be byte-identical to one written at once.
func TestRoundTripAcrossWriteSplits(t *testing.T) {
	t.Parallel()

	const log2C = 12
	c := 1 << log2C
	plain := make([]byte, 3*c+123)
	if _, err := rand.Read(plain); err != nil {
		t.Fatalf("rand: %v", err)
	}

	// Fix the salt so the two ciphertexts are comparable at all.
	var salt [SaltSize]byte
	h, err := newHeaderWithSalt(singlePart(log2C), salt)
	if err != nil {
		t.Fatalf("newHeaderWithSalt: %v", err)
	}

	writeWith := func(split func(p []byte) [][]byte) []byte {
		var out bytes.Buffer
		w, err := newEncryptWriter(&out, testDEK, h)
		if err != nil {
			t.Fatalf("newEncryptWriter: %v", err)
		}
		for _, piece := range split(plain) {
			if _, err := w.Write(piece); err != nil {
				t.Fatalf("Write: %v", err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		return out.Bytes()
	}

	whole := writeWith(func(p []byte) [][]byte { return [][]byte{p} })

	splits := map[string]func([]byte) [][]byte{
		"one byte at a time": func(p []byte) [][]byte {
			var out [][]byte
			for i := range p {
				out = append(out, p[i:i+1])
			}
			return out
		},
		"exact chunk boundaries": func(p []byte) [][]byte {
			var out [][]byte
			for len(p) > 0 {
				n := min(c, len(p))
				out, p = append(out, p[:n]), p[n:]
			}
			return out
		},
		"random pieces": func(p []byte) [][]byte {
			r := mrand.New(mrand.NewPCG(7, 11))
			var out [][]byte
			for len(p) > 0 {
				n := min(1+r.IntN(2*c), len(p))
				out, p = append(out, p[:n]), p[n:]
			}
			return out
		},
		"empty writes interleaved": func(p []byte) [][]byte {
			return [][]byte{p[:c], {}, p[c : 2*c], {}, p[2*c:]}
		},
	}

	for name, split := range splits {
		t.Run(name, func(t *testing.T) {
			if got := writeWith(split); !bytes.Equal(got, whole) {
				t.Errorf("ciphertext differs from the single-write encoding")
			}
		})
	}
}

// TestCloseIsTheCommitPoint pins down the property the proxy's checksum handling
// depends on: until Close, the final chunk has not been written, and what has
// been written so far does not decrypt.
func TestCloseIsTheCommitPoint(t *testing.T) {
	t.Parallel()

	const log2C = 12
	c := 1 << log2C
	plain := bytes.Repeat([]byte{7}, 3*c)

	var out bytes.Buffer
	w, err := NewEncryptWriter(&out, testDEK, singlePart(log2C))
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatalf("Write: %v", err)
	}

	withoutClose := bytes.Clone(out.Bytes())
	full, err := SealedSize(int64(len(plain)), log2C)
	if err != nil {
		t.Fatalf("SealedSize: %v", err)
	}
	if int64(len(withoutClose)) >= full {
		t.Errorf("before Close %d bytes were written, which is not less than the complete %d", len(withoutClose), full)
	}

	_, err = openSegment(testDEK, singlePart(log2C), withoutClose)
	requireIntegrityError(t, "segment without Close", err)

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got, err := openSegment(testDEK, singlePart(log2C), out.Bytes())
	if err != nil {
		t.Fatalf("after Close: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("plaintext differs after Close")
	}
}

func TestWriteAfterCloseFails(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	w, err := NewEncryptWriter(&out, testDEK, singlePart(12))
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := w.Write([]byte("x")); !errors.Is(err, ErrWriterClosed) {
		t.Errorf("Write after Close returned %v, want ErrWriterClosed", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close returned %v, want nil", err)
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	t.Parallel()

	sealed := sealSegment(t, testDEK, singlePart(12), []byte("confidential"))
	other := bytes.Repeat([]byte{0x2b}, KeySize)

	_, err := openSegment(other, singlePart(12), sealed)
	requireIntegrityError(t, "wrong key", err)
}

func TestDecryptRejectsShortHeader(t *testing.T) {
	t.Parallel()

	sealed := sealSegment(t, testDEK, singlePart(12), []byte("x"))
	for _, n := range []int{0, 1, HeaderSize - 1} {
		_, err := openSegment(testDEK, singlePart(12), sealed[:n])
		requireIntegrityError(t, fmt.Sprintf("header truncated to %d bytes", n), err)
	}
}
