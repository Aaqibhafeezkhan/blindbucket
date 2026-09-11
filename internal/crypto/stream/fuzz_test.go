package stream

import (
	"bytes"
	"io"
	"testing"
)

// fuzzWant is the set of segment identities the decoder fuzzer tries. Each input
// is offered to every one of them, so an input crafted for a multipart segment is
// exercised too.
var fuzzWant = []SegmentParams{
	{Log2ChunkSize: MinLog2ChunkSize},
	{Log2ChunkSize: MinLog2ChunkSize, Multipart: true, Index: 1},
	{Log2ChunkSize: DefaultLog2ChunkSize},
}

// FuzzDecryptReader requires two things of every input: the decoder must not
// panic, and anything it accepts must be canonical.
//
// Canonical means the accepted ciphertext is exactly what re-encrypting the
// recovered plaintext under the same header produces. Without that property
// there could be two distinct ciphertexts decrypting to the same plaintext --
// trailing bytes silently ignored, a short final chunk padded, a chunk boundary
// interpreted two ways -- which is the malleability an AEAD is supposed to rule
// out.
func FuzzDecryptReader(f *testing.F) {
	seedCorpus(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, want := range fuzzWant {
			r, err := NewDecryptReader(bytes.NewReader(data), testDEK, want)
			if err != nil {
				continue
			}
			plain, err := io.ReadAll(r)
			_ = r.Close()
			if err != nil {
				continue
			}

			h, err := parseHeader(data[:HeaderSize])
			if err != nil {
				t.Fatalf("decoder accepted a segment whose header does not parse: %v", err)
			}

			var reencoded bytes.Buffer
			w, err := newEncryptWriter(&reencoded, testDEK, h)
			if err != nil {
				t.Fatalf("re-encrypting under the accepted header failed: %v", err)
			}
			if _, err := w.Write(plain); err != nil {
				t.Fatalf("re-encrypt write: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("re-encrypt close: %v", err)
			}

			if !bytes.Equal(reencoded.Bytes(), data) {
				t.Fatalf("accepted a non-canonical segment: %d bytes in, %d bytes when re-encrypted",
					len(data), reencoded.Len())
			}
		}
	})
}

// FuzzRoundTrip requires that any plaintext survives encryption and decryption
// unchanged, and that its ciphertext has exactly the length SealedSize predicts.
func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte(nil), uint8(MinLog2ChunkSize))
	f.Add([]byte("hello"), uint8(MinLog2ChunkSize))
	f.Add(bytes.Repeat([]byte{1}, 1<<MinLog2ChunkSize), uint8(MinLog2ChunkSize))
	f.Add(bytes.Repeat([]byte{1}, 1<<MinLog2ChunkSize+1), uint8(MinLog2ChunkSize))

	f.Fuzz(func(t *testing.T, plain []byte, log2C uint8) {
		// Keep the fuzzer to the small chunk sizes; large ones only make each
		// execution slower without reaching new code.
		log2C = MinLog2ChunkSize + log2C%3
		p := SegmentParams{Log2ChunkSize: log2C}

		var sealed bytes.Buffer
		w, err := NewEncryptWriter(&sealed, testDEK, p)
		if err != nil {
			t.Fatalf("NewEncryptWriter: %v", err)
		}
		if _, err := w.Write(plain); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		want, err := SealedSize(int64(len(plain)), log2C)
		if err != nil {
			t.Fatalf("SealedSize: %v", err)
		}
		if int64(sealed.Len()) != want {
			t.Fatalf("ciphertext is %d bytes, SealedSize says %d", sealed.Len(), want)
		}

		got, err := openSegment(testDEK, p, sealed.Bytes())
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatal("plaintext differs after a round trip")
		}
	})
}

// FuzzParseHeader requires that header parsing never panics and that whatever it
// accepts re-serialises to the identical 32 bytes.
func FuzzParseHeader(f *testing.F) {
	valid, err := newHeaderWithSalt(SegmentParams{Log2ChunkSize: DefaultLog2ChunkSize}, [SaltSize]byte{})
	if err != nil {
		f.Fatalf("newHeaderWithSalt: %v", err)
	}
	f.Add(valid.raw[:])
	f.Add(make([]byte, HeaderSize))
	f.Add([]byte("BLBK"))

	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := parseHeader(data)
		if err != nil {
			return
		}
		again, err := newHeaderWithSalt(h.params, h.salt)
		if err != nil {
			t.Fatalf("a parsed header failed to re-serialise: %v", err)
		}
		if !bytes.Equal(again.raw[:], data) {
			t.Fatalf("header is not canonical: parsed %x, re-serialised %x", data, again.raw)
		}
	})
}

// seedCorpus adds valid segments across the interesting sizes, so the fuzzer
// starts from inputs that reach the decoder's later stages instead of having to
// discover a valid header by chance.
func seedCorpus(f *testing.F) {
	f.Helper()

	c := 1 << MinLog2ChunkSize
	for _, size := range []int{0, 1, c - 1, c, c + 1, 2 * c, 2*c + 1} {
		plain := bytes.Repeat([]byte{0xab}, size)
		for _, p := range fuzzWant[:2] {
			var out bytes.Buffer
			w, err := NewEncryptWriter(&out, testDEK, p)
			if err != nil {
				f.Fatalf("NewEncryptWriter: %v", err)
			}
			if _, err := w.Write(plain); err != nil {
				f.Fatalf("Write: %v", err)
			}
			if err := w.Close(); err != nil {
				f.Fatalf("Close: %v", err)
			}
			f.Add(out.Bytes())
		}
	}
}
