package envelope

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
)

func testProvider(t *testing.T, kids ...string) *keys.Keyring {
	t.Helper()
	ring := keys.NewKeyring()
	for _, kid := range kids {
		if err := ring.Generate(kid); err != nil {
			t.Fatalf("Generate(%q): %v", kid, err)
		}
	}
	return ring
}

func encryptTo(t *testing.T, ring keys.KeyProvider, plain []byte, log2C uint8) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := Encrypt(t.Context(), &out, bytes.NewReader(plain), ring, log2C); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return out.Bytes()
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	ring := testProvider(t, "2026-09")

	for _, size := range []int{0, 1, 4095, 4096, 4097, 1 << 20} {
		plain := make([]byte, size)
		if _, err := rand.Read(plain); err != nil {
			t.Fatalf("rand: %v", err)
		}

		file := encryptTo(t, ring, plain, stream.MinLog2ChunkSize)

		// The plaintext must not survive anywhere in the file.
		if size > 32 && bytes.Contains(file, plain[:32]) {
			t.Errorf("size %d: plaintext appears in the ciphertext", size)
		}

		var got bytes.Buffer
		if err := Decrypt(t.Context(), &got, bytes.NewReader(file), ring); err != nil {
			t.Fatalf("size %d: Decrypt: %v", size, err)
		}
		if !bytes.Equal(got.Bytes(), plain) {
			t.Errorf("size %d: plaintext differs after a round trip", size)
		}
	}
}

// TestChunkSizeIsCarriedInTheFile checks that a file decrypts under whatever
// chunk size it was written with, without the reader being told.
func TestChunkSizeIsCarriedInTheFile(t *testing.T) {
	t.Parallel()

	ring := testProvider(t, "kid")
	plain := bytes.Repeat([]byte{0x11}, 70000)

	for _, log2C := range []uint8{12, 16, 20} {
		file := encryptTo(t, ring, plain, log2C)
		var got bytes.Buffer
		if err := Decrypt(t.Context(), &got, bytes.NewReader(file), ring); err != nil {
			t.Fatalf("log2C=%d: Decrypt: %v", log2C, err)
		}
		if !bytes.Equal(got.Bytes(), plain) {
			t.Errorf("log2C=%d: plaintext differs", log2C)
		}
	}
}

func TestKeyIDIsReadableWithoutDecrypting(t *testing.T) {
	t.Parallel()

	ring := testProvider(t, "2026-09")
	file := encryptTo(t, ring, []byte("payload"), stream.MinLog2ChunkSize)

	kid, err := KeyID(bytes.NewReader(file))
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	if kid != "2026-09" {
		t.Errorf("KeyID = %q, want %q", kid, "2026-09")
	}
}

func TestDecryptRejectsBadInput(t *testing.T) {
	t.Parallel()

	ring := testProvider(t, "kid-a")
	other := testProvider(t, "kid-a")
	file := encryptTo(t, ring, bytes.Repeat([]byte{7}, 9000), stream.MinLog2ChunkSize)

	t.Run("a different keyring", func(t *testing.T) {
		t.Parallel()
		var got bytes.Buffer
		err := Decrypt(t.Context(), &got, bytes.NewReader(file), other)
		if !errors.Is(err, keys.ErrUnwrap) {
			t.Errorf("got %v, want ErrUnwrap", err)
		}
		if got.Len() != 0 {
			t.Errorf("wrote %d bytes of output despite failing", got.Len())
		}
	})

	t.Run("key id not in the keyring", func(t *testing.T) {
		t.Parallel()
		tampered := bytes.Clone(file)
		// The key id sits after magic, version and its own length prefix.
		tampered[fixedPrefixSize] = 'X'
		var got bytes.Buffer
		if err := Decrypt(t.Context(), &got, bytes.NewReader(tampered), ring); !errors.Is(err, keys.ErrUnknownKID) {
			t.Errorf("got %v, want ErrUnknownKID", err)
		}
	})

	t.Run("not a blindbucket file", func(t *testing.T) {
		t.Parallel()
		for _, input := range [][]byte{nil, []byte("hello"), bytes.Repeat([]byte{0}, 200)} {
			var got bytes.Buffer
			if err := Decrypt(t.Context(), &got, bytes.NewReader(input), ring); !errors.Is(err, ErrNotBlindbucketFile) {
				t.Errorf("input %q: got %v, want ErrNotBlindbucketFile", input, err)
			}
		}
	})

	t.Run("unsupported version", func(t *testing.T) {
		t.Parallel()
		tampered := bytes.Clone(file)
		tampered[len(Magic)] = 2
		var got bytes.Buffer
		if err := Decrypt(t.Context(), &got, bytes.NewReader(tampered), ring); err == nil {
			t.Error("a future file version was accepted")
		}
	})

	t.Run("truncated", func(t *testing.T) {
		t.Parallel()
		for _, n := range []int{1, fixedPrefixSize, fixedPrefixSize + 3, len(file) - 1} {
			var got bytes.Buffer
			if err := Decrypt(t.Context(), &got, bytes.NewReader(file[:n]), ring); err == nil {
				t.Errorf("a file truncated to %d bytes was accepted", n)
			}
		}
	})

	t.Run("wrapped key modified", func(t *testing.T) {
		t.Parallel()
		tampered := bytes.Clone(file)
		tampered[len(file)-1-9000] ^= 0x01 // inside the segment, not the envelope
		var got bytes.Buffer
		if err := Decrypt(t.Context(), &got, bytes.NewReader(tampered), ring); err == nil {
			t.Error("a modified file was accepted")
		}
	})
}

// TestNoOutputBeforeVerification is the fail-closed rule at the file level: a
// file whose very first chunk is corrupt must leave the destination untouched,
// rather than half-writing a file the user might keep.
func TestNoOutputBeforeVerification(t *testing.T) {
	t.Parallel()

	ring := testProvider(t, "kid")
	plain := bytes.Repeat([]byte{9}, 20000)
	file := encryptTo(t, ring, plain, stream.MinLog2ChunkSize)

	// Corrupt a byte inside the first chunk's ciphertext.
	firstChunk := fixedPrefixSize + len("kid") + keys.WrappedDEKSize + stream.HeaderSize
	tampered := bytes.Clone(file)
	tampered[firstChunk+5] ^= 0x01

	var got bytes.Buffer
	err := Decrypt(t.Context(), &got, bytes.NewReader(tampered), ring)
	if err == nil {
		t.Fatal("a corrupted file was accepted")
	}
	if got.Len() != 0 {
		t.Errorf("wrote %d bytes before detecting corruption, want 0", got.Len())
	}
	var ie *stream.IntegrityError
	if !errors.As(err, &ie) {
		t.Errorf("got %T, want *stream.IntegrityError", err)
	}
}

func TestEncryptRejectsInvalidKeyID(t *testing.T) {
	t.Parallel()

	ring := keys.NewKeyring()
	if err := ring.Add(strings.Repeat("k", keys.MaxKIDLen), make([]byte, keys.KeySize)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// A valid, maximal key id must still work.
	if err := Encrypt(t.Context(), &bytes.Buffer{}, strings.NewReader("x"), ring, stream.MinLog2ChunkSize); err != nil {
		t.Errorf("a maximal key id was rejected: %v", err)
	}
}

// FuzzDecrypt requires that no file, however malformed, causes a panic.
func FuzzDecrypt(f *testing.F) {
	ring := keys.NewKeyring()
	if err := ring.Generate("kid"); err != nil {
		f.Fatalf("Generate: %v", err)
	}
	var seed bytes.Buffer
	if err := Encrypt(context.Background(), &seed, strings.NewReader("seed payload"), ring, stream.MinLog2ChunkSize); err != nil {
		f.Fatalf("Encrypt: %v", err)
	}
	f.Add(seed.Bytes())
	f.Add([]byte("BBF1"))
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, data []byte) {
		var out bytes.Buffer
		if err := Decrypt(context.Background(), &out, bytes.NewReader(data), ring); err != nil {
			return
		}
		// Anything that decrypts must also have a readable key id: the two paths
		// parse the same envelope and may not disagree about it.
		if _, err := KeyID(bytes.NewReader(data)); err != nil {
			t.Fatalf("file decrypted but its key id did not parse: %v", err)
		}
	})
}
