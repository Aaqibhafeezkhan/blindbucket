package stream

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestChunkNonceLayout pins the nonce layout from docs/FORMAT.md section 4.3:
// uint88_be(i) followed by the final flag. Getting this wrong would not fail any
// round-trip test -- encoder and decoder would simply agree on the wrong thing --
// so it is checked against fixed expected bytes.
func TestChunkNonceLayout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		index uint64
		final bool
		want  string
	}{
		{0, false, "000000000000000000000000"},
		{0, true, "000000000000000000000001"},
		{1, false, "000000000000000000000100"},
		{255, false, "00000000000000000000ff00"},
		{256, true, "000000000000000000010001"},
		{1<<32 - 1, false, "00000000000000ffffffff00"},
		{1<<64 - 1, true, "000000ffffffffffffffff01"},
	}

	for _, tc := range tests {
		got := chunkNonce(tc.index, tc.final)
		if hex.EncodeToString(got[:]) != tc.want {
			t.Errorf("chunkNonce(%d, %t) = %x, want %s", tc.index, tc.final, got, tc.want)
		}
	}
}

// TestSetNonceMatchesChunkNonce keeps the allocation-free hot path honest: the
// in-place nonce builder must agree with the readable reference in every case,
// including the transition back from a final chunk.
func TestSetNonceMatchesChunkNonce(t *testing.T) {
	t.Parallel()

	h, err := newHeader(singlePart(DefaultLog2ChunkSize))
	if err != nil {
		t.Fatalf("newHeader: %v", err)
	}
	s, err := newSealer(testDEK, h)
	if err != nil {
		t.Fatalf("newSealer: %v", err)
	}

	// Interleave final and non-final so a stale flag byte would show up.
	for _, index := range []uint64{0, 1, 2, 1 << 20, 1<<64 - 1, 7} {
		for _, final := range []bool{true, false, true} {
			want := chunkNonce(index, final)
			s.setNonce(index, final)
			if !bytes.Equal(s.nonce[:], want[:]) {
				t.Fatalf("setNonce(%d, %t) = %x, chunkNonce says %x", index, final, s.nonce, want)
			}
		}
	}
}

// TestSubkeyDependsOnSalt is the reason retries are safe: two segments with
// different salts must not share an encryption key, so reusing a chunk counter
// across upload attempts cannot repeat a (key, nonce) pair.
func TestSubkeyDependsOnSalt(t *testing.T) {
	t.Parallel()

	var a, b [SaltSize]byte
	b[SaltSize-1] = 1

	keyA, err := deriveSubkey(testDEK, a)
	if err != nil {
		t.Fatalf("deriveSubkey: %v", err)
	}
	keyB, err := deriveSubkey(testDEK, b)
	if err != nil {
		t.Fatalf("deriveSubkey: %v", err)
	}
	if bytes.Equal(keyA, keyB) {
		t.Error("salts differing in one bit produced the same subkey")
	}
	if len(keyA) != KeySize {
		t.Errorf("subkey is %d bytes, want %d", len(keyA), KeySize)
	}

	// And it must be deterministic, or nothing would decrypt twice.
	again, err := deriveSubkey(testDEK, a)
	if err != nil {
		t.Fatalf("deriveSubkey: %v", err)
	}
	if !bytes.Equal(keyA, again) {
		t.Error("subkey derivation is not deterministic")
	}
}

// TestAnyChunkSizeAcceptsWhatTheHeaderDeclares covers the wildcard the file
// format relies on, and confirms a stated size still has to match.
func TestAnyChunkSizeAcceptsWhatTheHeaderDeclares(t *testing.T) {
	t.Parallel()

	for _, log2C := range []uint8{12, 16, 20} {
		plain := bytes.Repeat([]byte{3}, 5000)
		sealed := sealSegment(t, testDEK, singlePart(log2C), plain)

		got, err := openSegment(testDEK, SegmentParams{Log2ChunkSize: AnyChunkSize}, sealed)
		if err != nil {
			t.Fatalf("log2C=%d: AnyChunkSize rejected a valid segment: %v", log2C, err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("log2C=%d: plaintext differs", log2C)
		}

		// A caller that names a size still gets it enforced.
		wrong := log2C + 1
		if wrong > MaxLog2ChunkSize {
			wrong = MinLog2ChunkSize
		}
		_, err = openSegment(testDEK, singlePart(wrong), sealed)
		requireIntegrityError(t, "explicit chunk size mismatch", err)
	}
}
