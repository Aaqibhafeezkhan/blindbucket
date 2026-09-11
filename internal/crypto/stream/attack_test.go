package stream

import (
	"bytes"
	"fmt"
	"runtime"
	"testing"
)

// Attack tests simulate an active storage provider (actor A2 in
// docs/THREAT_MODEL.md). Every one of them must produce an error. Returning
// plaintext -- any plaintext -- is the failure being tested for.

const (
	attackLog2C = 12
	attackChunk = 1 << attackLog2C
)

// attackSegment returns a four-chunk segment: three full chunks and a partial
// final one, which exercises both the full and short paths of the decoder.
func attackSegment(t *testing.T) (plain, sealed []byte) {
	t.Helper()
	plain = make([]byte, 3*attackChunk+100)
	for i := range plain {
		plain[i] = byte(i)
	}
	return plain, sealSegment(t, testDEK, singlePart(attackLog2C), plain)
}

// chunkStart returns the ciphertext offset of full chunk i.
func chunkStart(i int) int { return HeaderSize + i*(attackChunk+TagSize) }

func TestAttackHeaderSingleBitFlips(t *testing.T) {
	t.Parallel()

	_, sealed := attackSegment(t)

	// Every single-bit change anywhere in the header must be caught: the fields
	// are validated on parse, and the whole header is the associated data of
	// every chunk, so even the salt cannot be touched unnoticed.
	for byteIdx := range HeaderSize {
		for bit := range 8 {
			tampered := bytes.Clone(sealed)
			tampered[byteIdx] ^= 1 << bit

			_, err := openSegment(testDEK, singlePart(attackLog2C), tampered)
			requireIntegrityError(t, fmt.Sprintf("header byte %d bit %d flipped", byteIdx, bit), err)
		}
	}
}

func TestAttackHeaderFields(t *testing.T) {
	t.Parallel()

	_, sealed := attackSegment(t)

	tests := []struct {
		name   string
		mutate func(b []byte)
	}{
		{"bad magic", func(b []byte) { copy(b[offMagic:], "XXXX") }},
		{"unknown version", func(b []byte) { b[offVersion] = 2 }},
		{"version zero", func(b []byte) { b[offVersion] = 0 }},
		{"chunk size below minimum", func(b []byte) { b[offLog2C] = MinLog2ChunkSize - 1 }},
		{"chunk size above maximum", func(b []byte) { b[offLog2C] = MaxLog2ChunkSize + 1 }},
		{"chunk size reinterpreted", func(b []byte) { b[offLog2C] = attackLog2C + 1 }},
		{"reserved byte set", func(b []byte) { b[offReserved] = 1 }},
		{"undefined flag bit", func(b []byte) { b[offFlags] = 0x02 }},
		{"multipart flag set", func(b []byte) { b[offFlags] = flagMultipart }},
		{"segment index changed", func(b []byte) { b[offIndex+3] = 5 }},
		{"salt changed", func(b []byte) { b[offSalt] ^= 0xff }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tampered := bytes.Clone(sealed)
			tc.mutate(tampered)
			_, err := openSegment(testDEK, singlePart(attackLog2C), tampered)
			requireIntegrityError(t, tc.name, err)
		})
	}
}

// TestAttackOversizedChunkSizeAllocatesNothing is the allocation guard from
// docs/FORMAT.md section 5.2. A header is attacker-controlled and unauthenticated
// until the first chunk verifies, so a claim of 2^30-byte chunks must be rejected
// before any buffer is sized from it.
func TestAttackOversizedChunkSizeAllocatesNothing(t *testing.T) {
	// Deliberately not t.Parallel(): the budget is checked against
	// runtime.MemStats, which counts allocations for the whole process. A
	// parallel sibling allocating at the same time is charged to this test and
	// fails it for no reason -- which is exactly what happened while the machine
	// was busy running benchmarks. Go defers parallel tests until the sequential
	// ones finish, so staying sequential is what makes the measurement mean
	// anything.
	_, sealed := attackSegment(t)
	tampered := bytes.Clone(sealed)
	tampered[offLog2C] = 30 // 1 GiB chunks

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	_, err := openSegment(testDEK, singlePart(attackLog2C), tampered)

	runtime.ReadMemStats(&after)
	requireIntegrityError(t, "log2C = 30", err)

	const budget = 1 << 20
	if grew := after.TotalAlloc - before.TotalAlloc; grew > budget {
		t.Errorf("rejecting a 1 GiB chunk-size claim allocated %d bytes, budget is %d", grew, budget)
	}
}

func TestAttackChunkTampering(t *testing.T) {
	t.Parallel()

	_, sealed := attackSegment(t)

	tests := []struct {
		name   string
		mutate func(b []byte) []byte
	}{
		{"bit flip in the first chunk's data", func(b []byte) []byte {
			b[chunkStart(0)] ^= 0x01
			return b
		}},
		{"bit flip in a middle chunk's data", func(b []byte) []byte {
			b[chunkStart(1)+7] ^= 0x80
			return b
		}},
		{"bit flip in the final chunk's data", func(b []byte) []byte {
			b[chunkStart(3)] ^= 0x01
			return b
		}},
		{"bit flip in the first chunk's tag", func(b []byte) []byte {
			b[chunkStart(1)-1] ^= 0x01
			return b
		}},
		{"bit flip in the final chunk's tag", func(b []byte) []byte {
			b[len(b)-1] ^= 0x01
			return b
		}},
		{"two full chunks swapped", func(b []byte) []byte {
			a, c := chunkStart(0), chunkStart(1)
			size := attackChunk + TagSize
			tmp := bytes.Clone(b[a : a+size])
			copy(b[a:a+size], b[c:c+size])
			copy(b[c:c+size], tmp)
			return b
		}},
		{"a chunk duplicated over its successor", func(b []byte) []byte {
			a, c := chunkStart(0), chunkStart(1)
			size := attackChunk + TagSize
			copy(b[c:c+size], b[a:a+size])
			return b
		}},
		{"final chunk removed", func(b []byte) []byte {
			return b[:chunkStart(3)]
		}},
		{"truncated exactly at a chunk boundary", func(b []byte) []byte {
			return b[:chunkStart(2)]
		}},
		{"truncated inside a chunk", func(b []byte) []byte {
			return b[:chunkStart(2)+17]
		}},
		{"truncated to the header alone", func(b []byte) []byte {
			return b[:HeaderSize]
		}},
		{"truncated inside the final tag", func(b []byte) []byte {
			return b[:len(b)-1]
		}},
		{"extra bytes appended", func(b []byte) []byte {
			return append(b, 0x00)
		}},
		{"a full extra chunk appended", func(b []byte) []byte {
			return append(b, bytes.Repeat([]byte{0}, attackChunk+TagSize)...)
		}},
		{"first chunk repeated at the end", func(b []byte) []byte {
			size := attackChunk + TagSize
			return append(b, b[chunkStart(0):chunkStart(0)+size]...)
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := openSegment(testDEK, singlePart(attackLog2C), tc.mutate(bytes.Clone(sealed)))
			requireIntegrityError(t, tc.name, err)
		})
	}
}

// TestAttackNoPlaintextBeforeTheFailingChunk checks the fail-closed rule at the
// level this package is responsible for: a reader may hand out the plaintext of
// chunks that verified, but not one byte of the chunk that did not.
func TestAttackNoPlaintextBeforeTheFailingChunk(t *testing.T) {
	t.Parallel()

	plain, sealed := attackSegment(t)

	tampered := bytes.Clone(sealed)
	tampered[chunkStart(2)+11] ^= 0x40 // corrupt the third chunk

	r, err := NewDecryptReader(bytes.NewReader(tampered), testDEK, singlePart(attackLog2C))
	if err != nil {
		t.Fatalf("NewDecryptReader: %v", err)
	}
	defer func() { _ = r.Close() }()

	var got bytes.Buffer
	if _, err := got.ReadFrom(r); err == nil {
		t.Fatal("expected an integrity failure, got a complete read")
	}

	// Exactly the first two chunks were authentic, so exactly those may have been
	// released -- no more, and nothing from the corrupted chunk.
	if n := got.Len(); n != 2*attackChunk {
		t.Errorf("released %d bytes before failing, want exactly the %d verified bytes", n, 2*attackChunk)
	}
	if !bytes.Equal(got.Bytes(), plain[:got.Len()]) {
		t.Error("the bytes released before the failure were not authentic plaintext")
	}
}

// TestAttackVerifyFirstCatchesTamperingUpFront covers the proxy's ordering
// requirement: tampering that reaches the first chunk must be detectable before
// any status line is committed to.
func TestAttackVerifyFirstCatchesTamperingUpFront(t *testing.T) {
	t.Parallel()

	_, sealed := attackSegment(t)

	tests := map[string]func(b []byte){
		"salt changed":     func(b []byte) { b[offSalt+3] ^= 0xff },
		"first chunk data": func(b []byte) { b[chunkStart(0)+2] ^= 0x01 },
		"first chunk tag":  func(b []byte) { b[chunkStart(1)-3] ^= 0x01 },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tampered := bytes.Clone(sealed)
			mutate(tampered)

			r, err := NewDecryptReader(bytes.NewReader(tampered), testDEK, singlePart(attackLog2C))
			if err != nil {
				requireIntegrityError(t, name, err) // caught even earlier, at the header
				return
			}
			defer func() { _ = r.Close() }()
			requireIntegrityError(t, name, r.VerifyFirst())
		})
	}
}

func TestAttackMultipartSegmentIdentity(t *testing.T) {
	t.Parallel()

	part3 := SegmentParams{Log2ChunkSize: attackLog2C, Multipart: true, Index: 3}
	plain := bytes.Repeat([]byte{9}, attackChunk+5)
	sealed := sealSegment(t, testDEK, part3, plain)

	if got, err := openSegment(testDEK, part3, sealed); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("the segment must decrypt as itself: %v", err)
	}

	wrong := map[string]SegmentParams{
		"a different part number":        {Log2ChunkSize: attackLog2C, Multipart: true, Index: 4},
		"read as a single-part object":   {Log2ChunkSize: attackLog2C},
		"read with the wrong chunk size": {Log2ChunkSize: attackLog2C + 1, Multipart: true, Index: 3},
	}
	for name, want := range wrong {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := openSegment(testDEK, want, sealed)
			requireIntegrityError(t, name, err)
		})
	}

	// Renumbering the part in the header must fail too: the index is in the
	// associated data of every chunk, so it cannot be rewritten to match.
	t.Run("part renumbered in the header", func(t *testing.T) {
		t.Parallel()
		tampered := bytes.Clone(sealed)
		tampered[offIndex+3] = 4
		_, err := openSegment(testDEK, SegmentParams{Log2ChunkSize: attackLog2C, Multipart: true, Index: 4}, tampered)
		requireIntegrityError(t, "part renumbered", err)
	})
}

// TestAttackEmptySegmentCannotBeSmuggled checks the one place the format allows
// a zero-byte chunk: only as the single chunk of an empty segment.
func TestAttackEmptySegmentCannotBeSmuggled(t *testing.T) {
	t.Parallel()

	empty := sealSegment(t, testDEK, singlePart(attackLog2C), nil)
	if got, err := openSegment(testDEK, singlePart(attackLog2C), empty); err != nil || len(got) != 0 {
		t.Fatalf("an empty segment must decrypt to nothing: %d bytes, %v", len(got), err)
	}

	// A bare tag appended to a complete segment claims a second, empty chunk.
	_, sealed := attackSegment(t)
	tampered := append(bytes.Clone(sealed), empty[HeaderSize:]...)
	_, err := openSegment(testDEK, singlePart(attackLog2C), tampered)
	requireIntegrityError(t, "empty chunk appended", err)
}
