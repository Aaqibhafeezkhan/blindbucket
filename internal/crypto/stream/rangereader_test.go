package stream

import (
	"bytes"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"testing"
)

// rangeSegment builds a segment whose plaintext is a recognisable pattern, so a
// range that returns the wrong bytes is obvious rather than merely unequal.
func rangeSegment(t *testing.T, log2C uint8, size int) (plain, sealed []byte) {
	t.Helper()
	plain = make([]byte, size)
	for i := range plain {
		plain[i] = byte(i*31 + 7)
	}
	return plain, sealSegment(t, testDEK, singlePart(log2C), plain)
}

// readRange performs a range read the way the proxy will: the header is fetched
// separately, and the ciphertext is served from the mapped offsets.
func readRange(t *testing.T, sealed []byte, log2C uint8, start, end int64) ([]byte, error) {
	t.Helper()

	rng, err := MapRange(start, end, int64(len(sealed)), log2C)
	if err != nil {
		return nil, err
	}
	if rng.CipherStart < HeaderSize || rng.CipherEnd >= int64(len(sealed)) {
		t.Fatalf("mapped ciphertext %d-%d lies outside the %d-byte segment",
			rng.CipherStart, rng.CipherEnd, len(sealed))
	}

	src := bytes.NewReader(sealed[rng.CipherStart : rng.CipherEnd+1])
	r, err := NewRangeReader(src, sealed[:HeaderSize], testDEK, singlePart(log2C), rng)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()

	if err := r.VerifyFirst(); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if _, err := out.ReadFrom(r); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func TestMapRangeWorkedExample(t *testing.T) {
	t.Parallel()

	// The example from docs/FORMAT.md section 8: a 100 MiB object, bytes
	// 1000000-1999999 at the default chunk size.
	const plain = 100 << 20
	sealed, err := SealedSize(plain, DefaultLog2ChunkSize)
	if err != nil {
		t.Fatalf("SealedSize: %v", err)
	}

	rng, err := MapRange(1000000, 1999999, sealed, DefaultLog2ChunkSize)
	if err != nil {
		t.Fatalf("MapRange: %v", err)
	}

	checks := []struct {
		name      string
		got, want int64
	}{
		{"first chunk", int64(rng.FirstChunk), 15},
		{"last chunk", int64(rng.LastChunk), 30},
		{"cipher start", rng.CipherStart, 983312},
		{"cipher end", rng.CipherEnd, 2032143},
		{"skip", rng.Skip, 16960},
		{"length", rng.Length, 1000000},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
	if rng.LastIsFinal {
		t.Error("chunk 30 of 1600 was reported as final")
	}
	if !rng.NeedsSeparateHeader {
		t.Error("a range starting at chunk 15 needs the header fetched separately")
	}
	// The fetched ciphertext must be exactly the 16 chunks it covers.
	if got, want := rng.CipherEnd-rng.CipherStart+1, int64(16*(65536+16)); got != want {
		t.Errorf("fetched %d ciphertext bytes, want %d", got, want)
	}
}

func TestRangeReadMatchesPlaintext(t *testing.T) {
	t.Parallel()

	const log2C = 12
	c := 1 << log2C

	for _, size := range []int{1, c - 1, c, c + 1, 3*c + 100} {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			t.Parallel()
			plain, sealed := rangeSegment(t, log2C, size)

			// Every single-byte range, plus a sample of wider ones. Chunk
			// boundaries are where the arithmetic goes wrong if it is wrong.
			var ranges [][2]int64
			for i := range int64(size) {
				ranges = append(ranges, [2]int64{i, i})
			}
			for _, edge := range []int64{0, 1, int64(c) - 1, int64(c), int64(c) + 1} {
				if edge < int64(size) {
					ranges = append(ranges, [2]int64{edge, int64(size) - 1})
					ranges = append(ranges, [2]int64{0, edge})
				}
			}

			for _, rg := range ranges {
				got, err := readRange(t, sealed, log2C, rg[0], rg[1])
				if err != nil {
					t.Fatalf("range %d-%d: %v", rg[0], rg[1], err)
				}
				want := plain[rg[0] : rg[1]+1]
				if !bytes.Equal(got, want) {
					t.Fatalf("range %d-%d returned %d bytes, want %d (first mismatch at %d)",
						rg[0], rg[1], len(got), len(want), firstDiff(got, want))
				}
			}
		})
	}
}

func TestRangeReadRandom(t *testing.T) {
	t.Parallel()

	const log2C = 12
	plain, sealed := rangeSegment(t, log2C, 20000)
	r := mrand.New(mrand.NewPCG(3, 5))

	for range 2000 {
		start := r.Int64N(int64(len(plain)))
		end := start + r.Int64N(int64(len(plain))-start)
		got, err := readRange(t, sealed, log2C, start, end)
		if err != nil {
			t.Fatalf("range %d-%d: %v", start, end, err)
		}
		if want := plain[start : end+1]; !bytes.Equal(got, want) {
			t.Fatalf("range %d-%d differs at offset %d", start, end, firstDiff(got, want))
		}
	}
}

// TestRangeReadClampsPastTheEnd matches HTTP semantics: a range whose end runs
// past the object is served up to the last byte rather than refused.
func TestRangeReadClampsPastTheEnd(t *testing.T) {
	t.Parallel()

	const log2C = 12
	plain, sealed := rangeSegment(t, log2C, 5000)

	got, err := readRange(t, sealed, log2C, 4900, 999999)
	if err != nil {
		t.Fatalf("MapRange: %v", err)
	}
	if !bytes.Equal(got, plain[4900:]) {
		t.Errorf("got %d bytes, want the final %d", len(got), len(plain)-4900)
	}
}

func TestMapRangeRejectsImpossibleRanges(t *testing.T) {
	t.Parallel()

	const log2C = 12
	_, sealed := rangeSegment(t, log2C, 5000)
	size := int64(len(sealed))

	bad := [][2]int64{
		{-1, 10},
		{10, 5},
		{5000, 5100},
		{99999, 100000},
	}
	for _, rg := range bad {
		if _, err := MapRange(rg[0], rg[1], size, log2C); err == nil {
			t.Errorf("range %d-%d was accepted", rg[0], rg[1])
		}
	}
	if _, err := MapRange(0, 10, size, log2C); err != nil {
		t.Errorf("a valid range was refused: %v", err)
	}
}

// TestRangeReadDetectsTampering is the point of authenticating per chunk: a
// range read must be as safe as a whole-object read.
func TestRangeReadDetectsTampering(t *testing.T) {
	t.Parallel()

	const log2C = 12
	c := int64(1) << log2C
	_, sealed := rangeSegment(t, log2C, int(4*c))

	tests := map[string]func(b []byte) []byte{
		"a bit flipped inside the range": func(b []byte) []byte {
			b[HeaderSize+int(c+TagSize)+20] ^= 0x01
			return b
		},
		"the header replaced": func(b []byte) []byte {
			b[offSalt] ^= 0xff
			return b
		},
		"a chunk moved": func(b []byte) []byte {
			size := int(c + TagSize)
			copy(b[HeaderSize+size:HeaderSize+2*size], b[HeaderSize:HeaderSize+size])
			return b
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := readRange(t, mutate(bytes.Clone(sealed)), log2C, c, 2*c+50)
			if err == nil {
				t.Fatal("tampered ciphertext produced plaintext")
			}
			var ie *IntegrityError
			if !errors.As(err, &ie) {
				t.Errorf("got %T (%v), want *IntegrityError", err, err)
			}
		})
	}
}

// TestRangeReadRejectsShortUpstream covers a provider that returns less than the
// range it was asked for.
func TestRangeReadRejectsShortUpstream(t *testing.T) {
	t.Parallel()

	const log2C = 12
	c := int64(1) << log2C
	_, sealed := rangeSegment(t, log2C, int(4*c))

	rng, err := MapRange(0, 2*c, int64(len(sealed)), log2C)
	if err != nil {
		t.Fatalf("MapRange: %v", err)
	}
	truncated := sealed[rng.CipherStart : rng.CipherEnd-100]

	r, err := NewRangeReader(bytes.NewReader(truncated), sealed[:HeaderSize], testDEK,
		singlePart(log2C), rng)
	if err != nil {
		t.Fatalf("NewRangeReader: %v", err)
	}
	defer func() { _ = r.Close() }()

	var out bytes.Buffer
	if _, err := out.ReadFrom(r); err == nil {
		t.Error("a short upstream response was accepted")
	}
}

// TestRangeReadFinalChunkFlag checks the case the nonce depends on: the last
// chunk of the object must be opened as final, and only it.
func TestRangeReadFinalChunkFlag(t *testing.T) {
	t.Parallel()

	const log2C = 12
	c := int64(1) << log2C
	plain, sealed := rangeSegment(t, log2C, int(3*c)+17)

	// A range ending exactly at the last byte touches the final chunk.
	rng, err := MapRange(3*c, 3*c+16, int64(len(sealed)), log2C)
	if err != nil {
		t.Fatalf("MapRange: %v", err)
	}
	if !rng.LastIsFinal {
		t.Error("the range covering the last byte was not marked final")
	}
	got, err := readRange(t, sealed, log2C, 3*c, 3*c+16)
	if err != nil {
		t.Fatalf("reading the final chunk: %v", err)
	}
	if !bytes.Equal(got, plain[3*c:]) {
		t.Error("the final chunk returned the wrong bytes")
	}

	// A range stopping one chunk earlier must not be.
	earlier, err := MapRange(0, c-1, int64(len(sealed)), log2C)
	if err != nil {
		t.Fatalf("MapRange: %v", err)
	}
	if earlier.LastIsFinal {
		t.Error("a range ending at chunk 0 of 4 was marked final")
	}
}

func firstDiff(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}
