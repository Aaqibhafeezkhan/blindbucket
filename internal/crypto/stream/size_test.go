package stream

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"
)

// allLog2 is every chunk size the format permits.
func allLog2() []uint8 {
	var out []uint8
	for l := uint8(MinLog2ChunkSize); l <= MaxLog2ChunkSize; l++ {
		out = append(out, l)
	}
	return out
}

func TestSealedSizeKnownValues(t *testing.T) {
	t.Parallel()

	// The worked example from docs/FORMAT.md section 7.2, plus the small cases
	// that are easiest to get wrong.
	tests := []struct {
		plain  int64
		log2C  uint8
		sealed int64
	}{
		{plain: 0, log2C: 16, sealed: 48},                // empty: header + one empty chunk's tag
		{plain: 1, log2C: 16, sealed: 49},                // one chunk of one byte
		{plain: 65535, log2C: 16, sealed: 65583},         // C-1: still one chunk
		{plain: 65536, log2C: 16, sealed: 65584},         // exactly C: still one chunk
		{plain: 65537, log2C: 16, sealed: 65601},         // C+1: two chunks
		{plain: 104857600, log2C: 16, sealed: 104883232}, // 100 MiB, the FORMAT.md example
		{plain: 0, log2C: 12, sealed: 48},
		{plain: 4096, log2C: 12, sealed: 4144},
		{plain: 4097, log2C: 12, sealed: 4161},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("plain=%d/log2C=%d", tc.plain, tc.log2C), func(t *testing.T) {
			t.Parallel()
			got, err := SealedSize(tc.plain, tc.log2C)
			if err != nil {
				t.Fatalf("SealedSize(%d, %d): unexpected error: %v", tc.plain, tc.log2C, err)
			}
			if got != tc.sealed {
				t.Errorf("SealedSize(%d, %d) = %d, want %d", tc.plain, tc.log2C, got, tc.sealed)
			}

			back, err := OpenedSize(tc.sealed, tc.log2C)
			if err != nil {
				t.Fatalf("OpenedSize(%d, %d): unexpected error: %v", tc.sealed, tc.log2C, err)
			}
			if back != tc.plain {
				t.Errorf("OpenedSize(%d, %d) = %d, want %d", tc.sealed, tc.log2C, back, tc.plain)
			}
		})
	}
}

// boundaryPlaintexts returns the plaintext sizes worth testing for a chunk size:
// zero, the chunk boundaries, and one byte either side of each.
func boundaryPlaintexts(log2C uint8) []int64 {
	c := int64(1) << log2C
	var out []int64
	out = append(out, 0, 1, 2)
	for k := int64(1); k <= 4; k++ {
		out = append(out, k*c-1, k*c, k*c+1)
	}
	out = append(out, 1000*c, 1000*c+1, 1000*c-1)
	return out
}

func TestSizeRoundTripAtBoundaries(t *testing.T) {
	t.Parallel()

	for _, log2C := range allLog2() {
		t.Run(fmt.Sprintf("log2C=%d", log2C), func(t *testing.T) {
			t.Parallel()
			for _, plain := range boundaryPlaintexts(log2C) {
				sealed, err := SealedSize(plain, log2C)
				if err != nil {
					t.Fatalf("SealedSize(%d, %d): %v", plain, log2C, err)
				}
				back, err := OpenedSize(sealed, log2C)
				if err != nil {
					t.Fatalf("OpenedSize(%d, %d) for plain=%d: %v", sealed, log2C, plain, err)
				}
				if back != plain {
					t.Errorf("round trip for plain=%d log2C=%d: sealed=%d, back=%d", plain, log2C, sealed, back)
				}
			}
		})
	}
}

func TestSizeRoundTripRandom(t *testing.T) {
	t.Parallel()

	r := rand.New(rand.NewPCG(1, 2))
	for _, log2C := range allLog2() {
		for range 2000 {
			plain := r.Int64N(MaxPlaintextSize)
			sealed, err := SealedSize(plain, log2C)
			if err != nil {
				t.Fatalf("SealedSize(%d, %d): %v", plain, log2C, err)
			}
			back, err := OpenedSize(sealed, log2C)
			if err != nil {
				t.Fatalf("OpenedSize(%d, %d) for plain=%d: %v", sealed, log2C, plain, err)
			}
			if back != plain {
				t.Fatalf("round trip for plain=%d log2C=%d: sealed=%d, back=%d", plain, log2C, sealed, back)
			}
		}
	}
}

// TestOpenedSizeAcceptsExactlyReachableSizes walks every ciphertext length in a
// window and requires OpenedSize to accept precisely the lengths some plaintext
// actually produces. This is the property that matters: a size outside the image
// of SealedSize was corrupted or forged, and decoding it into a plausible number
// would hand the caller a lie.
func TestOpenedSizeAcceptsExactlyReachableSizes(t *testing.T) {
	t.Parallel()

	for _, log2C := range []uint8{12, 13, 16} {
		t.Run(fmt.Sprintf("log2C=%d", log2C), func(t *testing.T) {
			t.Parallel()

			c := int64(1) << log2C
			limit := HeaderSize + 3*(c+TagSize) + 4*TagSize

			// The plaintext bound must be derived from the ciphertext window, not
			// guessed: ciphertext is never shorter than its plaintext, so walking
			// plain up to limit covers every reachable size in range.
			reachable := make(map[int64]int64) // sealed -> plain
			for plain := int64(0); plain <= limit; plain++ {
				sealed, err := SealedSize(plain, log2C)
				if err != nil {
					t.Fatalf("SealedSize(%d, %d): %v", plain, log2C, err)
				}
				if sealed <= limit {
					reachable[sealed] = plain
				}
			}

			for sealed := int64(0); sealed <= limit; sealed++ {
				plain, err := OpenedSize(sealed, log2C)
				want, isReachable := reachable[sealed]

				switch {
				case isReachable && err != nil:
					t.Errorf("OpenedSize(%d, %d) rejected a reachable size: %v", sealed, log2C, err)
				case isReachable && plain != want:
					t.Errorf("OpenedSize(%d, %d) = %d, want %d", sealed, log2C, plain, want)
				case !isReachable && err == nil:
					t.Errorf("OpenedSize(%d, %d) accepted an unreachable size, returned %d", sealed, log2C, plain)
				case !isReachable:
					var ie *IntegrityError
					if !errors.As(err, &ie) {
						t.Errorf("OpenedSize(%d, %d) rejected with %T, want *IntegrityError", sealed, log2C, err)
					} else if ie.Kind != KindSize {
						t.Errorf("OpenedSize(%d, %d) reported kind %q, want %q", sealed, log2C, ie.Kind, KindSize)
					}
				}
			}
		})
	}
}

func TestOpenedSizeRejectsImpossibleRemainders(t *testing.T) {
	t.Parallel()

	const log2C = 16
	c := int64(1) << log2C

	// A full chunk plus a remainder of 1..16 bytes: no plaintext produces this,
	// because the tag alone already accounts for 16 bytes.
	base, err := SealedSize(c, log2C)
	if err != nil {
		t.Fatalf("SealedSize: %v", err)
	}
	for r := int64(1); r <= TagSize; r++ {
		if _, err := OpenedSize(base+r, log2C); err == nil {
			t.Errorf("OpenedSize(%d, %d) accepted remainder %d, want rejection", base+r, log2C, r)
		}
	}
	// One past the band is reachable again: it is a chunk plus one byte.
	if _, err := OpenedSize(base+TagSize+1, log2C); err != nil {
		t.Errorf("OpenedSize(%d, %d) rejected a reachable size: %v", base+TagSize+1, log2C, err)
	}
}

func TestSizeRejectsOutOfRangeInputs(t *testing.T) {
	t.Parallel()

	t.Run("sealed", func(t *testing.T) {
		t.Parallel()
		for _, sealed := range []int64{-1, 0, 1, 47, maxSealedPayload + 1} {
			if _, err := OpenedSize(sealed, DefaultLog2ChunkSize); err == nil {
				t.Errorf("OpenedSize(%d) accepted an out-of-range size", sealed)
			}
		}
	})

	t.Run("plain", func(t *testing.T) {
		t.Parallel()
		for _, plain := range []int64{-1, MaxPlaintextSize + 1} {
			if _, err := SealedSize(plain, DefaultLog2ChunkSize); err == nil {
				t.Errorf("SealedSize(%d) accepted an out-of-range size", plain)
			}
		}
	})

	t.Run("log2C", func(t *testing.T) {
		t.Parallel()
		for _, log2C := range []uint8{0, 11, 21, 30, 255} {
			if _, err := SealedSize(1, log2C); err == nil {
				t.Errorf("SealedSize with log2C=%d was accepted", log2C)
			}
			if _, err := OpenedSize(48, log2C); err == nil {
				t.Errorf("OpenedSize with log2C=%d was accepted", log2C)
			}
		}
	})

	t.Run("segments", func(t *testing.T) {
		t.Parallel()
		for _, segments := range []int64{-1, 0, MaxParts + 1} {
			if _, err := SealedSizeSegments(1, DefaultLog2ChunkSize, segments); err == nil {
				t.Errorf("SealedSizeSegments with segments=%d was accepted", segments)
			}
			if _, err := OpenedSizeSegments(48, DefaultLog2ChunkSize, segments); err == nil {
				t.Errorf("OpenedSizeSegments with segments=%d was accepted", segments)
			}
		}
	})
}

// TestMultipartSizeMatchesConcatenatedSegments checks the claim that makes listing
// sizes work: for parts obeying the size rules, the total ciphertext size depends
// only on the total plaintext size and the part count, not on where the part
// boundaries fall.
func TestMultipartSizeMatchesConcatenatedSegments(t *testing.T) {
	t.Parallel()

	const log2C = 16
	c := int64(1) << log2C

	partitions := [][]int64{
		{c, 1},
		{c, c},
		{c, c, 1},
		{80 * c, 80 * c, 3*c + 17},
		{5 * c, 5 * c, 5 * c, 5*c - 1},
		{c, c, c, c, c, c, c, c, c, 42},
	}

	for _, parts := range partitions {
		t.Run(fmt.Sprintf("parts=%d", len(parts)), func(t *testing.T) {
			t.Parallel()

			var total, concatenated int64
			for _, p := range parts {
				total += p
				segment, err := SealedSize(p, log2C)
				if err != nil {
					t.Fatalf("SealedSize(%d): %v", p, err)
				}
				concatenated += segment
			}

			formula, err := SealedSizeSegments(total, log2C, int64(len(parts)))
			if err != nil {
				t.Fatalf("SealedSizeSegments: %v", err)
			}
			if formula != concatenated {
				t.Errorf("formula gives %d, concatenated segments give %d", formula, concatenated)
			}

			back, err := OpenedSizeSegments(concatenated, log2C, int64(len(parts)))
			if err != nil {
				t.Fatalf("OpenedSizeSegments(%d, %d): %v", concatenated, len(parts), err)
			}
			if back != total {
				t.Errorf("OpenedSizeSegments = %d, want %d", back, total)
			}
		})
	}
}

// TestMultipartSizeRejectsWrongSegmentCount covers a lying provider: the ETag
// suffix claims a different part count than the object actually has.
func TestMultipartSizeRejectsWrongSegmentCount(t *testing.T) {
	t.Parallel()

	const log2C = 16
	c := int64(1) << log2C

	sealed, err := SealedSizeSegments(3*c, log2C, 3)
	if err != nil {
		t.Fatalf("SealedSizeSegments: %v", err)
	}

	// The true plaintext size must only be recoverable with the true part count.
	plain, err := OpenedSizeSegments(sealed, log2C, 3)
	if err != nil || plain != 3*c {
		t.Fatalf("OpenedSizeSegments with the true count: got %d, %v", plain, err)
	}
	for _, wrong := range []int64{1, 2, 4, 10} {
		if got, err := OpenedSizeSegments(sealed, log2C, wrong); err == nil && got == 3*c {
			t.Errorf("segment count %d recovered the correct size %d, which makes the count unverifiable", wrong, got)
		}
	}
}

func TestChunkCount(t *testing.T) {
	t.Parallel()

	const log2C = 16
	c := int64(1) << log2C
	tests := []struct{ plain, want int64 }{
		{0, 1}, {1, 1}, {c - 1, 1}, {c, 1}, {c + 1, 2}, {2 * c, 2}, {2*c + 1, 3},
	}
	for _, tc := range tests {
		if got := ChunkCount(tc.plain, log2C); got != tc.want {
			t.Errorf("ChunkCount(%d, %d) = %d, want %d", tc.plain, log2C, got, tc.want)
		}
	}
}

// FuzzOpenedSize requires that no input panics and that every accepted size is
// genuinely reachable.
func FuzzOpenedSize(f *testing.F) {
	f.Add(int64(48), uint8(16), int64(1))
	f.Add(int64(104883232), uint8(16), int64(1))
	f.Add(int64(0), uint8(0), int64(0))
	f.Add(int64(-1), uint8(255), int64(-1))

	f.Fuzz(func(t *testing.T, sealed int64, log2C uint8, segments int64) {
		plain, err := OpenedSizeSegments(sealed, log2C, segments)
		if err != nil {
			return
		}
		back, err := SealedSizeSegments(plain, log2C, segments)
		if err != nil {
			t.Fatalf("accepted sealed=%d log2C=%d segments=%d -> plain=%d, which does not seal: %v",
				sealed, log2C, segments, plain, err)
		}
		if back != sealed {
			t.Fatalf("accepted sealed=%d log2C=%d segments=%d -> plain=%d, which seals to %d",
				sealed, log2C, segments, plain, back)
		}
	})
}
