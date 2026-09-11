package manifest

import (
	"errors"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
)

// sealed is the ciphertext size of a part carrying plain bytes.
func sealed(t *testing.T, plain int64, log2C uint8) int64 {
	t.Helper()
	s, err := stream.SealedSize(plain, log2C)
	if err != nil {
		t.Fatalf("SealedSize(%d): %v", plain, err)
	}
	return s
}

func TestPartsFromUpstream(t *testing.T) {
	const log2C = 16

	uploaded := []UploadedPart{
		{Number: 1, CipherSize: sealed(t, 8<<20, log2C)},
		{Number: 2, CipherSize: sealed(t, 8<<20, log2C)},
		{Number: 3, CipherSize: sealed(t, 5000, log2C)}, // last part, unaligned is fine
	}
	parts, err := PartsFromUpstream(uploaded, log2C)
	if err != nil {
		t.Fatalf("PartsFromUpstream: %v", err)
	}
	want := []int64{8 << 20, 8 << 20, 5000}
	for i, p := range parts {
		if p.PlainSize != want[i] {
			t.Errorf("part %d: got %d, want %d", p.Number, p.PlainSize, want[i])
		}
	}

	// The whole point of the rules: the total inverts from ciphertext size and
	// part count alone, which is what a listing has to work from.
	var totalCipher, totalPlain int64
	for i, up := range uploaded {
		totalCipher += up.CipherSize
		totalPlain += parts[i].PlainSize
	}
	got, err := stream.OpenedSizeSegments(totalCipher, log2C, int64(len(parts)))
	if err != nil {
		t.Fatalf("OpenedSizeSegments: %v", err)
	}
	if got != totalPlain {
		t.Errorf("listing arithmetic gives %d, the parts sum to %d", got, totalPlain)
	}
}

func TestPartsFromUpstreamRejectsBrokenRules(t *testing.T) {
	const log2C = 16
	chunk := int64(1) << log2C

	cases := []struct {
		name     string
		uploaded []UploadedPart
		want     error
	}{
		{
			name:     "no parts",
			uploaded: nil,
			want:     ErrPartRules,
		},
		{
			// The rule that matters: a non-final part off the chunk grid makes
			// the total size unrecoverable.
			name: "non-final part not a multiple of the chunk size",
			uploaded: []UploadedPart{
				{Number: 1, CipherSize: sealed(t, chunk+1, log2C)},
				{Number: 2, CipherSize: sealed(t, 100, log2C)},
			},
			want: ErrPartRules,
		},
		{
			name:     "empty last part",
			uploaded: []UploadedPart{{Number: 1, CipherSize: sealed(t, 0, log2C)}},
			want:     ErrPartRules,
		},
		{
			name: "empty middle part",
			uploaded: []UploadedPart{
				{Number: 1, CipherSize: sealed(t, 0, log2C)},
				{Number: 2, CipherSize: sealed(t, 10, log2C)},
			},
			want: ErrPartRules,
		},
		{
			name:     "ciphertext size no encoder produces",
			uploaded: []UploadedPart{{Number: 1, CipherSize: 33}},
			want:     ErrPartRules,
		},
		{
			name:     "part beyond the 5 GiB ceiling",
			uploaded: []UploadedPart{{Number: 1, CipherSize: MaxPartCiphertext + 1}},
			want:     ErrPartTooLarge,
		},
		{
			name: "repeated part number",
			uploaded: []UploadedPart{
				{Number: 2, CipherSize: sealed(t, chunk, log2C)},
				{Number: 2, CipherSize: sealed(t, 10, log2C)},
			},
			want: ErrPartRules,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PartsFromUpstream(tc.uploaded, log2C)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// A single part is legal and needs no alignment, because it is also the last.
func TestSinglePartNeedsNoAlignment(t *testing.T) {
	const log2C = 16
	parts, err := PartsFromUpstream(
		[]UploadedPart{{Number: 1, CipherSize: sealed(t, 12345, log2C)}}, log2C)
	if err != nil {
		t.Fatalf("PartsFromUpstream: %v", err)
	}
	if len(parts) != 1 || parts[0].PlainSize != 12345 {
		t.Fatalf("got %+v", parts)
	}
}

// The default part sizes of the common clients must pass at every permitted
// chunk size. If this fails, the gateway rejects ordinary uploads.
func TestClientDefaultPartSizesAreLegal(t *testing.T) {
	defaults := map[string]int64{
		"aws cli / boto3": 8 << 20,
		"minimum allowed": 5 << 20,
		"rclone":          5 << 20,
		"mc":              16 << 20,
		"large":           64 << 20,
	}
	for log2C := uint8(stream.MinLog2ChunkSize); log2C <= stream.MaxLog2ChunkSize; log2C++ {
		for name, size := range defaults {
			uploaded := []UploadedPart{
				{Number: 1, CipherSize: sealed(t, size, log2C)},
				{Number: 2, CipherSize: sealed(t, 1, log2C)},
			}
			if _, err := PartsFromUpstream(uploaded, log2C); err != nil {
				t.Errorf("chunk size 2^%d, %s part of %d bytes: %v", log2C, name, size, err)
			}
		}
	}
}

func TestMaxPartPlaintext(t *testing.T) {
	for log2C := uint8(stream.MinLog2ChunkSize); log2C <= stream.MaxLog2ChunkSize; log2C++ {
		maximum, err := MaxPartPlaintext(log2C)
		if err != nil {
			t.Fatalf("chunk size 2^%d: %v", log2C, err)
		}
		s, err := stream.SealedSize(maximum, log2C)
		if err != nil || s > MaxPartCiphertext {
			t.Errorf("chunk size 2^%d: %d bytes seals to %d, over the limit (%v)",
				log2C, maximum, s, err)
		}
		// One chunk more must not fit, or the bound is not tight.
		if s, err := stream.SealedSize(maximum+(int64(1)<<log2C), log2C); err == nil &&
			s <= MaxPartCiphertext {
			t.Errorf("chunk size 2^%d: bound %d is not tight", log2C, maximum)
		}
	}
}
