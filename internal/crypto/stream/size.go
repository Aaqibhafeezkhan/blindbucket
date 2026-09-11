package stream

import "fmt"

// maxSealedPayload bounds the ciphertext sizes this package will reason about,
// so that the inverse arithmetic cannot overflow on an attacker-supplied length.
// It sits above the largest value SealedSizeSegments can return for
// MaxPlaintextSize at the smallest permitted chunk size.
const maxSealedPayload = 1 << 47

// ChunkCount returns the number of chunks a single segment carrying plain bytes
// of plaintext contains.
//
// A segment always holds at least one chunk: an empty segment is one chunk
// carrying zero bytes of plaintext, which is a bare authentication tag. That is
// what makes the header of an empty segment authenticated like any other.
func ChunkCount(plain int64, log2C uint8) int64 {
	c := int64(1) << log2C
	if n := (plain + c - 1) / c; n > 0 {
		return n
	}
	return 1
}

// SealedSize returns the exact ciphertext size of a single segment carrying
// plain bytes of plaintext.
//
// The format is deterministic in length, which is what lets the proxy set an
// exact upstream Content-Length before reading the first byte of the body. The
// same property means the storage provider can compute the plaintext size; that
// is an accepted metadata leak, recorded in docs/THREAT_MODEL.md.
func SealedSize(plain int64, log2C uint8) (int64, error) {
	return SealedSizeSegments(plain, log2C, 1)
}

// SealedSizeSegments returns the exact ciphertext size of an object made of
// segments concatenated segments carrying plain bytes of plaintext in total.
//
// For segments > 1 the result is only correct if every segment except the last
// carries an exact multiple of the chunk size and no segment is empty, which is
// what docs/FORMAT.md section 7.3 requires of multipart parts. Under that rule
// the total chunk count collapses to ceil(plain/C) regardless of where the part
// boundaries fall, which is why the plaintext size of a multipart object can be
// recovered from its ciphertext size and part count alone.
func SealedSizeSegments(plain int64, log2C uint8, segments int64) (int64, error) {
	if err := ValidateLog2ChunkSize(log2C); err != nil {
		return 0, err
	}
	if err := validateSegmentCount(segments); err != nil {
		return 0, err
	}
	if plain < 0 || plain > MaxPlaintextSize {
		return 0, fmt.Errorf("stream: plaintext size %d outside 0..%d", plain, int64(MaxPlaintextSize))
	}

	// A segment always contributes at least one chunk. The max only takes effect
	// for the single empty segment, since valid multipart parts are never empty.
	chunks := (plain + int64(1)<<log2C - 1) / (int64(1) << log2C)
	if chunks < segments {
		chunks = segments
	}
	return HeaderSize*segments + plain + TagSize*chunks, nil
}

// OpenedSize inverts SealedSize for a single segment.
func OpenedSize(sealed int64, log2C uint8) (int64, error) {
	return OpenedSizeSegments(sealed, log2C, 1)
}

// OpenedSizeSegments inverts SealedSizeSegments, recovering the plaintext size of
// an object from its ciphertext size and its number of segments.
//
// Not every length is reachable. A plaintext of q*C + r bytes with 1 <= r < C
// leaves a remainder of r+16 modulo C+16, and an exact multiple of C leaves 0, so
// remainders of 1..16 are produced by no encoder at all. A size in that range
// means the value was corrupted or forged and is reported as an integrity
// failure rather than decoded into a plausible-looking number.
func OpenedSizeSegments(sealed int64, log2C uint8, segments int64) (int64, error) {
	if err := ValidateLog2ChunkSize(log2C); err != nil {
		return 0, err
	}
	if err := validateSegmentCount(segments); err != nil {
		return 0, err
	}

	minimum := HeaderSize*segments + TagSize
	if sealed < minimum {
		return 0, integrityf(KindSize,
			"ciphertext size %d is below the minimum %d for %d segment(s)", sealed, minimum, segments)
	}
	if sealed > maxSealedPayload {
		return 0, integrityf(KindSize, "ciphertext size %d exceeds the supported maximum", sealed)
	}

	stride := int64(1)<<log2C + TagSize
	payload := sealed - HeaderSize*segments

	// payload == TagSize is the empty single segment: one chunk of zero bytes.
	// It is the one case whose remainder legitimately falls in the excluded band.
	if payload != TagSize {
		if r := payload % stride; r >= 1 && r <= TagSize {
			return 0, integrityf(KindSize,
				"ciphertext size %d leaves remainder %d, which no encoder produces", sealed, r)
		}
	}

	chunks := (payload + stride - 1) / stride
	plain := payload - TagSize*chunks
	if plain < 0 {
		return 0, integrityf(KindSize, "ciphertext size %d yields a negative plaintext size", sealed)
	}

	// Recomputing forward is the cheapest way to be certain: it rejects every
	// length the rules above might have let through, including counts of segments
	// that cannot hold the recovered plaintext.
	if back, err := SealedSizeSegments(plain, log2C, segments); err != nil || back != sealed {
		return 0, integrityf(KindSize,
			"ciphertext size %d corresponds to no plaintext size for %d segment(s)", sealed, segments)
	}
	return plain, nil
}

func validateSegmentCount(segments int64) error {
	if segments < 1 || segments > MaxParts {
		return fmt.Errorf("stream: segment count %d outside 1..%d", segments, MaxParts)
	}
	return nil
}
