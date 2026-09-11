package stream

import (
	"errors"
	"fmt"
	"io"
)

// Range describes the ciphertext a plaintext byte range maps to.
//
// The mapping is pure arithmetic because the format is deterministic in length:
// chunk boundaries sit at fixed offsets, so a range read fetches only the chunks
// it touches rather than the whole object. See docs/FORMAT.md section 8.
type Range struct {
	// FirstChunk and LastChunk are the chunk indices the range touches.
	FirstChunk, LastChunk uint64
	// CipherStart and CipherEnd are inclusive ciphertext offsets covering those
	// chunks, excluding the segment header.
	CipherStart, CipherEnd int64
	// Skip is how many leading plaintext bytes of FirstChunk to discard.
	Skip int64
	// Length is how many plaintext bytes to emit.
	Length int64
	// LastIsFinal reports whether LastChunk is the segment's final chunk, which
	// determines the nonce it must be opened with.
	LastIsFinal bool
	// NeedsSeparateHeader reports whether the header lies outside
	// CipherStart..CipherEnd, so it has to be fetched on its own.
	NeedsSeparateHeader bool
}

// ErrRangeNotSatisfiable reports a range outside the object.
var ErrRangeNotSatisfiable = errors.New("stream: range not satisfiable")

// MapRange maps an inclusive plaintext range onto the ciphertext of a segment.
//
// sealed is the segment's total ciphertext size, which the caller learns from
// the provider. It is not authenticated, and it does not have to be: it only
// decides which chunk is treated as final, and a chunk opened under the wrong
// final flag fails authentication. A provider that lies here causes a failure,
// not a wrong answer.
func MapRange(start, end, sealed int64, log2C uint8) (Range, error) {
	plain, err := OpenedSize(sealed, log2C)
	if err != nil {
		return Range{}, err
	}
	if start < 0 || end < start {
		return Range{}, fmt.Errorf("%w: %d-%d", ErrRangeNotSatisfiable, start, end)
	}
	if start >= plain {
		return Range{}, fmt.Errorf("%w: offset %d is past the end of %d bytes",
			ErrRangeNotSatisfiable, start, plain)
	}
	if end >= plain {
		end = plain - 1
	}

	c := int64(1) << log2C
	first := start / c
	last := end / c
	chunks := ChunkCount(plain, log2C)

	stride := c + TagSize
	cipherStart := int64(HeaderSize) + first*stride
	cipherEnd := int64(HeaderSize) + (last+1)*stride
	if cipherEnd > sealed {
		cipherEnd = sealed
	}

	return Range{
		// Both are non-negative: start is checked above and end is clamped to
		// plain-1, so neither conversion can wrap.
		//nolint:gosec // bounded by the checks above.
		FirstChunk: uint64(first),
		//nolint:gosec // bounded by the checks above.
		LastChunk:   uint64(last),
		CipherStart: cipherStart,
		CipherEnd:   cipherEnd - 1,
		Skip:        start - first*c,
		Length:      end - start + 1,
		LastIsFinal: last == chunks-1,
		// Chunk 0 starts right after the header, so a range that includes it can
		// be fetched in one request and split by the caller.
		NeedsSeparateHeader: first > 0,
	}, nil
}

// RangeReader decrypts a contiguous run of chunks and emits exactly the
// plaintext bytes the range asked for.
//
// Unlike DecryptReader it does not need a byte of lookahead: the caller already
// knows how many chunks there are and which one is final, so each chunk's nonce
// is determined up front.
type RangeReader struct {
	src    io.Reader
	sealer *sealer
	rng    Range

	buf       *[]byte
	log2C     uint8
	plain     []byte // verified plaintext not yet emitted
	next      uint64
	remaining int64 // plaintext bytes still to emit
	skip      int64
	err       error
	done      bool
}

// NewRangeReader decrypts chunks rng.FirstChunk..rng.LastChunk of a segment.
//
// rawHeader is the segment's 32-byte header, which the caller fetches
// separately when the range does not start at chunk 0. src must supply the
// ciphertext beginning exactly at rng.CipherStart.
func NewRangeReader(src io.Reader, rawHeader, dek []byte, want SegmentParams, rng Range) (*RangeReader, error) {
	if err := want.validateExpectation(); err != nil {
		return nil, err
	}
	h, err := parseHeader(rawHeader)
	if err != nil {
		return nil, err
	}
	if err := h.requireParams(want); err != nil {
		return nil, err
	}
	if rng.LastChunk < rng.FirstChunk {
		return nil, fmt.Errorf("stream: range ends at chunk %d before it starts at %d",
			rng.LastChunk, rng.FirstChunk)
	}

	s, err := newSealer(dek, h)
	if err != nil {
		return nil, err
	}
	return &RangeReader{
		src:       src,
		sealer:    s,
		rng:       rng,
		buf:       getChunkBuf(h.params.Log2ChunkSize),
		log2C:     h.params.Log2ChunkSize,
		next:      rng.FirstChunk,
		remaining: rng.Length,
		skip:      rng.Skip,
	}, nil
}

// VerifyFirst decrypts and verifies the first chunk of the range without
// consuming it, so a caller can commit to a response only once the data has
// proved authentic.
func (r *RangeReader) VerifyFirst() error {
	if r.err != nil {
		return r.err
	}
	if r.next > r.rng.FirstChunk || r.done {
		return nil
	}
	return r.fill()
}

func (r *RangeReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	for len(r.plain) == 0 {
		if r.remaining == 0 || r.done {
			r.release()
			return 0, io.EOF
		}
		if err := r.fill(); err != nil {
			return 0, err
		}
	}
	n := copy(p, r.plain)
	r.plain = r.plain[n:]
	r.remaining -= int64(n)
	if r.remaining == 0 {
		r.done = true
	}
	return n, nil
}

// Close releases the chunk buffer. It does not close the underlying reader.
func (r *RangeReader) Close() error {
	r.release()
	return nil
}

// fill reads, verifies and decrypts the next chunk of the range.
func (r *RangeReader) fill() error {
	if r.buf == nil {
		return r.setErr(integrityf(KindChunk, "reader already released"))
	}
	if r.next > r.rng.LastChunk {
		return r.setErr(chunkErrorf(r.next, "read past the end of the requested range"))
	}

	isLast := r.next == r.rng.LastChunk
	final := isLast && r.rng.LastIsFinal

	full := *r.buf
	n, err := io.ReadFull(r.src, full)
	switch {
	case err == nil:
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		// Only the segment's own final chunk may be short. Anything else means
		// the provider returned less than the range it was asked for.
		if !final {
			return r.setErr(chunkErrorf(r.next,
				"ciphertext ended after %d bytes, short of a full chunk", n))
		}
		if n < TagSize {
			return r.setErr(chunkErrorf(r.next,
				"truncated: %d bytes left, which is less than a bare tag", n))
		}
		full = full[:n]
	default:
		return r.setErr(err)
	}

	plain, err := r.sealer.open(full[:0], full, r.next, final)
	if err != nil {
		return r.setErr(err)
	}

	// Discard the part of the first chunk that precedes the requested offset.
	if r.skip > 0 {
		if r.skip >= int64(len(plain)) {
			return r.setErr(chunkErrorf(r.next, "chunk is shorter than the offset into it"))
		}
		plain = plain[r.skip:]
		r.skip = 0
	}
	if int64(len(plain)) > r.remaining {
		plain = plain[:r.remaining]
	}

	r.plain = plain
	r.next++
	return nil
}

func (r *RangeReader) release() {
	putChunkBuf(r.log2C, r.buf)
	r.buf = nil
	r.plain = nil
}

func (r *RangeReader) setErr(err error) error {
	if r.err == nil {
		r.err = err
	}
	r.release()
	return r.err
}
