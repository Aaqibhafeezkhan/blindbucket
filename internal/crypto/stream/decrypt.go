package stream

import (
	"bufio"
	"errors"
	"io"
)

// peekBufSize is the internal buffer of the bufio.Reader wrapped around the
// ciphertext source. It only has to be large enough for the one-byte lookahead:
// reads of a whole chunk are larger than this buffer, so bufio passes them
// straight through to the underlying reader instead of copying them.
const peekBufSize = 64

// DecryptReader yields the authenticated plaintext of exactly one segment.
//
// No byte is returned before the chunk it belongs to has been fully verified, so
// everything read from a DecryptReader may be forwarded to a client directly.
// Any deviation -- a bad tag, a manipulated header field, truncation, trailing
// bytes, the wrong key -- surfaces as an *IntegrityError and is terminal.
//
// A DecryptReader is not safe for concurrent use.
type DecryptReader struct {
	src    *bufio.Reader
	header header
	sealer *sealer

	buf   *[]byte
	plain []byte // verified plaintext of the current chunk, not yet returned
	next  uint64 // index of the chunk to read next

	done bool
	err  error
}

// NewDecryptReader reads and validates the segment header from src and prepares
// decryption. It does not yet verify any ciphertext; see VerifyFirst.
//
// want states what the caller expects this segment to be. Mismatching the chunk
// size, the multipart flag or the segment index is an error -- this is what
// catches a provider serving a different part than the one asked for.
func NewDecryptReader(src io.Reader, dek []byte, want SegmentParams) (*DecryptReader, error) {
	if err := want.validateExpectation(); err != nil {
		return nil, err
	}

	br := bufio.NewReaderSize(src, peekBufSize)
	var raw [HeaderSize]byte
	if _, err := io.ReadFull(br, raw[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, integrityf(KindHeader, "segment is shorter than its %d-byte header", HeaderSize)
		}
		return nil, err
	}

	h, err := parseHeader(raw[:])
	if err != nil {
		return nil, err
	}
	if err := h.requireParams(want); err != nil {
		return nil, err
	}

	s, err := newSealer(dek, h)
	if err != nil {
		return nil, err
	}
	return &DecryptReader{
		src:    br,
		header: h,
		sealer: s,
		buf:    getChunkBuf(h.params.Log2ChunkSize),
	}, nil
}

// VerifyFirst decrypts and verifies the first chunk, without consuming it.
//
// It exists so that a caller can establish the segment is authentic before it
// commits to an answer it cannot retract. The proxy calls this before writing an
// HTTP status: a wrong key, forged metadata or a tampered header then produces a
// proper S3 error response instead of a connection abort halfway through a body.
// See CONCEPT.md section 8.7.
func (r *DecryptReader) VerifyFirst() error {
	if r.err != nil {
		return r.err
	}
	if r.next > 0 || r.done {
		return nil
	}
	if err := r.fill(); err != nil {
		return err
	}
	return nil
}

// Header returns the verified header of this segment. Its fields are only
// trustworthy once VerifyFirst or the first Read has succeeded, because the
// header is authenticated by the chunks, not on its own.
func (r *DecryptReader) Header() SegmentParams { return r.header.params }

func (r *DecryptReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	for len(r.plain) == 0 {
		if r.done {
			r.release()
			return 0, io.EOF
		}
		if err := r.fill(); err != nil {
			return 0, err
		}
	}
	n := copy(p, r.plain)
	r.plain = r.plain[n:]
	return n, nil
}

// Close releases the chunk buffer. It does not close the underlying reader.
// Calling it is optional but lets the buffer be reused.
func (r *DecryptReader) Close() error {
	r.release()
	return nil
}

// fill reads, verifies and decrypts the next chunk into r.plain.
func (r *DecryptReader) fill() error {
	if r.buf == nil {
		return r.setErr(integrityf(KindChunk, "reader already released"))
	}

	full := *r.buf
	n, err := io.ReadFull(r.src, full)

	var final bool
	switch {
	case err == nil:
		// A whole chunk arrived. Whether it is the final one depends entirely on
		// whether anything follows it -- and the format demands the answer be
		// right, because the final flag is part of the nonce. One byte of
		// lookahead settles it.
		if _, perr := r.src.Peek(1); perr != nil {
			if !errors.Is(perr, io.EOF) {
				return r.setErr(perr)
			}
			final = true
		}

	case errors.Is(err, io.ErrUnexpectedEOF):
		// A short chunk can only be the last one.
		final = true
		if n < TagSize {
			return r.setErr(chunkErrorf(r.next,
				"truncated: %d bytes left, which is less than a bare tag", n))
		}
		if n == TagSize && r.next > 0 {
			return r.setErr(chunkErrorf(r.next,
				"empty chunk, which is only valid as the single chunk of an empty segment"))
		}
		full = full[:n]

	case errors.Is(err, io.EOF):
		// Nothing at all where a chunk was expected. The preceding chunk was
		// sealed as non-final, so the segment has been cut short.
		return r.setErr(chunkErrorf(r.next, "segment ends after a non-final chunk"))

	default:
		return r.setErr(err)
	}

	// Decrypt in place: the plaintext reuses the ciphertext's storage, so a chunk
	// costs no allocation.
	plain, err := r.sealer.open(full[:0], full, r.next, final)
	if err != nil {
		return r.setErr(err)
	}

	r.plain = plain
	r.next++
	r.done = final
	return nil
}

func (r *DecryptReader) release() {
	putChunkBuf(r.header.params.Log2ChunkSize, r.buf)
	r.buf = nil
	r.plain = nil
}

// setErr records err as terminal and returns it. Once a segment has failed
// verification there is no safe way to continue reading it.
func (r *DecryptReader) setErr(err error) error {
	if r.err == nil {
		r.err = err
	}
	r.release()
	return r.err
}
