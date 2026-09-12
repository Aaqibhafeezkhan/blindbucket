package stream

import (
	"errors"
	"fmt"
	"io"
)

// ErrWriterClosed is returned by writes to an EncryptWriter that was closed.
var ErrWriterClosed = errors.New("stream: write to closed EncryptWriter")

// EncryptWriter encrypts everything written to it as a single segment.
//
// Close is the commit point. The final chunk is not written until Close is
// called, because until then the encoder cannot know whether more plaintext
// follows -- and the final chunk must be sealed with the final flag set. A
// segment whose writer was never closed is truncated and will not decrypt.
//
// That property is load-bearing beyond this package: the proxy verifies the
// client's end-to-end checksum in the window between the last full chunk and
// Close, so a mismatching checksum can abort the upstream request before a
// complete body has ever been sent. See docs/adr/ADR-005-checksums.md.
//
// An EncryptWriter is not safe for concurrent use.
type EncryptWriter struct {
	dst    io.Writer
	header header
	sealer *sealer

	// buf holds the chunk being assembled, with room for its tag so that sealing
	// happens in place. It is held back once full: see the type comment.
	buf  *[]byte
	n    int    // plaintext bytes currently in buf
	next uint64 // index of the chunk buf will become

	total         int64
	headerWritten bool
	closed        bool
	err           error
}

// NewEncryptWriter returns a writer that seals its input as one segment into dst.
//
// The returned writer satisfies io.WriteCloser. Callers must call Close to
// produce a valid segment, and should call it even on an aborted stream to
// release the chunk buffer.
func NewEncryptWriter(dst io.Writer, dek []byte, p SegmentParams) (*EncryptWriter, error) {
	h, err := newHeader(p)
	if err != nil {
		return nil, err
	}
	return newEncryptWriter(dst, dek, h)
}

func newEncryptWriter(dst io.Writer, dek []byte, h header) (*EncryptWriter, error) {
	s, err := newSealer(dek, h)
	if err != nil {
		return nil, err
	}
	return &EncryptWriter{
		dst:    dst,
		header: h,
		sealer: s,
		buf:    getChunkBuf(h.params.Log2ChunkSize),
	}, nil
}

// Header returns the segment header as it appears on the wire. It is available
// before any byte is written, which lets a caller compute offsets up front.
func (w *EncryptWriter) Header() [HeaderSize]byte { return w.header.raw }

// Salt returns the segment's salt.
//
// It identifies this segment among every other encryption of the same
// plaintext: FORMAT.md section 4.1 requires a fresh one per segment, including
// per retried attempt at the same part number. That makes it the thing a
// manifest records to pin down *which* attempt a part is (FORMAT.md section 10).
func (w *EncryptWriter) Salt() [SaltSize]byte { return w.header.salt }

func (w *EncryptWriter) Write(p []byte) (int, error) {
	switch {
	case w.err != nil:
		return 0, w.err
	case w.closed:
		return 0, ErrWriterClosed
	}

	chunk := w.header.chunkSize()
	written := 0
	for len(p) > 0 {
		// A full buffer is held back until we know more plaintext follows. We know
		// it now, so it can be sealed as a non-final chunk.
		if w.n == chunk {
			if err := w.flush(false); err != nil {
				return written, err
			}
		}

		take := min(chunk-w.n, len(p))
		if w.total+int64(take) > MaxPlaintextSize {
			return written, w.fail(fmt.Errorf("stream: segment exceeds the maximum plaintext size of %d bytes",
				int64(MaxPlaintextSize)))
		}
		copy((*w.buf)[w.n:], p[:take])
		w.n += take
		w.total += int64(take)
		p = p[take:]
		written += take
	}
	return written, nil
}

// Close seals the final chunk and completes the segment. It does not close dst.
//
// Calling Close twice is safe; the second call returns the result of the first.
func (w *EncryptWriter) Close() error {
	if w.closed {
		return w.err
	}
	w.closed = true
	defer func() {
		putChunkBuf(w.header.params.Log2ChunkSize, w.buf)
		w.buf = nil
	}()

	if w.err != nil {
		return w.err
	}
	// Always flush, even with an empty buffer: an empty segment is one chunk
	// carrying zero bytes, which is what authenticates the header of an empty
	// object.
	return w.flush(true)
}

// PlaintextSize returns the number of plaintext bytes written so far.
func (w *EncryptWriter) PlaintextSize() int64 { return w.total }

// flush seals the buffered plaintext as chunk w.next and writes it to dst.
func (w *EncryptWriter) flush(final bool) error {
	if !w.headerWritten {
		if _, err := w.dst.Write(w.header.raw[:]); err != nil {
			return w.fail(err)
		}
		w.headerWritten = true
	}

	buf := *w.buf
	sealed := w.sealer.seal(buf[:0], buf[:w.n], w.next, final)
	if _, err := w.dst.Write(sealed); err != nil {
		return w.fail(err)
	}
	w.next++
	w.n = 0
	return nil
}

// fail records err as terminal: every later operation reports it unchanged.
func (w *EncryptWriter) fail(err error) error {
	if w.err == nil {
		w.err = err
	}
	return w.err
}
