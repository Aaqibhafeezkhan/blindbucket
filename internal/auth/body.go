package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// DecodedLengthHeader carries the plaintext length of an aws-chunked body.
const DecodedLengthHeader = "X-Amz-Decoded-Content-Length"

// BodyReader yields a request's plaintext body and verifies everything the
// client asked to have verified.
//
// The verification completes exactly when the body does: the error surfaces on
// the Read that would otherwise have returned io.EOF. That timing is what makes
// the whole design work. The encrypter downstream withholds its final chunk
// until Close, so a checksum that fails here aborts the upstream request before
// a complete body was ever sent, and no object is created -- without anything
// having been buffered. See CONCEPT.md section 9.3.
type BodyReader struct {
	src       io.Reader
	chunked   *ChunkedReader
	checksums []*expectation
	verified  bool
	err       error
}

// NewBodyReader wraps r's body according to how res says it is protected. It
// also returns the plaintext length, which the proxy needs before it can compute
// the upstream Content-Length.
func NewBodyReader(r *http.Request, res *Result) (*BodyReader, int64, error) {
	checksums, err := checksumsFrom(r.Header)
	if err != nil {
		return nil, 0, err
	}

	if res.PayloadMode.Streaming() {
		announced, err := announcedTrailerChecksums(r.Header)
		if err != nil {
			return nil, 0, err
		}
		checksums = append(checksums, announced...)

		length, err := decodedLength(r)
		if err != nil {
			return nil, 0, err
		}
		chunked, err := NewChunkedReader(r.Body, res, length)
		if err != nil {
			return nil, 0, err
		}
		chunked.SetChecksums(checksums)
		return &BodyReader{src: chunked, chunked: chunked, checksums: checksums}, length, nil
	}

	if r.ContentLength < 0 {
		return nil, 0, ErrMissingContentLength
	}

	// A hex x-amz-content-sha256 is a checksum like any other, so it joins the
	// same list and is settled at the same moment.
	if res.PayloadMode == PayloadHashed {
		expected, err := hex.DecodeString(res.PayloadHash)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: x-amz-content-sha256 is not hex", ErrMalformedAuth)
		}
		checksums = append(checksums, &expectation{
			name: "x-amz-content-sha256", hash: sha256.New(), expected: expected,
		})
	}

	return &BodyReader{src: r.Body, checksums: checksums}, r.ContentLength, nil
}

// Checksums reports which checksums this reader is verifying, by header name.
// The proxy echoes the verified ones back to the client.
func (b *BodyReader) Checksums() []string {
	out := make([]string, 0, len(b.checksums))
	for _, e := range b.checksums {
		out = append(out, e.name)
	}
	return out
}

func (b *BodyReader) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}

	n, err := b.src.Read(p)
	if n > 0 && b.chunked == nil {
		// The chunked reader feeds the hashes itself, because it has to
		// distinguish framing bytes from payload.
		for _, e := range b.checksums {
			e.hash.Write(p[:n])
		}
	}

	if err == io.EOF && !b.verified {
		b.verified = true
		if verr := b.verify(); verr != nil {
			b.err = verr
			return n, verr
		}
	}
	if err != nil && err != io.EOF {
		b.err = err
	}
	return n, err
}

// verify settles every expectation. The chunked reader has already settled its
// own, including any that arrived in the trailer.
func (b *BodyReader) verify() error {
	if b.chunked != nil {
		return nil
	}
	for _, e := range b.checksums {
		if err := e.verify(); err != nil {
			return err
		}
	}
	return nil
}

// Trailer returns any trailing headers an aws-chunked body carried.
func (b *BodyReader) Trailer() http.Header {
	if b.chunked == nil {
		return nil
	}
	return b.chunked.Trailer()
}

func decodedLength(r *http.Request) (int64, error) {
	raw := r.Header.Get(DecodedLengthHeader)
	if raw == "" {
		return 0, fmt.Errorf("%w: %s is required for an aws-chunked body",
			ErrMalformedChunkedBody, DecodedLengthHeader)
	}
	length, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || length < 0 {
		return 0, fmt.Errorf("%w: %s is %q", ErrMalformedChunkedBody, DecodedLengthHeader, raw)
	}
	return length, nil
}
