package auth

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// aws-chunked framing limits. A body is untrusted input: a client must not be
// able to make the proxy allocate or spin by declaring absurd values.
const (
	maxChunkHeaderLine = 4 << 10
	maxTrailerLines    = 16
	maxChunkSize       = 1 << 30 // 1 GiB, far above any real client's chunk
)

// String-to-sign prefixes for the two aws-chunked signature kinds.
const (
	chunkPayloadAlgorithm = "AWS4-HMAC-SHA256-PAYLOAD"
	chunkTrailerAlgorithm = "AWS4-HMAC-SHA256-TRAILER"
)

// emptyStringSHA256 is the hash of no bytes, which the chunk string-to-sign
// includes in place of canonical headers.
var emptyStringSHA256 = func() string {
	sum := sha256.Sum256(nil)
	return hex.EncodeToString(sum[:])
}()

// ErrMalformedChunkedBody reports a body that does not follow the aws-chunked
// framing.
var ErrMalformedChunkedBody = errors.New("auth: malformed aws-chunked body")

// ErrChunkSignature reports a chunk whose signature does not match, which breaks
// the chain and invalidates everything after it.
var ErrChunkSignature = errors.New("auth: chunk signature does not match")

// ChunkedReader decodes an aws-chunked request body and yields the plaintext.
//
// Chunk signatures are verified as the body streams, not by buffering each chunk
// first. A chunk's bytes are therefore forwarded before its signature is known
// to be good -- which is safe here because of how the write path is ordered: the
// encrypter withholds its final chunk until Close, so a failure at any point
// means the upstream request never completes and no object is created. See
// CONCEPT.md section 9.3.
type ChunkedReader struct {
	src  *bufio.Reader
	mode PayloadMode

	signingKey []byte
	scope      string
	timestamp  string
	prevSig    string

	// remaining counts bytes left in the chunk being read.
	remaining int64
	// chunkSig is the signature claimed for the current chunk, and chunkHash
	// accumulates its data.
	chunkSig  string
	chunkHash hash.Hash

	// checksums run over the whole decoded body and are settled from the
	// trailer once the last chunk has been seen.
	checksums []*expectation

	decoded         int64
	expectedDecoded int64

	trailer http.Header
	done    bool
	err     error
}

// NewChunkedReader wraps an aws-chunked body.
//
// decodedLength is the value of x-amz-decoded-content-length, which the proxy
// also needs in order to compute the upstream Content-Length before streaming.
func NewChunkedReader(body io.Reader, res *Result, decodedLength int64) (*ChunkedReader, error) {
	if !res.PayloadMode.Streaming() {
		return nil, fmt.Errorf("auth: payload mode is not aws-chunked")
	}
	if decodedLength < 0 {
		return nil, fmt.Errorf("%w: x-amz-decoded-content-length is required", ErrMalformedChunkedBody)
	}
	return &ChunkedReader{
		src:             bufio.NewReaderSize(body, 32<<10),
		mode:            res.PayloadMode,
		signingKey:      res.SigningKey,
		scope:           res.Authorization.Credential.Scope(),
		timestamp:       res.Time.UTC().Format(amzDateFormat),
		prevSig:         res.Seed,
		expectedDecoded: decodedLength,
		trailer:         make(http.Header),
	}, nil
}

// SetChecksums registers checksums to run over the decoded body. They are
// settled against the trailer when the body ends.
func (c *ChunkedReader) SetChecksums(expectations []*expectation) { c.checksums = expectations }

// Trailer returns the trailing headers, valid once Read has returned io.EOF.
func (c *ChunkedReader) Trailer() http.Header { return c.trailer }

func (c *ChunkedReader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	if c.done {
		return 0, io.EOF
	}

	if c.remaining == 0 {
		if err := c.nextChunk(); err != nil {
			return 0, err
		}
		if c.done {
			return 0, io.EOF
		}
	}

	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := io.ReadFull(c.src, p)
	if err != nil {
		return 0, c.fail(fmt.Errorf("%w: chunk ended after %d of %d bytes",
			ErrMalformedChunkedBody, n, c.remaining))
	}

	if c.chunkHash != nil {
		c.chunkHash.Write(p[:n])
	}
	for _, e := range c.checksums {
		e.hash.Write(p[:n])
	}
	c.remaining -= int64(n)
	c.decoded += int64(n)

	if c.remaining == 0 {
		if err := c.finishChunk(); err != nil {
			return n, err
		}
	}
	return n, nil
}

// nextChunk reads and validates a chunk header.
func (c *ChunkedReader) nextChunk() error {
	line, err := c.readLine()
	if err != nil {
		return c.fail(err)
	}

	sizeText, sig, err := splitChunkHeader(line, c.mode.Signed())
	if err != nil {
		return c.fail(err)
	}
	size, err := strconv.ParseInt(sizeText, 16, 64)
	if err != nil || size < 0 || size > maxChunkSize {
		return c.fail(fmt.Errorf("%w: chunk size %q", ErrMalformedChunkedBody, sizeText))
	}

	c.chunkSig = sig
	if c.mode.Signed() {
		c.chunkHash = sha256.New()
	}

	if size == 0 {
		// The final, empty chunk. Its signature covers no data, and the trailer
		// follows it.
		if err := c.finishChunk(); err != nil {
			return err
		}
		if err := c.readTrailer(); err != nil {
			return c.fail(err)
		}
		if err := c.settle(); err != nil {
			return c.fail(err)
		}
		c.done = true
		return nil
	}

	c.remaining = size
	return nil
}

// finishChunk consumes the CRLF after a chunk's data and verifies its signature.
func (c *ChunkedReader) finishChunk() error {
	if err := c.expectCRLF(); err != nil {
		return c.fail(err)
	}
	if !c.mode.Signed() {
		return nil
	}

	stringToSign := strings.Join([]string{
		chunkPayloadAlgorithm,
		c.timestamp,
		c.scope,
		c.prevSig,
		emptyStringSHA256,
		hex.EncodeToString(c.chunkHash.Sum(nil)),
	}, "\n")

	expected := Sign(c.signingKey, stringToSign)
	if !equalSignature(expected, c.chunkSig) {
		return c.fail(ErrChunkSignature)
	}
	// Each signature feeds the next, so a single altered chunk invalidates the
	// remainder of the body rather than just itself.
	c.prevSig = c.chunkSig
	return nil
}

// readTrailer reads the trailing headers after the final chunk.
func (c *ChunkedReader) readTrailer() error {
	var canonical strings.Builder
	var trailerSig string

	for range maxTrailerLines {
		line, err := c.readLine()
		if errors.Is(err, io.EOF) {
			// A body with no trailer section ends right after the final chunk's
			// CRLF. STREAMING-AWS4-HMAC-SHA256-PAYLOAD is exactly that shape,
			// and it is what the MinIO client sends -- treating the missing
			// section as a malformed body rejected every mc upload.
			break
		}
		if err != nil {
			return err
		}
		if line == "" {
			break
		}

		name, value, found := strings.Cut(line, ":")
		if !found {
			return fmt.Errorf("%w: trailer line %q is not name:value", ErrMalformedChunkedBody, line)
		}
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)

		if name == "x-amz-trailer-signature" {
			trailerSig = value
			continue
		}
		c.trailer.Set(name, value)
		canonical.WriteString(name + ":" + value + "\n")
	}

	if c.mode != PayloadStreamingSignedTrailer {
		return nil
	}
	sum := sha256.Sum256([]byte(canonical.String()))
	stringToSign := strings.Join([]string{
		chunkTrailerAlgorithm,
		c.timestamp,
		c.scope,
		c.prevSig,
		hex.EncodeToString(sum[:]),
	}, "\n")
	if !equalSignature(Sign(c.signingKey, stringToSign), trailerSig) {
		return fmt.Errorf("%w: trailer signature", ErrChunkSignature)
	}
	return nil
}

// settle checks everything that can only be known once the body has ended.
func (c *ChunkedReader) settle() error {
	if c.decoded != c.expectedDecoded {
		return fmt.Errorf("%w: body decoded to %d bytes, x-amz-decoded-content-length said %d",
			ErrMalformedChunkedBody, c.decoded, c.expectedDecoded)
	}

	// A checksum may arrive in the trailer rather than in the request headers,
	// which is how current AWS SDKs send it by default. Its hash has been
	// running since the first byte because X-Amz-Trailer announced it.
	trailerChecksums, err := checksumsFrom(c.trailer)
	if err != nil {
		return err
	}

	settled := make(map[*expectation]bool, len(c.checksums))
	for _, arrived := range trailerChecksums {
		running := c.find(arrived.name)
		if running == nil {
			// Ignoring it would silently drop an integrity check the client
			// believes is being made.
			return fmt.Errorf("%w: %s arrived in the trailer but was not announced in X-Amz-Trailer",
				ErrChecksumMismatch, arrived.name)
		}
		if err := (&expectation{
			name: arrived.name, hash: running.hash, expected: arrived.expected,
		}).verify(); err != nil {
			return err
		}
		settled[running] = true
	}

	for _, e := range c.checksums {
		switch {
		case settled[e]:
		case e.expected != nil:
			// Declared in the request headers, so settle it here.
			if err := e.verify(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: %s was announced in X-Amz-Trailer but never arrived",
				ErrChecksumMismatch, e.name)
		}
	}
	return nil
}

// find returns the running expectation for a checksum name.
func (c *ChunkedReader) find(name string) *expectation {
	for _, e := range c.checksums {
		if strings.EqualFold(e.name, name) {
			return e
		}
	}
	return nil
}

// readLine reads one CRLF-terminated line, bounded so a client cannot make the
// proxy buffer indefinitely.
func (c *ChunkedReader) readLine() (string, error) {
	line, err := c.src.ReadString('\n')
	if err != nil {
		// A final line without its newline is still a line; only an empty read
		// means there was nothing there.
		if !errors.Is(err, io.EOF) || line == "" {
			return "", fmt.Errorf("%w: %w", ErrMalformedChunkedBody, err)
		}
	}
	if len(line) > maxChunkHeaderLine {
		return "", fmt.Errorf("%w: line of %d bytes exceeds the limit", ErrMalformedChunkedBody, len(line))
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}

func (c *ChunkedReader) expectCRLF() error {
	var crlf [2]byte
	if _, err := io.ReadFull(c.src, crlf[:]); err != nil {
		return fmt.Errorf("%w: expected CRLF after chunk data: %w", ErrMalformedChunkedBody, err)
	}
	if crlf != [2]byte{'\r', '\n'} {
		return fmt.Errorf("%w: expected CRLF after chunk data, got %q", ErrMalformedChunkedBody, crlf)
	}
	return nil
}

func (c *ChunkedReader) fail(err error) error {
	if c.err == nil {
		c.err = err
	}
	return c.err
}

// splitChunkHeader separates the size from the optional chunk signature.
func splitChunkHeader(line string, wantSignature bool) (size, signature string, err error) {
	size, rest, hasExt := strings.Cut(line, ";")
	if !hasExt {
		if wantSignature {
			return "", "", fmt.Errorf("%w: chunk header %q carries no signature",
				ErrMalformedChunkedBody, line)
		}
		return size, "", nil
	}

	value, ok := strings.CutPrefix(rest, "chunk-signature=")
	if !ok {
		return "", "", fmt.Errorf("%w: unexpected chunk extension %q", ErrMalformedChunkedBody, rest)
	}
	if !wantSignature {
		// A signature where none was announced means the client and the
		// x-amz-content-sha256 header disagree about the mode.
		return "", "", fmt.Errorf("%w: chunk carries a signature but the payload mode is unsigned",
			ErrMalformedChunkedBody)
	}
	return size, value, nil
}
