package stream

import (
	"errors"
	"fmt"
	"math"
)

// Kind classifies an integrity failure. The values match the labels of the
// blindbucket_integrity_failures_total metric.
type Kind string

// Integrity failure kinds reported by this package.
const (
	// KindHeader marks a segment header that is malformed or does not match what
	// the caller expected.
	KindHeader Kind = "header"
	// KindChunk marks a chunk whose authentication tag did not verify, or a
	// stream that ended or continued where the format forbids it.
	KindChunk Kind = "chunk"
	// KindSize marks a ciphertext length that no encoder could have produced.
	KindSize Kind = "size"
)

// IntegrityError reports that ciphertext, a header field or a size failed
// verification.
//
// Every deviation is reported as one of these rather than as a decoding quirk:
// for this package there is no such thing as a recoverable parse error, only
// data that verifies and data that does not. An IntegrityError never carries
// plaintext or key material, so it is safe to log in full.
type IntegrityError struct {
	// Kind classifies the failure for metrics and alerting.
	Kind Kind
	// Detail describes what was wrong, without revealing protected data.
	Detail string
	// Chunk is the zero-based index of the offending chunk, or -1 if the failure
	// is not tied to one.
	Chunk int64
}

func (e *IntegrityError) Error() string {
	if e.Chunk >= 0 {
		return fmt.Sprintf("stream: integrity failure (%s) at chunk %d: %s", e.Kind, e.Chunk, e.Detail)
	}
	return fmt.Sprintf("stream: integrity failure (%s): %s", e.Kind, e.Detail)
}

// integrityf builds an IntegrityError that is not tied to a specific chunk.
func integrityf(kind Kind, format string, args ...any) *IntegrityError {
	return &IntegrityError{Kind: kind, Detail: fmt.Sprintf(format, args...), Chunk: -1}
}

// chunkErrorf builds an IntegrityError tied to chunk index i.
//
// The index is a uint64 on the wire but only ever reported as an int64. A
// segment cannot hold more than MaxPlaintextSize/2^MinLog2ChunkSize chunks, so
// the guard below is unreachable in practice and exists so the conversion is
// total rather than assumed.
func chunkErrorf(i uint64, format string, args ...any) *IntegrityError {
	index := int64(-1)
	if i <= math.MaxInt64 {
		index = int64(i)
	}
	return &IntegrityError{Kind: KindChunk, Detail: fmt.Sprintf(format, args...), Chunk: index}
}

// AsIntegrityError reports whether err is or wraps an *IntegrityError, and
// returns it. Callers use it to decide between a 5xx and an integrity metric.
func AsIntegrityError(err error) (*IntegrityError, bool) {
	var ie *IntegrityError
	ok := errors.As(err, &ie)
	return ie, ok
}
