package stream

import "fmt"

// Format constants. See docs/FORMAT.md section 4.
const (
	// HeaderSize is the fixed size of a segment header in bytes.
	HeaderSize = 32
	// TagSize is the AES-GCM authentication tag size in bytes.
	TagSize = 16
	// NonceSize is the AES-GCM nonce size in bytes.
	NonceSize = 12
	// SaltSize is the size of the per-segment salt in bytes.
	SaltSize = 20
	// KeySize is the size of a DEK and of a derived subkey in bytes.
	KeySize = 32

	// Version is the format version this package reads and writes.
	Version = 1

	// MinLog2ChunkSize and MaxLog2ChunkSize bound the permitted chunk sizes,
	// 4 KiB to 1 MiB.
	MinLog2ChunkSize = 12
	MaxLog2ChunkSize = 20
	// DefaultLog2ChunkSize selects 64 KiB chunks. See docs/adr/ADR-001-segment-format.md.
	DefaultLog2ChunkSize = 16

	// MaxParts is the largest S3 part number, and therefore the largest segment
	// index a multipart segment may carry.
	MaxParts = 10000
)

// Magic is the four-byte marker every segment header starts with.
var Magic = [4]byte{'B', 'L', 'B', 'K'}

// Header field offsets, in the order they appear on the wire.
const (
	offMagic    = 0
	offVersion  = 4
	offLog2C    = 5
	offFlags    = 6
	offReserved = 7
	offIndex    = 8
	offSalt     = 12
)

// flagMultipart marks a segment as belonging to a multipart object. It is the
// only defined flag bit; every other bit must be zero.
const flagMultipart = 0x01

// MaxPlaintextSize caps the plaintext of a single segment at 64 TiB. It sits far
// above S3's 5 GiB limit for a single PUT or part and exists so that the size
// arithmetic cannot overflow an int64 for any accepted input.
const MaxPlaintextSize = 1 << 46

// SegmentParams describes the authenticated header fields of a segment.
//
// Because the header is supplied as associated data to every chunk, these values
// are authenticated: a storage provider cannot reinterpret the chunk size,
// present a multipart segment as a single-part one, or renumber a part without
// decryption failing.
type SegmentParams struct {
	// Log2ChunkSize selects the chunk size as 2^Log2ChunkSize bytes.
	Log2ChunkSize uint8
	// Multipart reports whether this segment is one part of a multipart object.
	Multipart bool
	// Index is 0 for a single-part segment, otherwise the S3 part number.
	Index uint32
}

// Validate reports whether p is a permitted combination of header fields.
//
// The flag and index must agree: a single-part segment carries index 0, and a
// multipart segment carries a valid S3 part number. Without this rule there would
// be headers that parse but denote nothing.
func (p SegmentParams) Validate() error {
	if err := ValidateLog2ChunkSize(p.Log2ChunkSize); err != nil {
		return err
	}
	if p.Multipart {
		if p.Index < 1 || p.Index > MaxParts {
			return fmt.Errorf("stream: multipart segment index %d outside 1..%d", p.Index, MaxParts)
		}
		return nil
	}
	if p.Index != 0 {
		return fmt.Errorf("stream: single-part segment must have index 0, got %d", p.Index)
	}
	return nil
}

// ChunkSize returns the chunk size in bytes that p selects.
func (p SegmentParams) ChunkSize() int64 { return 1 << p.Log2ChunkSize }

// ValidateLog2ChunkSize reports whether log2C names a permitted chunk size.
//
// This check exists to be run before any buffer is allocated from an untrusted
// header: the header is only authenticated once the first chunk verifies, so a
// header claiming log2C = 30 would otherwise coerce a 1 GiB allocation from a
// 32-byte read. See docs/FORMAT.md section 5.2.
func ValidateLog2ChunkSize(log2C uint8) error {
	if log2C < MinLog2ChunkSize || log2C > MaxLog2ChunkSize {
		return fmt.Errorf("stream: log2 chunk size %d outside %d..%d",
			log2C, MinLog2ChunkSize, MaxLog2ChunkSize)
	}
	return nil
}
