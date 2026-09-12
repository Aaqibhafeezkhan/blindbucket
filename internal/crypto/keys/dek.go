package keys

import (
	"crypto/rand"
	"log/slog"
)

// KeySize is the length of a DEK and of a KEK in bytes.
const KeySize = 32

// DEK is a data encryption key: one per object, or one per multipart upload.
//
// It implements slog.LogValuer so that it cannot reach a log by accident, not
// even through a struct that happens to contain it.
type DEK [KeySize]byte

// LogValue redacts the key. This is the only representation slog will ever emit.
func (DEK) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// String redacts the key, so that %s and %v cannot print it either.
func (DEK) String() string { return "[REDACTED]" }

// NewDEK draws a fresh data encryption key from the system CSPRNG.
//
// A DEK is never derived from anything the storage provider chooses -- notably
// not from an upstream UploadId, which a provider could repeat in order to force
// two uploads to share a key. See docs/adr/ADR-006-upload-token.md.
func NewDEK() (DEK, error) {
	var dek DEK
	if _, err := rand.Read(dek[:]); err != nil {
		return DEK{}, err
	}
	return dek, nil
}

// Bytes returns the raw key material. Callers must not retain or log it.
func (d *DEK) Bytes() []byte { return d[:] }

// Wipe overwrites the key in place.
//
// Go cannot guarantee this is effective: the garbage collector may have copied
// the value elsewhere, and nothing prevents it being paged out. It reduces the
// window, it does not close it. The proxy host must be trusted regardless; see
// docs/THREAT_MODEL.md section 5.5.
func (d *DEK) Wipe() { clear(d[:]) }
