package auth

import (
	//nolint:gosec // Content-MD5 is defined by S3 to be MD5; this is compatibility, not a choice.
	"crypto/md5"
	//nolint:gosec // x-amz-checksum-sha1 is defined by S3 to be SHA-1, likewise.
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"net/http"
	"strings"
)

// ErrChecksumMismatch reports a body that does not match the checksum the client
// supplied.
//
// The client computed it over plaintext, so this is caught at the proxy and
// never reaches the provider, whose view of the object is ciphertext with a
// completely different checksum.
var ErrChecksumMismatch = errors.New("auth: payload checksum does not match")

// ErrUnsupportedChecksum reports an algorithm this build cannot compute.
var ErrUnsupportedChecksum = errors.New("auth: unsupported checksum algorithm")

// crc64NVMETable is the CRC-64/NVME polynomial in the reflected form Go's
// hash/crc64 expects. Go's implementation already applies the initial and final
// inversion the specification calls for, so the table alone is enough.
//
// Verified against the standard check value: CRC-64/NVME("123456789") is
// 0xAE8B14860A799888.
var crc64NVMETable = crc64.MakeTable(0x9a6c9329ac4bc9b5)

// ChecksumAlgorithm names one of the algorithms S3 clients attach to uploads.
type ChecksumAlgorithm string

// The algorithms recognised here. AWS SDKs pick one of these automatically;
// CRC32 and CRC64NVME are the current defaults depending on SDK version.
const (
	ChecksumCRC32     ChecksumAlgorithm = "CRC32"
	ChecksumCRC32C    ChecksumAlgorithm = "CRC32C"
	ChecksumCRC64NVME ChecksumAlgorithm = "CRC64NVME"
	ChecksumSHA1      ChecksumAlgorithm = "SHA1"
	ChecksumSHA256    ChecksumAlgorithm = "SHA256"
)

// HeaderName returns the header or trailer name carrying this algorithm.
func (a ChecksumAlgorithm) HeaderName() string {
	return "x-amz-checksum-" + strings.ToLower(string(a))
}

// newHash returns a running hash for the algorithm.
func (a ChecksumAlgorithm) newHash() (hash.Hash, error) {
	switch a {
	case ChecksumCRC32:
		return crc32.NewIEEE(), nil
	case ChecksumCRC32C:
		return crc32.New(crc32.MakeTable(crc32.Castagnoli)), nil
	case ChecksumCRC64NVME:
		return crc64.New(crc64NVMETable), nil
	case ChecksumSHA1:
		//nolint:gosec // the algorithm is named by the client's header; see above.
		return sha1.New(), nil
	case ChecksumSHA256:
		return sha256.New(), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedChecksum, a)
	}
}

// parseChecksumAlgorithm maps a header name onto an algorithm.
func parseChecksumAlgorithm(headerName string) (ChecksumAlgorithm, bool) {
	name, ok := strings.CutPrefix(strings.ToLower(headerName), "x-amz-checksum-")
	if !ok {
		return "", false
	}
	alg := ChecksumAlgorithm(strings.ToUpper(name))
	if _, err := alg.newHash(); err != nil {
		return "", false
	}
	return alg, true
}

// expectation is one checksum a body has to satisfy.
//
// expected is nil while the value is still to come: a client may announce a
// checksum in X-Amz-Trailer and send it only after the body. The hash has to run
// from the first byte regardless, which is exactly why the announcement matters.
type expectation struct {
	name     string // the header it came from, for error messages
	hash     hash.Hash
	expected []byte
}

// verify compares the running hash against what the client claimed.
func (e *expectation) verify() error {
	got := e.hash.Sum(nil)
	// The comparison is constant-time out of habit rather than necessity: a
	// checksum is not a secret, but treating every comparison of
	// caller-supplied bytes the same way removes a category of mistake.
	if subtle.ConstantTimeCompare(got, e.expected) != 1 {
		return fmt.Errorf("%w: %s", ErrChecksumMismatch, e.name)
	}
	return nil
}

// checksumsFrom collects the checksums declared in a header set.
//
// Both real request headers and aws-chunked trailers arrive this way, so the
// same code covers a checksum sent up front and one sent after the body.
func checksumsFrom(h http.Header) ([]*expectation, error) {
	var out []*expectation

	for name, values := range h {
		if len(values) == 0 {
			continue
		}
		alg, ok := parseChecksumAlgorithm(name)
		if !ok {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(values[0]))
		if err != nil {
			return nil, fmt.Errorf("auth: %s is not valid base64: %w", name, err)
		}
		hasher, err := alg.newHash()
		if err != nil {
			return nil, err
		}
		if want := expectedLength(alg); len(raw) != want {
			return nil, fmt.Errorf("auth: %s decodes to %d bytes, want %d", name, len(raw), want)
		}
		out = append(out, &expectation{name: name, hash: hasher, expected: raw})
	}

	if md5Value := h.Get("Content-MD5"); md5Value != "" {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(md5Value))
		if err != nil {
			return nil, fmt.Errorf("auth: Content-MD5 is not valid base64: %w", err)
		}
		if len(raw) != md5.Size {
			return nil, fmt.Errorf("auth: Content-MD5 decodes to %d bytes, want %d", len(raw), md5.Size)
		}
		//nolint:gosec // MD5 is what Content-MD5 means; it is a compatibility
		// requirement, not a security choice.
		out = append(out, &expectation{name: "Content-MD5", hash: md5.New(), expected: raw})
	}

	return out, nil
}

// announcedTrailerChecksums reads the X-Amz-Trailer header, which names the
// checksums a client will send after the body.
//
// Without this the hash would have nothing to compare against by the time the
// value arrives, and the body would already be gone. Current AWS SDKs send
// checksums this way by default, so it is the common path rather than an edge.
func announcedTrailerChecksums(h http.Header) ([]*expectation, error) {
	raw := h.Get("X-Amz-Trailer")
	if raw == "" {
		return nil, nil
	}

	var out []*expectation
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		alg, ok := parseChecksumAlgorithm(name)
		if !ok {
			return nil, fmt.Errorf("%w: announced trailer %q", ErrUnsupportedChecksum, name)
		}
		hasher, err := alg.newHash()
		if err != nil {
			return nil, err
		}
		out = append(out, &expectation{name: name, hash: hasher})
	}
	return out, nil
}

func expectedLength(alg ChecksumAlgorithm) int {
	switch alg {
	case ChecksumCRC32, ChecksumCRC32C:
		return 4
	case ChecksumCRC64NVME:
		return 8
	case ChecksumSHA1:
		return sha1.Size
	case ChecksumSHA256:
		return sha256.Size
	default:
		return 0
	}
}

// ComputeChecksum returns the base64 value a client would have sent for data.
// It exists so the proxy can echo a verified checksum back in its response.
func ComputeChecksum(alg ChecksumAlgorithm, data []byte) (string, error) {
	h, err := alg.newHash()
	if err != nil {
		return "", err
	}
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}
