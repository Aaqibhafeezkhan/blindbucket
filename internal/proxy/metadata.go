package proxy

import (
	"fmt"
	"maps"
	"net/http"
	"strconv"
	"strings"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
)

// Metadata keys blindbucket sets on upstream objects, without the
// x-amz-meta- prefix. See docs/FORMAT.md section 6.3.
const (
	metaPrefix    = "bb-"
	metaVersion   = "bb-v"
	metaKeyID     = "bb-kid"
	metaDEK       = "bb-dek"
	metaChunkSize = "bb-c"
)

// objectMeta is what blindbucket records alongside an object so it can be read
// back later.
type objectMeta struct {
	Version       int
	KeyID         string
	WrappedDEK    []byte
	Log2ChunkSize uint8
	// HasChunkSize reports whether Log2ChunkSize came from the object itself
	// rather than from the configured fallback. Only a recorded value may be
	// checked against the authenticated segment header: a fallback that happens
	// to differ is a stale configuration, not tampering.
	HasChunkSize bool
}

// headers renders the metadata for an upstream request.
func (m objectMeta) headers() map[string]string {
	return map[string]string{
		metaVersion:   strconv.Itoa(m.Version),
		metaKeyID:     m.KeyID,
		metaDEK:       keys.EncodeWrapped(m.WrappedDEK),
		metaChunkSize: strconv.Itoa(int(m.Log2ChunkSize)),
	}
}

// parseObjectMeta reads blindbucket's metadata off an upstream response.
//
// fallbackLog2C is used for objects written before bb-c existed, and for any
// provider that drops the header. It is the configured chunk size, which is
// correct for every object a given deployment wrote.
func parseObjectMeta(md map[string]string, fallbackLog2C uint8) (objectMeta, error) {
	lookup := func(key string) string {
		// Providers canonicalise metadata keys differently -- MinIO returns
		// "Bb-Kid", others lower-case -- so match case-insensitively.
		for name, value := range md {
			if strings.EqualFold(name, key) {
				return value
			}
		}
		return ""
	}

	raw := lookup(metaDEK)
	if raw == "" {
		return objectMeta{}, errNotEncrypted
	}

	version, err := strconv.Atoi(lookup(metaVersion))
	if err != nil {
		return objectMeta{}, fmt.Errorf("object metadata has no usable %s: %w", metaVersion, err)
	}
	if version != stream.Version {
		return objectMeta{}, fmt.Errorf("object is format version %d, this build reads %d",
			version, stream.Version)
	}

	kid := lookup(metaKeyID)
	if err := keys.ValidateKID(kid); err != nil {
		return objectMeta{}, fmt.Errorf("object metadata has no usable %s: %w", metaKeyID, err)
	}

	wrapped, err := keys.DecodeWrapped(raw)
	if err != nil {
		return objectMeta{}, fmt.Errorf("object metadata has an unreadable %s: %w", metaDEK, err)
	}
	if len(wrapped) != keys.WrappedDEKSize {
		return objectMeta{}, fmt.Errorf("wrapped key is %d bytes, want %d",
			len(wrapped), keys.WrappedDEKSize)
	}

	log2C, recorded := fallbackLog2C, false
	if raw := lookup(metaChunkSize); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 || parsed > 255 {
			return objectMeta{}, fmt.Errorf("object metadata has an unreadable %s", metaChunkSize)
		}
		log2C, recorded = uint8(parsed), true
	}
	if err := stream.ValidateLog2ChunkSize(log2C); err != nil {
		return objectMeta{}, err
	}

	return objectMeta{
		Version:       version,
		KeyID:         kid,
		WrappedDEK:    wrapped,
		Log2ChunkSize: log2C,
		HasChunkSize:  recorded,
	}, nil
}

// clientMetadata extracts the user metadata a client sent, and refuses any
// attempt to write blindbucket's own keys.
//
// Letting a client set bb-dek would let it swap the wrapped key of an object it
// is allowed to write for one from an object it is not.
func clientMetadata(h http.Header) (map[string]string, error) {
	out := make(map[string]string)
	for name, values := range h {
		if !strings.HasPrefix(strings.ToLower(name), "x-amz-meta-") || len(values) == 0 {
			continue
		}
		key := name[len("x-amz-meta-"):]
		if strings.HasPrefix(strings.ToLower(key), metaPrefix) {
			return nil, fmt.Errorf("metadata key %q uses the reserved %q prefix", key, metaPrefix)
		}
		out[key] = values[0]
	}
	return out, nil
}

// responseHeadersToStrip are removed before a response reaches the client.
//
// The checksum headers are the subtle ones: they describe the ciphertext, so an
// SDK that validates them against the plaintext it received would report
// corruption on a perfectly good object.
var responseHeadersToStrip = []string{
	"X-Amz-Checksum-Crc32",
	"X-Amz-Checksum-Crc32c",
	"X-Amz-Checksum-Crc64nvme",
	"X-Amz-Checksum-Sha1",
	"X-Amz-Checksum-Sha256",
	"X-Amz-Checksum-Type",
	"X-Amz-Sdk-Checksum-Algorithm",
	"Content-Length",
	"Content-Range",
	"Accept-Ranges",
}

// copyResponseHeaders forwards the upstream's headers to the client, minus
// blindbucket's own metadata and anything that describes the ciphertext.
func copyResponseHeaders(dst, src http.Header) {
	for name, values := range src {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-amz-meta-"+metaPrefix) {
			continue
		}
		dst[name] = slicesClone(values)
	}
	for _, name := range responseHeadersToStrip {
		dst.Del(name)
	}
}

func slicesClone(v []string) []string {
	out := make([]string, len(v))
	copy(out, v)
	return out
}

// mergeMetadata combines the client's metadata with blindbucket's own.
func mergeMetadata(client map[string]string, own objectMeta) map[string]string {
	out := make(map[string]string, len(client)+4)
	maps.Copy(out, client)
	maps.Copy(out, own.headers())
	return out
}
