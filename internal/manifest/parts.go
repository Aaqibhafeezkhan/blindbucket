package manifest

import (
	"errors"
	"fmt"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
)

// MaxPartCiphertext is S3's limit on the size of a single part, and therefore on
// the ciphertext of one segment. The plaintext limit that follows from it is
// about 5 GiB - 1.25 MiB at the default chunk size.
const MaxPartCiphertext = 5 << 30

// ErrPartRules reports a part list that breaks the size rules of
// docs/FORMAT.md section 7.3.
//
// The rules exist so that the plaintext size of a multipart object can be
// recovered from its ciphertext size and part count alone, without opening it.
// Breaking them is refused at CompleteMultipartUpload rather than accepted,
// because an object whose size cannot be recovered would list wrongly forever.
var ErrPartRules = errors.New("manifest: part sizes break the multipart rules")

// ErrPartTooLarge reports a part whose ciphertext exceeds what S3 stores.
var ErrPartTooLarge = errors.New("manifest: part exceeds the maximum size")

// UploadedPart is one part as the upstream reports it from ListParts.
type UploadedPart struct {
	Number uint32
	// CipherSize is the stored size of the part, which is one whole segment.
	CipherSize int64
	ETag       string
	// Salt is the segment salt of the attempt this part was completed from.
	// It comes from the client echoing back what the gateway sealed into the
	// part's ETag, because a part of an open upload cannot be read.
	Salt [stream.SaltSize]byte
}

// PartsFromUpstream converts the upstream's ciphertext part sizes into the part
// list of a manifest, enforcing the rules of docs/FORMAT.md section 7.3.
//
// Every part is its own segment, so each ciphertext size inverts on its own. The
// rules then make the total invert as well: with every part but the last an
// exact multiple of the chunk size, the chunk counts of the parts sum to
// ceil(P/C) for the whole object, which is what the listing arithmetic needs.
func PartsFromUpstream(uploaded []UploadedPart, log2C uint8) ([]Part, error) {
	if err := stream.ValidateLog2ChunkSize(log2C); err != nil {
		return nil, err
	}
	if len(uploaded) == 0 {
		return nil, fmt.Errorf("%w: the upload has no parts", ErrPartRules)
	}
	if len(uploaded) > stream.MaxParts {
		return nil, fmt.Errorf("%w: %d parts exceeds the maximum of %d",
			ErrPartRules, len(uploaded), stream.MaxParts)
	}

	chunk := int64(1) << log2C
	parts := make([]Part, 0, len(uploaded))
	for i, up := range uploaded {
		if up.CipherSize > MaxPartCiphertext {
			return nil, fmt.Errorf("%w: part %d is %d bytes of ciphertext, the maximum is %d",
				ErrPartTooLarge, up.Number, up.CipherSize, int64(MaxPartCiphertext))
		}
		plain, err := stream.OpenedSize(up.CipherSize, log2C)
		if err != nil {
			return nil, fmt.Errorf("%w: part %d is %d bytes, which is not a size this format "+
				"produces at chunk size %d", ErrPartRules, up.Number, up.CipherSize, chunk)
		}

		last := i == len(uploaded)-1
		switch {
		case last && plain == 0:
			return nil, fmt.Errorf("%w: the last part is empty", ErrPartRules)
		case !last && plain == 0:
			return nil, fmt.Errorf("%w: part %d is empty", ErrPartRules, up.Number)
		case !last && plain%chunk != 0:
			// The message names the fix, because a client that hits this has a
			// part size setting to change and nothing else it can do.
			return nil, fmt.Errorf("%w: part %d is %d bytes, which is not a multiple of the "+
				"chunk size %d; configure a part size that is a multiple of %d",
				ErrPartRules, up.Number, plain, chunk, chunk)
		}
		parts = append(parts, Part{Number: up.Number, PlainSize: plain, Salt: up.Salt})
	}

	m := &Manifest{Parts: parts}
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPartRules, err)
	}
	return parts, nil
}

// MaxPartPlaintext returns the largest plaintext a single part may carry at the
// given chunk size.
func MaxPartPlaintext(log2C uint8) (int64, error) {
	if err := stream.ValidateLog2ChunkSize(log2C); err != nil {
		return 0, err
	}
	// Walk down from the cap to the largest size the format actually produces:
	// only sizes that invert cleanly are storable, and the chunk-aligned one
	// below the cap always does.
	chunk := int64(1) << log2C
	for plain := (MaxPartCiphertext / chunk) * chunk; plain > 0; plain -= chunk {
		sealed, err := stream.SealedSize(plain, log2C)
		if err == nil && sealed <= MaxPartCiphertext {
			return plain, nil
		}
	}
	return 0, fmt.Errorf("manifest: no part size fits at chunk size %d", chunk)
}
