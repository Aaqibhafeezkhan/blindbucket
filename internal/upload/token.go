// Package upload implements the stateless upload token that stands in for an
// upstream multipart UploadId.
//
// A client treats an UploadId as an opaque string and hands it back unchanged
// with every part and with the completion. That is what lets blindbucket keep no
// upload state at all: everything a request needs -- the upstream upload id, the
// data key, the manifest id -- travels inside the token, sealed under a key that
// every instance can derive. Any instance can serve any part, instances can
// restart mid-upload, and no load balancer needs sticky sessions.
//
// See CONCEPT.md section 10.3 and docs/adr/ADR-006-upload-token.md.
package upload

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
)

const (
	// TokenVersion is the leading byte of every token.
	TokenVersion = 0x01
	// nonceSize and tagSize are AES-GCM's.
	nonceSize = 12
	tagSize   = 16
	// aadPrefix domain-separates the token's associated data.
	aadPrefix = "blindbucket/v1/upload-token"
	// maxUploadIDLen bounds the upstream upload id a token may carry. Real ones
	// are well under 200 bytes; the bound is what stops a token from being used
	// as a place to park megabytes at the gateway's expense.
	maxUploadIDLen = 1024
	// maxTokenLen bounds the encoded token a client may present, before any of
	// it is decoded.
	maxTokenLen = 4096
)

// ErrToken reports a token that is missing, malformed, or does not authenticate.
//
// Like a failed unwrap it carries no detail: a forged token, a token for another
// object and a token sealed under a retired KEK must look the same from outside.
var ErrToken = errors.New("upload: invalid upload token")

// Token is the state of one multipart upload.
type Token struct {
	// KID names the KEK whose token key seals this token. It travels in clear
	// text so that a KEK rotation during a running upload still finds the right
	// key for tokens issued before it.
	KID string
	// UploadID is the upstream provider's own UploadId.
	UploadID string
	// WrappedDEK is the object's data key, wrapped under KID with the object's
	// associated data -- the same bytes that end up in bb-dek.
	WrappedDEK []byte
	// ManifestID is the manifest this upload will write (rule R1).
	ManifestID manifest.ID
}

// Seal renders t as the opaque UploadId handed to the client.
//
// bucket and key are authenticated but not stored: a token is bound to the
// object it was issued for, so one obtained for a writable key cannot be
// replayed against another.
func Seal(ctx context.Context, provider keys.KeyProvider, t Token, bucket, key string) (string, error) {
	if err := keys.ValidateKID(t.KID); err != nil {
		return "", err
	}
	if l := len(t.UploadID); l == 0 || l > maxUploadIDLen {
		return "", fmt.Errorf("upload: upstream upload id is %d bytes, outside 1..%d", l, maxUploadIDLen)
	}
	if len(t.WrappedDEK) != keys.WrappedDEKSize {
		return "", fmt.Errorf("upload: wrapped key is %d bytes, want %d",
			len(t.WrappedDEK), keys.WrappedDEKSize)
	}

	aead, err := tokenAEAD(ctx, provider, t.KID)
	if err != nil {
		return "", err
	}
	aad, err := tokenAAD(bucket, key)
	if err != nil {
		return "", err
	}

	body := make([]byte, 0, 2+len(t.UploadID)+keys.WrappedDEKSize+manifest.IDSize)
	//nolint:gosec // the length is bounded by maxUploadIDLen above.
	body = binary.BigEndian.AppendUint16(body, uint16(len(t.UploadID)))
	body = append(body, t.UploadID...)
	body = append(body, t.WrappedDEK...)
	body = append(body, t.ManifestID[:]...)
	defer clear(body)

	out := make([]byte, 0, 1+2+len(t.KID)+nonceSize+len(body)+tagSize)
	out = append(out, TokenVersion)
	//nolint:gosec // ValidateKID bounds a kid to 64 bytes.
	out = binary.BigEndian.AppendUint16(out, uint16(len(t.KID)))
	out = append(out, t.KID...)

	nonceAt := len(out)
	out = append(out, make([]byte, nonceSize)...)
	if _, err := rand.Read(out[nonceAt:]); err != nil {
		return "", err
	}
	out = aead.Seal(out, out[nonceAt:nonceAt+nonceSize], body, aad)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Open reverses Seal. Every failure reports ErrToken.
func Open(ctx context.Context, provider keys.KeyProvider, token, bucket, key string) (*Token, error) {
	if token == "" || len(token) > maxTokenLen {
		return nil, fmt.Errorf("%w: length %d", ErrToken, len(token))
	}
	// Strict: a base64 encoding with non-zero trailing bits decodes to the same
	// bytes as the canonical one, so without this two different strings would be
	// the same token. Nothing is forged either way, but a token should have one
	// spelling.
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("%w: not valid base64url", ErrToken)
	}
	if len(raw) < 3 || raw[0] != TokenVersion {
		return nil, fmt.Errorf("%w: unrecognised token version", ErrToken)
	}

	kidLen := int(binary.BigEndian.Uint16(raw[1:3]))
	if len(raw) < 3+kidLen+nonceSize+tagSize {
		return nil, fmt.Errorf("%w: truncated", ErrToken)
	}
	kid := string(raw[3 : 3+kidLen])
	// Validated before it reaches the key provider: the kid is the one field an
	// unauthenticated token gets to choose.
	if err := keys.ValidateKID(kid); err != nil {
		return nil, fmt.Errorf("%w: unusable key id", ErrToken)
	}

	aead, err := tokenAEAD(ctx, provider, kid)
	if err != nil {
		// An unknown kid is indistinguishable from a forged one to the client.
		if errors.Is(err, keys.ErrUnknownKID) {
			return nil, fmt.Errorf("%w: unknown key id", ErrToken)
		}
		return nil, err
	}
	aad, err := tokenAAD(bucket, key)
	if err != nil {
		return nil, err
	}

	nonce := raw[3+kidLen : 3+kidLen+nonceSize]
	body, err := aead.Open(nil, nonce, raw[3+kidLen+nonceSize:], aad)
	if err != nil {
		return nil, fmt.Errorf("%w: authentication failed", ErrToken)
	}
	defer clear(body)

	// Past this point the bytes are authentic, so parsing them is safe.
	if len(body) < 2 {
		return nil, fmt.Errorf("%w: truncated body", ErrToken)
	}
	idLen := int(binary.BigEndian.Uint16(body[:2]))
	if idLen == 0 || idLen > maxUploadIDLen ||
		len(body) != 2+idLen+keys.WrappedDEKSize+manifest.IDSize {
		return nil, fmt.Errorf("%w: malformed body", ErrToken)
	}

	out := &Token{
		KID:        kid,
		UploadID:   string(body[2 : 2+idLen]),
		WrappedDEK: append([]byte(nil), body[2+idLen:2+idLen+keys.WrappedDEKSize]...),
	}
	copy(out.ManifestID[:], body[2+idLen+keys.WrappedDEKSize:])
	return out, nil
}

// tokenAEAD builds the AEAD for the token key of kid.
func tokenAEAD(ctx context.Context, provider keys.KeyProvider, kid string) (cipher.AEAD, error) {
	tk, err := provider.TokenKey(ctx, kid)
	if err != nil {
		return nil, err
	}
	defer clear(tk)
	block, err := aes.NewCipher(tk)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// tokenAAD binds a token to one bucket and key.
func tokenAAD(bucket, key string) ([]byte, error) {
	if len(bucket) > 0xffff || len(key) > 0xffff {
		return nil, errors.New("upload: bucket or key exceeds the length prefix")
	}
	aad := make([]byte, 0, len(aadPrefix)+4+len(bucket)+len(key))
	aad = append(aad, aadPrefix...)
	//nolint:gosec // both lengths are bounded immediately above.
	aad = binary.BigEndian.AppendUint16(aad, uint16(len(bucket)))
	aad = append(aad, bucket...)
	//nolint:gosec // both lengths are bounded immediately above.
	aad = binary.BigEndian.AppendUint16(aad, uint16(len(key)))
	aad = append(aad, key...)
	return aad, nil
}
