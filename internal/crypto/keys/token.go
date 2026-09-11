package keys

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
)

// tokenKeyInfo domain-separates the upload-token key from every other key
// derived from a KEK. See docs/FORMAT.md section 3.
const tokenKeyInfo = "blindbucket/v1/upload-token"

// TokenKeySize is the length of a derived upload-token key in bytes.
const TokenKeySize = KeySize

// deriveTokenKey derives the key that seals upload tokens under a given KEK.
//
// It hangs off the KEK rather than off a DEK because a token has to be readable
// before any object exists: the whole point is that an instance which never saw
// the CreateMultipartUpload can still open the token a client hands it. The kid
// travels in clear text at the front of the token so that a KEK rotation during
// a running upload does not orphan the tokens already issued.
func deriveTokenKey(kek []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, kek, nil, tokenKeyInfo, TokenKeySize)
}

// TokenKey implements KeyProvider.
func (r *Keyring) TokenKey(_ context.Context, kid string) ([]byte, error) {
	kek, err := r.lookup(kid)
	if err != nil {
		return nil, err
	}
	defer clear(kek[:])
	return deriveTokenKey(kek[:])
}
