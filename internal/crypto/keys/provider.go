package keys

import (
	"context"
	"errors"
)

// ErrUnknownKID reports that a key identifier is not present in the keyring.
//
// It is what a client sees after a KEK has been retired while objects still
// reference it, and it is deliberately distinct from an authentication failure:
// one means "cannot find the key", the other means "the data does not match it".
var ErrUnknownKID = errors.New("keys: unknown key id")

// ErrUnwrap reports that a wrapped key failed authentication.
//
// It carries no detail on purpose. The causes -- wrong KEK, tampered ciphertext,
// mismatching associated data because bucket or key changed -- are
// indistinguishable to an attacker and should stay that way.
var ErrUnwrap = errors.New("keys: unwrapping failed")

// KeyProvider is where key-encryption keys come from.
//
// Implementations wrap and unwrap data keys under a KEK identified by kid. The
// file-backed Keyring does this locally against KEKs held in memory. The Vault
// and AWS KMS providers are deferred; the design is that they decrypt the keyring
// at startup and then behave identically, so that no request pays for a round
// trip to a key service.
type KeyProvider interface {
	// ActiveKID returns the id of the KEK new data keys are wrapped under.
	ActiveKID() string

	// Wrap encrypts dek under the KEK named kid, bound to aad.
	Wrap(ctx context.Context, kid string, dek, aad []byte) ([]byte, error)

	// Unwrap reverses Wrap. It fails if aad does not match the value used to
	// wrap, which is what binds a data key to the object it belongs to.
	Unwrap(ctx context.Context, kid string, wrapped, aad []byte) ([]byte, error)

	// TokenKey derives the key that seals multipart upload tokens under the KEK
	// named kid. The caller must not retain or log it.
	//
	// It is separate from Wrap because a token is not a data key: it is opened
	// by an instance that may never have seen the upload being created, and it
	// is keyed off the KEK so that it can be opened without knowing which object
	// it belongs to. See CONCEPT.md section 10.3.
	TokenKey(ctx context.Context, kid string) ([]byte, error)
}
