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
// Implementations wrap and unwrap data keys under a KEK identified by kid, and
// the Keyring is the only one: it does this locally, against KEKs held in
// memory. Vault and AWS KMS do not appear here on purpose. They supply the
// *root key* that unlocks the keyring, once, at startup (internal/rootkey and
// ADR-013), after which every wrap and unwrap is local again. Putting a key
// service on the data path would add its latency to every PUT and GET and make
// a key-service outage a data outage.
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
	// it belongs to. See docs/adr/ADR-006-upload-token.md.
	TokenKey(ctx context.Context, kid string) ([]byte, error)
}
