package keys

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// AuditSecretSize is the length of the secret an audit key is derived from.
const AuditSecretSize = 32

// HKDF info strings for the two keys derived from the audit secret. Separate
// strings are what stop the signing seed and the name key from ever being the
// same bytes, which matters because one of them is published as a public key and
// the other must not be derivable from it.
const (
	auditSignInfo = "blindbucket/v1/audit-sign"
	auditNameInfo = "blindbucket/v1/audit-name"
)

// AuditKey is the key material behind a signed audit log: one stored secret,
// two derived uses.
//
// The Ed25519 half signs the checkpoints that make a log's chain unforgeable.
// The name half encrypts the bucket and key of each entry, so that a log carried
// off the host says no more about what is stored than the bucket does
// (ADR-015, ADR-016).
//
// Only the secret is ever written, and only wrapped. Everything else is derived
// on load.
type AuditKey struct {
	secret [AuditSecretSize]byte
}

// NewAuditKey generates a fresh audit secret.
func NewAuditKey() (*AuditKey, error) {
	var k AuditKey
	if _, err := rand.Read(k.secret[:]); err != nil {
		return nil, err
	}
	return &k, nil
}

// AuditKeyFromSecret adopts an existing secret.
func AuditKeyFromSecret(secret []byte) (*AuditKey, error) {
	if len(secret) != AuditSecretSize {
		return nil, fmt.Errorf("keys: audit secret is %d bytes, want %d",
			len(secret), AuditSecretSize)
	}
	var k AuditKey
	copy(k.secret[:], secret)
	return &k, nil
}

// Secret returns a copy of the stored secret. The caller owns it and should
// wipe it.
func (k *AuditKey) Secret() []byte {
	out := make([]byte, AuditSecretSize)
	copy(out, k.secret[:])
	return out
}

// Signer derives the Ed25519 private key that signs checkpoints.
func (k *AuditKey) Signer() (ed25519.PrivateKey, error) {
	seed, err := hkdf.Key(sha256.New, k.secret[:], nil, auditSignInfo, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	return ed25519.NewKeyFromSeed(seed), nil
}

// Public derives the Ed25519 public key that verifies them.
//
// This is the only part of an audit key that is written in clear, and that is
// the point: verifying a log is then a check anyone can run, including someone
// who must not be given the keyring. See ADR-016.
func (k *AuditKey) Public() (ed25519.PublicKey, error) {
	priv, err := k.Signer()
	if err != nil {
		return nil, err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("keys: derived signer has no Ed25519 public key")
	}
	return pub, nil
}

// NameKey derives the key that encrypts bucket and object names in log entries.
//
// It is deliberately not the name key of ADR-015: the two are independent, so an
// entry in a log and the name of an object in the bucket are different opaque
// strings for the same object.
func (k *AuditKey) NameKey() ([]byte, error) {
	return hkdf.Key(sha256.New, k.secret[:], nil, auditNameInfo, KeySize)
}

// Wipe zeroes the secret.
func (k *AuditKey) Wipe() { clear(k.secret[:]) }
