package keys

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Root-key sources a keyring file may name.
//
// The hierarchy in FORMAT.md §3 has always said the root key is external: "AWS
// KMS | Vault Transit | Argon2id(passphrase)". These are the three, spelled the
// way the file spells them.
const (
	// SourcePassphrase stretches an operator's passphrase into the root key
	// with Argon2id. The key exists only in memory and only while the process
	// runs; nothing but the KDF parameters is stored.
	SourcePassphrase = "passphrase"
	// SourceVaultTransit stores the root key encrypted by a Vault Transit key.
	// Vault holds the key that opens it and never hands it out.
	SourceVaultTransit = "vault-transit"
	// SourceAWSKMS stores the root key as a KMS ciphertext blob.
	SourceAWSKMS = "awskms"
)

// RootKeyRef describes how a keyring's root key is obtained.
//
// For a passphrase keyring it is the KDF parameters and nothing else. For the
// two service-backed sources it is the encrypted root key itself, together with
// the name of the key that opens it -- a reminder for the operator, and the
// reason a keyring file is enough to know what to ask for.
//
// The ciphertext is safe at rest for the same reason the KEK entries are: it is
// only openable by something this file does not contain.
type RootKeyRef struct {
	Source string `json:"source"`

	// Ciphertext is the encrypted root key, in whatever envelope the service
	// uses: Vault's own "vault:v1:..." string, or base64 of a KMS blob. Empty
	// for a passphrase keyring.
	Ciphertext string `json:"ciphertext,omitempty"`

	// KeyName is the Transit key or the KMS key id the ciphertext was produced
	// under. It is not trusted for anything -- the caller's configuration
	// decides which service is asked -- but it makes a mismatch diagnosable
	// instead of a decryption failure with no explanation.
	KeyName string `json:"key_name,omitempty"`

	// Context is the AWS KMS encryption context the ciphertext was produced
	// under: the service's own associated data, the same idea this format
	// applies to every DEK (section 6 of FORMAT.md). It is recorded here
	// because decrypting requires exactly the context that encrypted, and a
	// keyring has to be openable from the file alone.
	//
	// Storing it in the untrusted file costs nothing: KMS binds the ciphertext
	// to the context cryptographically, so a modified one fails to decrypt
	// rather than opening anything. What it buys is a value that appears in
	// CloudTrail and that a key policy can require with a kms:EncryptionContext
	// condition -- so a grant can be narrowed to this use of the key.
	//
	// Absent in keyrings written before it existed, which decrypt with no
	// context, as they were encrypted.
	Context map[string]string `json:"context,omitempty"`
}

// Bounds on an encryption context read from a keyring file. AWS enforces its
// own limits; these exist because the file is untrusted input and nothing
// should be able to make this build assemble an unbounded request.
const (
	maxContextPairs = 16
	maxContextField = 256
)

// validate rejects a reference that cannot be acted on.
//
// A keyring file is untrusted input, so a source this build does not know is an
// error rather than something to fall back from: falling back would mean
// prompting for a passphrase for a keyring that has none.
func (r RootKeyRef) validate() error {
	switch r.Source {
	case SourcePassphrase, "":
		return nil
	case SourceVaultTransit, SourceAWSKMS:
		if r.Ciphertext == "" {
			return fmt.Errorf("keys: a %s keyring carries no encrypted root key", r.Source)
		}
		return r.validateContext()
	default:
		return fmt.Errorf("keys: unsupported root-key source %q", r.Source)
	}
}

func (r RootKeyRef) validateContext() error {
	if len(r.Context) > maxContextPairs {
		return fmt.Errorf("keys: encryption context has %d entries, at most %d are allowed",
			len(r.Context), maxContextPairs)
	}
	for k, v := range r.Context {
		if k == "" {
			return fmt.Errorf("keys: encryption context has an empty key")
		}
		if len(k) > maxContextField || len(v) > maxContextField {
			return fmt.Errorf("keys: encryption context entry %q exceeds %d bytes",
				k, maxContextField)
		}
	}
	return nil
}

// ReadRootKeyRef reports how a keyring file's root key is obtained, without
// opening it.
//
// The caller needs this before it can produce the key: it decides whether to
// prompt for a passphrase or to ask Vault or KMS, and what to ask them for.
func ReadRootKeyRef(data []byte) (RootKeyRef, error) {
	file, err := parseKeyringFile(data)
	if err != nil {
		return RootKeyRef{}, err
	}
	ref := file.RootKey
	if ref.Source == "" {
		// A file written before this field existed is a passphrase keyring;
		// that is what the KDF parameters in it are for.
		ref.Source = SourcePassphrase
	}
	if err := ref.validate(); err != nil {
		return RootKeyRef{}, err
	}
	return ref, nil
}

// DecodeKMSCiphertext returns the raw blob of an awskms reference.
func (r RootKeyRef) DecodeKMSCiphertext() ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(r.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("keys: the stored root key is not valid base64: %w", err)
	}
	return raw, nil
}

// NewRootKey returns a fresh root key for a service-backed keyring.
//
// Unlike the passphrase case there is nothing to stretch: the key is uniformly
// random, and its secrecy rests on the service that encrypts it rather than on
// how hard it is to guess.
func NewRootKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("keys: generating a root key: %w", err)
	}
	return key, nil
}
