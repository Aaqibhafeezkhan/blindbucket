package keys

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// keyringVersion is the on-disk format version of a keyring file.
const keyringVersion = 1

// Keyring holds the key-encryption keys of a deployment in memory and wraps data
// keys under them locally.
//
// Holding the KEKs in memory is the point of the three-level hierarchy: the
// keyring is decrypted once at startup, and wrapping a data key afterwards costs
// no network round trip and no per-object key service call. See
// docs/adr/ADR-002-key-hierarchy.md.
//
// A Keyring is safe for concurrent use.
type Keyring struct {
	mu      sync.RWMutex
	active  string
	keks    map[string][KeySize]byte
	created map[string]time.Time
}

// NewKeyring returns an empty keyring.
func NewKeyring() *Keyring {
	return &Keyring{
		keks:    make(map[string][KeySize]byte),
		created: make(map[string]time.Time),
	}
}

// Generate adds a fresh random KEK under kid. The first key added becomes
// active.
func (r *Keyring) Generate(kid string) error {
	var kek [KeySize]byte
	if _, err := rand.Read(kek[:]); err != nil {
		return err
	}
	return r.Add(kid, kek[:])
}

// Add inserts an existing KEK. The first key added becomes active.
func (r *Keyring) Add(kid string, kek []byte) error {
	if err := ValidateKID(kid); err != nil {
		return err
	}
	if len(kek) != KeySize {
		return fmt.Errorf("keys: KEK %q is %d bytes, want %d", kid, len(kek), KeySize)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.keks[kid]; exists {
		return fmt.Errorf("keys: key id %q already exists", kid)
	}
	var stored [KeySize]byte
	copy(stored[:], kek)
	r.keks[kid] = stored
	r.created[kid] = time.Now().UTC()
	if r.active == "" {
		r.active = kid
	}
	return nil
}

// SetActive selects the KEK new data keys are wrapped under.
func (r *Keyring) SetActive(kid string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.keks[kid]; !ok {
		return fmt.Errorf("%w: %q", ErrUnknownKID, kid)
	}
	r.active = kid
	return nil
}

// ActiveKID implements KeyProvider.
func (r *Keyring) ActiveKID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.active
}

// KIDs returns every key id in the keyring, sorted.
func (r *Keyring) KIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.keks))
	for kid := range r.keks {
		out = append(out, kid)
	}
	sort.Strings(out)
	return out
}

// Created reports when a key was added.
func (r *Keyring) Created(kid string) (time.Time, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.created[kid]
	return t, ok
}

// Wrap implements KeyProvider.
func (r *Keyring) Wrap(_ context.Context, kid string, dek, aad []byte) ([]byte, error) {
	kek, err := r.lookup(kid)
	if err != nil {
		return nil, err
	}
	return sealKey(kek[:], dek, aad)
}

// Unwrap implements KeyProvider.
func (r *Keyring) Unwrap(_ context.Context, kid string, wrapped, aad []byte) ([]byte, error) {
	kek, err := r.lookup(kid)
	if err != nil {
		return nil, err
	}
	return openKey(kek[:], wrapped, aad)
}

func (r *Keyring) lookup(kid string) ([KeySize]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	kek, ok := r.keks[kid]
	if !ok {
		return [KeySize]byte{}, fmt.Errorf("%w: %q", ErrUnknownKID, kid)
	}
	return kek, nil
}

// A compile-time assertion that the keyring is a usable KeyProvider.
var _ KeyProvider = (*Keyring)(nil)

// KDFParams describes how a passphrase is stretched into the root key that
// protects a keyring file.
type KDFParams struct {
	Algorithm   string `json:"algorithm"`
	Salt        string `json:"salt"`
	Time        uint32 `json:"time"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Parallelism uint8  `json:"parallelism"`
}

// DefaultKDFParams follows the second recommended option of RFC 9106: 64 MiB of
// memory, three passes, four lanes. The memory cost is what makes a stolen
// keyring file expensive to attack offline.
var DefaultKDFParams = KDFParams{
	Algorithm:   "argon2id",
	Time:        3,
	MemoryKiB:   64 * 1024,
	Parallelism: 4,
}

// Bounds on KDF parameters read from a file.
//
// A keyring file is untrusted input: it may have been written by someone else,
// or tampered with. Without these bounds a file could ask for 100 GiB of memory
// and turn opening it into a denial of service against the reader.
const (
	maxKDFMemoryKiB   = 1 << 20 // 1 GiB
	maxKDFTime        = 16
	maxKDFParallelism = 16
	kdfSaltSize       = 16
)

func (p KDFParams) validate() error {
	switch {
	case p.Algorithm != "argon2id":
		return fmt.Errorf("keys: unsupported KDF %q", p.Algorithm)
	case p.Time == 0 || p.Time > maxKDFTime:
		return fmt.Errorf("keys: KDF time %d outside 1..%d", p.Time, maxKDFTime)
	case p.MemoryKiB == 0 || p.MemoryKiB > maxKDFMemoryKiB:
		return fmt.Errorf("keys: KDF memory %d KiB outside 1..%d", p.MemoryKiB, maxKDFMemoryKiB)
	case p.Parallelism == 0 || p.Parallelism > maxKDFParallelism:
		return fmt.Errorf("keys: KDF parallelism %d outside 1..%d", p.Parallelism, maxKDFParallelism)
	}
	return nil
}

// deriveRootKey stretches a passphrase into the key that wraps the KEKs.
func (p KDFParams) deriveRootKey(passphrase []byte) ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(p.Salt)
	if err != nil {
		return nil, fmt.Errorf("keys: KDF salt is not valid base64: %w", err)
	}
	if len(salt) < kdfSaltSize {
		return nil, fmt.Errorf("keys: KDF salt is %d bytes, want at least %d", len(salt), kdfSaltSize)
	}
	return argon2.IDKey(passphrase, salt, p.Time, p.MemoryKiB, p.Parallelism, KeySize), nil
}

// keyringFile is the on-disk representation. Only wrapped key material appears
// in it; the root key exists solely in memory, derived from the passphrase.
type keyringFile struct {
	Version   int    `json:"version"`
	ActiveKID string `json:"active_kid"`
	// RootKey says where the root key comes from. Absent in files written
	// before service-backed sources existed, which are passphrase keyrings --
	// that is what KDF below is for, and it is written only for those.
	RootKey RootKeyRef `json:"root_key,omitempty"`
	// A pointer, so a service-sealed keyring omits it entirely rather than
	// carrying a zeroed Argon2id block it can never use: encoding/json's
	// omitempty does nothing for a struct value.
	KDF  *KDFParams `json:"kdf,omitempty"`
	Keys []keyEntry `json:"keys"`
}

type keyEntry struct {
	KID     string    `json:"kid"`
	Created time.Time `json:"created"`
	Wrapped string    `json:"wrapped"`
}

// Marshal renders the keyring as a file, with every KEK wrapped under a root key
// derived from passphrase.
func (r *Keyring) Marshal(passphrase []byte, params KDFParams) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("keys: refusing to write a keyring without a passphrase")
	}

	params.Algorithm = "argon2id"
	if params.Salt == "" {
		salt := make([]byte, kdfSaltSize)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		params.Salt = base64.StdEncoding.EncodeToString(salt)
	}
	rootKey, err := params.deriveRootKey(passphrase)
	if err != nil {
		return nil, err
	}
	defer clear(rootKey)

	return r.marshal(rootKey, RootKeyRef{Source: SourcePassphrase}, &params)
}

// MarshalWithRootKey renders the keyring under a root key held elsewhere.
//
// ref records what has to be asked to get that key back, and is written into
// the file. The caller owns rootKey and should wipe it.
func (r *Keyring) MarshalWithRootKey(rootKey []byte, ref RootKeyRef) ([]byte, error) {
	if len(rootKey) != KeySize {
		return nil, fmt.Errorf("keys: root key is %d bytes, want %d", len(rootKey), KeySize)
	}
	if err := ref.validate(); err != nil {
		return nil, err
	}
	if ref.Source == SourcePassphrase || ref.Source == "" {
		return nil, fmt.Errorf("keys: MarshalWithRootKey needs a service-backed source")
	}
	return r.marshal(rootKey, ref, nil)
}

func (r *Keyring) marshal(rootKey []byte, ref RootKeyRef, params *KDFParams) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active == "" {
		return nil, fmt.Errorf("keys: refusing to write an empty keyring")
	}

	file := keyringFile{
		Version: keyringVersion, ActiveKID: r.active, RootKey: ref, KDF: params,
	}
	for _, kid := range sortedKeys(r.keks) {
		aad, err := kekAAD(kid)
		if err != nil {
			return nil, err
		}
		kek := r.keks[kid]
		wrapped, err := sealKey(rootKey, kek[:], aad)
		if err != nil {
			return nil, err
		}
		file.Keys = append(file.Keys, keyEntry{
			KID:     kid,
			Created: r.created[kid],
			Wrapped: base64.StdEncoding.EncodeToString(wrapped),
		})
	}

	out, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// parseKeyringFile decodes and version-checks a keyring file.
func parseKeyringFile(data []byte) (keyringFile, error) {
	var file keyringFile
	if err := json.Unmarshal(data, &file); err != nil {
		return keyringFile{}, fmt.Errorf("keys: keyring is not valid JSON: %w", err)
	}
	if file.Version != keyringVersion {
		return keyringFile{}, fmt.Errorf("keys: keyring version %d, this build supports %d",
			file.Version, keyringVersion)
	}
	if len(file.Keys) == 0 {
		return keyringFile{}, fmt.Errorf("keys: keyring contains no keys")
	}
	return file, nil
}

// LoadKeyring parses a keyring file and unwraps its KEKs with passphrase.
//
// The key id is authenticated as associated data, so an attacker who reorders or
// relabels entries in the file cannot make a KEK load under a different id.
func LoadKeyring(data, passphrase []byte) (*Keyring, error) {
	file, err := parseKeyringFile(data)
	if err != nil {
		return nil, err
	}
	if src := file.RootKey.Source; src != "" && src != SourcePassphrase {
		return nil, fmt.Errorf(
			"keys: this keyring's root key comes from %s, not from a passphrase", src)
	}

	if file.KDF == nil {
		return nil, fmt.Errorf("keys: this keyring records no KDF parameters")
	}
	rootKey, err := file.KDF.deriveRootKey(passphrase)
	if err != nil {
		return nil, err
	}
	defer clear(rootKey)
	return openKeyring(file, rootKey, "wrong passphrase, or the keyring was modified")
}

// LoadKeyringWithRootKey unwraps a keyring whose root key came from elsewhere.
//
// It is the same operation as LoadKeyring past the KDF: Vault and KMS replace
// how the root key is obtained, not what it protects or how. The caller owns
// rootKey and should wipe it.
func LoadKeyringWithRootKey(data, rootKey []byte) (*Keyring, error) {
	file, err := parseKeyringFile(data)
	if err != nil {
		return nil, err
	}
	if len(rootKey) != KeySize {
		return nil, fmt.Errorf("keys: root key is %d bytes, want %d", len(rootKey), KeySize)
	}
	return openKeyring(file, rootKey, "the root key does not open this keyring")
}

// openKeyring unwraps every KEK in a parsed file under rootKey.
func openKeyring(file keyringFile, rootKey []byte, wrongKeyHint string) (*Keyring, error) {
	ring := NewKeyring()
	for _, entry := range file.Keys {
		aad, err := kekAAD(entry.KID)
		if err != nil {
			return nil, err
		}
		wrapped, err := base64.StdEncoding.DecodeString(entry.Wrapped)
		if err != nil {
			return nil, fmt.Errorf("keys: key %q is not valid base64: %w", entry.KID, err)
		}
		kek, err := openKey(rootKey, wrapped, aad)
		if err != nil {
			return nil, fmt.Errorf("%w (%s)", err, wrongKeyHint)
		}
		if err := ring.Add(entry.KID, kek); err != nil {
			clear(kek)
			return nil, err
		}
		clear(kek)
		if !entry.Created.IsZero() {
			ring.created[entry.KID] = entry.Created
		}
	}

	if err := ring.SetActive(file.ActiveKID); err != nil {
		return nil, fmt.Errorf("keys: active key id %q is not in the keyring", file.ActiveKID)
	}
	return ring, nil
}

func sortedKeys(m map[string][KeySize]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
