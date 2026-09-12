package manifest

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
)

// Format constants. See docs/FORMAT.md section 10.
const (
	// IDSize is the length of a manifest id in bytes.
	IDSize = 16
	// MACSize is the length of the trailing HMAC-SHA256.
	MACSize = 32
	// entrySize is the on-wire size of one BBM2 part entry: uint16 number,
	// uint64 size, and the part's segment salt.
	entrySize = 10 + stream.SaltSize
	// macKeyInfo domain-separates the manifest key from every other key derived
	// from a DEK.
	macKeyInfo = "blindbucket/v1/manifest"
	// Prefix is where manifests live inside a user bucket.
	Prefix = ".blindbucket/m/"
)

// Magic is the four-byte marker a manifest written by this build starts with.
//
// BBM2 differs from BBM1 in one field: each part entry carries the salt of that
// part's segment. That is what pins a manifest to the exact segments it was
// completed from, rather than to a shape any segment of the right size could
// fill -- see MagicV1 and docs/FORMAT.md section 10.
var Magic = [4]byte{'B', 'B', 'M', '2'}

// MagicV1 marks a manifest written before part salts were recorded.
//
// Those are still read: objects written under it are not rewritten, and
// refusing them would make an upgrade lose data. What they cannot do is detect
// retry substitution (THREAT_MODEL section 5.2), because they do not say which
// attempt at a part they were completed from. HasSalts reports the difference.
var MagicV1 = [4]byte{'B', 'B', 'M', '1'}

// ErrVerify reports a manifest that failed authentication or does not describe
// the object it was loaded for.
//
// It carries no detail about which check failed. A wrong MAC, a manifest from a
// different key and a manifest from an older upload of the same key are
// indistinguishable to whoever supplied it, and should stay that way.
var ErrVerify = errors.New("manifest: verification failed")

// ID identifies one manifest, and through it one version of one object.
//
// A fresh id is minted by every operation that makes a multipart object visible
// (rule R1 in CONCEPT.md section 10.8). Manifests are never shared between
// object versions, which is what lets a request delete exactly the manifest it
// replaced without racing anything else. The rule is model-checked; see
// spec/tla/Multipart.tla.
type ID [IDSize]byte

// NewID draws a fresh manifest id from the system CSPRNG.
func NewID() (ID, error) {
	var id ID
	if _, err := rand.Read(id[:]); err != nil {
		return ID{}, err
	}
	return id, nil
}

// String renders the id as unpadded base64url: 22 characters, safe in an S3
// object key and in the x-amz-meta-bb-mid header alike.
func (id ID) String() string { return base64.RawURLEncoding.EncodeToString(id[:]) }

// ParseID reverses String.
func ParseID(s string) (ID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return ID{}, fmt.Errorf("manifest: id is not valid base64url: %w", err)
	}
	if len(raw) != IDSize {
		return ID{}, fmt.Errorf("manifest: id is %d bytes, want %d", len(raw), IDSize)
	}
	var id ID
	copy(id[:], raw)
	return id, nil
}

// ObjectKey returns where the manifest for objectKey with this id is stored.
//
// The object key is hashed rather than embedded. S3 keys may be 1024 bytes long
// and the manifest path would have to carry one whole, plus a prefix and the id,
// which overruns the same 1024-byte limit. A fixed-width hash keeps every
// manifest path the same length whatever the object is called.
func (id ID) ObjectKey(objectKey string) string {
	sum := sha256.Sum256([]byte(objectKey))
	return Prefix + hex.EncodeToString(sum[:]) + "/" + id.String()
}

// PrefixFor returns the listing prefix holding every manifest of objectKey.
func PrefixFor(objectKey string) string {
	sum := sha256.Sum256([]byte(objectKey))
	return Prefix + hex.EncodeToString(sum[:]) + "/"
}

// Part records one part of a multipart object.
type Part struct {
	// Number is the S3 part number, 1..10000. It is also the segment index in
	// that part's authenticated segment header, which is what stops a provider
	// from reordering parts.
	Number uint32
	// PlainSize is the part's plaintext size in bytes.
	PlainSize int64
	// Salt is the salt of that part's segment header.
	//
	// It names which *attempt* at this part number the object was completed
	// from. A client that retries a part produces a second valid segment under
	// the same number, and without this a provider could serve either one and
	// every tag would still verify (THREAT_MODEL section 5.2). Zero in a
	// manifest read from BBM1, where it was not recorded.
	Salt [stream.SaltSize]byte
}

// Manifest is the authenticated part list of a multipart object.
//
// Each part is a segment authenticated on its own, but nothing in the segments
// binds them into a whole: a provider could serve an object with parts missing
// and every individual tag would still verify. The manifest closes that gap, and
// binding it to bucket, key and manifest id stops it being replayed from
// somewhere else.
type Manifest struct {
	Bucket string
	Key    string
	ID     ID
	Parts  []Part
	// legacy reports that this manifest was read from a BBM1 file and carries
	// no part salts. It is not set on manifests this build writes.
	legacy bool
}

// HasSalts reports whether the manifest pins each part to a specific segment.
//
// False only for a manifest written before BBM2. A reader must not treat a
// zero salt as a salt to compare against -- that would reject every object
// written by an older build.
func (m *Manifest) HasSalts() bool { return !m.legacy }

// PlainSize returns the total plaintext size of the object.
func (m *Manifest) PlainSize() int64 {
	var total int64
	for _, p := range m.Parts {
		total += p.PlainSize
	}
	return total
}

// macKey derives the manifest key from the object's data key.
func macKey(dek []byte) ([]byte, error) {
	if len(dek) != stream.KeySize {
		return nil, fmt.Errorf("manifest: DEK is %d bytes, want %d", len(dek), stream.KeySize)
	}
	return hkdf.Key(sha256.New, dek, nil, macKeyInfo, stream.KeySize)
}

// Marshal renders the manifest and appends its HMAC under a key derived from dek.
func (m *Manifest) Marshal(dek []byte) ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	key, err := macKey(dek)
	if err != nil {
		return nil, err
	}
	defer clear(key)

	size := len(Magic) + 2 + len(m.Bucket) + 2 + len(m.Key) + IDSize + 2 +
		entrySize*len(m.Parts) + MACSize
	out := make([]byte, 0, size)
	out = append(out, Magic[:]...)
	if out, err = appendLP(out, m.Bucket); err != nil {
		return nil, err
	}
	if out, err = appendLP(out, m.Key); err != nil {
		return nil, err
	}
	out = append(out, m.ID[:]...)
	//nolint:gosec // validate bounds the part count to MaxParts.
	out = binary.BigEndian.AppendUint16(out, uint16(len(m.Parts)))
	for _, p := range m.Parts {
		//nolint:gosec // validate bounds part numbers to 1..MaxParts.
		out = binary.BigEndian.AppendUint16(out, uint16(p.Number))
		//nolint:gosec // validate rejects negative sizes.
		out = binary.BigEndian.AppendUint64(out, uint64(p.PlainSize))
		out = append(out, p.Salt[:]...)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(out)
	return mac.Sum(out), nil
}

// Unmarshal parses and authenticates a manifest, and checks that it describes
// the object it was loaded for.
//
// bucket, key and id are what the caller expects: they come from the request and
// from the object's own bb-mid metadata, never from the manifest. Comparing them
// is what makes a manifest from a different object, or from an earlier upload of
// this one, a failure rather than a plausible-looking part list.
func Unmarshal(raw, dek []byte, bucket, key string, id ID) (*Manifest, error) {
	key2, err := macKey(dek)
	if err != nil {
		return nil, err
	}
	defer clear(key2)

	if len(raw) < len(Magic)+MACSize {
		return nil, fmt.Errorf("%w: %d bytes is too short to be a manifest", ErrVerify, len(raw))
	}
	body, want := raw[:len(raw)-MACSize], raw[len(raw)-MACSize:]

	// The MAC is checked before a single length prefix inside body is believed,
	// so parsing never runs on bytes an attacker chose.
	mac := hmac.New(sha256.New, key2)
	mac.Write(body)
	if subtle.ConstantTimeCompare(mac.Sum(nil), want) != 1 {
		return nil, fmt.Errorf("%w: bad authentication tag", ErrVerify)
	}

	m, err := parseBody(body)
	if err != nil {
		return nil, err
	}
	// Authentic, but possibly authentic for something else.
	if m.Bucket != bucket || m.Key != key || m.ID != id {
		return nil, fmt.Errorf("%w: manifest belongs to a different object version", ErrVerify)
	}
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVerify, err)
	}
	return m, nil
}

// parseBody decodes an already-authenticated manifest body.
func parseBody(body []byte) (*Manifest, error) {
	r := &reader{buf: body}
	magic, ok := r.next(len(Magic))
	if !ok {
		return nil, fmt.Errorf("%w: truncated magic", ErrVerify)
	}
	var legacy bool
	switch [4]byte(magic) {
	case Magic:
	case MagicV1:
		legacy = true
	default:
		return nil, fmt.Errorf("%w: not a blindbucket manifest", ErrVerify)
	}
	bucket, ok := r.lp()
	if !ok {
		return nil, fmt.Errorf("%w: truncated bucket", ErrVerify)
	}
	key, ok := r.lp()
	if !ok {
		return nil, fmt.Errorf("%w: truncated key", ErrVerify)
	}
	rawID, ok := r.next(IDSize)
	if !ok {
		return nil, fmt.Errorf("%w: truncated manifest id", ErrVerify)
	}
	count, ok := r.uint16()
	if !ok {
		return nil, fmt.Errorf("%w: truncated part count", ErrVerify)
	}

	m := &Manifest{Bucket: bucket, Key: key, Parts: make([]Part, 0, count), legacy: legacy}
	copy(m.ID[:], rawID)
	for range count {
		number, ok1 := r.uint16()
		size, ok2 := r.uint64()
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("%w: truncated part list", ErrVerify)
		}
		if size > stream.MaxPlaintextSize {
			return nil, fmt.Errorf("%w: part %d claims %d bytes", ErrVerify, number, size)
		}
		//nolint:gosec // bounded immediately above.
		part := Part{Number: uint32(number), PlainSize: int64(size)}
		if !legacy {
			salt, ok := r.next(stream.SaltSize)
			if !ok {
				return nil, fmt.Errorf("%w: truncated part list", ErrVerify)
			}
			copy(part.Salt[:], salt)
		}
		m.Parts = append(m.Parts, part)
	}
	if r.remaining() != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrVerify, r.remaining())
	}
	return m, nil
}

// validate enforces the structural rules a manifest must satisfy in both
// directions. Part sizes are checked separately, against the chunk size, by
// ValidateParts.
func (m *Manifest) validate() error {
	switch {
	case len(m.Parts) == 0:
		return errors.New("manifest: a multipart object has at least one part")
	case len(m.Parts) > stream.MaxParts:
		return fmt.Errorf("manifest: %d parts exceeds the maximum of %d", len(m.Parts), stream.MaxParts)
	case len(m.Bucket) > 0xffff || len(m.Key) > 0xffff:
		return errors.New("manifest: bucket or key exceeds the length prefix")
	}
	var previous uint32
	for i, p := range m.Parts {
		if p.Number < 1 || p.Number > stream.MaxParts {
			return fmt.Errorf("manifest: part number %d outside 1..%d", p.Number, stream.MaxParts)
		}
		// Strictly ascending. S3 permits gaps in part numbers but not repeats,
		// and the order is what the offsets of a range request are built on.
		if i > 0 && p.Number <= previous {
			return fmt.Errorf("manifest: part numbers %d and %d are not ascending", previous, p.Number)
		}
		previous = p.Number
		if p.PlainSize < 0 || p.PlainSize > stream.MaxPlaintextSize {
			return fmt.Errorf("manifest: part %d has an impossible size %d", p.Number, p.PlainSize)
		}
	}
	return nil
}

// appendLP appends s prefixed by its uint16 big-endian length.
func appendLP(dst []byte, s string) ([]byte, error) {
	if len(s) > 0xffff {
		return nil, fmt.Errorf("manifest: field of %d bytes exceeds the length prefix", len(s))
	}
	//nolint:gosec // bounded immediately above.
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(s)))
	return append(dst, s...), nil
}

// reader is a bounds-checked cursor over an authenticated manifest body.
type reader struct {
	buf []byte
	pos int
}

func (r *reader) remaining() int { return len(r.buf) - r.pos }

func (r *reader) next(n int) ([]byte, bool) {
	if n < 0 || r.remaining() < n {
		return nil, false
	}
	out := r.buf[r.pos : r.pos+n]
	r.pos += n
	return out, true
}

func (r *reader) uint16() (uint16, bool) {
	b, ok := r.next(2)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint16(b), true
}

func (r *reader) uint64() (uint64, bool) {
	b, ok := r.next(8)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint64(b), true
}

func (r *reader) lp() (string, bool) {
	n, ok := r.uint16()
	if !ok {
		return "", false
	}
	b, ok := r.next(int(n))
	if !ok {
		return "", false
	}
	return string(b), true
}

// PeekIdentity reads the bucket, key and id out of a manifest **without
// authenticating it**.
//
// It exists for `blindbucket gc`, which has to learn which object a manifest
// belongs to before it can look that object up -- and which therefore has no
// data key to verify the manifest with. Nothing read here may be trusted on its
// own.
//
// What makes it safe to act on is the caller's obligation to check the result
// against the manifest's own location: a manifest lives under
// hex(SHA-256(key)), so a key that does not hash to the directory the manifest
// was found in is a forgery or a misplaced object, and MatchesLocation says so.
// Every other field stays untrusted, which is why gc compares ids rather than
// believing them.
func PeekIdentity(raw []byte) (bucket, key string, id ID, err error) {
	if len(raw) < len(Magic)+MACSize {
		return "", "", ID{}, fmt.Errorf("manifest: %d bytes is too short to be a manifest", len(raw))
	}
	m, parseErr := parseBody(raw[:len(raw)-MACSize])
	if parseErr != nil {
		return "", "", ID{}, parseErr
	}
	return m.Bucket, m.Key, m.ID, nil
}

// MatchesLocation reports whether key hashes to the directory a manifest was
// found in, which is what makes an unauthenticated key usable.
//
// SHA-256 is collision-resistant, so a key that hashes to the right directory is
// the key that directory belongs to. An attacker who could write a forged
// manifest into a bucket still cannot make it claim a different object.
func MatchesLocation(objectKey, manifestObjectKey string) bool {
	return strings.HasPrefix(manifestObjectKey, PrefixFor(objectKey))
}
