package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"time"
)

// Version is the audit log format version, recorded in every head.
const Version = 1

// Record types.
const (
	TypeHead       = "head"
	TypeEntry      = "entry"
	TypeCheckpoint = "checkpoint"
)

// Domain separation for the three hashed contexts. Without distinct prefixes a
// head and an entry with the right fields could hash identically, and one could
// be presented as the other.
const (
	domainHead       = "blindbucket/v1/audit-head"
	domainEntry      = "blindbucket/v1/audit-entry"
	domainCheckpoint = "blindbucket/v1/audit-checkpoint"
)

// timeFormat is how a timestamp is written, and -- because the hash covers the
// string and not a parsed value -- also exactly what is hashed. Formatting and
// hashing can therefore never disagree.
const timeFormat = time.RFC3339Nano

// ErrMalformed reports a log line that is not a record this format defines.
var ErrMalformed = errors.New("audit: malformed record")

// Record is one line of the log. Exactly one of the three pointers is set, and
// which one is named by Type.
//
// The nesting is deliberate. A flat struct with every field of every record
// type and `omitempty` throughout would make "absent" and "empty" the same
// thing on disk, and an absent field that hashes as an empty one is how a
// tamper-evidence scheme stops being one.
type Record struct {
	Type       string      `json:"type"`
	Head       *Head       `json:"head,omitempty"`
	Entry      *Entry      `json:"entry,omitempty"`
	Checkpoint *Checkpoint `json:"checkpoint,omitempty"`
}

// Head opens a chain. It is the first line of every log file.
//
// PrevChain and PrevHash are empty in the first file of a sequence and carry the
// previous file's identity and final hash in every file after a rotation, so
// that a rotated sequence remains one chain rather than a pile of unrelated
// ones.
type Head struct {
	Version   int    `json:"v"`
	Chain     string `json:"chain"`
	Opened    string `json:"opened"`
	PublicKey string `json:"pubkey"`
	PrevChain string `json:"prev_chain"`
	PrevHash  string `json:"prev_hash"`
	Hash      string `json:"hash"`
}

// Entry is one served request.
//
// Bucket and Key are encrypted (ADR-016); everything else is in clear, because
// everything else is either the operator's own vocabulary -- the credential's
// configured name, the key id -- or already public to the client that sent it.
// Principal is set only when authentication failed, where there is no client
// name to record and the access key id that was attempted is the thing worth
// having.
//
// Every field is a string or an integer as written, never a parsed value: the
// hash is computed over these exact bytes, so a verifier cannot disagree with a
// writer about how a timestamp or a number renders.
type Entry struct {
	Seq       uint64 `json:"seq"`
	Time      string `json:"time"`
	Op        string `json:"op"`
	Bucket    string `json:"bucket"`
	Key       string `json:"key"`
	Client    string `json:"client"`
	Principal string `json:"principal"`
	RequestID string `json:"request_id"`
	Status    int    `json:"status"`
	Code      string `json:"code"`
	KID       string `json:"kid"`
	Bytes     int64  `json:"bytes"`
	Hash      string `json:"hash"`
}

// Checkpoint is a signed assertion that the chain reached Hash at Seq.
//
// It is not itself a link in the chain: removing one breaks nothing and proves
// nothing, it only removes evidence. Chaining them would buy nothing, because an
// attacker who can drop a checkpoint can drop the entries after it just as
// easily -- which is the truncation window ADR-016 names and does not pretend to
// close.
type Checkpoint struct {
	Seq       uint64 `json:"seq"`
	Time      string `json:"time"`
	Hash      string `json:"hash"`
	Signature string `json:"sig"`
}

// hasher starts a hash over a domain-separated context.
func hasher(domain string) *chainHash {
	c := &chainHash{h: sha256.New()}
	c.raw([]byte(domain))
	return c
}

// chainHash accumulates the canonical encoding of a record's fields.
//
// Canonical means: over typed fields in a fixed order with length prefixes,
// never over the JSON. JSON has no canonical form -- key order, escaping and
// whitespace are all free -- so a scheme that hashed the serialised line would
// let an attacker re-render a record into different bytes with the same meaning,
// or the same bytes with a different one.
type chainHash struct {
	h hash.Hash
}

func (c *chainHash) raw(b []byte) { _, _ = c.h.Write(b) }

// lp appends a length-prefixed field, as docs/FORMAT.md section 1 defines it.
//
// The prefix is what makes a concatenation of variable-length fields
// unambiguous: without it, op "GetObject" with bucket "x" and op "GetObjectX"
// with bucket "" would hash the same.
func (c *chainHash) lp(s string) error {
	if len(s) > 0xffff {
		return fmt.Errorf("audit: field of %d bytes exceeds the length prefix", len(s))
	}
	var n [2]byte
	//nolint:gosec // the length is rejected above if it exceeds 0xffff.
	binary.BigEndian.PutUint16(n[:], uint16(len(s)))
	c.raw(n[:])
	c.raw([]byte(s))
	return nil
}

func (c *chainHash) u64(v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	c.raw(b[:])
}

func (c *chainHash) u32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	c.raw(b[:])
}

func (c *chainHash) sum() []byte { return c.h.Sum(nil) }

func (c *chainHash) sumHex() string { return hex.EncodeToString(c.sum()) }

// chainHashOf computes the genesis hash of a head.
//
// It binds the chain's own id and public key, so an entry cannot be lifted out
// of one chain and replayed into another: its own hash covers a seq and a chain
// that would both have to match.
func (h *Head) chainHashOf() (string, error) {
	c := hasher(domainHead)
	c.u32(uint32(h.Version)) //nolint:gosec // Version is a small constant.
	for _, field := range []string{h.Chain, h.Opened, h.PublicKey, h.PrevChain, h.PrevHash} {
		if err := c.lp(field); err != nil {
			return "", err
		}
	}
	return c.sumHex(), nil
}

// chainHashOf computes an entry's hash from its fields and the hash before it.
func (e *Entry) chainHashOf(chain, prev string) (string, error) {
	c := hasher(domainEntry)
	c.u64(e.Seq)
	fields := []string{
		chain, e.Time, e.Op, e.Bucket, e.Key,
		e.Client, e.Principal, e.RequestID, e.Code, e.KID,
	}
	for _, field := range fields {
		if err := c.lp(field); err != nil {
			return "", err
		}
	}
	c.u32(uint32(e.Status)) //nolint:gosec // a bounded HTTP status.
	//nolint:gosec // Append clamps Bytes at or above zero before an entry exists.
	c.u64(uint64(e.Bytes))
	if err := c.lp(prev); err != nil {
		return "", err
	}
	return c.sumHex(), nil
}

// signedMessage is what an Ed25519 signature over a checkpoint covers.
func (p *Checkpoint) signedMessage(chain string) ([]byte, error) {
	c := hasher(domainCheckpoint)
	c.u64(p.Seq)
	for _, field := range []string{chain, p.Time, p.Hash} {
		if err := c.lp(field); err != nil {
			return nil, err
		}
	}
	return c.sum(), nil
}

// marshalLine renders a record as one line of the log.
func marshalLine(r Record) ([]byte, error) {
	out, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// parseLine decodes one line and checks that exactly the expected shape is
// present.
//
// A record carrying two bodies, or none, is rejected rather than interpreted by
// its Type alone. Accepting a line whose Type says "entry" while a head sits
// beside it would mean the bytes on disk say one thing and the verifier reads
// another, which is the whole property being defended.
func parseLine(line []byte) (Record, error) {
	var r Record
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Record{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	present := 0
	for _, set := range []bool{r.Head != nil, r.Entry != nil, r.Checkpoint != nil} {
		if set {
			present++
		}
	}
	if present != 1 {
		return Record{}, fmt.Errorf("%w: %d record bodies, want exactly 1", ErrMalformed, present)
	}
	switch {
	case r.Type == TypeHead && r.Head != nil:
	case r.Type == TypeEntry && r.Entry != nil:
	case r.Type == TypeCheckpoint && r.Checkpoint != nil:
	default:
		return Record{}, fmt.Errorf("%w: type %q does not match the body present",
			ErrMalformed, r.Type)
	}
	return r, nil
}

// parseTime reads a timestamp back for display. The value is never hashed; the
// string is.
func parseTime(s string) time.Time {
	t, err := time.Parse(timeFormat, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
