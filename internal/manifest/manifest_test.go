package manifest

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
)

func testDEK(t *testing.T) []byte {
	t.Helper()
	dek := make([]byte, stream.KeySize)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return dek
}

func sample(t *testing.T) (*Manifest, []byte) {
	t.Helper()
	id, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	return &Manifest{
		Bucket: "photos",
		Key:    "2026/holiday.tar",
		ID:     id,
		Parts: []Part{
			{Number: 1, PlainSize: 8 << 20},
			{Number: 2, PlainSize: 8 << 20},
			{Number: 3, PlainSize: 1234},
		},
	}, testDEK(t)
}

func TestRoundTrip(t *testing.T) {
	m, dek := sample(t)
	raw, err := m.Marshal(dek)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got, err := Unmarshal(raw, dek, m.Bucket, m.Key, m.ID)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Bucket != m.Bucket || got.Key != m.Key || got.ID != m.ID {
		t.Errorf("identity not preserved: %+v", got)
	}
	if len(got.Parts) != len(m.Parts) {
		t.Fatalf("got %d parts, want %d", len(got.Parts), len(m.Parts))
	}
	for i := range m.Parts {
		if got.Parts[i] != m.Parts[i] {
			t.Errorf("part %d: got %+v, want %+v", i, got.Parts[i], m.Parts[i])
		}
	}
	if want := int64(8<<20 + 8<<20 + 1234); got.PlainSize() != want {
		t.Errorf("PlainSize = %d, want %d", got.PlainSize(), want)
	}
}

// Every single-bit change anywhere in the manifest must be caught. This is the
// property the HMAC exists for, so it is checked exhaustively over positions
// rather than at a couple of hand-picked offsets.
func TestEveryBitFlipIsCaught(t *testing.T) {
	m, dek := sample(t)
	raw, err := m.Marshal(dek)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	for i := range raw {
		for bit := range 8 {
			tampered := bytes.Clone(raw)
			tampered[i] ^= 1 << bit
			if _, err := Unmarshal(tampered, dek, m.Bucket, m.Key, m.ID); err == nil {
				t.Fatalf("byte %d bit %d: tampered manifest accepted", i, bit)
			} else if !errors.Is(err, ErrVerify) {
				t.Fatalf("byte %d bit %d: got %v, want ErrVerify", i, bit, err)
			}
		}
	}
}

// A manifest is authentic for exactly one object version. Replaying a valid one
// against a different bucket, key or manifest id is the attack the binding
// exists to stop.
func TestManifestIsBoundToItsObject(t *testing.T) {
	m, dek := sample(t)
	raw, err := m.Marshal(dek)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	other, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}

	cases := []struct {
		name        string
		bucket, key string
		id          ID
	}{
		{"different bucket", "other", m.Key, m.ID},
		{"different key", m.Bucket, "2026/other.tar", m.ID},
		{"different manifest id", m.Bucket, m.Key, other},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Unmarshal(raw, dek, tc.bucket, tc.key, tc.id); !errors.Is(err, ErrVerify) {
				t.Fatalf("got %v, want ErrVerify", err)
			}
		})
	}
}

// A manifest from an earlier upload of the same key does not verify, because
// every upload draws its own DEK and the MAC key hangs off it.
func TestManifestFromAnotherUploadDoesNotVerify(t *testing.T) {
	m, dek := sample(t)
	raw, err := m.Marshal(dek)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := Unmarshal(raw, testDEK(t), m.Bucket, m.Key, m.ID); !errors.Is(err, ErrVerify) {
		t.Fatalf("got %v, want ErrVerify", err)
	}
}

func TestTruncationAndExtension(t *testing.T) {
	m, dek := sample(t)
	raw, err := m.Marshal(dek)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	for _, n := range []int{0, 1, len(Magic), len(raw) - MACSize, len(raw) - 1} {
		if _, err := Unmarshal(raw[:n], dek, m.Bucket, m.Key, m.ID); err == nil {
			t.Errorf("truncation to %d bytes accepted", n)
		}
	}
	if _, err := Unmarshal(append(bytes.Clone(raw), 0), dek, m.Bucket, m.Key, m.ID); err == nil {
		t.Error("extended manifest accepted")
	}
}

func TestMarshalRejectsStructurallyImpossibleManifests(t *testing.T) {
	dek := testDEK(t)
	id, _ := NewID()
	base := func() *Manifest {
		return &Manifest{Bucket: "b", Key: "k", ID: id, Parts: []Part{{Number: 1, PlainSize: 10}}}
	}

	cases := map[string]func(*Manifest){
		"no parts":           func(m *Manifest) { m.Parts = nil },
		"part number zero":   func(m *Manifest) { m.Parts[0].Number = 0 },
		"part number beyond": func(m *Manifest) { m.Parts[0].Number = stream.MaxParts + 1 },
		"negative size":      func(m *Manifest) { m.Parts[0].PlainSize = -1 },
		"repeated number": func(m *Manifest) {
			m.Parts = []Part{{Number: 2, PlainSize: 10}, {Number: 2, PlainSize: 10}}
		},
		"descending numbers": func(m *Manifest) {
			m.Parts = []Part{{Number: 3, PlainSize: 10}, {Number: 2, PlainSize: 10}}
		},
		"oversized key": func(m *Manifest) { m.Key = strings.Repeat("x", 0x10000) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := base()
			mutate(m)
			if _, err := m.Marshal(dek); err == nil {
				t.Fatal("accepted a manifest that cannot describe an object")
			}
		})
	}
}

// Part numbers may have gaps: S3 permits 1, 5, 9 as long as they ascend.
func TestGapsInPartNumbersAreLegal(t *testing.T) {
	dek := testDEK(t)
	id, _ := NewID()
	m := &Manifest{Bucket: "b", Key: "k", ID: id, Parts: []Part{
		{Number: 1, PlainSize: 1 << 20}, {Number: 5, PlainSize: 1 << 20}, {Number: 9, PlainSize: 7},
	}}
	raw, err := m.Marshal(dek)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := Unmarshal(raw, dek, "b", "k", id); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
}

func TestIDEncoding(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	if len(id.String()) != 22 {
		t.Errorf("id renders as %d characters, want 22", len(id.String()))
	}
	back, err := ParseID(id.String())
	if err != nil || back != id {
		t.Fatalf("round trip failed: %v %x != %x", err, back, id)
	}
	for _, bad := range []string{"", "!!!", "AAAA", id.String() + "AA"} {
		if _, err := ParseID(bad); err == nil {
			t.Errorf("ParseID(%q) accepted", bad)
		}
	}
}

// The manifest path must stay inside S3's key limit for the longest key a client
// may use, which is the reason the key is hashed rather than embedded.
func TestObjectKeyStaysWithinTheKeyLimit(t *testing.T) {
	id, _ := NewID()
	longest := strings.Repeat("k", 1024)
	path := id.ObjectKey(longest)
	if len(path) > 1024 {
		t.Errorf("manifest path is %d bytes, over S3's 1024-byte limit", len(path))
	}
	if !strings.HasPrefix(path, Prefix) {
		t.Errorf("manifest path %q is outside the reserved prefix", path)
	}
	if got := id.ObjectKey("a"); len(got) != len(id.ObjectKey("b")) {
		t.Error("manifest paths are not fixed width")
	}
	if !strings.HasPrefix(path, PrefixFor(longest)) {
		t.Error("ObjectKey and PrefixFor disagree")
	}
}
