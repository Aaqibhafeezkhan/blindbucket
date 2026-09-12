package names

import (
	"bytes"
	"strings"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i * 7)
	}
	return key
}

func newTestEncrypter(t *testing.T) *Encrypter {
	t.Helper()
	e, err := New(testKey(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// The round trip is the whole contract, and the interesting inputs are the
// degenerate ones: keys with no directory, trailing separators, empty segments,
// and the non-ASCII names S3 permits.
func TestRoundTrip(t *testing.T) {
	t.Parallel()
	e := newTestEncrypter(t)

	for _, plain := range []string{
		"a",
		"a/b",
		"a/b/c.txt",
		"photos/2026-01/IMG_0001.jpg",
		"trailing/",
		"a//b",
		"/leading",
		"//",
		strings.Repeat("x", 200),
		"ümlaut/日本語/emoji-🔒.bin",
		"spaces and + and = and ?",
	} {
		stored, err := e.EncryptKey(plain)
		if err != nil {
			t.Fatalf("EncryptKey(%q): %v", plain, err)
		}
		if stored == plain {
			t.Errorf("EncryptKey(%q) returned the plaintext", plain)
		}
		if strings.Contains(stored, plain) && plain != "" {
			t.Errorf("EncryptKey(%q) contains the plaintext", plain)
		}

		back, err := e.DecryptKey(stored)
		if err != nil {
			t.Fatalf("DecryptKey(%q from %q): %v", stored, plain, err)
		}
		if back != plain {
			t.Errorf("round trip changed %q into %q", plain, back)
		}
	}
}

// The empty key is the one input that maps to itself, because there is no
// segment to encrypt. It has to survive rather than error.
func TestEmptyKey(t *testing.T) {
	t.Parallel()
	e := newTestEncrypter(t)

	stored, err := e.EncryptKey("")
	if err != nil || stored != "" {
		t.Fatalf("EncryptKey(\"\") = %q, %v", stored, err)
	}
	back, err := e.DecryptKey("")
	if err != nil || back != "" {
		t.Fatalf("DecryptKey(\"\") = %q, %v", back, err)
	}
}

// Determinism is what makes a point lookup possible, and it is also the
// feature's central cost. Both halves are worth pinning.
func TestDeterminism(t *testing.T) {
	t.Parallel()
	e := newTestEncrypter(t)

	first, err := e.EncryptKey("a/b/c.txt")
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	second, err := e.EncryptKey("a/b/c.txt")
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	if first != second {
		t.Fatal("the same key encrypted to two different stored keys; a point lookup would miss")
	}
}

// A separator is the only part of a key that survives, and the segment count
// has to survive with it or prefix listing breaks.
func TestSegmentStructureIsPreserved(t *testing.T) {
	t.Parallel()
	e := newTestEncrypter(t)

	stored, err := e.EncryptKey("a/b/c/d")
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	if got := strings.Count(stored, "/"); got != 3 {
		t.Errorf("stored key has %d separators, want 3", got)
	}

	// And the prefix relationship: "a/b/" must still select "a/b/c/d".
	prefix, whole, err := e.EncryptPrefix("a/b/")
	if err != nil {
		t.Fatalf("EncryptPrefix: %v", err)
	}
	if !whole {
		t.Error("a prefix ending in a separator should be reported as whole")
	}
	if !strings.HasPrefix(stored, prefix) {
		t.Errorf("encrypted prefix %q does not select %q", prefix, stored)
	}
}

// The same segment under two different parents must not look the same. This is
// what the path context in the IV buys, and without it a provider could tell
// that two directories hold something identically named.
func TestSameNameUnderDifferentParents(t *testing.T) {
	t.Parallel()
	e := newTestEncrypter(t)

	one, err := e.EncryptKey("photos/report.pdf")
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	two, err := e.EncryptKey("invoices/report.pdf")
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	leaf := func(s string) string { return s[strings.LastIndex(s, "/")+1:] }
	if leaf(one) == leaf(two) {
		t.Error("report.pdf encrypts identically under two parents; the path context is not applied")
	}
}

// What the design does *not* hide, asserted so that a future change cannot
// quietly claim otherwise: two objects with the same name under the same parent
// are visibly the same name. ADR-015 and the threat model both say so.
func TestSiblingEqualityIsVisible(t *testing.T) {
	t.Parallel()
	e := newTestEncrypter(t)

	one, err := e.EncryptKey("dir/same.txt")
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	two, err := e.EncryptKey("dir/same.txt")
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	if one != two {
		t.Fatal("this is documented as leaking and the docs must match the code")
	}
}

// A different name key must produce different stored keys, or a keyring would
// not actually be protecting anything.
func TestDifferentKeysDiffer(t *testing.T) {
	t.Parallel()

	other := make([]byte, KeySize)
	for i := range other {
		other[i] = byte(255 - i)
	}
	e1 := newTestEncrypter(t)
	e2, err := New(other)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	a, err := e1.EncryptKey("a/b")
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	b, err := e2.EncryptKey("a/b")
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	if a == b {
		t.Fatal("two different name keys produced the same stored key")
	}
	if _, err := e2.DecryptKey(a); err == nil {
		t.Fatal("a stored key decrypted under the wrong name key")
	}
}

// The synthetic IV authenticates the segment. A provider that edits a stored
// key gets an error rather than a different plaintext name -- which matters,
// because a silently different name is an object served from the wrong place.
func TestTamperedStoredKeyIsRefused(t *testing.T) {
	t.Parallel()
	e := newTestEncrypter(t)

	stored, err := e.EncryptKey("a/secret.txt")
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}

	for name, mutate := range map[string]func(string) string{
		"a flipped character in the ciphertext": func(s string) string {
			b := []byte(s)
			i := len(b) - 1
			if b[i] == 'A' {
				b[i] = 'B'
			} else {
				b[i] = 'A'
			}
			return string(b)
		},
		"a truncated segment": func(s string) string { return s[:len(s)-4] },
		"a segment that is not base32": func(s string) string {
			return strings.Replace(s, s[:1], "!", 1)
		},
		"a segment shorter than an IV": func(s string) string {
			i := strings.Index(s, "/")
			return "AAAA" + s[i:]
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := e.DecryptKey(mutate(stored)); err == nil {
				t.Error("a modified stored key decrypted without complaint")
			}
		})
	}
}

// Moving a segment between positions must not decrypt, or a provider could
// reshape a tree by swapping directory components.
func TestSegmentsAreBoundToTheirPosition(t *testing.T) {
	t.Parallel()
	e := newTestEncrypter(t)

	stored, err := e.EncryptKey("a/b")
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	parts := strings.Split(stored, "/")
	swapped := parts[1] + "/" + parts[0]
	if _, err := e.DecryptKey(swapped); err == nil {
		t.Fatal("swapping two segments produced a readable key")
	}
}

// A partial-segment prefix has no encrypted form. The caller has to be told, or
// it would narrow an upstream listing with something that matches nothing.
func TestPartialPrefixIsReported(t *testing.T) {
	t.Parallel()
	e := newTestEncrypter(t)

	stored, whole, err := e.EncryptPrefix("photos/2026")
	if err != nil {
		t.Fatalf("EncryptPrefix: %v", err)
	}
	if whole {
		t.Error("a prefix ending mid-segment was reported as whole")
	}
	// The parent is still usable to narrow the listing.
	full, err := e.EncryptKey("photos/2026-01/x.jpg")
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	if !strings.HasPrefix(full, stored) {
		t.Errorf("the parent prefix %q does not select %q", stored, full)
	}

	if _, whole, err := e.EncryptPrefix("photo"); err != nil || whole {
		t.Errorf("a bare partial segment should be reported as not whole (whole=%v, err=%v)", whole, err)
	}
}

// A key that would exceed S3's limit once encrypted is refused rather than
// stored truncated, which would be an object that cannot be found again.
func TestOverlongKeyIsRefused(t *testing.T) {
	t.Parallel()
	e := newTestEncrypter(t)

	if _, err := e.EncryptKey(strings.Repeat("a", 1000)); err == nil {
		t.Fatal("a key that encrypts past the S3 limit was accepted")
	}
}

func TestRejectsAWrongSizedKey(t *testing.T) {
	t.Parallel()

	for _, size := range []int{0, 16, 31, 33, 64} {
		if _, err := New(bytes.Repeat([]byte{1}, size)); err == nil {
			t.Errorf("a %d byte name key was accepted", size)
		}
	}
}

// FuzzRoundTrip: every key S3 would accept must survive the mapping unchanged.
//
// The interesting failures are not crashes but silent corruption -- a key that
// comes back subtly different is an object stored where nobody will look for
// it again.
func FuzzRoundTrip(f *testing.F) {
	for _, seed := range []string{
		"", "a", "a/b/c", "a//b", "/", "trailing/", "ümlaut", strings.Repeat("x", 300),
	} {
		f.Add(seed)
	}

	e, err := New(make([]byte, KeySize))
	if err != nil {
		f.Fatalf("New: %v", err)
	}
	f.Fuzz(func(t *testing.T, plain string) {
		stored, err := e.EncryptKey(plain)
		if err != nil {
			// Only a length refusal is legitimate.
			if !strings.Contains(err.Error(), "too long") {
				t.Fatalf("EncryptKey(%q): %v", plain, err)
			}
			return
		}
		back, err := e.DecryptKey(stored)
		if err != nil {
			t.Fatalf("DecryptKey after EncryptKey(%q): %v", plain, err)
		}
		if back != plain {
			t.Fatalf("round trip changed %q into %q", plain, back)
		}
	})
}

// FuzzDecryptKey: anything the decoder accepts must re-encrypt to exactly the
// bytes it came from.
//
// This is the same property the segment decoder is fuzzed for. It rules out a
// second stored key decrypting to one plaintext name, which would mean two
// objects the gateway believes are the same object.
func FuzzDecryptKey(f *testing.F) {
	e, err := New(make([]byte, KeySize))
	if err != nil {
		f.Fatalf("New: %v", err)
	}
	for _, seed := range []string{"a", "a/b", "photos/2026/x.jpg"} {
		if stored, err := e.EncryptKey(seed); err == nil {
			f.Add(stored)
		}
	}
	// The first thing this target found: base32 leaves spare bits in the final
	// character, so several spellings decode to one byte string. This one
	// decodes to "a" but is not what "a" encrypts to, and before canonicality
	// was enforced it named the same object under a second stored key.
	f.Add("BLMZVZKNQROUBWAIYIKW7CVL6EC2")

	f.Fuzz(func(t *testing.T, stored string) {
		plain, err := e.DecryptKey(stored)
		if err != nil {
			return
		}
		again, err := e.EncryptKey(plain)
		if err != nil {
			t.Fatalf("a key that decrypted to %q would not re-encrypt: %v", plain, err)
		}
		if again != stored {
			t.Fatalf("accepted %q but re-encrypts %q to %q", stored, plain, again)
		}
	})
}

// TestNonCanonicalEncodingIsRefused pins the first thing FuzzDecryptKey found.
//
// Base32 encodes 17 bytes into 28 characters, which hold 140 bits against the
// 136 that are used. The decoder ignores the four spare bits, so sixteen
// spellings of a segment decode to the same bytes. Accepting them would mean
// several stored keys naming one object -- an object the gateway would believe
// it had seen more than once, and a way to write past a check that had already
// looked at the canonical name.
func TestNonCanonicalEncodingIsRefused(t *testing.T) {
	t.Parallel()
	e, err := New(make([]byte, KeySize))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	canonical, err := e.EncryptKey("a")
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	const variant = "BLMZVZKNQROUBWAIYIKW7CVL6EC2"
	if variant == canonical {
		t.Fatalf("the variant is the canonical spelling; the test has gone stale")
	}
	if _, err := e.DecryptKey(variant); err == nil {
		t.Error("a non-canonical spelling of a stored key was accepted")
	}
	if back, err := e.DecryptKey(canonical); err != nil || back != "a" {
		t.Errorf("the canonical spelling stopped working: %q, %v", back, err)
	}
}
