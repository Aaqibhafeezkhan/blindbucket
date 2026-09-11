package keys

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// testKDF is deliberately weak so the tests stay fast. Production uses
// DefaultKDFParams, which is what makes an offline attack on a stolen keyring
// expensive.
var testKDF = KDFParams{Algorithm: "argon2id", Time: 1, MemoryKiB: 8 * 1024, Parallelism: 1}

var testPassphrase = []byte("correct horse battery staple")

func newTestKeyring(t *testing.T, kids ...string) *Keyring {
	t.Helper()
	ring := NewKeyring()
	for _, kid := range kids {
		if err := ring.Generate(kid); err != nil {
			t.Fatalf("Generate(%q): %v", kid, err)
		}
	}
	return ring
}

func TestWrapRoundTrip(t *testing.T) {
	t.Parallel()

	ring := newTestKeyring(t, "2026-09")
	ctx := context.Background()

	dek, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	aad, err := ObjectAAD("2026-09", "backups", "db/2026-09-11.dump")
	if err != nil {
		t.Fatalf("ObjectAAD: %v", err)
	}

	wrapped, err := ring.Wrap(ctx, "2026-09", dek.Bytes(), aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if len(wrapped) != WrappedDEKSize {
		t.Errorf("wrapped DEK is %d bytes, the format says %d", len(wrapped), WrappedDEKSize)
	}
	if n := len(EncodeWrapped(wrapped)); n != 80 {
		t.Errorf("wrapped DEK encodes to %d characters, docs/FORMAT.md says 80", n)
	}

	got, err := ring.Unwrap(ctx, "2026-09", wrapped, aad)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, dek.Bytes()) {
		t.Error("unwrapped key differs from the original")
	}
}

// TestUnwrapRequiresMatchingContext is the property that makes swapping objects
// detectable: a data key wrapped for one object must not unwrap for another.
func TestUnwrapRequiresMatchingContext(t *testing.T) {
	t.Parallel()

	ring := newTestKeyring(t, "kid-a", "kid-b")
	ctx := context.Background()
	dek, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}

	aad, err := ObjectAAD("kid-a", "backups", "important.tar")
	if err != nil {
		t.Fatalf("ObjectAAD: %v", err)
	}
	wrapped, err := ring.Wrap(ctx, "kid-a", dek.Bytes(), aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	fileAAD, err := FileAAD("kid-a")
	if err != nil {
		t.Fatalf("FileAAD: %v", err)
	}

	wrong := map[string][]byte{
		"different bucket": mustObjectAAD(t, "kid-a", "other", "important.tar"),
		"different key":    mustObjectAAD(t, "kid-a", "backups", "other.tar"),
		"different kid":    mustObjectAAD(t, "kid-b", "backups", "important.tar"),
		"file context":     fileAAD,
		"empty":            nil,
	}
	for name, aad := range wrong {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ring.Unwrap(ctx, "kid-a", wrapped, aad); !errors.Is(err, ErrUnwrap) {
				t.Errorf("unwrapping with %s returned %v, want ErrUnwrap", name, err)
			}
		})
	}

	t.Run("different KEK", func(t *testing.T) {
		t.Parallel()
		if _, err := ring.Unwrap(ctx, "kid-b", wrapped, aad); !errors.Is(err, ErrUnwrap) {
			t.Errorf("unwrapping under the wrong KEK returned %v, want ErrUnwrap", err)
		}
	})

	t.Run("unknown kid", func(t *testing.T) {
		t.Parallel()
		if _, err := ring.Unwrap(ctx, "kid-c", wrapped, aad); !errors.Is(err, ErrUnknownKID) {
			t.Errorf("unwrapping under an unknown kid returned %v, want ErrUnknownKID", err)
		}
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		t.Parallel()
		for i := range wrapped {
			tampered := bytes.Clone(wrapped)
			tampered[i] ^= 0x01
			if _, err := ring.Unwrap(ctx, "kid-a", tampered, aad); !errors.Is(err, ErrUnwrap) {
				t.Fatalf("flipping byte %d was accepted", i)
			}
		}
	})
}

// TestObjectAADIsUnambiguous covers the reason for length prefixes: without them
// two different (bucket, key) pairs could share associated data, and the provider
// could swap those two objects with their metadata undetected.
func TestObjectAADIsUnambiguous(t *testing.T) {
	t.Parallel()

	a := mustObjectAAD(t, "k", "ab", "c")
	b := mustObjectAAD(t, "k", "a", "bc")
	if bytes.Equal(a, b) {
		t.Error(`("ab","c") and ("a","bc") produce the same associated data`)
	}

	c := mustObjectAAD(t, "ka", "b", "c")
	d := mustObjectAAD(t, "k", "ab", "c")
	if bytes.Equal(c, d) {
		t.Error(`("ka","b") and ("k","ab") produce the same associated data`)
	}
}

// TestFileAADCannotCollideWithObjectAAD checks the claim in docs/FORMAT.md
// section 6.2 that the kid length bound keeps the two encodings apart.
func TestFileAADCannotCollideWithObjectAAD(t *testing.T) {
	t.Parallel()

	fileAAD, err := FileAAD("2026-09")
	if err != nil {
		t.Fatalf("FileAAD: %v", err)
	}
	if !bytes.HasPrefix(fileAAD, []byte(aadObjectPrefix)) {
		t.Fatal("the two prefixes are expected to share their first 18 bytes")
	}

	// The byte that distinguishes them is the first after the shared prefix. In
	// the object form it is the high byte of uint16_be(len(kid)); reaching the
	// file form's '-' (0x2D) there would need a kid of 0x2D66 bytes.
	const shared = len(aadObjectPrefix)
	if fileAAD[shared] != '-' {
		t.Fatalf("file AAD continues with %#02x, want '-'", fileAAD[shared])
	}
	colliding := 0x2D66
	if colliding <= MaxKIDLen {
		t.Fatalf("a kid of %d bytes would collide and is within the %d-byte bound", colliding, MaxKIDLen)
	}
	if err := ValidateKID(strings.Repeat("a", MaxKIDLen+1)); err == nil {
		t.Error("a kid one byte over the bound was accepted")
	}
}

func TestValidateKID(t *testing.T) {
	t.Parallel()

	valid := []string{"a", "2026-09", "prod_key.1", strings.Repeat("k", MaxKIDLen)}
	for _, kid := range valid {
		if err := ValidateKID(kid); err != nil {
			t.Errorf("ValidateKID(%q) = %v, want nil", kid, err)
		}
	}

	invalid := []string{"", strings.Repeat("k", MaxKIDLen+1), "with space", "slash/key", "kid\x00", "ümlaut"}
	for _, kid := range invalid {
		if err := ValidateKID(kid); !errors.Is(err, ErrKIDInvalid) {
			t.Errorf("ValidateKID(%q) = %v, want ErrKIDInvalid", kid, err)
		}
	}
}

func TestKeyringFileRoundTrip(t *testing.T) {
	t.Parallel()

	ring := newTestKeyring(t, "2026-08", "2026-09")
	if err := ring.SetActive("2026-09"); err != nil {
		t.Fatalf("SetActive: %v", err)
	}

	data, err := ring.Marshal(testPassphrase, testKDF)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Nothing unwrapped may appear in the file.
	ctx := context.Background()
	aad := mustObjectAAD(t, "2026-09", "b", "k")
	dek, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	if bytes.Contains(data, dek.Bytes()) {
		t.Error("the keyring file contains raw key material")
	}

	loaded, err := LoadKeyring(data, testPassphrase)
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	if got := loaded.ActiveKID(); got != "2026-09" {
		t.Errorf("active kid is %q, want %q", got, "2026-09")
	}
	if got := loaded.KIDs(); len(got) != 2 {
		t.Errorf("keyring has %v, want two keys", got)
	}

	// A key wrapped by the original must unwrap with the reloaded keyring: the
	// KEKs survived the round trip byte for byte.
	wrapped, err := ring.Wrap(ctx, "2026-09", dek.Bytes(), aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	got, err := loaded.Unwrap(ctx, "2026-09", wrapped, aad)
	if err != nil {
		t.Fatalf("Unwrap after reload: %v", err)
	}
	if !bytes.Equal(got, dek.Bytes()) {
		t.Error("key material differs after a file round trip")
	}
}

func TestKeyringRejectsTampering(t *testing.T) {
	t.Parallel()

	ring := newTestKeyring(t, "kid-a", "kid-b")
	data, err := ring.Marshal(testPassphrase, testKDF)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	t.Run("wrong passphrase", func(t *testing.T) {
		t.Parallel()
		if _, err := LoadKeyring(data, []byte("wrong")); !errors.Is(err, ErrUnwrap) {
			t.Errorf("got %v, want ErrUnwrap", err)
		}
	})

	// Relabelling an entry must fail: the kid is authenticated as associated
	// data, so a KEK cannot be made to load under a different name.
	t.Run("entries relabelled", func(t *testing.T) {
		t.Parallel()
		var file keyringFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		file.Keys[0].KID, file.Keys[1].KID = file.Keys[1].KID, file.Keys[0].KID
		swapped, err := json.Marshal(file)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, err := LoadKeyring(swapped, testPassphrase); !errors.Is(err, ErrUnwrap) {
			t.Errorf("got %v, want ErrUnwrap", err)
		}
	})

	t.Run("wrapped key modified", func(t *testing.T) {
		t.Parallel()
		var file keyringFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		raw, err := base64.StdEncoding.DecodeString(file.Keys[0].Wrapped)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		raw[len(raw)-1] ^= 0x01
		file.Keys[0].Wrapped = base64.StdEncoding.EncodeToString(raw)
		modified, err := json.Marshal(file)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, err := LoadKeyring(modified, testPassphrase); !errors.Is(err, ErrUnwrap) {
			t.Errorf("got %v, want ErrUnwrap", err)
		}
	})
}

// TestKeyringRejectsHostileKDFParams covers a keyring file as untrusted input: a
// file must not be able to turn opening it into a denial of service.
func TestKeyringRejectsHostileKDFParams(t *testing.T) {
	t.Parallel()

	ring := newTestKeyring(t, "kid")
	data, err := ring.Marshal(testPassphrase, testKDF)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	hostile := map[string]func(*keyringFile){
		"absurd memory":      func(f *keyringFile) { f.KDF.MemoryKiB = 1 << 30 },
		"absurd time":        func(f *keyringFile) { f.KDF.Time = 1 << 20 },
		"absurd parallelism": func(f *keyringFile) { f.KDF.Parallelism = 255 },
		"zero memory":        func(f *keyringFile) { f.KDF.MemoryKiB = 0 },
		"unknown algorithm":  func(f *keyringFile) { f.KDF.Algorithm = "md5" },
		"short salt":         func(f *keyringFile) { f.KDF.Salt = base64.StdEncoding.EncodeToString([]byte("x")) },
	}

	for name, mutate := range hostile {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var file keyringFile
			if err := json.Unmarshal(data, &file); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			mutate(&file)
			out, err := json.Marshal(file)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, err := LoadKeyring(out, testPassphrase); err == nil {
				t.Error("hostile KDF parameters were accepted")
			}
		})
	}
}

func TestKeyringRefusesEmptyInputs(t *testing.T) {
	t.Parallel()

	if _, err := NewKeyring().Marshal(testPassphrase, testKDF); err == nil {
		t.Error("marshalling an empty keyring was accepted")
	}
	ring := newTestKeyring(t, "kid")
	if _, err := ring.Marshal(nil, testKDF); err == nil {
		t.Error("marshalling without a passphrase was accepted")
	}
	if err := ring.Add("kid", make([]byte, KeySize)); err == nil {
		t.Error("adding a duplicate key id was accepted")
	}
	if err := ring.Add("other", make([]byte, KeySize-1)); err == nil {
		t.Error("adding a short KEK was accepted")
	}
	if err := ring.SetActive("missing"); !errors.Is(err, ErrUnknownKID) {
		t.Errorf("SetActive on a missing key returned %v, want ErrUnknownKID", err)
	}
}

// TestDEKIsRedacted checks that a data key cannot reach a log, whether it is
// formatted directly or carried inside a struct.
func TestDEKIsRedacted(t *testing.T) {
	t.Parallel()

	dek := DEK{}
	for i := range dek {
		dek[i] = 0xAB
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("unwrapped", "dek", dek, "nested", struct{ Key DEK }{dek})
	logger.Info("formatted", "printed", fmt.Sprintf("%v", dek))

	out := buf.String()
	if strings.Contains(out, "abababab") || strings.Contains(out, "171 171") {
		t.Errorf("key material reached the log: %s", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("expected redaction markers, got: %s", out)
	}
}

// FuzzLoadKeyring requires that no keyring file, however malformed, causes a
// panic. The file is attacker-reachable in any deployment where it is shipped
// alongside the binary.
func FuzzLoadKeyring(f *testing.F) {
	ring := NewKeyring()
	if err := ring.Generate("kid"); err != nil {
		f.Fatalf("Generate: %v", err)
	}
	data, err := ring.Marshal(testPassphrase, testKDF)
	if err != nil {
		f.Fatalf("Marshal: %v", err)
	}
	f.Add(data)
	f.Add([]byte("{}"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		ring, err := LoadKeyring(data, testPassphrase)
		if err == nil && ring.ActiveKID() == "" {
			t.Fatal("loaded a keyring with no active key id")
		}
	})
}

func mustObjectAAD(t *testing.T, kid, bucket, key string) []byte {
	t.Helper()
	aad, err := ObjectAAD(kid, bucket, key)
	if err != nil {
		t.Fatalf("ObjectAAD: %v", err)
	}
	return aad
}
