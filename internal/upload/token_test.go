package upload

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
)

func testRing(t *testing.T, kids ...string) *keys.Keyring {
	t.Helper()
	ring := keys.NewKeyring()
	for _, kid := range kids {
		if err := ring.Generate(kid); err != nil {
			t.Fatalf("Generate(%q): %v", kid, err)
		}
	}
	return ring
}

func testToken(t *testing.T, ring *keys.Keyring, kid, bucket, key string) (Token, string) {
	t.Helper()
	dek, err := keys.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	aad, err := keys.ObjectAAD(kid, bucket, key)
	if err != nil {
		t.Fatalf("ObjectAAD: %v", err)
	}
	wrapped, err := ring.Wrap(t.Context(), kid, dek.Bytes(), aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	id, err := manifest.NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	tok := Token{KID: kid, UploadID: "upstream-upload-id-42", WrappedDEK: wrapped, ManifestID: id}

	sealed, err := Seal(t.Context(), ring, tok, bucket, key)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return tok, sealed
}

func TestTokenRoundTrip(t *testing.T) {
	ring := testRing(t, "2026-09")
	want, sealed := testToken(t, ring, "2026-09", "photos", "2026/holiday.tar")

	got, err := Open(t.Context(), ring, sealed, "photos", "2026/holiday.tar")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.KID != want.KID || got.UploadID != want.UploadID || got.ManifestID != want.ManifestID {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if !bytes.Equal(got.WrappedDEK, want.WrappedDEK) {
		t.Error("wrapped key not preserved")
	}
}

// A token is issued for one object. Replaying it against another bucket or key
// is what the associated data exists to stop: without it, a client allowed to
// write one key could obtain a token and use it to write any other.
func TestTokenIsBoundToBucketAndKey(t *testing.T) {
	ring := testRing(t, "2026-09")
	_, sealed := testToken(t, ring, "2026-09", "photos", "2026/holiday.tar")

	cases := []struct{ name, bucket, key string }{
		{"different bucket", "backups", "2026/holiday.tar"},
		{"different key", "photos", "2026/secret.tar"},
		{"both", "backups", "other"},
		// The classic length-prefix confusion: without lp() these two would
		// produce the same associated data.
		{"shifted boundary", "photos2", "026/holiday.tar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Open(t.Context(), ring, sealed, tc.bucket, tc.key); !errors.Is(err, ErrToken) {
				t.Fatalf("got %v, want ErrToken", err)
			}
		})
	}
}

func TestEveryBitFlipIsCaught(t *testing.T) {
	ring := testRing(t, "2026-09")
	_, sealed := testToken(t, ring, "2026-09", "photos", "k")
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	for i := range raw {
		for bit := range 8 {
			tampered := bytes.Clone(raw)
			tampered[i] ^= 1 << bit
			encoded := base64.RawURLEncoding.EncodeToString(tampered)
			if _, err := Open(t.Context(), ring, encoded, "photos", "k"); err == nil {
				t.Fatalf("byte %d bit %d: tampered token accepted", i, bit)
			}
		}
	}
}

// The kid travels in clear text so a rotation mid-upload still finds the right
// token key. A token sealed under a KEK that is no longer in the ring must fail
// as an ordinary bad token, not as a distinguishable "unknown key" signal.
func TestTokenSurvivesRotationAndFailsOnRetiredKeys(t *testing.T) {
	ring := testRing(t, "2026-09")
	_, sealed := testToken(t, ring, "2026-09", "photos", "k")

	// A newer KEK becomes active; the old token must still open.
	if err := ring.Generate("2026-10"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := ring.SetActive("2026-10"); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	if _, err := Open(t.Context(), ring, sealed, "photos", "k"); err != nil {
		t.Fatalf("token did not survive a KEK rotation: %v", err)
	}

	// A ring without the issuing KEK cannot open it.
	other := testRing(t, "2026-10")
	if _, err := Open(t.Context(), other, sealed, "photos", "k"); !errors.Is(err, ErrToken) {
		t.Fatalf("got %v, want ErrToken", err)
	}
}

// A token sealed under a different deployment's keyring must not open here,
// even though the kid matches.
func TestTokenFromAnotherDeploymentIsRejected(t *testing.T) {
	mine := testRing(t, "2026-09")
	theirs := testRing(t, "2026-09")
	_, sealed := testToken(t, theirs, "2026-09", "photos", "k")

	if _, err := Open(t.Context(), mine, sealed, "photos", "k"); !errors.Is(err, ErrToken) {
		t.Fatalf("got %v, want ErrToken", err)
	}
}

func TestOpenRejectsMalformedInput(t *testing.T) {
	ring := testRing(t, "2026-09")
	_, sealed := testToken(t, ring, "2026-09", "photos", "k")
	raw, _ := base64.RawURLEncoding.DecodeString(sealed)

	cases := map[string]string{
		"empty":         "",
		"not base64":    "!!!!not base64!!!!",
		"too long":      strings.Repeat("A", maxTokenLen+1),
		"truncated":     base64.RawURLEncoding.EncodeToString(raw[:len(raw)/2]),
		"one byte":      base64.RawURLEncoding.EncodeToString([]byte{TokenVersion}),
		"wrong version": base64.RawURLEncoding.EncodeToString(append([]byte{0x02}, raw[1:]...)),
		"absurd kid length": base64.RawURLEncoding.EncodeToString(
			append([]byte{TokenVersion, 0xff, 0xff}, raw[3:]...)),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(t.Context(), ring, token, "photos", "k"); !errors.Is(err, ErrToken) {
				t.Fatalf("got %v, want ErrToken", err)
			}
		})
	}
}

func TestSealRejectsUnusableTokens(t *testing.T) {
	ring := testRing(t, "2026-09")
	wrapped := make([]byte, keys.WrappedDEKSize)
	if _, err := rand.Read(wrapped); err != nil {
		t.Fatalf("rand: %v", err)
	}
	base := Token{KID: "2026-09", UploadID: "u", WrappedDEK: wrapped}

	cases := map[string]func(*Token){
		"no kid":            func(tk *Token) { tk.KID = "" },
		"invalid kid":       func(tk *Token) { tk.KID = "has spaces" },
		"no upload id":      func(tk *Token) { tk.UploadID = "" },
		"huge upload id":    func(tk *Token) { tk.UploadID = strings.Repeat("u", maxUploadIDLen+1) },
		"short wrapped dek": func(tk *Token) { tk.WrappedDEK = wrapped[:10] },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tk := base
			mutate(&tk)
			if _, err := Seal(t.Context(), ring, tk, "b", "k"); err == nil {
				t.Fatal("Seal accepted an unusable token")
			}
		})
	}
}

// Two tokens for the same upload must differ: the nonce is fresh each time, so
// a token is not a stable identifier an observer can correlate on.
func TestTokensAreNotDeterministic(t *testing.T) {
	ring := testRing(t, "2026-09")
	_, first := testToken(t, ring, "2026-09", "photos", "k")
	_, second := testToken(t, ring, "2026-09", "photos", "k")
	if first == second {
		t.Fatal("two tokens are byte-identical")
	}
}
