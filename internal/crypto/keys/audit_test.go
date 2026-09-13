package keys

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestAuditKeyDerivationIsStableAndSeparated(t *testing.T) {
	key, err := AuditKeyFromSecret(bytes.Repeat([]byte{1}, AuditSecretSize))
	if err != nil {
		t.Fatalf("AuditKeyFromSecret: %v", err)
	}

	pub, err := key.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	again, err := key.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	if !bytes.Equal(pub, again) {
		t.Error("the public key is not stable across derivations")
	}

	nameKey, err := key.NameKey()
	if err != nil {
		t.Fatalf("NameKey: %v", err)
	}
	// The two derivations share a secret and must share nothing else: one of
	// them is published.
	if bytes.Contains(nameKey, pub[:16]) || bytes.Equal(nameKey, key.Secret()) {
		t.Error("the name key is derivable from the public key or is the raw secret")
	}

	signer, err := key.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	msg := []byte("a checkpoint")
	if !ed25519.Verify(pub, msg, ed25519.Sign(signer, msg)) {
		t.Error("the derived public key does not verify the derived signer")
	}
}

func TestAuditKeySurvivesAKeyringRoundTrip(t *testing.T) {
	ring := NewKeyring()
	if err := ring.Generate("2026-09"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	original, err := NewAuditKey()
	if err != nil {
		t.Fatalf("NewAuditKey: %v", err)
	}
	ring.SetAuditKey(original)

	data, err := ring.Marshal(testPassphrase, testKDF)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	loaded, err := LoadKeyring(data, testPassphrase)
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	got, ok := loaded.AuditKey()
	if !ok {
		t.Fatal("the audit key did not survive the round trip")
	}
	if !bytes.Equal(got.Secret(), original.Secret()) {
		t.Error("the audit secret came back different")
	}

	// The public key is readable without the passphrase. That is the property
	// the whole verification story rests on.
	pub, err := PublicAuditKey(data)
	if err != nil {
		t.Fatalf("PublicAuditKey: %v", err)
	}
	want, err := original.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	if !bytes.Equal(pub, want) {
		t.Error("the recorded public key is not the derived one")
	}

	// And the secret is not.
	if bytes.Contains(data, original.Secret()) {
		t.Error("the audit secret appears in the keyring file in clear")
	}
}

// TestSwappedAuditPublicKeyIsRejected is why the public key can be stored
// unwrapped at all: it is checked against the secret on load, so an attacker who
// edits the file cannot make a log they signed verify against this keyring.
func TestSwappedAuditPublicKeyIsRejected(t *testing.T) {
	ring := NewKeyring()
	if err := ring.Generate("2026-09"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	key, err := NewAuditKey()
	if err != nil {
		t.Fatalf("NewAuditKey: %v", err)
	}
	ring.SetAuditKey(key)
	data, err := ring.Marshal(testPassphrase, testKDF)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	attacker, err := NewAuditKey()
	if err != nil {
		t.Fatalf("NewAuditKey: %v", err)
	}
	attackerPub, err := attacker.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}

	var file map[string]any
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	entry, ok := file["audit_key"].(map[string]any)
	if !ok {
		t.Fatal("no audit_key in the keyring file")
	}
	entry["public_key"] = base64.StdEncoding.EncodeToString(attackerPub)
	tampered, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	_, err = LoadKeyring(tampered, testPassphrase)
	if err == nil {
		t.Fatal("a keyring with a swapped audit public key loaded")
	}
	if !strings.Contains(err.Error(), "modified") {
		t.Errorf("the error does not say the file was modified: %v", err)
	}
}

// TestKeyringWithoutAnAuditKeyStillLoads is the compatibility case: every
// keyring written before audit logging existed is one of these, and it must keep
// working rather than becoming a startup failure.
func TestKeyringWithoutAnAuditKeyStillLoads(t *testing.T) {
	ring := NewKeyring()
	if err := ring.Generate("2026-09"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data, err := ring.Marshal(testPassphrase, testKDF)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(data, []byte("audit_key")) {
		t.Error("a keyring with no audit key wrote an audit_key field")
	}

	loaded, err := LoadKeyring(data, testPassphrase)
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	if _, ok := loaded.AuditKey(); ok {
		t.Error("a keyring with no audit key reported one")
	}
	if _, err := PublicAuditKey(data); !errors.Is(err, ErrNoAuditKey) {
		t.Errorf("PublicAuditKey returned %v, want ErrNoAuditKey", err)
	}
}

// TestAuditSecretIsNotUnwrappableAsAKEK covers the associated-data separation:
// the wrapped audit secret and a wrapped KEK are both AES-GCM under the root
// key, and only the AAD keeps them apart.
func TestAuditSecretIsNotUnwrappableAsAKEK(t *testing.T) {
	rootKey, err := NewRootKey()
	if err != nil {
		t.Fatalf("NewRootKey: %v", err)
	}
	key, err := NewAuditKey()
	if err != nil {
		t.Fatalf("NewAuditKey: %v", err)
	}
	entry, err := sealAudit(rootKey, key)
	if err != nil {
		t.Fatalf("sealAudit: %v", err)
	}
	wrapped, err := base64.StdEncoding.DecodeString(entry.Wrapped)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}

	aad, err := kekAAD("2026-09")
	if err != nil {
		t.Fatalf("kekAAD: %v", err)
	}
	if _, err := openKey(rootKey, wrapped, aad); err == nil {
		t.Error("the audit secret unwrapped as a KEK")
	}
}
