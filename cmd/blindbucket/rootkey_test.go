package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
)

// A keyring and the configuration that opens it have to agree. Neither
// mismatch can be recovered from by guessing, and both are things an operator
// does: pointing a Vault-configured gateway at an old passphrase keyring, or
// the reverse after moving a file between environments.
func TestOpenKeyringRefusesAMismatchedSource(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	ring := keys.NewKeyring()
	if err := ring.Generate("test-key"); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	t.Run("a passphrase keyring with a service provider", func(t *testing.T) {
		path := filepath.Join(dir, "passphrase.json")
		data, err := ring.Marshal([]byte("a passphrase"), keys.DefaultKDFParams)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		cfg := config.Keys{Provider: "vault", Vault: config.VaultKeys{
			Address: "http://127.0.0.1:1", Token: "t", KeyName: "k",
		}}
		_, err = openKeyring(context.Background(), path, cfg, &passphraseFlags{})
		if err == nil {
			t.Fatal("a Vault-configured gateway opened a passphrase keyring")
		}
		if !strings.Contains(err.Error(), "passphrase") || !strings.Contains(err.Error(), "vault") {
			t.Errorf("the error does not say what disagrees: %v", err)
		}
	})

	t.Run("a service keyring with no provider", func(t *testing.T) {
		path := filepath.Join(dir, "vault.json")
		root, err := keys.NewRootKey()
		if err != nil {
			t.Fatalf("NewRootKey: %v", err)
		}
		data, err := ring.MarshalWithRootKey(root, keys.RootKeyRef{
			Source: keys.SourceVaultTransit, Ciphertext: "vault:v1:x", KeyName: "k",
		})
		if err != nil {
			t.Fatalf("MarshalWithRootKey: %v", err)
		}
		clear(root)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		cfg := config.Keys{Provider: "file"}
		_, err = openKeyring(context.Background(), path, cfg, &passphraseFlags{})
		if err == nil {
			t.Fatal("a passphrase-configured gateway opened a Vault keyring")
		}
		if !strings.Contains(err.Error(), keys.SourceVaultTransit) {
			t.Errorf("the error does not name the source that sealed it: %v", err)
		}
	})
}
