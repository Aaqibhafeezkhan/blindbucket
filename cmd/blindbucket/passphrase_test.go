package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPassphraseIsAskedOnce is the regression test for a command that opens a
// keyring and then writes it back. `keygen --add` does exactly that, and it used
// to resolve the passphrase twice: on a terminal the second prompt, unconfirmed,
// became the passphrase the keyring was re-sealed under, so a typo there sealed
// it under something nobody knows.
//
// A terminal cannot be simulated here, so the test asserts the property that
// fixes it: the source is consulted once, and the answer is remembered.
func TestPassphraseIsAskedOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(path, []byte("a test passphrase\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	pass := passphraseFlags{file: path}

	first, err := pass.resolve("unused: ", false)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	// Removing the file makes a second read impossible, so a second answer can
	// only come from the cache.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	// Callers wipe what they are given. That must not empty the cache.
	clear(first)

	second, err := pass.resolve("unused: ", false)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if string(second) != "a test passphrase" {
		t.Errorf("second resolve returned %q, want the remembered passphrase", second)
	}

	pass.wipe()
	if _, err := pass.resolve("unused: ", false); err == nil {
		t.Error("resolve succeeded after wipe; the passphrase is still being held")
	}
}
