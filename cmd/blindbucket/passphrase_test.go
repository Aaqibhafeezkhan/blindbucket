package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
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

// TestWarnsAboutExposedKeyFiles covers the check THREAT_MODEL section 5.5 asks
// for and nothing used to perform: a keyring an offline attacker can simply
// read is the ordinary way a passphrase stops being worth anything.
func TestWarnsAboutExposedKeyFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if out := captureStderr(t, func() { warnIfExposed("keyring", path) }); out != "" {
		t.Errorf("a 0600 file warned: %s", out)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	out := captureStderr(t, func() { warnIfExposed("keyring", path) })
	if !strings.Contains(out, "0644") || !strings.Contains(out, path) {
		t.Errorf("a world-readable keyring produced %q", out)
	}
	// A missing file is the caller's error to report, not this check's.
	if out := captureStderr(t, func() {
		warnIfExposed("keyring", filepath.Join(dir, "absent"))
	}); out != "" {
		t.Errorf("a missing file warned: %s", out)
	}
}

// captureStderr collects what f writes to os.Stderr.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stderr
	os.Stderr = w
	f()
	os.Stderr = saved
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(out)
}
