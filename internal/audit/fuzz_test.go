package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
)

// FuzzVerify feeds arbitrary bytes to the verifier.
//
// A log file is untrusted input in the strongest sense: whoever an audit log
// defends against is exactly whoever had the opportunity to rewrite it, and the
// verifier is the first thing to read what they left. It has to reject, never
// crash and never hang -- so this asserts only that, and lets the corpus find
// the shapes a hand-written test would not think of.
func FuzzVerify(f *testing.F) {
	key, err := keys.AuditKeyFromSecret(bytes.Repeat([]byte{40}, keys.AuditSecretSize))
	if err != nil {
		f.Fatalf("AuditKeyFromSecret: %v", err)
	}
	pub, err := key.Public()
	if err != nil {
		f.Fatalf("Public: %v", err)
	}

	// Seeded with a genuine log, so the fuzzer starts from something structured
	// and mutates towards the interesting failures rather than towards noise.
	f.Add(genuineLog(f, key))
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte("{\n\n\n"))
	f.Add([]byte(`{"type":"head","head":{"v":1,"chain":"a","opened":"","pubkey":"",` +
		`"prev_chain":"","prev_hash":"","hash":"x"}}`))
	f.Add([]byte(`{"type":"entry","entry":{"seq":1,"time":"","op":"","bucket":"","key":"",` +
		`"client":"","principal":"","request_id":"","status":0,"code":"","kid":"",` +
		`"bytes":0,"hash":""}}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		// Both modes: with a key, the signature path runs as well.
		if _, err := Verify(bytes.NewReader(data), VerifyOptions{}); err != nil {
			_ = err
		}
		if _, err := Verify(bytes.NewReader(data), VerifyOptions{PublicKey: pub}); err != nil {
			_ = err
		}
		if _, err := ReadHead(bytes.NewReader(data)); err != nil {
			_ = err
		}
	})
}

// genuineLog writes a small real log and returns its bytes.
func genuineLog(f *testing.F, key *keys.AuditKey) []byte {
	f.Helper()
	signer, err := key.Signer()
	if err != nil {
		f.Fatalf("Signer: %v", err)
	}
	nameKey, err := key.NameKey()
	if err != nil {
		f.Fatalf("NameKey: %v", err)
	}
	path := filepath.Join(f.TempDir(), "audit.log")
	w, err := Open(Config{Path: path, Signer: signer, NameKey: nameKey, CheckpointInterval: -1})
	if err != nil {
		f.Fatalf("Open: %v", err)
	}
	for i := range 3 {
		if err := w.Append(event("PutObject", "b", "object"+string(rune('a'+i)))); err != nil {
			f.Fatalf("Append: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		f.Fatalf("Close: %v", err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // a fuzz seed path.
	if err != nil {
		f.Fatalf("ReadFile: %v", err)
	}
	return data
}
