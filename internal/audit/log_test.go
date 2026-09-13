package audit

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
)

// testKey builds a deterministic audit key, so a failure is reproducible.
func testKey(t *testing.T, seed byte) *keys.AuditKey {
	t.Helper()
	secret := bytes.Repeat([]byte{seed}, keys.AuditSecretSize)
	key, err := keys.AuditKeyFromSecret(secret)
	if err != nil {
		t.Fatalf("AuditKeyFromSecret: %v", err)
	}
	return key
}

func testConfig(t *testing.T, key *keys.AuditKey, path string) Config {
	t.Helper()
	signer, err := key.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	nameKey, err := key.NameKey()
	if err != nil {
		t.Fatalf("NameKey: %v", err)
	}
	return Config{
		Path:    path,
		Signer:  signer,
		NameKey: nameKey,
		// No timer in tests: a checkpoint goroutine firing at an arbitrary point
		// would make the record counts non-deterministic.
		CheckpointInterval: -1,
	}
}

func testPublic(t *testing.T, key *keys.AuditKey) ed25519.PublicKey {
	t.Helper()
	pub, err := key.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	return pub
}

// openWriter opens a log in a fresh temporary directory.
func openWriter(t *testing.T, key *keys.AuditKey) (*Writer, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	w, err := Open(testConfig(t, key, path))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w, path
}

func event(op, bucket, key string) Event {
	return Event{
		Time: time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC),
		Op:   op, Bucket: bucket, Key: key,
		Client: "backup-job", RequestID: "0123456789abcdef",
		Status: 200, KID: "2026-09", Bytes: 4096,
	}
}

// verifyFile verifies a log on disk.
func verifyFile(t *testing.T, path string, pub ed25519.PublicKey) (*Result, error) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // a test path.
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return Verify(bytes.NewReader(data), VerifyOptions{PublicKey: pub})
}

func TestAppendAndVerify(t *testing.T) {
	key := testKey(t, 1)
	w, path := openWriter(t, key)

	for i := range 5 {
		if err := w.Append(event("PutObject", "photos", "a/b/c"+string(rune('0'+i)))); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	result, err := verifyFile(t, path, testPublic(t, key))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	switch {
	case result.Entries != 5:
		t.Errorf("verified %d entries, want 5", result.Entries)
	case !result.SignaturesChecked:
		t.Error("signatures were not checked")
	case result.SignedThrough != 5:
		t.Errorf("signed through %d, want 5 after a clean close", result.SignedThrough)
	case result.Checkpoints == 0:
		t.Error("no checkpoint was written")
	}
}

// TestNamesAreNotInTheClear is the property that lets a log leave the host.
func TestNamesAreNotInTheClear(t *testing.T) {
	key := testKey(t, 2)
	w, path := openWriter(t, key)

	const bucket, objectKey = "payroll", "2026/q1/salaries.xlsx"
	if err := w.Append(event("GetObject", bucket, objectKey)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path) //nolint:gosec // a test path.
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	for _, secret := range []string{bucket, objectKey, "salaries", "payroll"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Errorf("the log contains %q in clear", secret)
		}
	}
	// The operator's own vocabulary is deliberately readable: an audit log that
	// hides which credential acted answers nothing.
	if !bytes.Contains(data, []byte("backup-job")) {
		t.Error("the client name should be readable")
	}
}

func TestNamesRoundTripWithTheKey(t *testing.T) {
	key := testKey(t, 3)
	w, path := openWriter(t, key)

	const bucket, objectKey = "photos", "2026/holiday/beach.jpg"
	if err := w.Append(event("PutObject", bucket, objectKey)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	nameKey, err := key.NameKey()
	if err != nil {
		t.Fatalf("NameKey: %v", err)
	}
	coder, err := newNameCoder(nameKey)
	if err != nil {
		t.Fatalf("newNameCoder: %v", err)
	}

	var got Entry
	data, err := os.ReadFile(path) //nolint:gosec // a test path.
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if _, err := Verify(bytes.NewReader(data), VerifyOptions{
		PublicKey: testPublic(t, key),
		OnEntry:   func(e *Entry) error { got = *e; return nil },
	}); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if plain, ok := coder.decode(got.Key); !ok || plain != objectKey {
		t.Errorf("decoded key %q (ok=%v), want %q", plain, ok, objectKey)
	}
	if plain, ok := coder.decode(got.Bucket); !ok || plain != bucket {
		t.Errorf("decoded bucket %q (ok=%v), want %q", plain, ok, bucket)
	}
}

// TestOverlongNameFallsBackToADigest covers the key S3 allows but the name
// encryption cannot represent. Logging it as a digest is what stops a client
// silencing the log by choosing a long enough name.
func TestOverlongNameFallsBackToADigest(t *testing.T) {
	key := testKey(t, 4)
	w, path := openWriter(t, key)

	long := strings.Repeat("x", 1000)
	if err := w.Append(event("PutObject", "bucket", long)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var got Entry
	data, err := os.ReadFile(path) //nolint:gosec // a test path.
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if _, err := Verify(bytes.NewReader(data), VerifyOptions{
		PublicKey: testPublic(t, key),
		OnEntry:   func(e *Entry) error { got = *e; return nil },
	}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !strings.HasPrefix(got.Key, digestPrefix) {
		t.Fatalf("key %q is not a digest", got.Key)
	}
	if strings.Contains(got.Key, long[:50]) {
		t.Error("the digest contains the plaintext")
	}
}

func TestReopenContinuesTheChain(t *testing.T) {
	key := testKey(t, 5)
	path := filepath.Join(t.TempDir(), "audit.log")

	first, err := Open(testConfig(t, key, path))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := first.Append(event("PutObject", "b", "one")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	chain := first.Chain()
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := Open(testConfig(t, key, path))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if second.Chain() != chain {
		t.Errorf("reopened as chain %q, want %q", second.Chain(), chain)
	}
	if err := second.Append(event("GetObject", "b", "two")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	result, err := verifyFile(t, path, testPublic(t, key))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Entries != 2 {
		t.Errorf("verified %d entries after a reopen, want 2", result.Entries)
	}
}

// TestReopenRefusesAnotherKey stops a log being extended under a key other than
// the one that started it, which would leave a file no single key verifies.
func TestReopenRefusesAnotherKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	first, err := Open(testConfig(t, testKey(t, 6), path))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := first.Append(event("PutObject", "b", "one")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, err = Open(testConfig(t, testKey(t, 7), path))
	if !errors.Is(err, ErrWrongKey) {
		t.Fatalf("reopening under another key: %v, want ErrWrongKey", err)
	}
}

// TestTornTailIsRecovered is the crash case: a process killed between
// checkpoints leaves a half-written line, and the gateway has to be able to
// start again.
func TestTornTailIsRecovered(t *testing.T) {
	key := testKey(t, 8)
	path := filepath.Join(t.TempDir(), "audit.log")

	w, err := Open(testConfig(t, key, path))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := w.Append(event("PutObject", "b", "one")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Simulate the torn write: a record that stops mid-line, with no newline.
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // a test path.
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := file.WriteString(`{"type":"entry","entry":{"seq":2,"time":"2026`); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	result, err := verifyFile(t, path, testPublic(t, key))
	if err != nil {
		t.Fatalf("Verify with a torn tail: %v", err)
	}
	if !result.TornTail {
		t.Error("the torn tail was not reported")
	}

	reopened, err := Open(testConfig(t, key, path))
	if err != nil {
		t.Fatalf("reopen over a torn tail: %v", err)
	}
	if err := reopened.Append(event("GetObject", "b", "two")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	after, err := verifyFile(t, path, testPublic(t, key))
	if err != nil {
		t.Fatalf("Verify after recovery: %v", err)
	}
	switch {
	case after.TornTail:
		t.Error("the tear survived the recovery")
	case after.Entries != 2:
		t.Errorf("verified %d entries, want 2", after.Entries)
	}
}

func TestRotationKeepsOneChain(t *testing.T) {
	key := testKey(t, 9)
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	cfg := testConfig(t, key, path)
	cfg.CheckpointEvery = 2
	cfg.RotateBytes = 1200 // a handful of records
	w, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := range 20 {
		if err := w.Append(event("PutObject", "b", "object"+string(rune('a'+i)))); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	archived, err := filepath.Glob(path + ".*")
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(archived) == 0 {
		t.Fatal("nothing was rotated")
	}

	// Oldest first: the archived files sort by their timestamp suffix, and the
	// live file is the newest of all.
	readers := make([]NamedReader, 0, len(archived)+1)
	for _, name := range append(archived, path) {
		data, err := os.ReadFile(name) //nolint:gosec // a test path.
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		readers = append(readers, NamedReader{Name: name, Reader: bytes.NewReader(data)})
	}

	results, err := VerifyChain(readers, VerifyOptions{PublicKey: testPublic(t, key)})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	var total uint64
	for _, r := range results {
		total += r.Entries
	}
	if total != 20 {
		t.Errorf("the rotated sequence holds %d entries, want 20", total)
	}
}

// TestRotationDetectsAMissingFile is the reason a rotated head records the
// previous chain and hash at all.
func TestRotationDetectsAMissingFile(t *testing.T) {
	key := testKey(t, 10)
	path := filepath.Join(t.TempDir(), "audit.log")

	cfg := testConfig(t, key, path)
	cfg.CheckpointEvery = 1
	cfg.RotateBytes = 600
	w, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := range 12 {
		if err := w.Append(event("PutObject", "b", "object"+string(rune('a'+i)))); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	archived, err := filepath.Glob(path + ".*")
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(archived) < 2 {
		t.Skipf("needed at least two rotations, got %d", len(archived))
	}

	// Drop a file from the middle. Dropping the *first* one is a different
	// case and deliberately not this test's: nothing in a set of files can say
	// what came before the earliest of them, which is why the head's PrevChain
	// is reported rather than treated as a break.
	kept := append([]string{archived[0]}, archived[2:]...)
	readers := make([]NamedReader, 0, len(kept)+1)
	for _, name := range append(kept, path) {
		data, err := os.ReadFile(name) //nolint:gosec // a test path.
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		readers = append(readers, NamedReader{Name: name, Reader: bytes.NewReader(data)})
	}
	if _, err := VerifyChain(readers, VerifyOptions{PublicKey: testPublic(t, key)}); err == nil {
		t.Error("a missing file in the middle of a rotated sequence went undetected")
	}
}

func TestConcurrentAppendsProduceOneChain(t *testing.T) {
	key := testKey(t, 11)
	w, path := openWriter(t, key)

	const goroutines, each = 8, 50
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				ev := event("PutObject", "b", "g"+string(rune('a'+g))+string(rune('0'+i%10)))
				if err := w.Append(ev); err != nil {
					t.Errorf("Append: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	result, err := verifyFile(t, path, testPublic(t, key))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Entries != goroutines*each {
		t.Errorf("verified %d entries, want %d", result.Entries, goroutines*each)
	}
}

// TestBrokenWriterStaysBroken is the fail-closed property: once a record is
// lost, the writer refuses rather than carrying on with a silent hole.
func TestBrokenWriterStaysBroken(t *testing.T) {
	key := testKey(t, 12)
	w, _ := openWriter(t, key)

	if err := w.Append(event("PutObject", "b", "one")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	// Close the underlying file behind the writer's back, which is what a disk
	// failure looks like from here.
	w.mu.Lock()
	_ = w.file.Close()
	w.mu.Unlock()

	// The buffer absorbs writes until it is flushed, so drive enough through to
	// force one.
	var appendErr error
	for range 20000 {
		if appendErr = w.Append(event("PutObject", "b", "two")); appendErr != nil {
			break
		}
	}
	if appendErr == nil {
		t.Fatal("no append failed after the file was closed")
	}
	if !errors.Is(appendErr, ErrBroken) {
		t.Errorf("append failed with %v, want ErrBroken", appendErr)
	}
	if err := w.Err(); !errors.Is(err, ErrBroken) {
		t.Errorf("Err() is %v, want a sticky ErrBroken", err)
	}
	// And it stays broken even though nothing else is wrong now.
	if err := w.Append(event("PutObject", "b", "three")); !errors.Is(err, ErrBroken) {
		t.Errorf("a later append returned %v, want ErrBroken", err)
	}
}
