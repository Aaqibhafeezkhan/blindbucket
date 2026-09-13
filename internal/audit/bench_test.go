package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
)

// BenchmarkAppend measures the serialised section of the log: encrypting two
// names, one SHA-256 over the entry, and a buffered write.
//
// ADR-016 rejected a background writer on the grounds that this is small against
// a request that has already made a network round trip -- the gateway's own
// share of a request is measured at 0.13 ms. This is the number that claim rests
// on, so it is measured rather than asserted.
func BenchmarkAppend(b *testing.B) {
	key := benchKey(b)
	w := benchWriter(b, key)

	ev := Event{
		Op: "PutObject", Bucket: "photos", Key: "2026/holiday/beach.jpg",
		Client: "backup-job", RequestID: "0123456789abcdef",
		Status: 200, KID: "2026-09", Bytes: 1 << 20,
	}

	b.ReportAllocs()
	for b.Loop() {
		if err := w.Append(ev); err != nil {
			b.Fatalf("Append: %v", err)
		}
	}
	b.StopTimer()
	if err := w.Close(); err != nil {
		b.Fatalf("Close: %v", err)
	}
}

// BenchmarkAppendWithCheckpoint includes the Ed25519 signature and the fsync
// that a checkpoint costs, at the default of one per 256 entries.
//
// The two benchmarks together are what the checkpoint interval should be chosen
// against: more checkpoints is a smaller truncation window and more fsyncs.
func BenchmarkAppendWithCheckpoint(b *testing.B) {
	key := benchKey(b)
	w := benchWriter(b, key)
	w.every = DefaultCheckpointEvery

	ev := Event{
		Op: "GetObject", Bucket: "photos", Key: "2026/holiday/beach.jpg",
		Client: "backup-job", RequestID: "0123456789abcdef", Status: 200,
	}

	b.ReportAllocs()
	for b.Loop() {
		if err := w.Append(ev); err != nil {
			b.Fatalf("Append: %v", err)
		}
	}
	b.StopTimer()
	if err := w.Close(); err != nil {
		b.Fatalf("Close: %v", err)
	}
}

// BenchmarkVerify measures the cost of reading a log back, which is what a
// gateway pays at startup to continue one.
func BenchmarkVerify(b *testing.B) {
	key := benchKey(b)
	w := benchWriter(b, key)
	const entries = 10000
	for range entries {
		if err := w.Append(Event{
			Op: "PutObject", Bucket: "photos", Key: "2026/holiday/beach.jpg",
			Client: "backup-job", Status: 200,
		}); err != nil {
			b.Fatalf("Append: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		b.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(w.path) //nolint:gosec // a benchmark path.
	if err != nil {
		b.Fatalf("ReadFile: %v", err)
	}
	pub, err := key.Public()
	if err != nil {
		b.Fatalf("Public: %v", err)
	}

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Verify(bytes.NewReader(data), VerifyOptions{PublicKey: pub}); err != nil {
			b.Fatalf("Verify: %v", err)
		}
	}
}

// benchKey builds a deterministic audit key.
func benchKey(b *testing.B) *keys.AuditKey {
	b.Helper()
	key, err := keys.AuditKeyFromSecret(bytes.Repeat([]byte{7}, keys.AuditSecretSize))
	if err != nil {
		b.Fatalf("AuditKeyFromSecret: %v", err)
	}
	return key
}

func benchWriter(b *testing.B, key *keys.AuditKey) *Writer {
	b.Helper()
	signer, err := key.Signer()
	if err != nil {
		b.Fatalf("Signer: %v", err)
	}
	nameKey, err := key.NameKey()
	if err != nil {
		b.Fatalf("NameKey: %v", err)
	}
	w, err := Open(Config{
		Path:               filepath.Join(b.TempDir(), "audit.log"),
		Signer:             signer,
		NameKey:            nameKey,
		CheckpointInterval: -1,
		// No checkpoint from the entry count either, so BenchmarkAppend measures
		// the append alone. The checkpoint has its own benchmark.
		CheckpointEvery: 1 << 30,
		RotateBytes:     -1,
	})
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	return w
}
