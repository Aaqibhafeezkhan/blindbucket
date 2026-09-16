package freshness

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// What a freshness index would cost, measured rather than estimated.
//
// THREAT_MODEL §5.1 leaves rollback as accepted risk: an older but genuine
// version of an object is cryptographically valid, and nothing in the format
// distinguishes "current" from "previous". Detecting it means remembering, per
// object, which write is the current one -- and the objection to remembering is
// ADR-002's, that a version index reintroduces the shared mutable state goal G5
// exists to avoid.
//
// That objection is about a *shared* index on the correctness path. A local one
// is a different thing with a different cost, and the cost is what decides
// whether it is worth having: how much memory an instance holds per live object,
// what a check adds to a request measured at 0.13 ms, and how long a restart
// takes to become useful again.
//
// It measures a prototype of a design under consideration, not shipped code --
// nothing verifies freshness yet. It lives here because this is the package the
// code would live in, and it is committed because ADR-018 rests on its numbers.

// An entry is what the index has to remember about one object.
//
// The name is kept as a keyed hash rather than in clear: ADR-015 encrypts object
// names in the bucket and ADR-016 encrypts them in the audit log, and an index
// that wrote them plainly would hand back on the gateway's disk exactly what
// both of those hide. Nothing here ever needs to read a name back -- the only
// question asked is "is this the write I recorded" -- so a hash suffices where
// the audit log needed reversible encryption.
type (
	nameHash [16]byte
	version  [16]byte
)

// index is the design under measurement: names to the version last written.
type index struct {
	prf []byte
	m   map[nameHash]version
}

func newIndex(prf []byte, hint int) *index {
	return &index{prf: prf, m: make(map[nameHash]version, hint)}
}

// name derives the stored hash of one object's identity. Bucket and key are
// length-prefixed for FORMAT.md §1's reason: without it "a/b" + "c" and "a" +
// "b/c" are the same bytes.
func (ix *index) name(bucket, key string) nameHash {
	mac := hmac.New(sha256.New, ix.prf)
	var lp [8]byte
	binary.BigEndian.PutUint64(lp[:], uint64(len(bucket)))
	mac.Write(lp[:])
	mac.Write([]byte(bucket))
	binary.BigEndian.PutUint64(lp[:], uint64(len(key)))
	mac.Write(lp[:])
	mac.Write([]byte(key))
	var h nameHash
	copy(h[:], mac.Sum(nil))
	return h
}

func (ix *index) record(bucket, key string, v version) {
	ix.m[ix.name(bucket, key)] = v
}

// check is what a read would pay: hash the identity, look it up, compare.
//
// A miss is not a failure. An index that has never seen an object cannot say
// anything about it, which is the trust-on-first-use bound the decision rests on.
func (ix *index) check(bucket, key string, got version) (known, fresh bool) {
	want, ok := ix.m[ix.name(bucket, key)]
	if !ok {
		return false, true
	}
	return true, want == got
}

// plainIndex is the rejected shape, kept only to price it: the same index with
// names in clear. Measured because "hash the name" should be a decision with a
// number behind it, not a reflex.
type plainIndex struct{ m map[string]version }

func newPlainIndex(hint int) *plainIndex {
	return &plainIndex{m: make(map[string]version, hint)}
}

func (ix *plainIndex) record(bucket, key string, v version) {
	ix.m[bucket+"/"+key] = v
}

// benchKeyAt mints the i-th key of a synthetic but realistically shaped bucket:
// a handful of top-level prefixes over a date tree. Derived from i rather than
// drawn from a slice, so generating ten million keys retains nothing and the
// measurement sees only the index.
func benchKeyAt(i int) string {
	prefixes := [...]string{"backups", "photos", "logs", "exports", "media"}
	return fmt.Sprintf("%s/%04d/%02d/%02d/object-%08d.bin",
		prefixes[i%len(prefixes)], 2020+i%6, 1+i%12, 1+i%28, i)
}

func benchVersionAt(i int) version {
	var v version
	binary.BigEndian.PutUint64(v[:8], uint64(i))
	binary.BigEndian.PutUint64(v[8:], uint64(i)*0x9e3779b97f4a7c15)
	return v
}

func benchPRF(tb testing.TB) []byte {
	tb.Helper()
	prf := make([]byte, 32)
	if _, err := rand.Read(prf); err != nil {
		tb.Fatalf("rand: %v", err)
	}
	return prf
}

// BenchmarkFreshnessIndex reports the retained heap of an index holding n live
// objects, per object and in total. This is the state an instance carries, and
// the number the decision turns on.
func BenchmarkFreshnessIndex(b *testing.B) {
	for _, n := range []int{100_000, 1_000_000, 10_000_000} {
		b.Run(fmt.Sprintf("objects=%d", n), func(b *testing.B) {
			prf := benchPRF(b)

			// Retained heap: a GC with the index still alive is what separates
			// what is held from what was merely allocated on the way. Run with
			// -benchtime=1x so the survivor is one index, not several.
			var ix *index
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)

			b.ReportAllocs()
			for b.Loop() {
				ix = newIndex(prf, n)
				for i := range n {
					ix.record("bucket", benchKeyAt(i), benchVersionAt(i))
				}
			}

			b.StopTimer()
			runtime.GC()
			runtime.ReadMemStats(&after)
			retained := after.HeapAlloc - before.HeapAlloc
			runtime.KeepAlive(ix)
			b.ReportMetric(float64(retained)/float64(n), "B/object")
			b.ReportMetric(float64(retained)/(1<<20), "MiB/index")
		})
	}
}

// BenchmarkFreshnessIndexPlainNames prices the same index with names in clear,
// so that hashing them is a trade with a number on both sides.
func BenchmarkFreshnessIndexPlainNames(b *testing.B) {
	const n = 1_000_000

	var ix *plainIndex
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	b.ReportAllocs()
	for b.Loop() {
		ix = newPlainIndex(n)
		for i := range n {
			ix.record("bucket", benchKeyAt(i), benchVersionAt(i))
		}
	}

	b.StopTimer()
	runtime.GC()
	runtime.ReadMemStats(&after)
	retained := after.HeapAlloc - before.HeapAlloc
	runtime.KeepAlive(ix)
	b.ReportMetric(float64(retained)/float64(n), "B/object")
	b.ReportMetric(float64(retained)/(1<<20), "MiB/index")
}

// BenchmarkFreshnessCheck is what a read would pay for the guarantee: one keyed
// hash of the object's identity and one map lookup, against a request the
// gateway already costs 0.13 ms to serve.
func BenchmarkFreshnessCheck(b *testing.B) {
	const n = 1_000_000
	prf := benchPRF(b)
	ix := newIndex(prf, n)
	for i := range n {
		ix.record("bucket", benchKeyAt(i), benchVersionAt(i))
	}

	// The keys are minted up front. Generating one costs a fmt.Sprintf, which is
	// an order of magnitude more than the lookup being measured -- an earlier
	// draft of this benchmark timed the Sprintf and reported it as the check.
	keys := make([]string, n)
	for i := range n {
		keys[i] = benchKeyAt(i)
	}

	b.ReportAllocs()
	i := 0
	for b.Loop() {
		known, fresh := ix.check("bucket", keys[i%n], benchVersionAt(i%n))
		if !known || !fresh {
			b.Fatalf("object %d: known=%v fresh=%v, want a recorded and current object", i%n, known, fresh)
		}
		i++
	}
}

// BenchmarkFreshnessCheckPooled is the same check with the HMAC reused instead
// of built per call. Measured because the naive shape allocates nine times per
// read, and whether that matters should be a number rather than a worry.
func BenchmarkFreshnessCheckPooled(b *testing.B) {
	const n = 1_000_000
	prf := benchPRF(b)
	ix := newIndex(prf, n)
	for i := range n {
		ix.record("bucket", benchKeyAt(i), benchVersionAt(i))
	}
	keys := make([]string, n)
	for i := range n {
		keys[i] = benchKeyAt(i)
	}

	mac := hmac.New(sha256.New, prf)
	var lp [8]byte
	var sum [sha256.Size]byte

	b.ReportAllocs()
	i := 0
	for b.Loop() {
		key := keys[i%n]
		mac.Reset()
		binary.BigEndian.PutUint64(lp[:], uint64(len("bucket")))
		mac.Write(lp[:])
		mac.Write([]byte("bucket"))
		binary.BigEndian.PutUint64(lp[:], uint64(len(key)))
		mac.Write(lp[:])
		mac.Write([]byte(key))
		var h nameHash
		copy(h[:], mac.Sum(sum[:0]))
		if _, ok := ix.m[h]; !ok {
			b.Fatalf("object %d is not in the index", i%n)
		}
		i++
	}
}

// BenchmarkFreshnessReplay is the restart cost: an index is only useful once it
// has been read back, and until then every object is unknown to it. Measures
// reading n fixed-width records and rebuilding the map.
func BenchmarkFreshnessReplay(b *testing.B) {
	const n = 1_000_000
	prf := benchPRF(b)

	path := filepath.Join(b.TempDir(), "freshness.log")
	f, err := os.Create(path)
	if err != nil {
		b.Fatalf("creating the log: %v", err)
	}
	w := bufio.NewWriterSize(f, 1<<20)
	src := newIndex(prf, 0)
	var rec [32]byte
	for i := range n {
		h := src.name("bucket", benchKeyAt(i))
		v := benchVersionAt(i)
		copy(rec[:16], h[:])
		copy(rec[16:], v[:])
		if _, err := w.Write(rec[:]); err != nil {
			b.Fatalf("writing the log: %v", err)
		}
	}
	if err := w.Flush(); err != nil {
		b.Fatalf("flushing the log: %v", err)
	}
	if err := f.Close(); err != nil {
		b.Fatalf("closing the log: %v", err)
	}
	size, err := os.Stat(path)
	if err != nil {
		b.Fatalf("sizing the log: %v", err)
	}

	b.ReportAllocs()
	var loaded *index
	for b.Loop() {
		in, err := os.Open(path)
		if err != nil {
			b.Fatalf("opening the log: %v", err)
		}
		r := bufio.NewReaderSize(in, 1<<20)
		ix := newIndex(prf, n)
		var buf [32]byte
		for {
			if _, err := readFull(r, buf[:]); err != nil {
				break
			}
			var h nameHash
			var v version
			copy(h[:], buf[:16])
			copy(v[:], buf[16:])
			ix.m[h] = v
		}
		if err := in.Close(); err != nil {
			b.Fatalf("closing the log: %v", err)
		}
		if len(ix.m) != n {
			b.Fatalf("replayed %d entries, want %d", len(ix.m), n)
		}
		loaded = ix
	}

	b.StopTimer()
	runtime.KeepAlive(loaded)
	b.ReportMetric(float64(size.Size())/float64(n), "B/object-on-disk")
	b.ReportMetric(float64(size.Size())/(1<<20), "MiB/log")
}

func readFull(r *bufio.Reader, p []byte) (int, error) {
	n := 0
	for n < len(p) {
		m, err := r.Read(p[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
