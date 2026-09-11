package stream

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// patternReader produces an endless deterministic byte stream without allocating
// per read, so a memory test measures the code under test and not its fixture.
type patternReader struct{ off byte }

func (p *patternReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = p.off
		p.off++
	}
	return len(b), nil
}

// streamThrough encrypts size bytes and decrypts them again through an io.Pipe,
// which is the topology the proxy uses: no buffer anywhere holds the object.
// It returns the SHA-256 of what went in and of what came out.
func streamThrough(t *testing.T, size int64, log2C uint8) (in, out [sha256.Size]byte) {
	t.Helper()

	pr, pw := io.Pipe()
	inHash := sha256.New()
	encDone := make(chan error, 1)

	go func() {
		w, err := NewEncryptWriter(pw, testDEK, singlePart(log2C))
		if err != nil {
			_ = pw.CloseWithError(err)
			encDone <- err
			return
		}
		src := io.TeeReader(io.LimitReader(&patternReader{}, size), inHash)
		_, copyErr := io.Copy(w, src)
		closeErr := w.Close()
		if copyErr == nil {
			copyErr = closeErr
		}
		_ = pw.CloseWithError(copyErr)
		encDone <- copyErr
	}()

	r, err := NewDecryptReader(pr, testDEK, singlePart(log2C))
	if err != nil {
		t.Fatalf("NewDecryptReader: %v", err)
	}
	outHash := sha256.New()
	n, err := io.Copy(outHash, r)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("reader Close: %v", err)
	}
	if err := <-encDone; err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if n != size {
		t.Fatalf("decrypted %d bytes, want %d", n, size)
	}

	copy(in[:], inHash.Sum(nil))
	copy(out[:], outHash.Sum(nil))
	return in, out
}

// TestAllocationIsIndependentOfStreamSize is the package-level statement of goal
// G3. A stream 64 times longer must not allocate materially more: the hot path
// allocates nothing per chunk, so total allocation reflects setup only.
func TestAllocationIsIndependentOfStreamSize(t *testing.T) {
	measure := func(size int64) uint64 {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		in, out := streamThrough(t, size, DefaultLog2ChunkSize)
		if in != out {
			t.Fatalf("size %d: SHA-256 differs after a round trip", size)
		}
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}

	small := measure(1 << 20)
	large := measure(64 << 20)

	// Generous: the point is that the ratio is near 1, not near 64.
	if large > small*4 {
		t.Errorf("allocation scales with stream size: %d bytes for 1 MiB, %d bytes for 64 MiB", small, large)
	}
	t.Logf("allocated %d bytes for 1 MiB and %d bytes for 64 MiB (ratio %.2f)",
		small, large, float64(large)/float64(small))
}

// TestLargeStreamRoundTrip is the milestone's memory proof. It defaults to a size
// that keeps the normal test run fast; the nightly job raises it to the 10 GiB of
// the M1 definition of done via BLINDBUCKET_STREAM_SIZE.
//
//	BLINDBUCKET_STREAM_SIZE=10GiB go test ./internal/crypto/stream -run TestLargeStreamRoundTrip -v
func TestLargeStreamRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the large stream round trip in short mode")
	}

	size := int64(128 << 20)
	if s := os.Getenv("BLINDBUCKET_STREAM_SIZE"); s != "" {
		parsed, err := parseSize(s)
		if err != nil {
			t.Fatalf("BLINDBUCKET_STREAM_SIZE: %v", err)
		}
		size = parsed
	}

	// Sample the heap while the stream runs: the interesting number is the peak,
	// not the total, and a flat peak over a large object is the whole claim.
	var peak atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				for {
					old := peak.Load()
					if m.HeapAlloc <= old || peak.CompareAndSwap(old, m.HeapAlloc) {
						break
					}
				}
			}
		}
	}()

	start := time.Now()
	in, out := streamThrough(t, size, DefaultLog2ChunkSize)
	elapsed := time.Since(start)

	close(stop)
	<-done

	if in != out {
		t.Fatalf("SHA-256 differs after a round trip of %d bytes", size)
	}

	const budget = 20 << 20 // the M1 definition of done, for the CLI path
	t.Logf("%s round trip in %s (%.0f MiB/s), peak heap %.1f MiB, budget %d MiB",
		humanSize(size), elapsed.Round(time.Millisecond),
		float64(size)/(1<<20)/elapsed.Seconds(),
		float64(peak.Load())/(1<<20), budget>>20)

	if p := peak.Load(); p > budget {
		t.Errorf("peak heap was %d bytes, budget is %d", p, budget)
	}
}

func parseSize(s string) (int64, error) {
	multipliers := []struct {
		suffix string
		factor int64
	}{
		{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1},
	}
	for _, m := range multipliers {
		if len(s) > len(m.suffix) && s[len(s)-len(m.suffix):] == m.suffix {
			n, err := strconv.ParseInt(s[:len(s)-len(m.suffix)], 10, 64)
			if err != nil {
				return 0, err
			}
			return n * m.factor, nil
		}
	}
	return strconv.ParseInt(s, 10, 64)
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MiB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
