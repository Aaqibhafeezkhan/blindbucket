package stream

import (
	"bytes"
	"io"
	"testing"
)

// benchSizes are the chunk sizes of the benchmark plan in bench/: 16, 64 and
// 256 KiB. 64 KiB is the default.
var benchSizes = []struct {
	name  string
	log2C uint8
}{
	{"16KiB", 14},
	{"64KiB", 16},
	{"256KiB", 18},
}

// benchPayload is large enough that per-segment costs do not dominate, and small
// enough to stay in cache-friendly territory.
const benchPayload = 8 << 20

func BenchmarkEncrypt(b *testing.B) {
	plain := bytes.Repeat([]byte{0x5a}, benchPayload)

	for _, sz := range benchSizes {
		b.Run(sz.name, func(b *testing.B) {
			b.SetBytes(benchPayload)
			b.ReportAllocs()
			b.ResetTimer()

			for range b.N {
				w, err := NewEncryptWriter(io.Discard, testDEK, singlePart(sz.log2C))
				if err != nil {
					b.Fatalf("NewEncryptWriter: %v", err)
				}
				if _, err := w.Write(plain); err != nil {
					b.Fatalf("Write: %v", err)
				}
				if err := w.Close(); err != nil {
					b.Fatalf("Close: %v", err)
				}
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	plain := bytes.Repeat([]byte{0x5a}, benchPayload)

	for _, sz := range benchSizes {
		b.Run(sz.name, func(b *testing.B) {
			var sealed bytes.Buffer
			w, err := NewEncryptWriter(&sealed, testDEK, singlePart(sz.log2C))
			if err != nil {
				b.Fatalf("NewEncryptWriter: %v", err)
			}
			if _, err := w.Write(plain); err != nil {
				b.Fatalf("Write: %v", err)
			}
			if err := w.Close(); err != nil {
				b.Fatalf("Close: %v", err)
			}
			ciphertext := sealed.Bytes()

			b.SetBytes(benchPayload)
			b.ReportAllocs()
			b.ResetTimer()

			for range b.N {
				r, err := NewDecryptReader(bytes.NewReader(ciphertext), testDEK, singlePart(sz.log2C))
				if err != nil {
					b.Fatalf("NewDecryptReader: %v", err)
				}
				if _, err := io.Copy(io.Discard, r); err != nil {
					b.Fatalf("Copy: %v", err)
				}
				if err := r.Close(); err != nil {
					b.Fatalf("Close: %v", err)
				}
			}
		})
	}
}

// BenchmarkChunkSteadyState measures the hot path alone -- one chunk sealed in
// place, with the header and key derivation already done. The target is zero
// allocations per chunk.
func BenchmarkChunkSteadyState(b *testing.B) {
	for _, sz := range benchSizes {
		b.Run(sz.name, func(b *testing.B) {
			h, err := newHeader(singlePart(sz.log2C))
			if err != nil {
				b.Fatalf("newHeader: %v", err)
			}
			s, err := newSealer(testDEK, h)
			if err != nil {
				b.Fatalf("newSealer: %v", err)
			}
			chunk := 1 << sz.log2C
			buf := make([]byte, chunk+TagSize)

			b.SetBytes(int64(chunk))
			b.ReportAllocs()
			b.ResetTimer()

			for i := range b.N {
				s.seal(buf[:0], buf[:chunk], uint64(i), false)
			}
		})
	}
}
