package stream

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

var updateVectors = flag.Bool("update", false, "regenerate testdata/vectors/segment_v1.json")

const vectorPath = "../../../testdata/vectors/segment_v1.json"

// vectorFile is the on-disk shape of the known-answer vectors. It is a normative
// part of docs/FORMAT.md: an implementation that reproduces every ciphertext
// below, byte for byte, is format-compatible.
type vectorFile struct {
	FormatVersion int      `json:"format_version"`
	Note          string   `json:"note"`
	Vectors       []vector `json:"vectors"`
}

type vector struct {
	Name          string `json:"name"`
	DEK           string `json:"dek"`
	Salt          string `json:"salt"`
	Log2ChunkSize uint8  `json:"log2_chunk_size"`
	Multipart     bool   `json:"multipart"`
	Index         uint32 `json:"index"`
	Plaintext     string `json:"plaintext"`
	Ciphertext    string `json:"ciphertext"`
}

// vectorSpecs describes which cases the vectors cover. Sizes cluster around the
// chunk boundary, because that is where an encoder's final-chunk handling either
// works or does not.
var vectorSpecs = []struct {
	name   string
	log2C  uint8
	params SegmentParams
	size   int
}{
	{name: "empty", log2C: 12, size: 0},
	{name: "single byte", log2C: 12, size: 1},
	{name: "one byte short of a chunk", log2C: 12, size: 4095},
	{name: "exactly one chunk", log2C: 12, size: 4096},
	{name: "one byte past a chunk", log2C: 12, size: 4097},
	{name: "two chunks and one byte", log2C: 12, size: 8193},
	{name: "default chunk size", log2C: 16, size: 100},
	{name: "maximum chunk size", log2C: 20, size: 1},
	{name: "multipart part 1", log2C: 12, params: SegmentParams{Multipart: true, Index: 1}, size: 4097},
	{name: "multipart part 10000", log2C: 12, params: SegmentParams{Multipart: true, Index: MaxParts}, size: 1},
}

// vectorDEK and vectorSalt derive fixed inputs from the vector's position, so
// every vector uses different key material while staying reproducible.
func vectorDEK(i int) []byte {
	dek := make([]byte, KeySize)
	for j := range dek {
		dek[j] = byte(i*KeySize + j)
	}
	return dek
}

func vectorSalt(i int) [SaltSize]byte {
	var salt [SaltSize]byte
	for j := range salt {
		salt[j] = byte(0xa0 + i*SaltSize + j)
	}
	return salt
}

// vectorPlaintext is a deterministic, non-repeating pattern: constant bytes would
// hide an encoder that mixes up chunk order.
func vectorPlaintext(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i*7 + 13)
	}
	return p
}

func buildVectors(t *testing.T) []vector {
	t.Helper()

	out := make([]vector, 0, len(vectorSpecs))
	for i, spec := range vectorSpecs {
		params := spec.params
		params.Log2ChunkSize = spec.log2C

		dek := vectorDEK(i)
		salt := vectorSalt(i)
		plain := vectorPlaintext(spec.size)

		h, err := newHeaderWithSalt(params, salt)
		if err != nil {
			t.Fatalf("%s: newHeaderWithSalt: %v", spec.name, err)
		}
		var sealed bytes.Buffer
		w, err := newEncryptWriter(&sealed, dek, h)
		if err != nil {
			t.Fatalf("%s: newEncryptWriter: %v", spec.name, err)
		}
		if _, err := w.Write(plain); err != nil {
			t.Fatalf("%s: Write: %v", spec.name, err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("%s: Close: %v", spec.name, err)
		}

		out = append(out, vector{
			Name:          spec.name,
			DEK:           hex.EncodeToString(dek),
			Salt:          hex.EncodeToString(salt[:]),
			Log2ChunkSize: params.Log2ChunkSize,
			Multipart:     params.Multipart,
			Index:         params.Index,
			Plaintext:     hex.EncodeToString(plain),
			Ciphertext:    hex.EncodeToString(sealed.Bytes()),
		})
	}
	return out
}

// TestKnownAnswerVectors checks the committed vectors in both directions. Run
// with -update to regenerate the file after a deliberate format change; a change
// that was not deliberate shows up here as a failure.
func TestKnownAnswerVectors(t *testing.T) {
	if *updateVectors {
		file := vectorFile{
			FormatVersion: Version,
			Note: "Known-answer vectors for the blindbucket segment format, " +
				"normative alongside docs/FORMAT.md. Every field is fixed, so the " +
				"ciphertext is fully determined. Regenerate with: go test ./internal/crypto/stream -update",
			Vectors: buildVectors(t),
		}
		data, err := json.MarshalIndent(file, "", "  ")
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(vectorPath), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(vectorPath, append(data, '\n'), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		t.Logf("wrote %d vectors to %s", len(file.Vectors), vectorPath)
		return
	}

	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read vectors: %v (generate them with -update)", err)
	}
	var file vectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if file.FormatVersion != Version {
		t.Fatalf("vectors are for format version %d, this package implements %d", file.FormatVersion, Version)
	}
	if len(file.Vectors) != len(vectorSpecs) {
		t.Fatalf("vector file has %d entries, the generator produces %d", len(file.Vectors), len(vectorSpecs))
	}

	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			dek := mustHex(t, v.DEK)
			plain := mustHex(t, v.Plaintext)
			wantSealed := mustHex(t, v.Ciphertext)

			var salt [SaltSize]byte
			copy(salt[:], mustHex(t, v.Salt))

			params := SegmentParams{Log2ChunkSize: v.Log2ChunkSize, Multipart: v.Multipart, Index: v.Index}

			// Forward: the same inputs must produce exactly these bytes.
			h, err := newHeaderWithSalt(params, salt)
			if err != nil {
				t.Fatalf("newHeaderWithSalt: %v", err)
			}
			var got bytes.Buffer
			w, err := newEncryptWriter(&got, dek, h)
			if err != nil {
				t.Fatalf("newEncryptWriter: %v", err)
			}
			if _, err := w.Write(plain); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if !bytes.Equal(got.Bytes(), wantSealed) {
				t.Errorf("ciphertext differs from the vector\n got %s\nwant %s",
					truncHex(got.Bytes()), truncHex(wantSealed))
			}

			// Backward: the recorded ciphertext must decrypt to the recorded
			// plaintext. A vector that only ever round-trips against itself would
			// not catch an encoder and decoder that are wrong in the same way.
			back, err := openSegment(dek, params, wantSealed)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(back, plain) {
				t.Errorf("decrypted plaintext differs from the vector")
			}

			// The recorded length must match the arithmetic.
			wantLen, err := SealedSize(int64(len(plain)), v.Log2ChunkSize)
			if err != nil {
				t.Fatalf("SealedSize: %v", err)
			}
			if int64(len(wantSealed)) != wantLen {
				t.Errorf("vector ciphertext is %d bytes, SealedSize says %d", len(wantSealed), wantLen)
			}
		})
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in vector: %v", err)
	}
	return b
}

func truncHex(b []byte) string {
	const limit = 48
	if len(b) <= limit {
		return hex.EncodeToString(b)
	}
	return fmt.Sprintf("%s... (%d bytes)", hex.EncodeToString(b[:limit]), len(b))
}
