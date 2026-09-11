package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"hash/crc64"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestCRC64NVMECheckValue validates the polynomial against the standard check
// value for CRC-64/NVME. Getting a CRC table wrong is silent: every checksum
// simply disagrees with the client's, and the cause is not obvious.
func TestCRC64NVMECheckValue(t *testing.T) {
	t.Parallel()

	const want uint64 = 0xAE8B14860A799888
	if got := crc64.Checksum([]byte("123456789"), crc64NVMETable); got != want {
		t.Errorf("CRC-64/NVME(%q) = %#016x, want %#016x", "123456789", got, want)
	}
}

func TestChecksumAlgorithms(t *testing.T) {
	t.Parallel()

	data := []byte("The quick brown fox jumps over the lazy dog")

	tests := []struct {
		alg  ChecksumAlgorithm
		want string
	}{
		{ChecksumCRC32, base64.StdEncoding.EncodeToString(bigEndian32(crc32.ChecksumIEEE(data)))},
		{ChecksumCRC32C, base64.StdEncoding.EncodeToString(
			bigEndian32(crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))))},
		{ChecksumSHA256, base64.StdEncoding.EncodeToString(sha256Sum(data))},
	}
	for _, tc := range tests {
		got, err := ComputeChecksum(tc.alg, data)
		if err != nil {
			t.Fatalf("%s: %v", tc.alg, err)
		}
		if got != tc.want {
			t.Errorf("%s = %q, want %q", tc.alg, got, tc.want)
		}
	}

	if _, err := ComputeChecksum("MD4", data); !errors.Is(err, ErrUnsupportedChecksum) {
		t.Errorf("an unknown algorithm returned %v, want ErrUnsupportedChecksum", err)
	}
	for _, alg := range []ChecksumAlgorithm{ChecksumCRC32, ChecksumCRC32C, ChecksumCRC64NVME,
		ChecksumSHA1, ChecksumSHA256} {
		if alg.HeaderName() != "x-amz-checksum-"+strings.ToLower(string(alg)) {
			t.Errorf("HeaderName for %s = %q", alg, alg.HeaderName())
		}
	}
}

func bigEndian32(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// chunkedBody builds an aws-chunked body.
//
// The per-chunk signatures are produced with this package's own Sign, so this
// exercises the framing, the chaining and the failure detection -- not the
// interoperability of the signature itself. That is covered where it can only
// be covered honestly: by running the real AWS CLI against the proxy.
func chunkedBody(t *testing.T, res *Result, chunks [][]byte, trailer map[string]string, signed bool) []byte {
	t.Helper()

	var out bytes.Buffer
	prev := res.Seed
	timestamp := res.Time.UTC().Format(amzDateFormat)
	scope := res.Authorization.Credential.Scope()

	emit := func(data []byte) {
		header := fmt.Sprintf("%x", len(data))
		if signed {
			sum := sha256.Sum256(data)
			sts := strings.Join([]string{
				chunkPayloadAlgorithm, timestamp, scope, prev,
				emptyStringSHA256, hex.EncodeToString(sum[:]),
			}, "\n")
			sig := Sign(res.SigningKey, sts)
			header += ";chunk-signature=" + sig
			prev = sig
		}
		out.WriteString(header + "\r\n")
		out.Write(data)
		out.WriteString("\r\n")
	}

	for _, c := range chunks {
		emit(c)
	}
	emit(nil) // the terminating empty chunk

	for name, value := range trailer {
		out.WriteString(strings.ToLower(name) + ":" + value + "\r\n")
	}
	out.WriteString("\r\n")
	return out.Bytes()
}

func chunkedResult(mode PayloadMode) *Result {
	return &Result{
		PayloadMode: mode,
		SigningKey:  SigningKey(testSecretKey, "20260911", testRegion),
		Seed:        strings.Repeat("a", 64),
		Time:        time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC),
		Authorization: Authorization{Credential: Credential{
			AccessKeyID: testAccessKey, Date: "20260911", Region: testRegion,
			Service: service, Terminator: terminator,
		}},
	}
}

// chunkedRequest wraps an aws-chunked body in a request the way a client sends
// one.
func chunkedRequest(t *testing.T, body []byte, decoded int64, headers map[string]string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPut, "/bucket/key", bytes.NewReader(body))
	r.Header.Set(DecodedLengthHeader, strconv.FormatInt(decoded, 10))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestChunkedDecoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mode   PayloadMode
		chunks [][]byte
		want   string
	}{
		{"single chunk", PayloadStreamingUnsignedTrailer, [][]byte{[]byte("hello world")}, "hello world"},
		{"several chunks", PayloadStreamingUnsignedTrailer,
			[][]byte{[]byte("one "), []byte("two "), []byte("three")}, "one two three"},
		{"empty body", PayloadStreamingUnsignedTrailer, nil, ""},
		{"signed chunks", PayloadStreamingSigned,
			[][]byte{[]byte("alpha"), []byte("beta")}, "alphabeta"},
		{"a large chunk", PayloadStreamingUnsignedTrailer,
			[][]byte{bytes.Repeat([]byte("x"), 200_000)}, strings.Repeat("x", 200_000)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := chunkedResult(tc.mode)
			body := chunkedBody(t, res, tc.chunks, nil, tc.mode.Signed())

			r := chunkedRequest(t, body, int64(len(tc.want)), nil)
			br, length, err := NewBodyReader(r, res)
			if err != nil {
				t.Fatalf("NewBodyReader: %v", err)
			}
			if length != int64(len(tc.want)) {
				t.Errorf("decoded length = %d, want %d", length, len(tc.want))
			}

			got, err := io.ReadAll(br)
			if err != nil {
				t.Fatalf("reading: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("decoded %d bytes, want %d", len(got), len(tc.want))
			}
		})
	}
}

// TestChunkedVerifiesTrailerChecksum covers what current AWS SDKs send by
// default: no checksum header up front, one in the trailer after the body.
func TestChunkedVerifiesTrailerChecksum(t *testing.T) {
	t.Parallel()

	payload := []byte("payload that gets checksummed")
	sum, err := ComputeChecksum(ChecksumCRC32, payload)
	if err != nil {
		t.Fatalf("ComputeChecksum: %v", err)
	}

	t.Run("correct checksum", func(t *testing.T) {
		t.Parallel()
		res := chunkedResult(PayloadStreamingUnsignedTrailer)
		body := chunkedBody(t, res, [][]byte{payload},
			map[string]string{"x-amz-checksum-crc32": sum}, false)

		r := chunkedRequest(t, body, int64(len(payload)),
			map[string]string{"X-Amz-Trailer": "x-amz-checksum-crc32"})
		br, _, err := NewBodyReader(r, res)
		if err != nil {
			t.Fatalf("NewBodyReader: %v", err)
		}
		got, err := io.ReadAll(br)
		if err != nil {
			t.Fatalf("reading: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Error("the decoded body differs")
		}
		if tr := br.Trailer().Get("x-amz-checksum-crc32"); tr != sum {
			t.Errorf("trailer checksum = %q, want %q", tr, sum)
		}
	})

	t.Run("wrong checksum", func(t *testing.T) {
		t.Parallel()
		res := chunkedResult(PayloadStreamingUnsignedTrailer)
		wrong := base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 0})
		body := chunkedBody(t, res, [][]byte{payload},
			map[string]string{"x-amz-checksum-crc32": wrong}, false)

		r := chunkedRequest(t, body, int64(len(payload)),
			map[string]string{"X-Amz-Trailer": "x-amz-checksum-crc32"})
		br, _, err := NewBodyReader(r, res)
		if err != nil {
			t.Fatalf("NewBodyReader: %v", err)
		}
		if _, err := io.ReadAll(br); !errors.Is(err, ErrChecksumMismatch) {
			t.Errorf("got %v, want ErrChecksumMismatch", err)
		}
	})

	t.Run("a trailer checksum that was never announced", func(t *testing.T) {
		t.Parallel()
		res := chunkedResult(PayloadStreamingUnsignedTrailer)
		body := chunkedBody(t, res, [][]byte{payload},
			map[string]string{"x-amz-checksum-crc32": sum}, false)

		// No X-Amz-Trailer: nothing was hashing, so the value cannot be checked.
		// Accepting it would silently drop an integrity check the client
		// believes is being made.
		br, _, err := NewBodyReader(chunkedRequest(t, body, int64(len(payload)), nil), res)
		if err != nil {
			t.Fatalf("NewBodyReader: %v", err)
		}
		if _, err := io.ReadAll(br); !errors.Is(err, ErrChecksumMismatch) {
			t.Errorf("got %v, want ErrChecksumMismatch", err)
		}
	})

	t.Run("an announced trailer that never arrives", func(t *testing.T) {
		t.Parallel()
		res := chunkedResult(PayloadStreamingUnsignedTrailer)
		body := chunkedBody(t, res, [][]byte{payload}, nil, false)

		br, _, err := NewBodyReader(chunkedRequest(t, body, int64(len(payload)),
			map[string]string{"X-Amz-Trailer": "x-amz-checksum-crc32"}), res)
		if err != nil {
			t.Fatalf("NewBodyReader: %v", err)
		}
		if _, err := io.ReadAll(br); !errors.Is(err, ErrChecksumMismatch) {
			t.Errorf("got %v, want ErrChecksumMismatch", err)
		}
	})
}

// TestChunkedSignatureChain checks that the chain does what a chain is for:
// altering any chunk invalidates it from that point on.
func TestChunkedSignatureChain(t *testing.T) {
	t.Parallel()

	res := chunkedResult(PayloadStreamingSigned)
	chunks := [][]byte{[]byte("first"), []byte("second"), []byte("third")}
	decoded := int64(len("firstsecondthird"))

	t.Run("intact", func(t *testing.T) {
		t.Parallel()
		body := chunkedBody(t, res, chunks, nil, true)
		br, _, err := NewBodyReader(chunkedRequest(t, body, decoded, nil), res)
		if err != nil {
			t.Fatalf("NewBodyReader: %v", err)
		}
		if _, err := io.ReadAll(br); err != nil {
			t.Fatalf("an intact signed body was rejected: %v", err)
		}
	})

	t.Run("a chunk's data altered", func(t *testing.T) {
		t.Parallel()
		body := chunkedBody(t, res, chunks, nil, true)
		altered := bytes.Replace(body, []byte("second"), []byte("SECOND"), 1)
		br, _, err := NewBodyReader(chunkedRequest(t, altered, decoded, nil), res)
		if err != nil {
			t.Fatalf("NewBodyReader: %v", err)
		}
		if _, err := io.ReadAll(br); !errors.Is(err, ErrChunkSignature) {
			t.Errorf("got %v, want ErrChunkSignature", err)
		}
	})

	t.Run("a chunk signed for a different seed", func(t *testing.T) {
		t.Parallel()
		other := chunkedResult(PayloadStreamingSigned)
		other.Seed = strings.Repeat("b", 64)
		body := chunkedBody(t, other, chunks, nil, true)

		br, _, err := NewBodyReader(chunkedRequest(t, body, decoded, nil), res)
		if err != nil {
			t.Fatalf("NewBodyReader: %v", err)
		}
		if _, err := io.ReadAll(br); !errors.Is(err, ErrChunkSignature) {
			t.Errorf("got %v, want ErrChunkSignature", err)
		}
	})
}

// TestChunkedWithoutTrailerSection covers a body that ends immediately after the
// final chunk, with no trailer block at all.
//
// STREAMING-AWS4-HMAC-SHA256-PAYLOAD has exactly that shape, and it is what the
// MinIO client sends. The helper above always writes a terminating blank line,
// so this case needs building by hand -- which is why the original decoder
// rejected every mc upload until a real client was pointed at it.
func TestChunkedWithoutTrailerSection(t *testing.T) {
	t.Parallel()

	res := chunkedResult(PayloadStreamingSigned)
	payload := []byte("no trailer follows this")

	var body bytes.Buffer
	prev := res.Seed
	timestamp := res.Time.UTC().Format(amzDateFormat)
	scope := res.Authorization.Credential.Scope()

	emit := func(data []byte) {
		sum := sha256.Sum256(data)
		sts := strings.Join([]string{
			chunkPayloadAlgorithm, timestamp, scope, prev,
			emptyStringSHA256, hex.EncodeToString(sum[:]),
		}, "\n")
		sig := Sign(res.SigningKey, sts)
		prev = sig
		fmt.Fprintf(&body, "%x;chunk-signature=%s\r\n", len(data), sig)
		body.Write(data)
		body.WriteString("\r\n")
	}
	emit(payload)
	emit(nil)
	// Deliberately nothing after the final chunk's CRLF.

	br, _, err := NewBodyReader(chunkedRequest(t, body.Bytes(), int64(len(payload)), nil), res)
	if err != nil {
		t.Fatalf("NewBodyReader: %v", err)
	}
	got, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("a body with no trailer section was rejected: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("decoded %q, want %q", got, payload)
	}
}

func TestChunkedRejectsMalformedFraming(t *testing.T) {
	t.Parallel()

	res := chunkedResult(PayloadStreamingUnsignedTrailer)

	tests := map[string]string{
		"no terminating chunk":    "5\r\nhello\r\n",
		"size is not hex":         "zz\r\nhello\r\n0\r\n\r\n",
		"negative size":           "-5\r\nhello\r\n0\r\n\r\n",
		"missing CRLF after data": "5\r\nhelloXX0\r\n\r\n",
		"short chunk":             "10\r\nhello\r\n0\r\n\r\n",
		"absurd chunk size":       "FFFFFFFFFFFFFFFF\r\n",
		"unknown chunk extension": "5;bogus=1\r\nhello\r\n0\r\n\r\n",
		"empty body":              "",
		"trailer without a colon": "5\r\nhello\r\n0\r\nnonsense\r\n\r\n",
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			br, _, err := NewBodyReader(chunkedRequest(t, []byte(body), 5, nil), res)
			if err != nil {
				return // rejected before reading, which is also fine
			}
			if _, err := io.ReadAll(br); err == nil {
				t.Error("a malformed body was accepted")
			}
		})
	}
}

// TestChunkedRejectsLengthMismatch covers a client that declares one length and
// sends another. The proxy computed the upstream Content-Length from the
// declared value, so a mismatch has to fail rather than silently truncate.
func TestChunkedRejectsLengthMismatch(t *testing.T) {
	t.Parallel()

	res := chunkedResult(PayloadStreamingUnsignedTrailer)
	body := chunkedBody(t, res, [][]byte{[]byte("hello")}, nil, false)

	for _, declared := range []int64{4, 6, 0, 1000} {
		br, _, err := NewBodyReader(chunkedRequest(t, body, declared, nil), res)
		if err != nil {
			continue
		}
		if _, err := io.ReadAll(br); !errors.Is(err, ErrMalformedChunkedBody) {
			t.Errorf("declared %d for a 5-byte body: got %v, want ErrMalformedChunkedBody", declared, err)
		}
	}
}

func TestChunkedRequiresDecodedLength(t *testing.T) {
	t.Parallel()

	res := chunkedResult(PayloadStreamingUnsignedTrailer)
	r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("0\r\n\r\n"))
	if _, _, err := NewBodyReader(r, res); !errors.Is(err, ErrMalformedChunkedBody) {
		t.Errorf("got %v, want ErrMalformedChunkedBody", err)
	}
}

// TestPlainBodyVerifiesPayloadHash covers the non-chunked path: the hex
// x-amz-content-sha256 is verified as the body streams, and the mismatch
// surfaces exactly when the body ends.
func TestPlainBodyVerifiesPayloadHash(t *testing.T) {
	t.Parallel()

	payload := []byte("a body that is hashed up front")
	sum := sha256.Sum256(payload)

	t.Run("matching hash", func(t *testing.T) {
		t.Parallel()
		res := &Result{PayloadMode: PayloadHashed, PayloadHash: hex.EncodeToString(sum[:])}
		r := httptest.NewRequest(http.MethodPut, "/bucket/key", bytes.NewReader(payload))
		r.ContentLength = int64(len(payload))

		br, length, err := NewBodyReader(r, res)
		if err != nil {
			t.Fatalf("NewBodyReader: %v", err)
		}
		if length != int64(len(payload)) {
			t.Errorf("length = %d, want %d", length, len(payload))
		}
		got, err := io.ReadAll(br)
		if err != nil {
			t.Fatalf("reading: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Error("the body differs")
		}
	})

	t.Run("mismatching hash", func(t *testing.T) {
		t.Parallel()
		res := &Result{PayloadMode: PayloadHashed, PayloadHash: strings.Repeat("0", 64)}
		r := httptest.NewRequest(http.MethodPut, "/bucket/key", bytes.NewReader(payload))
		r.ContentLength = int64(len(payload))

		br, _, err := NewBodyReader(r, res)
		if err != nil {
			t.Fatalf("NewBodyReader: %v", err)
		}
		if _, err := io.ReadAll(br); !errors.Is(err, ErrChecksumMismatch) {
			t.Errorf("got %v, want ErrChecksumMismatch", err)
		}
	})
}

func TestPlainBodyVerifiesHeaderChecksums(t *testing.T) {
	t.Parallel()

	payload := []byte("checksummed up front")
	crc, err := ComputeChecksum(ChecksumCRC32, payload)
	if err != nil {
		t.Fatalf("ComputeChecksum: %v", err)
	}

	newReader := func(t *testing.T, headers map[string]string) *BodyReader {
		t.Helper()
		r := httptest.NewRequest(http.MethodPut, "/bucket/key", bytes.NewReader(payload))
		r.ContentLength = int64(len(payload))
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		br, _, err := NewBodyReader(r, &Result{PayloadMode: PayloadUnsigned})
		if err != nil {
			t.Fatalf("NewBodyReader: %v", err)
		}
		return br
	}

	t.Run("correct", func(t *testing.T) {
		t.Parallel()
		br := newReader(t, map[string]string{"X-Amz-Checksum-Crc32": crc})
		if _, err := io.ReadAll(br); err != nil {
			t.Fatalf("a correct checksum was rejected: %v", err)
		}
	})

	t.Run("wrong", func(t *testing.T) {
		t.Parallel()
		br := newReader(t, map[string]string{
			"X-Amz-Checksum-Crc32": base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4}),
		})
		if _, err := io.ReadAll(br); !errors.Is(err, ErrChecksumMismatch) {
			t.Errorf("got %v, want ErrChecksumMismatch", err)
		}
	})

	t.Run("content-md5", func(t *testing.T) {
		t.Parallel()
		br := newReader(t, map[string]string{
			"Content-MD5": base64.StdEncoding.EncodeToString(make([]byte, 16)),
		})
		if _, err := io.ReadAll(br); !errors.Is(err, ErrChecksumMismatch) {
			t.Errorf("got %v, want ErrChecksumMismatch", err)
		}
	})

	t.Run("malformed checksum header", func(t *testing.T) {
		t.Parallel()
		r := httptest.NewRequest(http.MethodPut, "/bucket/key", bytes.NewReader(payload))
		r.ContentLength = int64(len(payload))
		r.Header.Set("X-Amz-Checksum-Crc32", "not base64!!")
		if _, _, err := NewBodyReader(r, &Result{PayloadMode: PayloadUnsigned}); err == nil {
			t.Error("a malformed checksum header was accepted")
		}
	})

	t.Run("checksum of the wrong length", func(t *testing.T) {
		t.Parallel()
		r := httptest.NewRequest(http.MethodPut, "/bucket/key", bytes.NewReader(payload))
		r.ContentLength = int64(len(payload))
		r.Header.Set("X-Amz-Checksum-Crc32", base64.StdEncoding.EncodeToString([]byte{1, 2}))
		if _, _, err := NewBodyReader(r, &Result{PayloadMode: PayloadUnsigned}); err == nil {
			t.Error("a two-byte CRC32 was accepted")
		}
	})
}

// FuzzChunkedReader requires that no body, however malformed, causes a panic.
func FuzzChunkedReader(f *testing.F) {
	res := chunkedResult(PayloadStreamingUnsignedTrailer)
	f.Add(chunkedBody(&testing.T{}, res, [][]byte{[]byte("seed")}, nil, false))
	f.Add([]byte("0\r\n\r\n"))
	f.Add([]byte("5\r\nhello\r\n0\r\n\r\n"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, body []byte) {
		r := chunkedRequest(t, body, 4, nil)
		br, _, err := NewBodyReader(r, res)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, br)
	})
}
