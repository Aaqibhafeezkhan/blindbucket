package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// These are the multipart entries in the attack catalogue: what a storage
// provider that is actively hostile, rather than merely unreliable, can do to a
// multipart object. Every one of them must end in a refusal, never in plaintext
// and never in a silently different object.

// manifestKeyOf returns where an object's manifest is stored.
func (h *harness) manifestKeyOf(t *testing.T, key string) (string, manifest.ID) {
	t.Helper()
	info, err := h.upstream.HeadObject(t.Context(), testBucket, key)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	for name, value := range info.Metadata {
		if strings.EqualFold(name, "bb-mid") {
			id, err := manifest.ParseID(value)
			if err != nil {
				t.Fatalf("bb-mid is unreadable: %v", err)
			}
			return id.ObjectKey(key), id
		}
	}
	t.Fatalf("object %q carries no bb-mid", key)
	return "", manifest.ID{}
}

// storeParts uploads a multipart object and returns the parts it was built from.
func (h *harness) storeParts(t *testing.T, key string, sizes ...int) [][]byte {
	t.Helper()
	parts := make([][]byte, 0, len(sizes))
	for _, size := range sizes {
		parts = append(parts, randomBytes(t, size))
	}
	h.mpuStore(t, key, parts)
	t.Cleanup(func() {
		mk, _ := h.manifestKeyOfQuiet(key)
		if mk != "" {
			_ = h.upstream.DeleteObject(context.Background(), testBucket, mk)
		}
	})
	return parts
}

func (h *harness) manifestKeyOfQuiet(key string) (string, bool) {
	info, err := h.upstream.HeadObject(context.Background(), testBucket, key)
	if err != nil {
		return "", false
	}
	for name, value := range info.Metadata {
		if strings.EqualFold(name, "bb-mid") {
			id, err := manifest.ParseID(value)
			if err != nil {
				return "", false
			}
			return id.ObjectKey(key), true
		}
	}
	return "", false
}

// expectIntegrityFailure asserts that a GET is refused rather than served.
func (h *harness) expectIntegrityFailure(t *testing.T, key, what string) {
	t.Helper()
	resp := h.do(t, http.MethodGet, key)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		t.Fatalf("%s: the object was served (%d bytes read)", what, len(body))
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("%s: status = %d, want 502", what, resp.StatusCode)
	}
	if body := readBody(t, resp); !strings.Contains(body, "IntegrityCheckFailed") {
		t.Errorf("%s: expected IntegrityCheckFailed, got %s", what, body)
	}
}

// A provider that reorders the parts is caught by the segment index, which is
// authenticated in every chunk's associated data.
func TestIntegrationMultipartAttackReorderedParts(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "reordered.bin")
	h.storeParts(t, key, testPart, testPart, testPart)

	sealed, err := stream.SealedSize(testPart, stream.MinLog2ChunkSize)
	if err != nil {
		t.Fatalf("SealedSize: %v", err)
	}
	h.rewriteUpstream(t, key, func(stored []byte) []byte {
		// Swap the first two segments. Every chunk still verifies on its own;
		// only the index in the header says they have moved.
		out := bytes.Clone(stored)
		copy(out[0:sealed], stored[sealed:2*sealed])
		copy(out[sealed:2*sealed], stored[0:sealed])
		return out
	})

	h.expectIntegrityFailure(t, key, "reordered parts")
}

// Dropping a part leaves every remaining segment authentic. What catches it is
// the manifest: it records how many parts there are and how large each is, so
// the object no longer has the size the manifest describes.
func TestIntegrationMultipartAttackDroppedPart(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "dropped.bin")
	h.storeParts(t, key, testPart, testPart, 500)

	sealed, err := stream.SealedSize(testPart, stream.MinLog2ChunkSize)
	if err != nil {
		t.Fatalf("SealedSize: %v", err)
	}
	h.rewriteUpstream(t, key, func(stored []byte) []byte {
		return bytes.Clone(stored[sealed:]) // the first part is gone
	})

	h.expectIntegrityFailure(t, key, "a dropped part")
}

// This is invariant I1 from the other side: an object whose manifest is missing
// must be refused, not served as whatever the segments happen to say. The data
// is still there and still decryptable with the data key, which is why the
// failure is an integrity error and not a NoSuchKey.
func TestIntegrationMultipartAttackDeletedManifest(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "no-manifest.bin")
	h.storeParts(t, key, testPart, 100)

	manifestKey, _ := h.manifestKeyOf(t, key)
	if err := h.upstream.DeleteObject(t.Context(), testBucket, manifestKey); err != nil {
		t.Fatalf("deleting the manifest: %v", err)
	}

	h.expectIntegrityFailure(t, key, "a deleted manifest")
}

// A manifest from another object does not verify here, because the MAC covers
// the bucket, the key and the manifest id, and the key it is checked under is
// derived from this object's data key.
func TestIntegrationMultipartAttackSubstitutedManifest(t *testing.T) {
	h := newHarness(t)
	victim := testKey(t, "victim.bin")
	donor := testKey(t, "donor.bin")
	h.storeParts(t, victim, testPart, 100)
	h.storeParts(t, donor, testPart, 100)

	victimManifest, _ := h.manifestKeyOf(t, victim)
	donorManifest, _ := h.manifestKeyOf(t, donor)

	donorBody := h.readUpstream(t, donorManifest)
	if _, err := h.upstream.PutObject(t.Context(), upstream.PutObjectInput{
		Bucket: testBucket, Key: victimManifest,
		Body: bytes.NewReader(donorBody), ContentLength: int64(len(donorBody)),
	}); err != nil {
		t.Fatalf("substituting the manifest: %v", err)
	}

	h.expectIntegrityFailure(t, victim, "a manifest from another object")
}

// Presenting a multipart object as a single-part one means dropping bb-mid, so
// that nothing looks for a manifest at all. The segment header catches it: the
// multipart flag is set and it is authenticated.
func TestIntegrationMultipartAttackStrippedManifestID(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "stripped-mid.bin")
	h.storeParts(t, key, testPart, 100)

	stored := h.readUpstream(t, key)
	info, err := h.upstream.HeadObject(t.Context(), testBucket, key)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	metadata := map[string]string{}
	for name, value := range info.Metadata {
		if strings.EqualFold(name, "bb-mid") {
			continue
		}
		metadata[name] = value
	}
	if _, err := h.upstream.PutObject(t.Context(), upstream.PutObjectInput{
		Bucket: testBucket, Key: key,
		Body: bytes.NewReader(stored), ContentLength: int64(len(stored)),
		Metadata: metadata,
	}); err != nil {
		t.Fatalf("rewriting without bb-mid: %v", err)
	}

	h.expectIntegrityFailure(t, key, "a multipart object passed off as single-part")
}

// Tampering inside a part behaves exactly as it does for a single-part object,
// and the boundary between the two outcomes is the status line (ADR-004): what
// can be caught before it becomes an error, and what cannot becomes an aborted
// connection. Being a multipart object changes neither.
func TestIntegrationMultipartAttackTamperedChunk(t *testing.T) {
	h := newHarness(t)

	t.Run("in the first chunk of the first part, a clean error", func(t *testing.T) {
		key := testKey(t, "early.bin")
		h.storeParts(t, key, testPart, 100)

		h.rewriteUpstream(t, key, func(stored []byte) []byte {
			out := bytes.Clone(stored)
			out[stream.HeaderSize+9] ^= 0x01
			return out
		})
		h.expectIntegrityFailure(t, key, "a flipped bit in the first chunk")
	})

	t.Run("in a later part, an aborted response", func(t *testing.T) {
		key := testKey(t, "late.bin")
		// The second part spans four chunks, so that the corrupted one is not
		// also the first: the bytes that do arrive then prove plaintext crossed
		// the part boundary before the abort.
		parts := h.storeParts(t, key, testPart, 4*testChunk)
		whole := append(bytes.Clone(parts[0]), parts[1]...)

		h.rewriteUpstream(t, key, func(stored []byte) []byte {
			out := bytes.Clone(stored)
			// The last chunk of the second part, which the client only reaches
			// long after the status line has gone out.
			out[len(out)-40] ^= 0x01
			return out
		})

		get := h.do(t, http.MethodGet, key)
		defer func() { _ = get.Body.Close() }()
		if get.StatusCode != http.StatusOK {
			t.Fatalf("status %d: the failure is expected mid-body, not before it", get.StatusCode)
		}

		body, err := io.ReadAll(get.Body)
		if err == nil {
			t.Fatal("the response completed despite corrupted data")
		}
		if int64(len(body)) >= get.ContentLength {
			t.Errorf("delivered %d of %d declared bytes; a client could mistake this for success",
				len(body), get.ContentLength)
		}
		// Everything that did arrive was released only after its own chunk
		// verified, so it must be authentic plaintext -- including across the
		// part boundary.
		if !bytes.Equal(body, whole[:len(body)]) {
			t.Error("the bytes delivered before the abort were not authentic plaintext")
		}
		// Three of the second part's four chunks precede the corrupted one, so
		// exactly that much plaintext must have been released -- which is only
		// possible if the reader moved from one segment to the next correctly.
		if want := testPart + 3*testChunk; len(body) != want {
			t.Errorf("delivered %d bytes, want %d (the whole first part plus the three "+
				"verified chunks of the second)", len(body), want)
		}
	})
}

// A range request must be refused on the same grounds as a whole read: the
// manifest is loaded and checked before any byte is served, so a range cannot be
// a way around the checks a full GET performs.
func TestIntegrationMultipartAttackRangeOverDeletedManifest(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "range-no-manifest.bin")
	h.storeParts(t, key, testPart, 100)

	manifestKey, _ := h.manifestKeyOf(t, key)
	if err := h.upstream.DeleteObject(t.Context(), testBucket, manifestKey); err != nil {
		t.Fatalf("deleting the manifest: %v", err)
	}

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, h.url(key), nil)
	req.Header.Set("Range", "bytes=0-99")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusPartialContent {
		t.Fatal("a range was served for an object whose manifest is gone")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
}

// A token names one upload. Once that upload is completed the provider's own
// upload id is consumed, so replaying the token cannot resurrect it -- which
// matters because a replayed completion is what would let a client delete the
// manifest of a live object.
func TestIntegrationMultipartAttackReplayedToken(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "replayed.bin")
	token := h.mpuStart(t, key, nil)

	etag, resp := h.mpuPart(t, key, token, 1, randomBytes(t, 4096))
	_ = resp.Body.Close()
	done := h.mpuComplete(t, key, token, []completeReqPart{{PartNumber: 1, ETag: etag}})
	if done.StatusCode != http.StatusOK {
		t.Fatalf("completion returned %d: %s", done.StatusCode, readBody(t, done))
	}
	_ = done.Body.Close()

	// The object is readable now.
	get := h.do(t, http.MethodGet, key)
	_ = get.Body.Close()
	if get.StatusCode != http.StatusOK {
		t.Fatalf("GET after completion returned %d", get.StatusCode)
	}

	// Replaying the completion must fail, and must leave the object readable.
	replay := h.mpuComplete(t, key, token, []completeReqPart{{PartNumber: 1, ETag: etag}})
	_ = replay.Body.Close()
	if replay.StatusCode == http.StatusOK {
		t.Error("a completed upload was completed a second time")
	}

	// And an abort with the spent token must not take the live manifest with it.
	target := fmt.Sprintf("%s?uploadId=%s", h.url(key), urlQueryEscape(token))
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodDelete, target, nil)
	abort, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("abort: %v", err)
	}
	_ = abort.Body.Close()

	after := h.do(t, http.MethodGet, key)
	defer func() { _ = after.Body.Close() }()
	if after.StatusCode != http.StatusOK {
		t.Fatalf("replaying the token made the object unreadable: %d %s",
			after.StatusCode, readBody(t, after))
	}
}

// readUpstream returns an object's stored bytes.
func (h *harness) readUpstream(t *testing.T, key string) []byte {
	t.Helper()
	out, err := h.upstream.GetObject(t.Context(), upstream.GetObjectInput{Bucket: testBucket, Key: key})
	if err != nil {
		t.Fatalf("reading %q upstream: %v", key, err)
	}
	defer func() { _ = out.Body.Close() }()
	raw, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("reading %q upstream: %v", key, err)
	}
	return raw
}

// TestIntegrationRetrySubstitution is THREAT_MODEL section 5.2, as an attack.
//
// A client that retries a part leaves two segments under the same part number,
// both genuine, both produced by this gateway under the same data key. Nothing
// in a segment distinguishes them: the part number is authenticated and equal,
// the sizes are equal, every chunk tag verifies. Before part salts were
// recorded in the manifest, a provider could serve either one and the object
// would read as valid with one part's contents silently replaced by an earlier
// attempt's.
//
// Here the provider does exactly that, with bytes this gateway itself wrote.
func TestIntegrationRetrySubstitution(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "retried.bin")
	ctx := context.Background()

	first := randomBytes(t, testPart)
	second := randomBytes(t, testPart)
	tail := randomBytes(t, 999)

	token := h.mpuStart(t, key, nil)

	// Part 1, first attempt. Its ciphertext is kept aside: this is what the
	// provider will substitute back in later.
	etag1a, resp := h.mpuPart(t, key, token, 1, first)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("part 1 attempt A returned %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	_ = etag1a

	// The same part again, with different content -- a retry, as a client that
	// changed its mind or resumed from a different buffer would produce.
	etag1b, resp := h.mpuPart(t, key, token, 1, second)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("part 1 attempt B returned %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	etag2, resp := h.mpuPart(t, key, token, 2, tail)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("part 2 returned %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	complete := h.mpuComplete(t, key, token, []completeReqPart{
		{PartNumber: 1, ETag: etag1b},
		{PartNumber: 2, ETag: etag2},
	})
	if complete.StatusCode != http.StatusOK {
		t.Fatalf("completion returned %d: %s", complete.StatusCode, readBody(t, complete))
	}
	_ = complete.Body.Close()

	whole := append(append([]byte{}, second...), tail...)
	if got := h.getOK(t, key); got != string(whole) {
		t.Fatalf("the object does not read back as the second attempt (%d bytes)", len(got))
	}

	// The provider now replaces part 1's segment with the first attempt's. To
	// produce those bytes it re-encrypts the same plaintext under the object's
	// own data key with a *different* salt, which is exactly what the first
	// attempt was. Everything about it is authentic except which attempt it is.
	substituted := h.reencryptPart(t, key, 1, first)
	h.rewriteUpstream(t, key, func(stored []byte) []byte {
		if len(substituted) > len(stored) {
			t.Fatalf("the substituted part is longer than the object")
		}
		out := append([]byte{}, stored...)
		copy(out, substituted)
		return out
	})

	resp = h.do(t, http.MethodGet, key)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK && string(body) == string(append(append([]byte{}, first...), tail...)) {
		t.Fatal("the gateway served an earlier attempt at part 1 as though it were the object")
	}
	if resp.StatusCode == http.StatusOK && len(body) == len(whole) {
		t.Fatal("the gateway served a full object after a part was substituted")
	}
	_ = ctx
}

// reencryptPart produces the ciphertext of one part as this gateway would have
// written it, under the object's own data key and a fresh salt.
//
// It stands in for an earlier upload attempt: the gateway wrote one exactly
// like this, and the provider kept it.
func (h *harness) reencryptPart(t *testing.T, key string, partNumber uint32, plain []byte) []byte {
	t.Helper()
	ctx := context.Background()

	info, err := h.upstream.HeadObject(ctx, testBucket, key)
	if err != nil {
		t.Fatalf("HEAD upstream: %v", err)
	}
	meta, err := objectmeta.Parse(info.Metadata, stream.MinLog2ChunkSize)
	if err != nil {
		t.Fatalf("parsing metadata: %v", err)
	}
	aad, err := keys.ObjectAAD(meta.KeyID, testBucket, key)
	if err != nil {
		t.Fatalf("ObjectAAD: %v", err)
	}
	dek, err := h.keyring.Unwrap(ctx, meta.KeyID, meta.WrappedDEK, aad)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	defer clear(dek)

	var buf bytes.Buffer
	ew, err := stream.NewEncryptWriter(&buf, dek, stream.SegmentParams{
		Log2ChunkSize: meta.Log2ChunkSize, Multipart: true, Index: partNumber,
	})
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	if _, err := ew.Write(plain); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes()
}
