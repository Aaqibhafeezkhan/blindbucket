package proxy

import (
	"bytes"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/gc"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
)

// These are the counterexamples from spec/tla/Multipart.tla, replayed against a
// real provider. Each one is an interleaving TLC produced for a *broken* set of
// rules; the point of the test is that the rules as implemented survive it.
//
// spec/tla/README.md writes each trace out step by step, and the hook names in
// hooks.go are the model's action names, so a test below can be read next to the
// trace it comes from.

// gate holds a request at a coordination point until the test lets it through.
type gate struct {
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

func newGate() *gate {
	return &gate{reached: make(chan struct{}), release: make(chan struct{})}
}

// wait is called from the hook, inside the request being held.
func (g *gate) wait() {
	g.once.Do(func() { close(g.reached) })
	<-g.release
}

// await blocks the test until the request has reached the point.
func (g *gate) await(t *testing.T, what string) {
	t.Helper()
	select {
	case <-g.reached:
	case <-time.After(30 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// open lets the held request continue.
func (g *gate) open() { close(g.release) }

// holdAt installs a hook that holds the named point of the request carrying
// uploadID. Points for other requests pass straight through.
func (h *harness) holdAt(t *testing.T, gates map[string]*gate) {
	t.Helper()
	h.gateway.hook = func(point string, req s3api.Request) {
		if g, ok := gates[point+"|"+req.UploadID]; ok {
			g.wait()
		}
	}
	t.Cleanup(func() { h.gateway.hook = nil })
}

// mustRead fetches an object and returns its plaintext, failing on any error.
func (h *harness) mustRead(t *testing.T, key, what string) []byte {
	t.Helper()
	resp := h.do(t, http.MethodGet, key)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: GET returned %d: %s", what, resp.StatusCode, readBody(t, resp))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s: reading the body: %v", what, err)
	}
	return body
}

// Scenario 1 of spec/tla/README.md, the second race ADR-010 records.
//
// Version 0.1 had a completion delete "the other manifests of this key". TLC
// reaches an unreadable object in eleven states: u1 completes, u2 writes its
// manifest, u1's cleanup runs late and takes u2's manifest with it, u2
// completes. Rule R3 replaces that with "only the id observed before my own
// replacement", which is what this test holds u1 open to exercise.
func TestIntegrationRaceCleanupAgainstConcurrentUpload(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "contested.bin")

	// A single-part object is visible first, exactly as in the trace, so that
	// u1's HEAD observes no manifest at all.
	h.store(t, key, randomBytes(t, 4096))

	tokenA := h.mpuStart(t, key, nil)
	tokenB := h.mpuStart(t, key, nil)
	partA := randomBytes(t, testPart)
	partB := randomBytes(t, testPart)
	etagA := h.uploadOnePart(t, key, tokenA, partA)
	etagB := h.uploadOnePart(t, key, tokenB, partB)

	// u1 is held after its completion, before its cleanup. u2 is held after it
	// has written its manifest.
	holdA := newGate()
	holdB := newGate()
	h.holdAt(t, map[string]*gate{
		hookUpComplete + "|" + tokenA: holdA,
		hookUpManifest + "|" + tokenB: holdB,
	})

	doneA := h.completeAsync(t, key, tokenA, etagA)
	holdA.await(t, "u1 to finish completing")

	doneB := h.completeAsync(t, key, tokenB, etagB)
	holdB.await(t, "u2 to write its manifest")

	// Now u1 runs its cleanup while u2's manifest is already on the provider.
	// Under the version 0.1 rule this is where u2's manifest disappeared.
	holdA.open()
	if status := <-doneA; status != http.StatusOK {
		t.Fatalf("u1 completion returned %d", status)
	}

	holdB.open()
	if status := <-doneB; status != http.StatusOK {
		t.Fatalf("u2 completion returned %d", status)
	}

	// The object is whichever upload completed last, and it must be readable.
	got := h.mustRead(t, key, "after the interleaved cleanup")
	if !bytes.Equal(got, partB) {
		t.Errorf("the visible object is not u2's: got %d bytes, want %d", len(got), len(partB))
	}
}

// Scenario 2 of spec/tla/README.md, the first race ADR-010 records.
//
// Version 0.1's gc listed the manifests, read the current id and deleted the
// rest, with no regard for uploads in flight. TLC's trace: an upload writes its
// manifest, gc sees it is not the current one and removes it, the upload then
// completes and the object is unreadable. R4 step 2 closes it by skipping any
// key with an open upload.
func TestIntegrationRaceGcAgainstUploadInFlight(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "gc-vs-upload.bin")

	h.store(t, key, randomBytes(t, 4096)) // a single-part object is visible

	token := h.mpuStart(t, key, nil)
	part := randomBytes(t, testPart)
	etag := h.uploadOnePart(t, key, token, part)

	// Hold the upload after its manifest is written and before it completes --
	// the exact window the old gc reached into.
	hold := newGate()
	h.holdAt(t, map[string]*gate{hookUpManifest + "|" + token: hold})

	done := h.completeAsync(t, key, token, etag)
	hold.await(t, "the upload to write its manifest")

	// The age guard is off on purpose: it would hide the ordering rule, and the
	// ordering rule is what is under test.
	result, err := gc.Run(t.Context(), gc.Config{
		Upstream: h.upstream, Bucket: testBucket, Prefix: key,
		DisableMinAge: true, Log: discardLogger(),
	})
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if result.Deleted != 0 {
		t.Errorf("gc deleted %d manifests while an upload was in flight", result.Deleted)
	}
	if result.KeysSkipped == 0 {
		t.Error("gc did not report the key as skipped; the open-upload check did not fire")
	}

	hold.open()
	if status := <-done; status != http.StatusOK {
		t.Fatalf("completion returned %d", status)
	}

	got := h.mustRead(t, key, "after a gc pass during the upload")
	if sha256.Sum256(got) != sha256.Sum256(part) {
		t.Error("the object survived gc but its contents changed")
	}
}

// Scenario 3 of spec/tla/README.md: the result that paid for the milestone.
//
// R4 fixes an order for two steps that both only read -- list the manifests,
// then ask for open uploads. Swapping them yields an unreadable object in twelve
// states, because a check that runs before the listing says nothing about
// manifests written after it. This test drives the exact interleaving: gc is
// held after its listing, an entire upload runs to completion inside that
// window, and the object must survive.
func TestIntegrationRaceGcOrderingIsLoadBearing(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "gc-ordering.bin")

	// An orphan from an earlier upload, so the pass has something real to do and
	// a clean run is distinguishable from a run that did nothing.
	h.mpuStore(t, key, [][]byte{randomBytes(t, testPart), randomBytes(t, 64)})
	staleManifest, _ := h.manifestKeyOf(t, key)
	h.store(t, key, randomBytes(t, 4096)) // a single-part PUT orphans it (10.8)

	hold := newGate()
	var once sync.Once
	cfg := gc.Config{
		Upstream: h.upstream, Bucket: testBucket, Prefix: key,
		DisableMinAge: true, Log: discardLogger(),
		Hook: func(point, _ string) {
			if point == gc.HookList {
				once.Do(hold.wait)
			}
		},
	}

	gcDone := make(chan *gc.Result, 1)
	gcErr := make(chan error, 1)
	go func() {
		result, err := gc.Run(t.Context(), cfg)
		gcDone <- result
		gcErr <- err
	}()
	hold.await(t, "gc to finish listing")

	// The whole upload happens inside the window between gc's listing and its
	// open-upload check. Its manifest is therefore written after the listing,
	// which is precisely what makes listing-first safe.
	fresh := randomBytes(t, testPart)
	h.mpuStore(t, key, [][]byte{fresh, randomBytes(t, 32)})

	hold.open()
	if err := <-gcErr; err != nil {
		t.Fatalf("gc: %v", err)
	}
	result := <-gcDone

	// The object written during the window must still be readable. This is the
	// assertion the swapped order fails.
	got := h.mustRead(t, key, "after gc ran across the upload")
	if !bytes.HasPrefix(got, fresh) {
		t.Fatal("the object written during the gc window is not the visible one")
	}

	// And gc must have done its actual job: the orphan from before the listing
	// is gone.
	if _, err := h.upstream.HeadObject(t.Context(), testBucket, staleManifest); err == nil {
		t.Error("gc left the stale manifest behind, so the pass proved nothing")
	}
	if result.Deleted == 0 {
		t.Error("gc deleted nothing at all")
	}
}

// The M4 definition of done: two uploads racing on one key with a gc pass
// running alongside must leave a readable object.
func TestIntegrationRaceParallelUploadsWithGc(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "parallel.bin")

	payloads := [][]byte{randomBytes(t, testPart), randomBytes(t, testPart)}
	var wg sync.WaitGroup
	for _, payload := range payloads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token := h.mpuStart(t, key, nil)
			etag := h.uploadOnePart(t, key, token, payload)
			resp := h.mpuComplete(t, key, token, []completeReqPart{{PartNumber: 1, ETag: etag}})
			_ = resp.Body.Close()
		}()
	}

	// A gc pass with no age guard at all, running against both uploads.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 3 {
			_, _ = gc.Run(t.Context(), gc.Config{
				Upstream: h.upstream, Bucket: testBucket, Prefix: key,
				DisableMinAge: true, Log: discardLogger(),
			})
		}
	}()
	wg.Wait()

	got := h.mustRead(t, key, "after two parallel uploads and a concurrent gc")
	if !bytes.Equal(got, payloads[0]) && !bytes.Equal(got, payloads[1]) {
		t.Fatalf("the object is neither upload's payload (%d bytes)", len(got))
	}
}

// Deleting a multipart object removes its manifest too, and only that one: the
// Del process of the model. A second object on another key must be untouched.
func TestIntegrationDeleteRemovesOnlyItsOwnManifest(t *testing.T) {
	h := newHarness(t)
	victim := testKey(t, "deleted.bin")
	bystander := testKey(t, "bystander.bin")

	h.mpuStore(t, victim, [][]byte{randomBytes(t, testPart), randomBytes(t, 10)})
	h.mpuStore(t, bystander, [][]byte{randomBytes(t, testPart), randomBytes(t, 10)})

	victimManifest, _ := h.manifestKeyOf(t, victim)
	bystanderManifest, _ := h.manifestKeyOf(t, bystander)

	resp := h.do(t, http.MethodDelete, victim)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE returned %d", resp.StatusCode)
	}

	if _, err := h.upstream.HeadObject(t.Context(), testBucket, victimManifest); err == nil {
		t.Error("the deleted object's manifest is still there")
	}
	if _, err := h.upstream.HeadObject(t.Context(), testBucket, bystanderManifest); err != nil {
		t.Errorf("the bystander's manifest was removed too: %v", err)
	}
	h.mustRead(t, bystander, "after a delete on another key")
}

// uploadOnePart uploads a single part and returns its ETag.
func (h *harness) uploadOnePart(t *testing.T, key, token string, body []byte) string {
	t.Helper()
	etag, resp := h.mpuPart(t, key, token, 1, body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("part upload returned %d: %s", resp.StatusCode, readBody(t, resp))
	}
	return etag
}

// completeAsync starts a completion and reports its status when it returns.
func (h *harness) completeAsync(t *testing.T, key, token, etag string) <-chan int {
	t.Helper()
	out := make(chan int, 1)
	go func() {
		resp := h.mpuComplete(t, key, token, []completeReqPart{{PartNumber: 1, ETag: etag}})
		_ = resp.Body.Close()
		out <- resp.StatusCode
	}()
	return out
}

// discardLogger keeps gc's own logging out of the test output; these tests
// deliberately provoke the situations it warns about.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
