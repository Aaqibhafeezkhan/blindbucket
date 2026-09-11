package gc

import (
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/manifest"
)

// splitManifestKey is the only place gc interprets an object key it found in a
// listing, so it has to reject anything that is not exactly a manifest path.
func TestSplitManifestKey(t *testing.T) {
	id, err := manifest.NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	good := id.ObjectKey("photos/2026/holiday.tar")

	hash, parsed, ok := splitManifestKey(good)
	if !ok {
		t.Fatalf("a real manifest path was rejected: %q", good)
	}
	if parsed != id {
		t.Errorf("id = %x, want %x", parsed, id)
	}
	if len(hash) != 64 {
		t.Errorf("hash is %d characters, want 64", len(hash))
	}

	bad := []string{
		"",
		"photos/holiday.tar",           // an ordinary object
		".blindbucket/m/",              // the prefix alone
		".blindbucket/m/" + hash,       // no id
		".blindbucket/m/" + hash + "/", // empty id
		".blindbucket/m/short/" + id.String(),
		".blindbucket/m/" + hash + "/" + id.String() + "/extra",
		".blindbucket/m/" + hash + "/not-an-id",
		".blindbucket/other/" + hash + "/" + id.String(),
	}
	for _, key := range bad {
		if _, _, ok := splitManifestKey(key); ok {
			t.Errorf("accepted %q as a manifest path", key)
		}
	}
}

// gc reads the object key out of a manifest it cannot authenticate, because it
// has no data key. What makes that safe is the location check: a key that does
// not hash back to the directory the manifest sits in is a forgery.
func TestLocationCheckRejectsAMisplacedManifest(t *testing.T) {
	id, err := manifest.NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	victim := "important/data.tar"
	attacker := "attacker/decoy.tar"

	if !manifest.MatchesLocation(victim, id.ObjectKey(victim)) {
		t.Error("a manifest in its own directory failed the location check")
	}
	// A manifest stored under the attacker's hash but naming the victim's key:
	// this is what would make gc act on the wrong object.
	if manifest.MatchesLocation(victim, id.ObjectKey(attacker)) {
		t.Error("a manifest naming another object passed the location check")
	}
}
