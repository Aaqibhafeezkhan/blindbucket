package proxy

import "github.com/LennardGeissler/blindbucket/internal/s3api"

// Coordination points, named after the actions of spec/tla/Multipart.tla.
//
// The model's counterexamples are interleavings of these, and the integration
// tests reproduce them by holding one request at a point until another request
// has passed its own. Keeping the names identical to the model's is what makes a
// trace and a test comparable line by line.
const (
	hookUpHead     = "upHead"     // after HEAD, the observation R3 licenses
	hookUpManifest = "upManifest" // after the manifest is written (R2)
	hookUpComplete = "upComplete" // after the object becomes visible
	hookUpCleanup  = "upCleanup"  // after the observed manifest is deleted (R3)

	hookDelHead     = "delHead"
	hookDelRemove   = "delRemove"
	hookDelManifest = "delManifest"
)

// at runs the coordination hook, if one is installed.
//
// It is a no-op in every build: nothing sets the field outside this package's
// tests, so the cost is one nil check on paths that already make several network
// round trips.
func (p *Proxy) at(point string, req s3api.Request) {
	if p.hook != nil {
		p.hook(point, req)
	}
}
