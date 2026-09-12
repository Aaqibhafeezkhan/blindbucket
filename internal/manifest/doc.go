// Package manifest builds and verifies the authenticated part list of a
// multipart object.
//
// The lifecycle of a manifest — when it is written, and which one a request is
// allowed to delete — is not a local decision. It is fixed by rules R1 to R4 in
// docs/adr/ADR-010-manifest-lifecycle-under-concurrency.md, and they are
// model-checked in spec/tla/Multipart.tla.
//
// Two of those rules are about ordering upstream calls that, read one at a
// time, look independent of each other. Completion writes the manifest before
// CompleteMultipartUpload and deletes only the manifest id it read beforehand;
// gc lists the manifests before it asks for open uploads, not after. The model
// produces an unreadable object for either order swapped. So functions on the
// completion, delete, rotation and gc paths name the model action they
// implement, and changing an order means changing the model and rerunning TLC.
package manifest
