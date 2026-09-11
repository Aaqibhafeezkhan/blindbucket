// Package upstream is a small signing S3 client built on net/http.
//
// A full SDK client is deliberately avoided: its middleware buffers or re-reads
// bodies, injects its own checksums and obscures what actually goes over the wire,
// all of which conflicts with a streaming proxy. See docs/adr/ (ADR-003).
package upstream
