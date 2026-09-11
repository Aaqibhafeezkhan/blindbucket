// Package stream implements the blindbucket segment format: authenticated,
// streaming encryption and decryption at constant memory, plus the size arithmetic
// and range mapping derived from it.
//
// It is the security-critical core of the project and has no dependency on HTTP or
// S3; docs/FORMAT.md is its normative specification.
package stream
