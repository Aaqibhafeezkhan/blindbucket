// Package s3api routes HTTP requests according to S3 semantics and renders
// S3-conformant XML errors.
//
// Routing cannot be expressed as ordinary path matching. S3 distinguishes
// operations by method, by query parameters (?uploads, ?partNumber=,
// ?list-type=2) and by headers (x-amz-copy-source) at least as much as by path,
// which is why this is a hand-written router rather than a mux.
package s3api

import (
	"net/http"
	"strings"
)

// Operation names an S3 operation.
type Operation string

// The operations this build recognises. Anything else is reported as
// unsupported rather than guessed at.
const (
	OpPutObject    Operation = "PutObject"
	OpGetObject    Operation = "GetObject"
	OpHeadObject   Operation = "HeadObject"
	OpDeleteObject Operation = "DeleteObject"
	OpUnsupported  Operation = "Unsupported"
)

// MaxKeyLength is S3's limit on object key length, in bytes.
const MaxKeyLength = 1024

// ReservedPrefix is where blindbucket keeps its own objects inside a user
// bucket. Client access to it is refused: from M4 it holds the multipart
// manifests, and a client that could delete one would make an object
// unreadable.
const ReservedPrefix = ".blindbucket/"

// Request is a classified S3 request.
type Request struct {
	Op     Operation
	Bucket string
	Key    string
}

// Route classifies an inbound request, or explains why it cannot be served.
//
// Only path-style addressing is handled; virtual-hosted style arrives with M3.
func Route(r *http.Request) (Request, *Error) {
	bucket, key := splitPath(r.URL.Path)

	switch {
	case bucket == "":
		// A request against the service root: ListBuckets and friends.
		return Request{Op: OpUnsupported}, ErrNotImplemented.WithMessage(
			"service-level operations are not implemented in this build")
	case key == "":
		return Request{Op: OpUnsupported, Bucket: bucket}, ErrNotImplemented.WithMessage(
			"bucket-level operations are not implemented in this build")
	}

	if len(key) > MaxKeyLength {
		return Request{}, ErrInvalidArgument.WithMessage(
			"object key is %d bytes, the maximum is %d", len(key), MaxKeyLength)
	}
	if strings.HasPrefix(key, ReservedPrefix) {
		return Request{}, ErrAccessDenied.WithMessage(
			"the %s prefix is reserved by the gateway", ReservedPrefix)
	}

	// A query parameter on an object request always selects a sub-resource --
	// ?acl, ?tagging, ?uploads, ?partNumber, a presigned URL's X-Amz-* set. None
	// of those are implemented here, and treating one as a plain object request
	// would be worse than refusing it: ?uploads answered as a PUT would send
	// plaintext to the provider.
	if len(r.URL.Query()) > 0 {
		return Request{Bucket: bucket, Key: key, Op: OpUnsupported},
			ErrNotImplemented.WithMessage("the sub-resource %q is not implemented in this build",
				firstQueryKey(r.URL.RawQuery))
	}

	op := objectOperation(r.Method)
	if op == OpUnsupported {
		return Request{Bucket: bucket, Key: key, Op: op},
			ErrNotImplemented.WithMessage("method %s is not implemented for objects", r.Method)
	}
	return Request{Op: op, Bucket: bucket, Key: key}, nil
}

func objectOperation(method string) Operation {
	switch method {
	case http.MethodPut:
		return OpPutObject
	case http.MethodGet:
		return OpGetObject
	case http.MethodHead:
		return OpHeadObject
	case http.MethodDelete:
		return OpDeleteObject
	default:
		return OpUnsupported
	}
}

// splitPath separates the bucket from the key in a path-style URL.
//
// The decoded path is used deliberately. S3 keys are flat strings in which '/'
// carries no special meaning, and a client that sends %2F means the same object
// as one that sends '/', so decoding first is what matches the real service.
func splitPath(path string) (bucket, key string) {
	trimmed := strings.TrimPrefix(path, "/")
	if trimmed == "" {
		return "", ""
	}
	bucket, key, _ = strings.Cut(trimmed, "/")
	return bucket, key
}

// firstQueryKey names the first query parameter, for an error message that says
// what was actually refused.
func firstQueryKey(rawQuery string) string {
	first, _, _ := strings.Cut(rawQuery, "&")
	name, _, _ := strings.Cut(first, "=")
	if name == "" {
		return rawQuery
	}
	return name
}
