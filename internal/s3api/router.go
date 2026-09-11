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
	"strconv"
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

	OpListObjectsV2 Operation = "ListObjectsV2"
	OpListObjects   Operation = "ListObjects"
	OpDeleteObjects Operation = "DeleteObjects"

	OpCreateMultipartUpload   Operation = "CreateMultipartUpload"
	OpUploadPart              Operation = "UploadPart"
	OpCompleteMultipartUpload Operation = "CompleteMultipartUpload"
	OpAbortMultipartUpload    Operation = "AbortMultipartUpload"
	OpListParts               Operation = "ListParts"
	OpListMultipartUploads    Operation = "ListMultipartUploads"

	OpListBuckets       Operation = "ListBuckets"
	OpHeadBucket        Operation = "HeadBucket"
	OpCreateBucket      Operation = "CreateBucket"
	OpDeleteBucket      Operation = "DeleteBucket"
	OpGetBucketLocation Operation = "GetBucketLocation"

	OpUnsupported Operation = "Unsupported"
)

// IsObject reports whether the operation addresses a single object.
func (o Operation) IsObject() bool {
	switch o {
	case OpPutObject, OpGetObject, OpHeadObject, OpDeleteObject,
		OpCreateMultipartUpload, OpUploadPart, OpCompleteMultipartUpload,
		OpAbortMultipartUpload, OpListParts:
		return true
	default:
		return false
	}
}

// IsMultipart reports whether the operation is part of a multipart upload.
func (o Operation) IsMultipart() bool {
	switch o {
	case OpCreateMultipartUpload, OpUploadPart, OpCompleteMultipartUpload,
		OpAbortMultipartUpload, OpListParts, OpListMultipartUploads:
		return true
	default:
		return false
	}
}

// MaxKeyLength is S3's limit on object key length, in bytes.
const MaxKeyLength = 1024

// ReservedPrefix is where blindbucket keeps its own objects inside a user
// bucket. Client access to it is refused: from M4 it holds the multipart
// manifests, and a client that could delete one would make an object
// unreadable.
const ReservedPrefix = ".blindbucket/"

// MaxPartNumber is S3's largest part number.
const MaxPartNumber = 10000

// Request is a classified S3 request.
type Request struct {
	Op     Operation
	Bucket string
	Key    string

	// UploadID is the opaque upload token a client presents on the multipart
	// operations. It is not the provider's own UploadId; see
	// docs/adr/ADR-006-upload-token.md.
	UploadID string
	// PartNumber is set for UploadPart, 1..MaxPartNumber.
	PartNumber int
}

// bucketQueryOps maps a bucket-level sub-resource to its operation. Only these
// are served; every other sub-resource is refused.
var bucketQueryOps = map[string]Operation{
	"location": OpGetBucketLocation,
	"delete":   OpDeleteObjects,
	"uploads":  OpListMultipartUploads,
}

// ignorableParams are query parameters that carry no meaning for the service.
//
// "x-id" is telemetry the AWS SDKs attach -- ?x-id=PutObject and friends --
// naming the operation the SDK believes it is performing. Real S3 ignores it,
// and rclone, which uses that SDK, sends it on every object request. Refusing it
// as an unknown sub-resource made every rclone upload fail with a 501, which is
// how this was found. It is still covered by the signature, because the
// canonical query string is built from the request as it arrived.
var ignorableParams = map[string]bool{
	"x-id": true,
}

// listingParams are the query parameters that shape a listing rather than
// selecting a different operation. They are forwarded to the provider
// unchanged, so pagination, prefixes and delimiters behave exactly as a client
// expects.
var listingParams = map[string]bool{
	"list-type":             true,
	"prefix":                true,
	"delimiter":             true,
	"max-keys":              true,
	"marker":                true,
	"continuation-token":    true,
	"start-after":           true,
	"encoding-type":         true,
	"fetch-owner":           true,
	"expected-bucket-owner": true,
}

// Route classifies an inbound request.
//
// baseDomain enables virtual-hosted-style addressing: with "s3.internal.example"
// configured, a request to bucket.s3.internal.example addresses that bucket.
// Leave it empty to accept path-style only.
func Route(r *http.Request, baseDomain string) (Request, *Error) {
	bucket, key := splitTarget(r, baseDomain)

	switch {
	case bucket == "":
		return routeService(r)
	case key == "":
		return routeBucket(r, bucket)
	default:
		return routeObject(r, bucket, key)
	}
}

// routeService handles requests against the endpoint root.
func routeService(r *http.Request) (Request, *Error) {
	if r.Method == http.MethodGet && len(r.URL.Query()) == 0 {
		return Request{Op: OpListBuckets}, nil
	}
	return Request{Op: OpUnsupported}, ErrNotImplemented.WithMessage(
		"service-level operation %s is not implemented in this build", r.Method)
}

// routeBucket handles requests against a bucket rather than an object.
func routeBucket(r *http.Request, bucket string) (Request, *Error) {
	query := r.URL.Query()
	req := Request{Bucket: bucket}

	// A query parameter is either a sub-resource selecting a different
	// operation, or one of the parameters that shape a listing. Anything else
	// names something this build does not implement, and answering it as a
	// listing would silently ignore what the client asked for.
	for name := range query {
		if op, known := bucketQueryOps[name]; known {
			switch {
			case op == OpGetBucketLocation && r.Method == http.MethodGet:
				req.Op = OpGetBucketLocation
				return req, nil
			case op == OpDeleteObjects && r.Method == http.MethodPost:
				req.Op = OpDeleteObjects
				return req, nil
			case op == OpListMultipartUploads && r.Method == http.MethodGet:
				req.Op = OpListMultipartUploads
				return req, nil
			}
			continue
		}
		if ignorableParams[strings.ToLower(name)] {
			continue
		}
		if !listingParams[name] {
			return Request{Bucket: bucket, Op: OpUnsupported}, ErrNotImplemented.WithMessage(
				"the bucket sub-resource %q is not implemented in this build", name)
		}
	}

	switch r.Method {
	case http.MethodGet:
		// list-type=2 selects ListObjectsV2; its absence means the older call,
		// which rclone and some backup tools still use.
		if query.Get("list-type") == "2" {
			req.Op = OpListObjectsV2
		} else {
			req.Op = OpListObjects
		}
		return req, nil
	case http.MethodHead:
		req.Op = OpHeadBucket
		return req, nil
	case http.MethodPut:
		req.Op = OpCreateBucket
		return req, nil
	case http.MethodDelete:
		req.Op = OpDeleteBucket
		return req, nil
	}
	return Request{Bucket: bucket, Op: OpUnsupported}, ErrNotImplemented.WithMessage(
		"method %s is not implemented for buckets", r.Method)
}

// objectQueryParams are the query parameters an object request may carry. A
// parameter outside this set names a sub-resource this build does not implement,
// and guessing at it would be worse than refusing: ?acl answered as a PUT would
// send plaintext to the provider.
var objectQueryParams = map[string]bool{
	"uploads":            true,
	"uploadId":           true,
	"partNumber":         true,
	"max-parts":          true,
	"part-number-marker": true,
}

// routeObject handles requests against a single object.
func routeObject(r *http.Request, bucket, key string) (Request, *Error) {
	if len(key) > MaxKeyLength {
		return Request{}, ErrInvalidArgument.WithMessage(
			"object key is %d bytes, the maximum is %d", len(key), MaxKeyLength)
	}
	if strings.HasPrefix(key, ReservedPrefix) {
		return Request{}, ErrAccessDenied.WithMessage(
			"the %s prefix is reserved by the gateway", ReservedPrefix)
	}

	query := r.URL.Query()
	for name := range query {
		if ignorableParams[strings.ToLower(name)] || objectQueryParams[name] {
			continue
		}
		return Request{Bucket: bucket, Key: key, Op: OpUnsupported},
			ErrNotImplemented.WithMessage("the sub-resource %q is not implemented in this build", name)
	}

	// Presence of the parameter decides, not its value. An empty ?uploadId= must
	// not fall through to the plain-object path: a PUT carrying ?partNumber=1 and
	// an empty upload id would then be served as PutObject, storing one part's
	// bytes as the whole object.
	_, initiating := query["uploads"]
	_, hasUploadID := query["uploadId"]
	_, hasPartNumber := query["partNumber"]
	if initiating || hasUploadID || hasPartNumber {
		return routeMultipart(r, bucket, key, initiating, query.Get("uploadId"))
	}

	op := objectOperation(r.Method)
	if op == OpUnsupported {
		return Request{Bucket: bucket, Key: key, Op: op},
			ErrNotImplemented.WithMessage("method %s is not implemented for objects", r.Method)
	}
	return Request{Op: op, Bucket: bucket, Key: key}, nil
}

// routeMultipart classifies the five object-level multipart operations.
//
// They are told apart by method and by which of ?uploads and ?uploadId is
// present, which is the only thing that distinguishes, for instance, a
// CompleteMultipartUpload from a DeleteObjects -- both are POSTs.
func routeMultipart(r *http.Request, bucket, key string, initiating bool, uploadID string) (Request, *Error) {
	req := Request{Bucket: bucket, Key: key, UploadID: uploadID}

	if initiating {
		if uploadID != "" {
			return unsupported(req), ErrInvalidRequest.WithMessage(
				"a request cannot carry both ?uploads and ?uploadId")
		}
		if r.Method != http.MethodPost {
			return unsupported(req), ErrNotImplemented.WithMessage(
				"method %s is not implemented for ?uploads on an object", r.Method)
		}
		req.Op = OpCreateMultipartUpload
		return req, nil
	}

	// Every operation below acts on an existing upload, so it needs a usable id.
	if uploadID == "" {
		return unsupported(req), ErrInvalidArgument.WithMessage("the request names no upload id")
	}

	switch r.Method {
	case http.MethodPut:
		number, apiErr := partNumber(r.URL.Query().Get("partNumber"))
		if apiErr != nil {
			return unsupported(req), apiErr
		}
		// UploadPartCopy: a part whose bytes come from another object rather
		// than from the request body. It needs a range-preserving copy path and
		// lands with CopyObject in M5.
		if r.Header.Get("X-Amz-Copy-Source") != "" {
			return unsupported(req), ErrNotImplemented.WithMessage(
				"UploadPartCopy is not implemented in this build")
		}
		req.Op, req.PartNumber = OpUploadPart, number
		return req, nil

	case http.MethodPost:
		req.Op = OpCompleteMultipartUpload
		return req, nil

	case http.MethodDelete:
		req.Op = OpAbortMultipartUpload
		return req, nil

	case http.MethodGet, http.MethodHead:
		req.Op = OpListParts
		return req, nil
	}
	return unsupported(req), ErrNotImplemented.WithMessage(
		"method %s is not implemented for multipart uploads", r.Method)
}

// partNumber parses and bounds the ?partNumber parameter.
func partNumber(raw string) (int, *Error) {
	if raw == "" {
		return 0, ErrInvalidArgument.WithMessage("a part upload must name a part number")
	}
	number, err := strconv.Atoi(raw)
	if err != nil || number < 1 || number > MaxPartNumber {
		return 0, ErrInvalidArgument.WithMessage(
			"part number %q is not an integer in 1..%d", raw, MaxPartNumber)
	}
	return number, nil
}

func unsupported(req Request) Request {
	req.Op = OpUnsupported
	return req
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

// splitTarget determines the bucket and key a request addresses, handling both
// addressing styles.
func splitTarget(r *http.Request, baseDomain string) (bucket, key string) {
	if b, ok := virtualHostBucket(r.Host, baseDomain); ok {
		return b, strings.TrimPrefix(r.URL.Path, "/")
	}
	return splitPath(r.URL.Path)
}

// virtualHostBucket extracts the bucket from a virtual-hosted-style authority.
func virtualHostBucket(host, baseDomain string) (string, bool) {
	if baseDomain == "" || host == "" {
		return "", false
	}
	// The authority may carry a port; the bucket never does.
	if idx := strings.LastIndex(host, ":"); idx > 0 && !strings.Contains(host[idx:], "]") {
		host = host[:idx]
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	base := strings.TrimSuffix(strings.ToLower(baseDomain), ".")

	prefix, ok := strings.CutSuffix(host, "."+base)
	if !ok || prefix == "" {
		return "", false
	}
	// A dotted prefix would be a sub-domain of the bucket, not a bucket name.
	if strings.Contains(prefix, ".") {
		return "", false
	}
	return prefix, true
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
