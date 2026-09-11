package s3api

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func request(t *testing.T, method, target string) *http.Request {
	t.Helper()
	return httptest.NewRequest(method, target, nil)
}

func TestRouteObjectOperations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method string
		target string
		want   Operation
		bucket string
		key    string
	}{
		{http.MethodPut, "/bucket/key", OpPutObject, "bucket", "key"},
		{http.MethodGet, "/bucket/key", OpGetObject, "bucket", "key"},
		{http.MethodHead, "/bucket/key", OpHeadObject, "bucket", "key"},
		{http.MethodDelete, "/bucket/key", OpDeleteObject, "bucket", "key"},
		{http.MethodGet, "/bucket/deep/nested/key.txt", OpGetObject, "bucket", "deep/nested/key.txt"},
		// A percent-encoded slash names the same object as a literal one, which
		// is what S3 itself does: a key is a flat string.
		{http.MethodGet, "/bucket/a%2Fb", OpGetObject, "bucket", "a/b"},
		{http.MethodGet, "/bucket/with%20space", OpGetObject, "bucket", "with space"},
	}

	for _, tc := range tests {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			t.Parallel()
			got, err := Route(request(t, tc.method, tc.target), "")
			if err != nil {
				t.Fatalf("Route returned %v", err)
			}
			if got.Op != tc.want || got.Bucket != tc.bucket || got.Key != tc.key {
				t.Errorf("got %+v, want {%s %s %s}", got, tc.want, tc.bucket, tc.key)
			}
		})
	}
}

// TestRouteRefusesSubResources is the safety property: a sub-resource must never
// be mistaken for a plain object request. Answering ?uploads as a PUT would send
// plaintext to the provider.
func TestRouteRefusesSubResources(t *testing.T) {
	t.Parallel()

	targets := []string{
		"/bucket/key?uploads",
		"/bucket/key?partNumber=1&uploadId=abc",
		"/bucket/key?acl",
		"/bucket/key?tagging",
		"/bucket/key?versionId=null",
		"/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=deadbeef",
		"/bucket/key?attributes",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			_, err := Route(request(t, http.MethodPut, target), "")
			if err == nil {
				t.Fatal("a sub-resource was routed as a plain object request")
			}
			if err.Code != "NotImplemented" {
				t.Errorf("code = %q, want NotImplemented", err.Code)
			}
		})
	}
}

func TestRouteRefusesReservedPrefix(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodHead} {
		_, err := Route(request(t, method, "/bucket/.blindbucket/m/abc/def"), "")
		if err == nil || err.Code != "AccessDenied" {
			t.Errorf("%s on the reserved prefix returned %v, want AccessDenied", method, err)
		}
	}
	// A key that merely starts with a dot is fine.
	if _, err := Route(request(t, http.MethodGet, "/bucket/.hidden"), ""); err != nil {
		t.Errorf("a key starting with a dot was refused: %v", err)
	}
}

func TestRouteBucketAndServiceLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method string
		target string
		want   Operation
		bucket string
	}{
		{http.MethodGet, "/", OpListBuckets, ""},
		{http.MethodGet, "/bucket", OpListObjects, "bucket"},
		{http.MethodGet, "/bucket/", OpListObjects, "bucket"},
		{http.MethodGet, "/bucket?list-type=2", OpListObjectsV2, "bucket"},
		{http.MethodGet, "/bucket?list-type=2&prefix=a/&delimiter=%2F", OpListObjectsV2, "bucket"},
		{http.MethodHead, "/bucket", OpHeadBucket, "bucket"},
		{http.MethodPut, "/bucket", OpCreateBucket, "bucket"},
		{http.MethodDelete, "/bucket", OpDeleteBucket, "bucket"},
		{http.MethodGet, "/bucket?location", OpGetBucketLocation, "bucket"},
		{http.MethodPost, "/bucket?delete", OpDeleteObjects, "bucket"},
	}

	for _, tc := range tests {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			t.Parallel()
			got, err := Route(request(t, tc.method, tc.target), "")
			if err != nil {
				t.Fatalf("Route returned %v", err)
			}
			if got.Op != tc.want || got.Bucket != tc.bucket {
				t.Errorf("got {%s %s}, want {%s %s}", got.Op, got.Bucket, tc.want, tc.bucket)
			}
		})
	}
}

// TestRouteRefusesBucketSubResources keeps ?acl, ?policy and friends from being
// served as a listing, which would answer a question nobody asked.
func TestRouteRefusesBucketSubResources(t *testing.T) {
	t.Parallel()

	for _, target := range []string{
		"/bucket?acl", "/bucket?policy", "/bucket?versioning", "/bucket?uploads",
		"/bucket?lifecycle", "/bucket?tagging",
	} {
		_, err := Route(request(t, http.MethodGet, target), "")
		if err == nil || err.Code != "NotImplemented" {
			t.Errorf("%q returned %v, want NotImplemented", target, err)
		}
	}
}

// TestRouteVirtualHostedStyle covers the addressing form AWS now prefers, where
// the bucket is a subdomain rather than the first path segment.
func TestRouteVirtualHostedStyle(t *testing.T) {
	t.Parallel()

	const base = "s3.internal.example"

	tests := []struct {
		host   string
		target string
		bucket string
		key    string
		op     Operation
	}{
		{"backups." + base, "/db.dump", "backups", "db.dump", OpGetObject},
		{"backups." + base + ":9000", "/db.dump", "backups", "db.dump", OpGetObject},
		{"BACKUPS." + base, "/db.dump", "backups", "db.dump", OpGetObject},
		{"backups." + base, "/deep/nested/key", "backups", "deep/nested/key", OpGetObject},
		{"backups." + base, "/", "backups", "", OpListObjects},
		// Not the base domain: falls back to path style.
		{"other.example", "/bucket/key", "bucket", "key", OpGetObject},
		// The base domain itself addresses the service, not a bucket.
		{base, "/bucket/key", "bucket", "key", OpGetObject},
	}

	for _, tc := range tests {
		t.Run(tc.host+tc.target, func(t *testing.T) {
			t.Parallel()
			r := request(t, http.MethodGet, tc.target)
			r.Host = tc.host

			got, err := Route(r, base)
			if err != nil {
				t.Fatalf("Route returned %v", err)
			}
			if got.Bucket != tc.bucket || got.Key != tc.key || got.Op != tc.op {
				t.Errorf("got {%s %q %q}, want {%s %q %q}",
					got.Op, got.Bucket, got.Key, tc.op, tc.bucket, tc.key)
			}
		})
	}

	// Without base_domain configured, a virtual-hosted request is parsed as
	// path style -- the proxy has no way to know the authority carried a bucket.
	// Operators who serve vhost-style clients must configure base_domain, and
	// this test records what happens if they do not.
	t.Run("falls back to path style without a base domain", func(t *testing.T) {
		t.Parallel()
		r := request(t, http.MethodGet, "/key")
		r.Host = "backups." + base
		got, err := Route(r, "")
		if err != nil {
			t.Fatalf("Route returned %v", err)
		}
		if got.Bucket != "key" || got.Op != OpListObjects {
			t.Errorf("got {%s %q}, want the path-style reading {%s %q}",
				got.Op, got.Bucket, OpListObjects, "key")
		}
	})

	t.Run("a dotted prefix is not a bucket", func(t *testing.T) {
		t.Parallel()
		r := request(t, http.MethodGet, "/bucket/key")
		r.Host = "a.b." + base
		got, err := Route(r, base)
		if err != nil {
			t.Fatalf("Route returned %v", err)
		}
		if got.Bucket != "bucket" {
			t.Errorf("bucket = %q, want the path-style fallback", got.Bucket)
		}
	})
}

func TestRouteRejectsOverlongKey(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("a", MaxKeyLength+1)
	_, err := Route(request(t, http.MethodPut, "/bucket/"+long), "")
	if err == nil || err.Code != "InvalidArgument" {
		t.Errorf("an overlong key returned %v, want InvalidArgument", err)
	}

	ok := strings.Repeat("a", MaxKeyLength)
	if _, err := Route(request(t, http.MethodPut, "/bucket/"+ok), ""); err != nil {
		t.Errorf("a key at the limit was refused: %v", err)
	}
}

func TestRouteRejectsUnsupportedMethods(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodOptions} {
		_, err := Route(request(t, method, "/bucket/key"), "")
		if err == nil || err.Code != "NotImplemented" {
			t.Errorf("%s returned %v, want NotImplemented", method, err)
		}
	}
}

func TestWriteErrorRendersS3XML(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	r := request(t, http.MethodGet, "/bucket/missing")
	WriteError(rec, r, ErrNoSuchKey, "req-123")

	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/xml" {
		t.Errorf("Content-Type = %q, want application/xml", ct)
	}
	if id := resp.Header.Get("x-amz-request-id"); id != "req-123" {
		t.Errorf("x-amz-request-id = %q, want req-123", id)
	}

	var parsed struct {
		XMLName   xml.Name `xml:"Error"`
		Code      string   `xml:"Code"`
		Message   string   `xml:"Message"`
		Resource  string   `xml:"Resource"`
		RequestID string   `xml:"RequestId"`
	}
	if err := xml.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("the error body is not valid XML: %v", err)
	}
	if parsed.Code != "NoSuchKey" {
		t.Errorf("Code = %q, want NoSuchKey", parsed.Code)
	}
	if parsed.Resource != "/bucket/missing" {
		t.Errorf("Resource = %q, want the request path", parsed.Resource)
	}
	if parsed.RequestID != "req-123" {
		t.Errorf("RequestId = %q, want req-123", parsed.RequestID)
	}
}

// TestWriteErrorOmitsBodyForHead keeps the response legal: a HEAD response must
// not carry a body, however useful the explanation would be.
func TestWriteErrorOmitsBodyForHead(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	WriteError(rec, request(t, http.MethodHead, "/bucket/missing"), ErrNoSuchKey, "req-1")
	if rec.Body.Len() != 0 {
		t.Errorf("HEAD error carried a %d-byte body", rec.Body.Len())
	}
}

func TestErrorWithMessageKeepsCodeAndStatus(t *testing.T) {
	t.Parallel()

	derived := ErrNotImplemented.WithMessage("the sub-resource %q is not implemented", "acl")
	switch {
	case derived.Code != ErrNotImplemented.Code:
		t.Errorf("code changed to %q", derived.Code)
	case derived.HTTPStatus != ErrNotImplemented.HTTPStatus:
		t.Errorf("status changed to %d", derived.HTTPStatus)
	case !strings.Contains(derived.Message, `"acl"`):
		t.Errorf("message = %q, want it to name the sub-resource", derived.Message)
	case ErrNotImplemented.Message == derived.Message:
		t.Error("WithMessage mutated the shared error value")
	}
}
