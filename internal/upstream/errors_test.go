package upstream

import (
	"net/http"
	"testing"
)

// A HEAD carries no body, so the status-to-code mapping is the only thing a
// caller has to go on. Answering NoSuchKey for a missing bucket sends a client
// -- or a readiness probe -- looking for the wrong thing, which is how this was
// found.
func TestStatusCodeDistinguishesBucketsFromKeys(t *testing.T) {
	cases := []struct {
		status int
		op     string
		want   string
	}{
		{http.StatusNotFound, "HeadObject", "NoSuchKey"},
		{http.StatusNotFound, "GetObject", "NoSuchKey"},
		{http.StatusNotFound, "Passthrough", "NoSuchBucket"},
		{http.StatusNotFound, "ListObjects", "NoSuchBucket"},
		{http.StatusNotFound, "DeleteObjects", "NoSuchBucket"},
		{http.StatusForbidden, "Passthrough", "AccessDenied"},
		{http.StatusPreconditionFailed, "CompleteMultipartUpload", "PreconditionFailed"},
	}
	for _, tc := range cases {
		if got := statusCode(tc.status, tc.op); got != tc.want {
			t.Errorf("statusCode(%d, %q) = %q, want %q", tc.status, tc.op, got, tc.want)
		}
	}
}
