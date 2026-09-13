package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/audit"
	"github.com/LennardGeissler/blindbucket/internal/auth"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// These need no provider. The fail-closed gate answers before anything upstream
// is touched, which is exactly the property being tested: a gateway that cannot
// record must not reach the storage it would have recorded.

func auditTestProxy(t *testing.T, writer *audit.Writer, failClosed bool) *Proxy {
	t.Helper()
	client, err := upstream.New(upstream.Config{
		// Port 1: nothing listens there, so any request that gets past the gate
		// fails on the provider rather than succeeding by accident.
		Endpoint: "http://127.0.0.1:1", Region: "us-east-1", PathStyle: true,
		AccessKeyID: "unused", SecretAccessKey: "unused",
	})
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	ring := keys.NewKeyring()
	if err := ring.Generate("test-key"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	verifier, err := auth.NewVerifier(auth.Config{Clients: []auth.Client{{
		Name: "test", AccessKeyID: "AKIATEST", SecretAccessKey: "secret",
		Buckets: []string{"*"},
	}}})
	if err != nil {
		t.Fatalf("auth.NewVerifier: %v", err)
	}
	p, err := New(Config{
		Upstream: client, Keys: ring, Verifier: verifier,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Audit:           writer,
		AuditFailClosed: failClosed,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	return p
}

// auditTestWriter opens a log whose next rotation will fail.
//
// The break is produced rather than simulated: the log sits in a directory that
// is made unwritable, and rotation then cannot rename the file into it. That is
// a real permissions failure on the real code path, which a stub error injected
// into the writer would not be.
func auditTestWriter(t *testing.T) (*audit.Writer, func()) {
	t.Helper()
	secret := make([]byte, keys.AuditSecretSize)
	for i := range secret {
		secret[i] = byte(i)
	}
	key, err := keys.AuditKeyFromSecret(secret)
	if err != nil {
		t.Fatalf("AuditKeyFromSecret: %v", err)
	}
	signer, err := key.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	nameKey, err := key.NameKey()
	if err != nil {
		t.Fatalf("NameKey: %v", err)
	}

	dir := filepath.Join(t.TempDir(), "logs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	w, err := audit.Open(audit.Config{
		Path:               filepath.Join(dir, "audit.log"),
		Signer:             signer,
		NameKey:            nameKey,
		CheckpointInterval: -1,
		CheckpointEvery:    1,
		RotateBytes:        1, // rotate at the first checkpoint
	})
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o700)
		_ = w.Close()
	})

	breakIt := func() {
		t.Helper()
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		// One append is enough: it checkpoints, then tries to rotate.
		_ = w.Append(audit.Event{Op: "PutObject", Bucket: "b", Key: "k", Status: 200})
		if w.Err() == nil {
			t.Skip("the log did not break; the test user can write to a 0500 directory " +
				"(running as root?)")
		}
	}
	return w, breakIt
}

// TestFailClosedRefusesOnceTheLogIsBroken is the behaviour ADR-016 trades one
// unrecorded request for.
func TestFailClosedRefusesOnceTheLogIsBroken(t *testing.T) {
	writer, breakIt := auditTestWriter(t)
	p := auditTestProxy(t, writer, true)

	// A healthy log does not interfere: this request fails on the unreachable
	// provider, not on the gate, so it must not be a 503 from us.
	first := httptest.NewRecorder()
	p.ServeHTTP(first, auditRequest())
	if first.Code == http.StatusServiceUnavailable {
		t.Fatalf("a healthy audit log produced %d", first.Code)
	}

	breakIt()

	second := httptest.NewRecorder()
	p.ServeHTTP(second, auditRequest())
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("a broken audit log produced %d, want %d",
			second.Code, http.StatusServiceUnavailable)
	}
	if body := second.Body.String(); !strings.Contains(body, "ServiceUnavailable") {
		t.Errorf("the response does not name the code: %s", body)
	}
}

// TestFailOpenKeepsServing is the other half: the setting exists, and it does
// what its name says rather than being advice.
func TestFailOpenKeepsServing(t *testing.T) {
	writer, breakIt := auditTestWriter(t)
	p := auditTestProxy(t, writer, false)
	breakIt()

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, auditRequest())
	if rec.Code == http.StatusServiceUnavailable {
		t.Errorf("fail_closed is off, but the gateway refused with %d", rec.Code)
	}
}

func auditRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	req.Header.Set("Authorization",
		"AWS4-HMAC-SHA256 Credential=AKIATEST/20260913/us-east-1/s3/aws4_request, "+
			"SignedHeaders=host;x-amz-date, Signature=deadbeef")
	req.Header.Set("X-Amz-Date", "20260913T100000Z")
	return req
}

// TestAttemptedAccessKeyIDIsRecovered covers the one field on the rejected path:
// who tried, when there is no verified client to name.
func TestAttemptedAccessKeyIDIsRecovered(t *testing.T) {
	cases := []struct {
		name, header, want string
	}{
		{"a well-formed header", "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260913/" +
			"us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=" +
			strings.Repeat("a", 64), "AKIAEXAMPLE"},
		// The verifier rejects this one before it parses -- the signature is the
		// wrong length -- and the identity is still recorded. That is the case
		// this function exists for.
		{"a malformed header", "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260913/" +
			"us-east-1/s3/aws4_request, Signature=ab", "AKIAEXAMPLE"},
		{"no header", "", ""},
		{"nonsense", "Basic abcdef", ""},
		{"an empty credential", "AWS4-HMAC-SHA256 Credential=", ""},
		{"an id and nothing else", "AWS4-HMAC-SHA256 Credential=AKIABARE", "AKIABARE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			if got := attemptedAccessKeyID(req); got != tc.want {
				t.Errorf("attemptedAccessKeyID = %q, want %q", got, tc.want)
			}
		})
	}
}
