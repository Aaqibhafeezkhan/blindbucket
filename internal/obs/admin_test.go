package obs

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// handlerFor builds the admin mux the way NewAdminServer does, without binding a
// port.
func handlerFor(t *testing.T, cfg AdminConfig) http.Handler {
	t.Helper()
	return NewAdminServer(cfg).server.Handler
}

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	body, _ := io.ReadAll(rec.Body)
	return rec.Code, string(body)
}

// Liveness must not depend on the provider: a restart loop caused by an upstream
// outage is worse than the outage.
func TestHealthzIgnoresReadiness(t *testing.T) {
	h := handlerFor(t, AdminConfig{
		Ready: func(context.Context) error { return errors.New("upstream is down") },
	})
	if code, body := get(t, h, "/healthz"); code != http.StatusOK {
		t.Errorf("healthz = %d %q while readiness fails, want 200", code, body)
	}
}

func TestReadyzReportsWhyItIsNotReady(t *testing.T) {
	failing := handlerFor(t, AdminConfig{
		Ready: func(context.Context) error { return errors.New("no active key in the keyring") },
	})
	code, body := get(t, failing, "/readyz")
	if code != http.StatusServiceUnavailable {
		t.Errorf("readyz = %d, want 503", code)
	}
	if !strings.Contains(body, "no active key") {
		t.Errorf("readyz body %q does not say what is wrong", body)
	}

	ready := handlerFor(t, AdminConfig{Ready: func(context.Context) error { return nil }})
	if code, _ := get(t, ready, "/readyz"); code != http.StatusOK {
		t.Errorf("readyz = %d when ready, want 200", code)
	}
}

// Profiles carry goroutine stacks and heap contents, so they are off unless
// somebody asked for them.
func TestPprofIsOffByDefault(t *testing.T) {
	off := handlerFor(t, AdminConfig{})
	if code, _ := get(t, off, "/debug/pprof/"); code != http.StatusNotFound {
		t.Errorf("pprof answered %d without being enabled, want 404", code)
	}

	on := handlerFor(t, AdminConfig{EnablePprof: true})
	if code, _ := get(t, on, "/debug/pprof/"); code != http.StatusOK {
		t.Errorf("pprof answered %d when enabled, want 200", code)
	}
}

// The metrics CONCEPT.md section 17.1 names must actually appear, with their
// label sets, or an alert written against them silently never fires.
func TestMetricsAreExported(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry)

	m.Request("GetObject", 200, 0)
	m.Upstream("HeadObject", 0)
	m.Bytes(InPlain, 1)
	m.Bytes(OutCipher, 1)
	m.StreamStarted(Upload)
	m.IntegrityFailure(KindChunk)
	m.AuthFailure("SignatureDoesNotMatch")
	m.ChecksumMismatch("CRC32")

	h := handlerFor(t, AdminConfig{Registry: registry})
	code, body := get(t, h, "/metrics")
	if code != http.StatusOK {
		t.Fatalf("metrics = %d, want 200", code)
	}

	for _, want := range []string{
		`blindbucket_requests_total{op="GetObject",status="2xx"} 1`,
		`blindbucket_upstream_duration_seconds_count{op="HeadObject"} 1`,
		`blindbucket_bytes_total{direction="in_plain"} 1`,
		`blindbucket_bytes_total{direction="out_cipher"} 1`,
		`blindbucket_active_streams{direction="upload"} 1`,
		`blindbucket_integrity_failures_total{kind="chunk"} 1`,
		`blindbucket_auth_failures_total{reason="SignatureDoesNotMatch"} 1`,
		`blindbucket_checksum_mismatches_total{algorithm="CRC32"} 1`,
		`blindbucket_request_duration_seconds_bucket{op="GetObject"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing from /metrics: %s", want)
		}
	}
}

// The status label is bucketed by class. The exact code belongs in a log line;
// as a label it would be unbounded enough to matter.
func TestStatusLabelIsBounded(t *testing.T) {
	cases := map[int]string{
		200: "2xx", 204: "2xx", 301: "3xx", 400: "4xx",
		404: "4xx", 500: "5xx", 502: "5xx", 0: "other",
	}
	for status, want := range cases {
		if got := statusLabel(status); got != want {
			t.Errorf("statusLabel(%d) = %q, want %q", status, got, want)
		}
	}
}

// A nil *Metrics has to be usable, or every call site needs a branch. The test
// is that none of these panics; there is nothing to assert afterwards.
func TestNilMetricsRecordNothing(*testing.T) {
	var m *Metrics
	m.Request("GetObject", 200, 0)
	m.Upstream("GetObject", 0)
	m.Bytes(InPlain, 1)
	m.StreamStarted(Upload)
	m.StreamFinished(Upload)
	m.IntegrityFailure(KindChunk)
	m.AuthFailure("x")
	m.ChecksumMismatch("x")
}
