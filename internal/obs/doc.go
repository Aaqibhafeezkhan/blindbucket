// Package obs provides the metrics of CONCEPT.md section 17.1 and the admin
// listener of section 17.3: /metrics, /healthz, /readyz and, behind a flag,
// /debug/pprof.
//
// Redaction of key material is not here. It lives with the types that hold the
// material -- keys.DEK and auth.Client implement slog.LogValuer -- because a
// value that can only be redacted by going through a particular package is a
// value that will eventually be logged without going through it.
package obs
