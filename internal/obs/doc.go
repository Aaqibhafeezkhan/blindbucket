// Package obs provides the gateway's metrics and its admin listener:
// /metrics, /healthz, /readyz and, behind a flag, /debug/pprof.
//
// Redaction of key material is not here. It lives with the types that hold the
// material -- keys.DEK and auth.Client implement slog.LogValuer -- because a
// value that can only be redacted by going through a particular package is a
// value that will eventually be logged without going through it.
package obs
