package proxy

import (
	"context"
	"net/http"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/audit"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
)

// auditFacts is what a handler knows and the request's audit entry wants.
//
// It travels in the request context rather than through every handler's
// signature because most handlers have nothing to contribute: an entry for
// ListBuckets has no key id and moves no object bytes, and threading two
// parameters through fifteen operations to say so would be noise. The ones that
// do know already log these values, and now also note them.
//
// One request is one goroutine, so the struct needs no lock.
type auditFacts struct {
	kid       string
	bytes     int64
	code      string
	principal string
}

// auditFactsKey is the context key. An unexported empty struct, so nothing
// outside this package can collide with it or reach the value.
type auditFactsKey struct{}

// withAuditFacts attaches a fresh fact set to a request.
func withAuditFacts(r *http.Request) (*http.Request, *auditFacts) {
	facts := &auditFacts{}
	return r.WithContext(context.WithValue(r.Context(), auditFactsKey{}, facts)), facts
}

// factsOf returns the request's fact set, or nil when auditing is off.
func factsOf(r *http.Request) *auditFacts {
	facts, _ := r.Context().Value(auditFactsKey{}).(*auditFacts)
	return facts
}

// noteObject records the key id and plaintext byte count of an operation that
// moved object data.
func (p *Proxy) noteObject(r *http.Request, kid string, plaintextBytes int64) {
	if p.audit == nil {
		return
	}
	if facts := factsOf(r); facts != nil {
		facts.kid, facts.bytes = kid, plaintextBytes
	}
}

// noteCode records the S3 error code a request ended with.
func (p *Proxy) noteCode(r *http.Request, code string) {
	if p.audit == nil {
		return
	}
	if facts := factsOf(r); facts != nil {
		facts.code = code
	}
}

// notePrincipal records the access key id a rejected caller claimed.
//
// It is written only when authentication failed, which is exactly when there is
// no client name to record and the identity that was attempted is the thing
// worth having. The value is attacker-controlled and is bounded and stripped of
// control characters by the audit writer, not here.
func (p *Proxy) notePrincipal(r *http.Request, accessKeyID string) {
	if p.audit == nil {
		return
	}
	if facts := factsOf(r); facts != nil {
		facts.principal = accessKeyID
	}
}

// auditGate reports the error a broken audit log should refuse requests with.
//
// This runs before the handler, not after, and the asymmetry is the point. An
// entry records an outcome and can only be written once the request is over, so
// a failure to write one cannot retroactively withhold the response it
// describes. Refusing the *next* request is the strongest fail-closed behaviour
// that ordering allows, and it costs exactly one request served without a
// record -- which is itself visible in the log, as the place the chain stops.
// See ADR-016.
func (p *Proxy) auditGate() *s3api.Error {
	if p.audit == nil || !p.auditFailClosed {
		return nil
	}
	if err := p.audit.Err(); err != nil {
		p.log.Error("refusing requests: the audit log cannot be written", "err", err)
		return errAuditUnavailable
	}
	return nil
}

// errAuditUnavailable is what a client sees while the audit log is broken.
//
// 503 with a retryable code, because that is true: the condition is an operator
// problem that can be fixed under the running gateway, and a client backing off
// and retrying is the correct response to it.
var errAuditUnavailable = &s3api.Error{
	Code:       "ServiceUnavailable",
	Message:    "The gateway cannot record this request in its audit log and will not serve it.",
	HTTPStatus: http.StatusServiceUnavailable,
}

// recordRequest appends one request to the audit log.
//
// It runs deferred, so it also records a download that ADR-004 aborted mid-body:
// the panic unwinds through this. That case is worth having rather than losing,
// because a transfer that failed authentication halfway is precisely the kind of
// event an audit log exists for.
func (p *Proxy) recordRequest(
	req s3api.Request, requestID, client string, status int, facts *auditFacts, started time.Time,
) {
	if p.audit == nil {
		return
	}
	err := p.audit.Append(audit.Event{
		Time:      started,
		Op:        string(req.Op),
		Bucket:    req.Bucket,
		Key:       req.Key,
		Client:    client,
		Principal: facts.principal,
		RequestID: requestID,
		Status:    status,
		Code:      facts.code,
		KID:       facts.kid,
		Bytes:     facts.bytes,
	})
	if err != nil {
		// Nothing here can fix it, and the request is already served. What this
		// does is make the failure loud and leave the writer broken, which
		// auditGate turns into a refusal of the next request.
		p.log.Error("could not write an audit record", "request_id", requestID, "err", err)
		p.metrics.AuditFailure()
	}
}
