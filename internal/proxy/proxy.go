// Package proxy implements the S3 operations blindbucket serves, translating
// between a plaintext-speaking client and a ciphertext-only upstream.
package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/auth"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/obs"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// errNotEncrypted reports an upstream object that blindbucket did not write.
var errNotEncrypted = objectmeta.ErrNotEncrypted

// errNotEncryptedAPI is what a client sees for such an object.
var errNotEncryptedAPI = &s3api.Error{
	Code:       "ObjectNotEncrypted",
	Message:    "The object was not written by this gateway and cannot be decrypted.",
	HTTPStatus: http.StatusBadGateway,
}

// Config configures a Proxy.
type Config struct {
	Upstream *upstream.Client
	Keys     keys.KeyProvider
	// Verifier authenticates inbound requests. It is required: a gateway that
	// can be configured to serve unauthenticated requests will eventually be
	// deployed that way by accident.
	Verifier *auth.Verifier
	// BaseDomain enables virtual-hosted-style addressing.
	BaseDomain string
	// Log2ChunkSize is the chunk size new objects are written with, and the
	// fallback for reading objects whose metadata does not record one.
	Log2ChunkSize uint8
	Logger        *slog.Logger
	// Metrics records what the gateway did. A nil value records nothing, which
	// is what the tests use.
	Metrics *obs.Metrics
}

// Proxy serves the S3 API, encrypting on the way in and decrypting on the way
// out.
type Proxy struct {
	upstream   *upstream.Client
	keys       keys.KeyProvider
	verifier   *auth.Verifier
	baseDomain string
	log2C      uint8
	log        *slog.Logger
	metrics    *obs.Metrics

	// hook is called at the coordination points named in hooks.go. It exists so
	// that the integration tests can replay the model's counterexamples, and is
	// nil everywhere else.
	hook func(point string, req s3api.Request)
}

// New validates cfg and builds a Proxy.
func New(cfg Config) (*Proxy, error) {
	switch {
	case cfg.Upstream == nil:
		return nil, errors.New("proxy: an upstream client is required")
	case cfg.Keys == nil:
		return nil, errors.New("proxy: a key provider is required")
	case cfg.Verifier == nil:
		return nil, errors.New("proxy: a request verifier is required")
	}
	log2C := cfg.Log2ChunkSize
	if log2C == 0 {
		log2C = stream.DefaultLog2ChunkSize
	}
	if err := stream.ValidateLog2ChunkSize(log2C); err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Proxy{
		upstream:   cfg.Upstream,
		keys:       cfg.Keys,
		verifier:   cfg.Verifier,
		baseDomain: cfg.BaseDomain,
		log2C:      log2C,
		log:        logger,
		metrics:    cfg.Metrics,
	}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	w.Header().Set("x-amz-request-id", requestID)

	// Counting here rather than in each handler means a new operation is
	// instrumented by existing, and a handler that returns early still counts.
	started := time.Now()
	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	w = recorder

	req, apiErr := s3api.Route(r, p.baseDomain)
	if apiErr != nil {
		p.fail(w, r, requestID, req, apiErr)
		p.metrics.Request(string(req.Op), recorder.status, time.Since(started))
		return
	}

	log := p.log.With(
		"request_id", requestID,
		"op", string(req.Op),
		"bucket", req.Bucket,
		"key", req.Key,
	)

	// Authentication comes before anything that touches the provider, so an
	// unsigned request cannot be used to probe what exists.
	authResult, authErr := p.verifier.Verify(r, req.Bucket)
	if authErr != nil {
		log.Warn("rejecting a request that failed verification", "err", authErr)
		translated := translateAuth(authErr)
		p.metrics.AuthFailure(translated.Code)
		p.fail(w, r, requestID, req, translated)
		p.metrics.Request(string(req.Op), recorder.status, time.Since(started))
		return
	}
	log = log.With("client", authResult.Client.Name)

	var err *s3api.Error
	switch req.Op {
	case s3api.OpPutObject:
		err = p.putObject(w, r, req, authResult, log)
	case s3api.OpGetObject:
		err = p.getObject(w, r, req, log)
	case s3api.OpHeadObject:
		err = p.headObject(w, r, req, log)
	case s3api.OpDeleteObject:
		err = p.deleteObject(w, r, req, log)
	case s3api.OpListObjectsV2, s3api.OpListObjects:
		err = p.listObjects(w, r, req, log)
	case s3api.OpDeleteObjects:
		err = p.deleteObjects(w, r, req, log)
	case s3api.OpCreateMultipartUpload:
		err = p.createMultipartUpload(w, r, req, log)
	case s3api.OpUploadPart:
		err = p.uploadPart(w, r, req, authResult, log)
	case s3api.OpCompleteMultipartUpload:
		err = p.completeMultipartUpload(w, r, req, log)
	case s3api.OpAbortMultipartUpload:
		err = p.abortMultipartUpload(w, r, req, log)
	case s3api.OpListParts:
		err = p.listParts(w, r, req, log)
	case s3api.OpListMultipartUploads:
		err = p.listMultipartUploads(w, r, req)
	case s3api.OpListBuckets, s3api.OpHeadBucket, s3api.OpCreateBucket,
		s3api.OpDeleteBucket, s3api.OpGetBucketLocation:
		err = p.passthrough(w, r, req, log)
	default:
		err = s3api.ErrNotImplemented
	}
	if err != nil {
		p.fail(w, r, requestID, req, err)
	}
	p.metrics.Request(string(req.Op), recorder.status, time.Since(started))
}

// statusRecorder remembers the status a handler wrote.
//
// It does not wrap Write beyond the implicit 200, because the byte counts are
// recorded where the plaintext and the ciphertext are actually distinguishable,
// which this layer cannot do.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (r *statusRecorder) WriteHeader(status int) {
	if !r.written {
		r.status, r.written = status, true
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.written = true
	return r.ResponseWriter.Write(b)
}

// Unwrap lets net/http reach the underlying writer for Flush and the like.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// fail logs and renders an error response.
func (p *Proxy) fail(w http.ResponseWriter, r *http.Request, requestID string, req s3api.Request, apiErr *s3api.Error) {
	// A 501 is a documented limit of this build, not a fault: logging it at
	// error level would make an alert fire every time a client tries a feature
	// that is simply not here yet.
	level := slog.LevelWarn
	if apiErr.HTTPStatus >= http.StatusInternalServerError &&
		apiErr.HTTPStatus != http.StatusNotImplemented {
		level = slog.LevelError
	}
	p.log.Log(r.Context(), level, "request failed",
		"request_id", requestID, "op", string(req.Op), "bucket", req.Bucket, "key", req.Key,
		"code", apiErr.Code, "status", apiErr.HTTPStatus, "detail", apiErr.Message)
	s3api.WriteError(w, r, apiErr, requestID)
}

// newRequestID returns an opaque id echoed to the client and carried in logs.
func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b[:])
}
