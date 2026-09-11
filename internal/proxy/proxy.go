// Package proxy implements the S3 operations blindbucket serves, translating
// between a plaintext-speaking client and a ciphertext-only upstream.
package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// errNotEncrypted reports an upstream object that blindbucket did not write.
//
// Such an object is served to nobody. Passing it through would mean the same
// endpoint sometimes returns authenticated plaintext and sometimes returns
// whatever happened to be in the bucket, with no way for a client to tell which.
var errNotEncrypted = errors.New("object was not written by this gateway")

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
	// Log2ChunkSize is the chunk size new objects are written with, and the
	// fallback for reading objects whose metadata does not record one.
	Log2ChunkSize uint8
	Logger        *slog.Logger
}

// Proxy serves the S3 API, encrypting on the way in and decrypting on the way
// out.
type Proxy struct {
	upstream *upstream.Client
	keys     keys.KeyProvider
	log2C    uint8
	log      *slog.Logger
}

// New validates cfg and builds a Proxy.
func New(cfg Config) (*Proxy, error) {
	switch {
	case cfg.Upstream == nil:
		return nil, errors.New("proxy: an upstream client is required")
	case cfg.Keys == nil:
		return nil, errors.New("proxy: a key provider is required")
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
	return &Proxy{upstream: cfg.Upstream, keys: cfg.Keys, log2C: log2C, log: logger}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	w.Header().Set("x-amz-request-id", requestID)

	req, apiErr := s3api.Route(r)
	if apiErr != nil {
		p.fail(w, r, requestID, req.Bucket, req.Key, apiErr)
		return
	}

	log := p.log.With(
		"request_id", requestID,
		"op", string(req.Op),
		"bucket", req.Bucket,
		"key", req.Key,
	)

	var err *s3api.Error
	switch req.Op {
	case s3api.OpPutObject:
		err = p.putObject(w, r, req, log)
	case s3api.OpGetObject:
		err = p.getObject(w, r, req, log)
	case s3api.OpHeadObject:
		err = p.headObject(w, r, req, log)
	case s3api.OpDeleteObject:
		err = p.deleteObject(w, r, req, log)
	default:
		err = s3api.ErrNotImplemented
	}
	if err != nil {
		p.fail(w, r, requestID, req.Bucket, req.Key, err)
	}
}

// fail logs and renders an error response.
func (p *Proxy) fail(w http.ResponseWriter, r *http.Request, requestID, bucket, key string, apiErr *s3api.Error) {
	level := slog.LevelWarn
	if apiErr.HTTPStatus >= http.StatusInternalServerError {
		level = slog.LevelError
	}
	p.log.Log(r.Context(), level, "request failed",
		"request_id", requestID, "bucket", bucket, "key", key,
		"code", apiErr.Code, "status", apiErr.HTTPStatus, "detail", apiErr.Message)
	s3api.WriteError(w, r, apiErr, requestID)
}

// translateUpstream turns a provider error into the S3 error a client expects.
//
// Provider errors are forwarded rather than flattened: a client that asked for a
// missing key must see NoSuchKey, not a gateway fault it might retry forever.
func translateUpstream(err error) *s3api.Error {
	apiErr, ok := upstream.AsAPIError(err)
	if !ok {
		return s3api.ErrInternal.WithMessage("upstream request failed")
	}
	switch apiErr.StatusCode {
	case http.StatusNotFound:
		if apiErr.Code == "NoSuchBucket" {
			return s3api.ErrNoSuchBucket
		}
		return s3api.ErrNoSuchKey
	case http.StatusForbidden:
		return s3api.ErrAccessDenied
	case http.StatusPreconditionFailed:
		return &s3api.Error{Code: "PreconditionFailed", Message: apiErr.Message,
			HTTPStatus: http.StatusPreconditionFailed}
	default:
		return &s3api.Error{
			Code:       "InternalError",
			Message:    "The upstream storage provider returned " + apiErr.Code + ".",
			HTTPStatus: http.StatusBadGateway,
		}
	}
}

// newRequestID returns an opaque id echoed to the client and carried in logs.
func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b[:])
}
