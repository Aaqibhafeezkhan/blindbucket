package proxy

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// putObject encrypts the client's body and streams the ciphertext upstream.
//
// Nothing is buffered. The exact upstream Content-Length is known before the
// first byte, because the segment format is deterministic in length.
func (p *Proxy) putObject(w http.ResponseWriter, r *http.Request, req s3api.Request, log *slog.Logger) *s3api.Error {
	if apiErr := rejectUnsupportedUpload(r); apiErr != nil {
		return apiErr
	}

	plainLen := r.ContentLength
	if plainLen < 0 {
		// Without a length there is no Content-Length to give the upstream, and
		// buffering the body to discover it is exactly what this proxy refuses
		// to do. Chunked uploads arrive with M3, which decodes aws-chunked and
		// reads the length from x-amz-decoded-content-length.
		return s3api.ErrMissingContentLength
	}

	sealedLen, err := stream.SealedSize(plainLen, p.log2C)
	if err != nil {
		return s3api.ErrEntityTooLarge.WithMessage("object of %d bytes cannot be stored: %v", plainLen, err)
	}

	clientMeta, err := clientMetadata(r.Header)
	if err != nil {
		return s3api.ErrInvalidArgument.WithMessage("%v", err)
	}

	kid := p.keys.ActiveKID()
	aad, err := keys.ObjectAAD(kid, req.Bucket, req.Key)
	if err != nil {
		return s3api.ErrInvalidArgument.WithMessage("%v", err)
	}
	dek, err := keys.NewDEK()
	if err != nil {
		return s3api.ErrInternal
	}
	defer dek.Wipe()

	wrapped, err := p.keys.Wrap(r.Context(), kid, dek.Bytes(), aad)
	if err != nil {
		log.Error("wrapping the data key failed", "err", err)
		return s3api.ErrInternal
	}

	meta := objectMeta{
		Version:       stream.Version,
		KeyID:         kid,
		WrappedDEK:    wrapped,
		Log2ChunkSize: p.log2C,
	}

	// The encrypter runs in its own goroutine writing into a pipe, and the
	// upstream request reads the other end. There is no buffer between them, so
	// a slow upstream slows the read from the client through TCP flow control.
	pr, pw := io.Pipe()
	encDone := make(chan error, 1)
	go func() {
		ew, err := stream.NewEncryptWriter(pw, dek.Bytes(), stream.SegmentParams{Log2ChunkSize: p.log2C})
		if err != nil {
			_ = pw.CloseWithError(err)
			encDone <- err
			return
		}
		_, copyErr := io.Copy(ew, r.Body)
		if copyErr == nil {
			// Close writes the final chunk. A body that ended early therefore
			// never becomes a complete segment.
			copyErr = ew.Close()
		}
		_ = pw.CloseWithError(copyErr)
		encDone <- copyErr
	}()

	out, putErr := p.upstream.PutObject(r.Context(), upstream.PutObjectInput{
		Bucket:             req.Bucket,
		Key:                req.Key,
		Body:               pr,
		ContentLength:      sealedLen,
		ContentType:        r.Header.Get("Content-Type"),
		CacheControl:       r.Header.Get("Cache-Control"),
		ContentDisposition: r.Header.Get("Content-Disposition"),
		ContentEncoding:    r.Header.Get("Content-Encoding"),
		ContentLanguage:    r.Header.Get("Content-Language"),
		Metadata:           mergeMetadata(clientMeta, meta),
	})

	// Unblock the encrypter if the upstream refused before reading the body.
	_ = pr.Close()
	encErr := <-encDone

	switch {
	case encErr != nil:
		// The client stopped sending, or encryption failed. Either way the
		// upstream never saw a complete body and stored nothing.
		log.Warn("upload aborted before completion", "err", encErr)
		return s3api.ErrInvalidRequest.WithMessage("the request body ended before %d bytes were read", plainLen)
	case putErr != nil:
		log.Warn("upstream rejected the upload", "err", putErr)
		return translateUpstream(putErr)
	}

	if out.ETag != "" {
		w.Header().Set("ETag", out.ETag)
	}
	if out.VersionID != "" {
		w.Header().Set("x-amz-version-id", out.VersionID)
	}
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusOK)
	log.Info("object stored", "plaintext_bytes", plainLen, "ciphertext_bytes", sealedLen, "kid", kid)
	return nil
}

// getObject decrypts an object on the way to the client.
//
// The order here is the whole of the fail-closed rule: the data key is
// unwrapped and the first chunk authenticated *before* a status line is
// written, so a wrong key, forged metadata or a tampered header produces a
// proper S3 error rather than a truncated body. See
// docs/adr/ADR-004-fail-closed.md.
func (p *Proxy) getObject(w http.ResponseWriter, r *http.Request, req s3api.Request, log *slog.Logger) *s3api.Error {
	if r.Header.Get("Range") != "" {
		return s3api.ErrNotImplemented.WithMessage("range requests are not implemented in this build")
	}

	out, err := p.upstream.GetObject(r.Context(), upstream.GetObjectInput{
		Bucket: req.Bucket, Key: req.Key,
	})
	if err != nil {
		return translateUpstream(err)
	}
	defer func() { _ = out.Body.Close() }()

	reader, meta, apiErr := p.openSegment(r, req, out.Metadata, out.Body, log)
	if apiErr != nil {
		return apiErr
	}
	defer func() { _ = reader.Close() }()

	plainLen, err := stream.OpenedSize(out.ContentLength, meta.Log2ChunkSize)
	if err != nil {
		return p.integrityError(log, "ciphertext size", err)
	}

	copyResponseHeaders(w.Header(), out.Header)
	w.Header().Set("Content-Length", strconv.FormatInt(plainLen, 10))
	w.WriteHeader(http.StatusOK)

	written, copyErr := io.Copy(w, reader)
	if copyErr != nil {
		// The status and Content-Length are already on the wire, so there is no
		// way to report this as an error document: appending one would hand the
		// client bytes it would read as object content. Aborting the connection
		// instead means the client sees a short read against the declared
		// length, which every correct client treats as a failure.
		log.Error("aborting response after an integrity or transport failure",
			"written_bytes", written, "expected_bytes", plainLen, "err", copyErr)
		panic(http.ErrAbortHandler)
	}
	log.Info("object served", "plaintext_bytes", plainLen, "kid", meta.KeyID)
	return nil
}

// headObject reports an object's plaintext size without reading it.
func (p *Proxy) headObject(w http.ResponseWriter, r *http.Request, req s3api.Request, log *slog.Logger) *s3api.Error {
	info, err := p.upstream.HeadObject(r.Context(), req.Bucket, req.Key)
	if err != nil {
		return translateUpstream(err)
	}

	meta, err := parseObjectMeta(info.Metadata, p.log2C)
	if errors.Is(err, errNotEncrypted) {
		return errNotEncryptedAPI
	}
	if err != nil {
		return p.integrityError(log, "object metadata", err)
	}

	// A HEAD never reads the body, so the chunk size cannot be taken from the
	// authenticated segment header here. It comes from the object's own
	// metadata, which is why that is recorded at write time; without it this
	// would silently report wrong sizes for any object written under a
	// different configuration.
	plainLen, err := stream.OpenedSize(info.ContentLength, meta.Log2ChunkSize)
	if err != nil {
		return p.integrityError(log, "ciphertext size", err)
	}

	copyResponseHeaders(w.Header(), info.Header)
	w.Header().Set("Content-Length", strconv.FormatInt(plainLen, 10))
	w.WriteHeader(http.StatusOK)
	return nil
}

// deleteObject removes an object upstream.
func (p *Proxy) deleteObject(w http.ResponseWriter, r *http.Request, req s3api.Request, _ *slog.Logger) *s3api.Error {
	if err := p.upstream.DeleteObject(r.Context(), req.Bucket, req.Key); err != nil {
		return translateUpstream(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// openSegment unwraps the data key and authenticates the first chunk.
//
// Everything that can fail is made to fail here, while an error response is
// still possible.
func (p *Proxy) openSegment(
	r *http.Request, req s3api.Request, metadata map[string]string, body io.Reader, log *slog.Logger,
) (*stream.DecryptReader, objectMeta, *s3api.Error) {
	meta, err := parseObjectMeta(metadata, p.log2C)
	if errors.Is(err, errNotEncrypted) {
		return nil, objectMeta{}, errNotEncryptedAPI
	}
	if err != nil {
		return nil, objectMeta{}, p.integrityError(log, "object metadata", err)
	}

	aad, err := keys.ObjectAAD(meta.KeyID, req.Bucket, req.Key)
	if err != nil {
		return nil, objectMeta{}, s3api.ErrInvalidArgument.WithMessage("%v", err)
	}
	dek, err := p.keys.Unwrap(r.Context(), meta.KeyID, meta.WrappedDEK, aad)
	if err != nil {
		if errors.Is(err, keys.ErrUnknownKID) {
			return nil, objectMeta{}, s3api.ErrIntegrity.WithMessage(
				"the key %q that protects this object is not in the keyring", meta.KeyID)
		}
		return nil, objectMeta{}, p.integrityError(log, "data key", err)
	}
	defer clear(dek)

	// AnyChunkSize: the segment states its own size, and unlike the metadata
	// that statement is authenticated.
	reader, err := stream.NewDecryptReader(body, dek, stream.SegmentParams{Log2ChunkSize: stream.AnyChunkSize})
	if err != nil {
		return nil, objectMeta{}, p.integrityError(log, "segment header", err)
	}
	if err := reader.VerifyFirst(); err != nil {
		_ = reader.Close()
		return nil, objectMeta{}, p.integrityError(log, "first chunk", err)
	}

	// Past this point the header is authenticated, so it can be trusted over the
	// metadata. A recorded chunk size that disagrees with it means the metadata
	// was altered.
	authenticated := reader.Header().Log2ChunkSize
	if meta.HasChunkSize && meta.Log2ChunkSize != authenticated {
		_ = reader.Close()
		return nil, objectMeta{}, p.integrityError(log, "chunk size",
			errors.New("object metadata disagrees with the authenticated segment header"))
	}
	meta.Log2ChunkSize = authenticated

	return reader, meta, nil
}

// integrityError logs a failed authentication and renders it for the client.
//
// A rise in these is security-relevant: it means either a bug or a provider
// modifying stored data. M5 turns this into the
// blindbucket_integrity_failures_total metric.
func (p *Proxy) integrityError(log *slog.Logger, kind string, err error) *s3api.Error {
	log.Error("integrity check failed", "kind", kind, "err", err)
	return s3api.ErrIntegrity.WithMessage("the stored object failed authentication (%s)", kind)
}

// rejectUnsupportedUpload refuses request features this build cannot honour.
//
// Silently ignoring them would be the dangerous option: a client that sends a
// checksum expects it to be verified, and accepting the upload without checking
// would turn a detected corruption into an undetected one.
func rejectUnsupportedUpload(r *http.Request) *s3api.Error {
	if sha := r.Header.Get("X-Amz-Content-Sha256"); strings.HasPrefix(sha, "STREAMING-") {
		return s3api.ErrNotImplemented.WithMessage(
			"chunked uploads (%s) are not implemented in this build", sha)
	}
	if r.Header.Get("Content-MD5") != "" {
		return s3api.ErrNotImplemented.WithMessage(
			"Content-MD5 verification is not implemented in this build")
	}
	if r.Header.Get("X-Amz-Copy-Source") != "" {
		return s3api.ErrNotImplemented.WithMessage("CopyObject is not implemented in this build")
	}
	for name := range r.Header {
		lower := strings.ToLower(name)
		switch {
		case strings.HasPrefix(lower, "x-amz-checksum-"), lower == "x-amz-sdk-checksum-algorithm":
			return s3api.ErrNotImplemented.WithMessage(
				"client checksums (%s) are not implemented in this build", name)
		case strings.HasPrefix(lower, "x-amz-server-side-encryption"):
			return s3api.ErrNotImplemented.WithMessage(
				"server-side encryption headers are not accepted; this gateway encrypts already")
		}
	}
	return nil
}
