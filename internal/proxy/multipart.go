package proxy

import (
	"encoding/xml"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/LennardGeissler/blindbucket/internal/auth"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/obs"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upload"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// maxCompleteBody bounds the part list a client may send. 10000 parts of about
// 80 bytes each is under a megabyte.
const maxCompleteBody = 4 << 20

// initiateResult is the body of a CreateMultipartUpload response.
type initiateResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

// completeRequest is the part list a client sends with CompleteMultipartUpload.
type completeRequest struct {
	XMLName xml.Name          `xml:"CompleteMultipartUpload"`
	Parts   []completeReqPart `xml:"Part"`
}

type completeReqPart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

// completeResult is the body of a CompleteMultipartUpload response.
type completeResult struct {
	XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
	Location string   `xml:"Location,omitempty"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

// listPartsResult is the body of a ListParts response.
type listPartsResult struct {
	XMLName      xml.Name        `xml:"ListPartsResult"`
	Bucket       string          `xml:"Bucket"`
	Key          string          `xml:"Key"`
	UploadID     string          `xml:"UploadId"`
	StorageClass string          `xml:"StorageClass,omitempty"`
	IsTruncated  bool            `xml:"IsTruncated"`
	Parts        []listPartsPart `xml:"Part"`
}

type listPartsPart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
	Size       int64  `xml:"Size"`
}

// createMultipartUpload opens an upload and hands the client a token.
//
// Everything that identifies the upload -- the provider's UploadId, the data key,
// the manifest id -- is minted here and then travels in the token, so no state
// is kept anywhere in the gateway. See docs/adr/ADR-006-upload-token.md.
//
// The manifest id is minted here rather than at completion because rule R1 wants
// one id per object version and the metadata that names it is fixed at this
// call: S3 records a multipart object's metadata from the create request, and
// there is no way to add it later.
func (p *Proxy) createMultipartUpload(
	w http.ResponseWriter, r *http.Request, req s3api.Request, log *slog.Logger,
) *s3api.Error {
	if apiErr := rejectUnsupportedUpload(r); apiErr != nil {
		return apiErr
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
	manifestID, err := manifest.NewID()
	if err != nil {
		return s3api.ErrInternal
	}

	meta := objectMeta{
		Version:       stream.Version,
		KeyID:         kid,
		WrappedDEK:    wrapped,
		Log2ChunkSize: p.log2C,
		ManifestID:    manifestID,
		Multipart:     true,
	}

	uploadID, err := p.upstream.CreateMultipartUpload(r.Context(), upstream.CreateMultipartUploadInput{
		Bucket:             req.Bucket,
		Key:                req.Key,
		ContentType:        r.Header.Get("Content-Type"),
		CacheControl:       r.Header.Get("Cache-Control"),
		ContentDisposition: r.Header.Get("Content-Disposition"),
		ContentEncoding:    passthroughContentEncoding(r),
		ContentLanguage:    r.Header.Get("Content-Language"),
		Metadata:           mergeMetadata(clientMeta, meta),
	})
	if err != nil {
		log.Warn("the upstream refused to open a multipart upload", "err", err)
		return translateUpstream(err)
	}

	token, err := upload.Seal(r.Context(), p.keys, upload.Token{
		KID:        kid,
		UploadID:   uploadID,
		WrappedDEK: wrapped,
		ManifestID: manifestID,
	}, req.Bucket, req.Key)
	if err != nil {
		// The upstream upload is already open; leaving it would hold storage
		// until the bucket's lifecycle rule expires it.
		if abortErr := p.upstream.AbortMultipartUpload(
			r.Context(), req.Bucket, req.Key, uploadID); abortErr != nil {
			log.Warn("could not abort the upload after sealing failed", "err", abortErr)
		}
		log.Error("sealing the upload token failed", "err", err)
		return s3api.ErrInternal
	}

	log.Info("multipart upload opened", "kid", kid, "manifest_id", manifestID.String())
	return writeXML(w, http.StatusOK, initiateResult{
		Bucket: req.Bucket, Key: req.Key, UploadID: token,
	})
}

// uploadPart encrypts one part and streams it upstream as its own segment.
//
// Each part attempt gets a fresh salt and therefore a fresh subkey, which is what
// makes a client retry of the same part number safe: a repeated (key, nonce) pair
// under GCM would be catastrophic, and this design makes one impossible whatever
// the client does. See CONCEPT.md section 10.4.
func (p *Proxy) uploadPart(
	w http.ResponseWriter, r *http.Request, req s3api.Request, authResult *auth.Result, log *slog.Logger,
) *s3api.Error {
	token, apiErr := p.openToken(r, req)
	if apiErr != nil {
		return apiErr
	}
	dek, apiErr := p.unwrapTokenDEK(r, req, token, log)
	if apiErr != nil {
		return apiErr
	}
	defer clear(dek)

	body, plainLen, err := auth.NewBodyReader(r, authResult)
	if err != nil {
		return translateBody(err)
	}
	if plainLen < 0 {
		return s3api.ErrMissingContentLength
	}

	sealedLen, err := stream.SealedSize(plainLen, p.log2C)
	if err != nil {
		return s3api.ErrEntityTooLarge.WithMessage("part of %d bytes cannot be stored: %v", plainLen, err)
	}
	// The 5 GiB ceiling is checked here rather than only at completion, so a
	// client learns on the part it sent instead of after uploading all of them.
	if sealedLen > manifest.MaxPartCiphertext {
		maximum, _ := manifest.MaxPartPlaintext(p.log2C)
		return s3api.ErrEntityTooLarge.WithMessage(
			"part of %d bytes exceeds the maximum part size of %d bytes", plainLen, maximum)
	}

	p.metrics.StreamStarted(obs.Upload)
	defer p.metrics.StreamFinished(obs.Upload)

	guard := newStallGuard(w, p.stall)
	defer guard.clear()

	pr, pw := io.Pipe()
	encDone := make(chan error, 1)
	go func() {
		ew, err := stream.NewEncryptWriter(pw, dek, stream.SegmentParams{
			Log2ChunkSize: p.log2C,
			Multipart:     true,
			//nolint:gosec // the router bounds the part number to 1..10000.
			Index: uint32(req.PartNumber),
		})
		if err != nil {
			_ = pw.CloseWithError(err)
			encDone <- err
			return
		}
		_, copyErr := io.Copy(ew, guardedReader{src: body, guard: guard})
		if copyErr == nil {
			copyErr = ew.Close()
		}
		_ = pw.CloseWithError(copyErr)
		encDone <- copyErr
	}()

	etag, putErr := p.upstream.UploadPart(r.Context(), upstream.UploadPartInput{
		Bucket:        req.Bucket,
		Key:           req.Key,
		UploadID:      token.UploadID,
		PartNumber:    req.PartNumber,
		Body:          pr,
		ContentLength: sealedLen,
	})

	_ = pr.Close()
	encErr := <-encDone

	// An upstream that refuses before reading a byte -- an expired upload, a
	// missing bucket, a denied request -- makes the encrypter fail too, because
	// closing the pipe is how it is unblocked. That consequence must not be
	// reported in place of its cause: the client needs to hear NoSuchUpload, not
	// IncompleteBody. Any other encrypter error is a real one (a failed checksum,
	// a client that stopped sending) and still takes precedence.
	if encErr != nil && putErr != nil && errors.Is(encErr, io.ErrClosedPipe) {
		encErr = nil
	}

	switch {
	case encErr != nil:
		log.Warn("part rejected before completion", "part", req.PartNumber, "err", encErr)
		return translateBody(encErr)
	case putErr != nil:
		if upstream.NoSuchUpload(putErr) {
			return s3api.ErrNoSuchUpload
		}
		log.Warn("the upstream rejected the part", "part", req.PartNumber, "err", putErr)
		return translateUpstream(putErr)
	}

	// The ETag is the provider's, over the ciphertext, and the client hands it
	// straight back at completion. It is deliberately not an MD5 of the
	// plaintext: there is none to offer without buffering the part.
	w.Header().Set("ETag", etag)
	echoVerifiedChecksums(w.Header(), r.Header, body.Trailer())
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusOK)
	p.metrics.Bytes(obs.InPlain, plainLen)
	p.metrics.Bytes(obs.OutCipher, sealedLen)
	log.Info("part stored", "part", req.PartNumber,
		"plaintext_bytes", plainLen, "ciphertext_bytes", sealedLen)
	return nil
}

// completeMultipartUpload assembles the parts and publishes the object.
//
// The order of the five upstream calls is the whole of rule R2 and R3, and it is
// checked by the model in spec/tla/Multipart.tla. Changing it means changing the
// model and rerunning TLC:
//
//  1. ListParts        -- the ciphertext sizes, converted and checked (10.5)
//  2. HEAD the key     -- remember the manifest id of whatever is visible now
//  3. PUT the manifest -- before the object becomes visible, never after (R2)
//  4. Complete         -- the object becomes visible
//  5. DELETE           -- only the id observed at step 2, and only now (R3)
func (p *Proxy) completeMultipartUpload(
	w http.ResponseWriter, r *http.Request, req s3api.Request, log *slog.Logger,
) *s3api.Error {
	token, apiErr := p.openToken(r, req)
	if apiErr != nil {
		return apiErr
	}
	dek, apiErr := p.unwrapTokenDEK(r, req, token, log)
	if apiErr != nil {
		return apiErr
	}
	defer clear(dek)

	requested, apiErr := readCompleteRequest(r)
	if apiErr != nil {
		return apiErr
	}

	// Step 1: the provider's own view of what was stored. The client's list says
	// which parts to assemble; the sizes come from here, because a client could
	// claim any size it liked and the size arithmetic has to be right.
	stored, err := p.upstream.ListParts(r.Context(), req.Bucket, req.Key, token.UploadID)
	if err != nil {
		if upstream.NoSuchUpload(err) {
			return s3api.ErrNoSuchUpload
		}
		return translateUpstream(err)
	}
	uploaded, apiErr := matchParts(requested, stored)
	if apiErr != nil {
		return apiErr
	}

	parts, err := manifest.PartsFromUpstream(uploaded, p.log2C)
	if err != nil {
		switch {
		case errors.Is(err, manifest.ErrPartTooLarge):
			return s3api.ErrEntityTooLarge.WithMessage("%v", err)
		case errors.Is(err, manifest.ErrPartRules):
			return s3api.ErrInvalidRequest.WithMessage("%v", err)
		default:
			return s3api.ErrInternal
		}
	}

	// Step 2: what is visible right now. This observation, and nothing else, is
	// what step 5 is allowed to delete.
	observed, hadManifest := p.observedManifest(r.Context(), req.Bucket, req.Key)
	p.at(hookUpHead, req)

	// Step 3: the manifest exists before the object does.
	m := &manifest.Manifest{
		Bucket: req.Bucket, Key: req.Key, ID: token.ManifestID, Parts: parts,
	}
	if err := p.writeManifest(r.Context(), m, dek); err != nil {
		log.Error("could not write the manifest", "err", err)
		return translateUpstream(err)
	}
	p.at(hookUpManifest, req)

	// Step 4: the object becomes visible.
	completed := make([]upstream.CompletedPart, 0, len(requested))
	for _, part := range requested {
		completed = append(completed, upstream.CompletedPart{
			PartNumber: part.PartNumber, ETag: part.ETag,
		})
	}
	out, err := p.upstream.CompleteMultipartUpload(r.Context(), upstream.CompleteMultipartUploadInput{
		Bucket: req.Bucket, Key: req.Key, UploadID: token.UploadID, Parts: completed,
	})
	if err != nil {
		// The manifest written at step 3 is now an orphan. It is left for gc
		// rather than deleted here: a delete on this path would be a delete of
		// something never observed as visible, which is exactly what rule R3
		// forbids, and the model shows why.
		if upstream.NoSuchUpload(err) {
			return s3api.ErrNoSuchUpload
		}
		log.Warn("the upstream refused to complete the upload", "err", err)
		return translateUpstream(err)
	}
	p.at(hookUpComplete, req)

	// Step 5: and only now, the manifest of the version just replaced. Best
	// effort -- a failure here leaves an orphan for gc, which is harmless,
	// whereas retrying in the request would delay a completed upload.
	if hadManifest && observed != token.ManifestID {
		if err := p.deleteManifest(r.Context(), req.Bucket, req.Key, observed); err != nil {
			log.Warn("could not remove the replaced manifest; gc will collect it",
				"manifest_id", observed.String(), "err", err)
		}
	}

	p.at(hookUpCleanup, req)

	if out.VersionID != "" {
		w.Header().Set("x-amz-version-id", out.VersionID)
	}
	log.Info("multipart upload completed",
		"parts", len(parts), "plaintext_bytes", m.PlainSize(), "manifest_id", token.ManifestID.String())
	return writeXML(w, http.StatusOK, completeResult{
		Bucket: req.Bucket, Key: req.Key, ETag: out.ETag,
	})
}

// abortMultipartUpload discards an upload.
//
// It deliberately removes no manifest. An abort observed no visible object and
// replaced none, so rule R3 licenses it to delete nothing; a manifest this upload
// may already have written is an orphan for gc. The alternative -- deleting the
// manifest id from the token -- races a completion in flight on another instance
// and reproduces exactly the failure I1 forbids.
func (p *Proxy) abortMultipartUpload(
	w http.ResponseWriter, r *http.Request, req s3api.Request, log *slog.Logger,
) *s3api.Error {
	token, apiErr := p.openToken(r, req)
	if apiErr != nil {
		return apiErr
	}
	if err := p.upstream.AbortMultipartUpload(r.Context(), req.Bucket, req.Key, token.UploadID); err != nil {
		return translateUpstream(err)
	}
	log.Info("multipart upload aborted")
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// listParts reports the parts stored so far, with plaintext sizes.
func (p *Proxy) listParts(
	w http.ResponseWriter, r *http.Request, req s3api.Request, log *slog.Logger,
) *s3api.Error {
	token, apiErr := p.openToken(r, req)
	if apiErr != nil {
		return apiErr
	}
	stored, err := p.upstream.ListParts(r.Context(), req.Bucket, req.Key, token.UploadID)
	if err != nil {
		if upstream.NoSuchUpload(err) {
			return s3api.ErrNoSuchUpload
		}
		return translateUpstream(err)
	}

	out := listPartsResult{
		Bucket: req.Bucket, Key: req.Key, UploadID: req.UploadID, Parts: []listPartsPart{},
	}
	for _, part := range stored {
		// A part that does not invert is reported at its stored size rather than
		// hidden: this is a listing, and a wrong conversion would be worse than
		// an honest ciphertext number.
		size := part.Size
		if plain, err := stream.OpenedSize(part.Size, p.log2C); err == nil {
			size = plain
		} else {
			log.Debug("part size left unconverted", "part", part.PartNumber, "size", part.Size)
		}
		out.Parts = append(out.Parts, listPartsPart{
			PartNumber: part.PartNumber, ETag: part.ETag, Size: size,
		})
	}
	return writeXML(w, http.StatusOK, out)
}

// listMultipartUploads is refused, with the reason.
//
// The UploadIds this call would return are the provider's, and a client cannot
// use one: every multipart operation here expects the sealed token, which also
// carries the data key and the manifest id. Those exist only inside the token
// the create call handed out, so there is nothing to reconstruct them from. An
// answer listing unusable ids would be worse than no answer.
func (p *Proxy) listMultipartUploads(_ http.ResponseWriter, _ *http.Request, _ s3api.Request) *s3api.Error {
	return s3api.ErrNotImplemented.WithMessage(
		"ListMultipartUploads is not implemented: the upload ids this gateway issues are " +
			"sealed tokens that cannot be recovered from the provider's listing")
}

// openToken recovers the upload state a client presented.
func (p *Proxy) openToken(r *http.Request, req s3api.Request) (*upload.Token, *s3api.Error) {
	if req.UploadID == "" {
		return nil, s3api.ErrInvalidArgument.WithMessage("the request names no upload id")
	}
	token, err := upload.Open(r.Context(), p.keys, req.UploadID, req.Bucket, req.Key)
	if err != nil {
		if errors.Is(err, upload.ErrToken) {
			// Deliberately the same answer for a forged token, a token for
			// another object and a token under a retired key.
			return nil, s3api.ErrNoSuchUpload
		}
		return nil, s3api.ErrInternal
	}
	return token, nil
}

// unwrapTokenDEK recovers the upload's data key from its token.
//
// The wrapped key inside the token is bound to bucket and key by its own
// associated data, so a token moved to another object fails here even if it
// somehow opened.
func (p *Proxy) unwrapTokenDEK(
	r *http.Request, req s3api.Request, token *upload.Token, log *slog.Logger,
) ([]byte, *s3api.Error) {
	aad, err := keys.ObjectAAD(token.KID, req.Bucket, req.Key)
	if err != nil {
		return nil, s3api.ErrInvalidArgument.WithMessage("%v", err)
	}
	dek, err := p.keys.Unwrap(r.Context(), token.KID, token.WrappedDEK, aad)
	if err != nil {
		if errors.Is(err, keys.ErrUnknownKID) {
			return nil, s3api.ErrIntegrity.WithMessage(
				"the key %q that protects this upload is not in the keyring", token.KID)
		}
		return nil, p.integrityError(log, "upload data key", err)
	}
	return dek, nil
}

// readCompleteRequest parses the part list a client sent.
func readCompleteRequest(r *http.Request) ([]completeReqPart, *s3api.Error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxCompleteBody))
	if err != nil {
		return nil, s3api.ErrIncompleteBody.WithMessage("could not read the request body")
	}
	var in completeRequest
	if err := xml.Unmarshal(raw, &in); err != nil {
		return nil, s3api.ErrInvalidRequest.WithMessage(
			"the CompleteMultipartUpload body is not valid XML")
	}
	if len(in.Parts) == 0 {
		return nil, s3api.ErrInvalidRequest.WithMessage("the completion names no parts")
	}
	if len(in.Parts) > stream.MaxParts {
		return nil, s3api.ErrInvalidRequest.WithMessage(
			"the completion names %d parts, the maximum is %d", len(in.Parts), stream.MaxParts)
	}
	return in.Parts, nil
}

// matchParts pairs the parts a client asked to assemble with what the provider
// actually holds.
//
// The sizes must come from the provider: they decide the recorded plaintext
// sizes, and a client that could name them could make an object list at any size
// it liked. The client's list still decides *which* parts are assembled and in
// what order, because that is what it will send to the provider.
func matchParts(requested []completeReqPart, stored []upstream.Part) ([]manifest.UploadedPart, *s3api.Error) {
	sizes := make(map[int]upstream.Part, len(stored))
	for _, part := range stored {
		sizes[part.PartNumber] = part
	}

	out := make([]manifest.UploadedPart, 0, len(requested))
	previous := 0
	for _, want := range requested {
		if want.PartNumber <= previous {
			return nil, s3api.ErrInvalidPartOrder
		}
		previous = want.PartNumber

		have, ok := sizes[want.PartNumber]
		if !ok {
			return nil, s3api.ErrInvalidPart.WithMessage(
				"part %d was never uploaded for this upload id", want.PartNumber)
		}
		//nolint:gosec // part numbers are bounded by the router and by S3 itself.
		out = append(out, manifest.UploadedPart{
			Number: uint32(want.PartNumber), CipherSize: have.Size, ETag: have.ETag,
		})
	}
	return out, nil
}
