// Package rotate re-wraps the data keys of stored objects under a new KEK.
//
// What moves is metadata. An object's data key stays the same; only the key that
// wraps it changes, so the ciphertext never leaves the provider and a terabyte
// rotates as cheaply as a megabyte. That is also the honest limit of what
// rotation buys: it protects against a compromised or expiring KEK, not against
// a compromised DEK. See CONCEPT.md section 11.2.
//
// The hard part is not the re-wrapping, it is doing it while clients are
// writing. Rotation reads an object and writes it back some time later, and in
// between a client may have replaced it. Writing back unconditionally would
// discard that write -- invariant I2, "rotation causes no lost update", which
// spec/tla/Multipart.tla produces a six-state counterexample for when the
// conditional write is removed. So the final write carries If-Match with the
// ETag seen at the start, and a 412 means the object changed and is skipped.
package rotate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// maxManifestBytes bounds a manifest read back from the provider.
const maxManifestBytes = 1 << 20

// Config describes one rotation run.
type Config struct {
	Upstream *upstream.Client
	Keys     keys.KeyProvider
	Bucket   string
	// Prefix restricts the run to object keys under it.
	Prefix string
	// TargetKID is the KEK to wrap under. Objects already on it are skipped,
	// which is what makes a run idempotent and resumable after an interruption.
	TargetKID string
	// Log2ChunkSize is the fallback for objects whose metadata records none.
	Log2ChunkSize uint8

	Concurrency int
	DryRun      bool
	// AllowUnconditional drops the If-Match on the final write.
	//
	// It exists for providers that do not implement conditional writes, and it
	// gives up invariant I2: a client write that lands mid-rotation is silently
	// replaced by the pre-rotation version. Callers must not set it without the
	// operator having said so, and must not run it while anything writes to the
	// prefix.
	AllowUnconditional bool

	Log *slog.Logger

	// Hook is called at the steps of the Rot process in spec/tla/Multipart.tla,
	// named as the model names them. It exists so that an integration test can
	// hold a rotation open and replay the I2 counterexample; it is nil
	// everywhere else.
	Hook func(point, key string)
}

// Step names of the rotation, matching the model's actions.
const (
	HookHead     = "rotHead"     // after the object and its etag are read
	HookCreate   = "rotCreate"   // after the upload is opened
	HookManifest = "rotManifest" // after the new manifest is written
	HookComplete = "rotComplete" // after the conditional write lands
)

func (c Config) at(point, key string) {
	if c.Hook != nil {
		c.Hook(point, key)
	}
}

// Result reports what a run did.
type Result struct {
	Scanned int64
	Rotated int64
	// AlreadyCurrent counts objects already wrapped under the target KEK.
	AlreadyCurrent int64
	// Conflicted counts objects a client wrote during the rotation. They keep
	// the client's version and the old KEK, and a later run picks them up.
	Conflicted int64
	// Foreign counts objects this gateway did not write.
	Foreign int64
	Failed  int64
}

// Run rotates every object under the configured prefix.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	switch {
	case cfg.Upstream == nil:
		return nil, errors.New("rotate: an upstream client is required")
	case cfg.Keys == nil:
		return nil, errors.New("rotate: a key provider is required")
	case cfg.Bucket == "":
		return nil, errors.New("rotate: a bucket is required")
	}
	if err := keys.ValidateKID(cfg.TargetKID); err != nil {
		return nil, fmt.Errorf("rotate: target key id: %w", err)
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 8
	}
	if cfg.Log2ChunkSize == 0 {
		cfg.Log2ChunkSize = stream.DefaultLog2ChunkSize
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}

	result := &Result{}
	keysCh := make(chan string)
	var wg sync.WaitGroup

	for range cfg.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for key := range keysCh {
				rotateOne(ctx, cfg, key, result)
			}
		}()
	}

	err := eachObject(ctx, cfg, func(key string) bool {
		select {
		case keysCh <- key:
			return true
		case <-ctx.Done():
			return false
		}
	})
	close(keysCh)
	wg.Wait()
	return result, err
}

// eachObject walks the prefix, skipping the gateway's own objects.
func eachObject(ctx context.Context, cfg Config, visit func(string) bool) error {
	query := url.Values{"list-type": {"2"}, "max-keys": {"1000"}}
	if cfg.Prefix != "" {
		query.Set("prefix", cfg.Prefix)
	}
	for {
		page, err := cfg.Upstream.ListObjects(ctx, cfg.Bucket, query)
		if err != nil {
			return fmt.Errorf("rotate: listing %s: %w", cfg.Bucket, err)
		}
		for _, entry := range page.Contents {
			// Manifests are rotated with the object they belong to, never on
			// their own: they carry no wrapped key of their own.
			if strings.HasPrefix(entry.Key, s3api.ReservedPrefix) {
				continue
			}
			if !visit(entry.Key) {
				return ctx.Err()
			}
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			return nil
		}
		query.Set("continuation-token", page.NextContinuationToken)
	}
}

// rotateOne re-wraps one object's data key.
func rotateOne(ctx context.Context, cfg Config, key string, result *Result) {
	atomic.AddInt64(&result.Scanned, 1)
	log := cfg.Log.With("key", key)

	info, err := cfg.Upstream.HeadObject(ctx, cfg.Bucket, key)
	if err != nil {
		log.Warn("could not read the object", "err", err)
		atomic.AddInt64(&result.Failed, 1)
		return
	}

	meta, err := objectmeta.Parse(info.Metadata, cfg.Log2ChunkSize)
	if errors.Is(err, objectmeta.ErrNotEncrypted) {
		// A bucket may hold objects this gateway never wrote. They have no
		// wrapped key, so there is nothing to rotate and nothing to complain
		// about.
		atomic.AddInt64(&result.Foreign, 1)
		return
	}
	if err != nil {
		log.Warn("object metadata is unusable", "err", err)
		atomic.AddInt64(&result.Failed, 1)
		return
	}

	// Idempotence: a run that is interrupted and started again does the
	// remaining work and nothing else.
	if meta.KeyID == cfg.TargetKID {
		atomic.AddInt64(&result.AlreadyCurrent, 1)
		return
	}

	cfg.at(HookHead, key)

	if cfg.DryRun {
		log.Info("would rotate", "from", meta.KeyID, "to", cfg.TargetKID)
		atomic.AddInt64(&result.Rotated, 1)
		return
	}

	rewrapped, err := rewrap(ctx, cfg, key, meta)
	if err != nil {
		log.Warn("could not re-wrap the data key", "err", err)
		atomic.AddInt64(&result.Failed, 1)
		return
	}

	switch err := writeBack(ctx, cfg, key, info, meta, rewrapped); {
	case err == nil:
		log.Debug("rotated", "from", meta.KeyID, "to", cfg.TargetKID)
		atomic.AddInt64(&result.Rotated, 1)
	case errors.Is(err, errChangedUnderUs):
		// A client wrote while the rotation was in flight. Its version stands;
		// this is invariant I2 holding, not a failure.
		log.Info("skipped: a client wrote during the rotation")
		atomic.AddInt64(&result.Conflicted, 1)
	default:
		log.Warn("could not write the rotated object back", "err", err)
		atomic.AddInt64(&result.Failed, 1)
	}
}

// errChangedUnderUs reports that the object was replaced mid-rotation.
var errChangedUnderUs = errors.New("rotate: the object changed during the rotation")

// rewrapped carries the metadata a rotated object must be written with.
type rewrapped struct {
	meta objectmeta.Meta
	// dek is needed only for a multipart object, whose manifest is signed with
	// a key derived from it.
	dek []byte
}

// rewrap unwraps the data key under the old KEK and wraps it under the new one.
//
// The key id is part of the associated data of both operations (FORMAT §6.1),
// so the unwrap has to use the id the object records and the wrap the new one.
func rewrap(ctx context.Context, cfg Config, key string, meta objectmeta.Meta) (*rewrapped, error) {
	oldAAD, err := keys.ObjectAAD(meta.KeyID, cfg.Bucket, key)
	if err != nil {
		return nil, err
	}
	dek, err := cfg.Keys.Unwrap(ctx, meta.KeyID, meta.WrappedDEK, oldAAD)
	if err != nil {
		return nil, fmt.Errorf("unwrapping under %q: %w", meta.KeyID, err)
	}

	newAAD, err := keys.ObjectAAD(cfg.TargetKID, cfg.Bucket, key)
	if err != nil {
		return nil, err
	}
	wrapped, err := cfg.Keys.Wrap(ctx, cfg.TargetKID, dek, newAAD)
	if err != nil {
		return nil, fmt.Errorf("wrapping under %q: %w", cfg.TargetKID, err)
	}

	out := meta
	out.KeyID = cfg.TargetKID
	out.WrappedDEK = wrapped
	return &rewrapped{meta: out, dek: dek}, nil
}

// writeBack republishes the object with its new metadata.
//
// Both shapes go through a multipart upload, single-part objects included. A
// plain CopyObject would work for them, but CompleteMultipartUpload is where the
// conditional write lives, and a single part keeps the size arithmetic identical
// (M = 1 gives the same result as a single-part object, FORMAT §7.2).
func writeBack(ctx context.Context, cfg Config, key string, info *upstream.ObjectInfo,
	meta objectmeta.Meta, next *rewrapped,
) error {
	defer clear(next.dek)

	// Rule R1: the copy is a new object version, so it mints a new manifest id
	// rather than pointing at the one the old version used.
	var layout []manifest.Part
	if meta.Multipart {
		parts, err := loadParts(ctx, cfg, key, meta, next.dek)
		if err != nil {
			return err
		}
		layout = parts

		id, err := manifest.NewID()
		if err != nil {
			return err
		}
		next.meta.ManifestID, next.meta.Multipart = id, true
	}

	clientMeta := map[string]string{}
	for name, value := range info.Metadata {
		if !strings.HasPrefix(strings.ToLower(name), objectmeta.Prefix) {
			clientMeta[name] = value
		}
	}
	for name, value := range next.meta.Headers() {
		clientMeta[name] = value
	}

	uploadID, err := cfg.Upstream.CreateMultipartUpload(ctx, upstream.CreateMultipartUploadInput{
		Bucket: cfg.Bucket, Key: key,
		ContentType:  info.ContentType,
		CacheControl: info.CacheControl,
		Metadata:     clientMeta,
	})
	if err != nil {
		return fmt.Errorf("opening the rotation upload: %w", err)
	}
	// Any failure from here leaves an upload the provider would keep until its
	// lifecycle rule expires it, so it is aborted on every path out.
	cfg.at(HookCreate, key)
	committed := false
	defer func() {
		if !committed {
			if err := cfg.Upstream.AbortMultipartUpload(ctx, cfg.Bucket, key, uploadID); err != nil {
				cfg.Log.Warn("could not abort a failed rotation upload", "key", key, "err", err)
			}
		}
	}()

	// There are two windows in which a client can replace the object, and each
	// has its own guard. x-amz-copy-source-if-match covers the copy: if the
	// object changed between the HEAD and here, the provider refuses and the
	// rotation never reads a version it was not looking at. If-Match on the
	// completion covers the rest -- a write that lands after the parts are
	// copied but before the object is published. Both are 412, and both mean the
	// same thing to a caller: leave the client's version alone.
	completed, err := copyParts(ctx, cfg, key, info, layout, meta.Log2ChunkSize, uploadID)
	if err != nil {
		if upstream.PreconditionFailed(err) {
			return errChangedUnderUs
		}
		return err
	}

	// Rule R2: the manifest exists before the object that names it does.
	if next.meta.Multipart {
		m := &manifest.Manifest{
			Bucket: cfg.Bucket, Key: key, ID: next.meta.ManifestID, Parts: layout,
		}
		if err := writeManifest(ctx, cfg, m, next.dek); err != nil {
			return err
		}
	}
	cfg.at(HookManifest, key)

	ifMatch := info.ETag
	if cfg.AllowUnconditional {
		ifMatch = ""
	}
	_, err = cfg.Upstream.CompleteMultipartUpload(ctx, upstream.CompleteMultipartUploadInput{
		Bucket: cfg.Bucket, Key: key, UploadID: uploadID,
		Parts: completed, IfMatch: ifMatch,
	})
	if err != nil {
		if upstream.PreconditionFailed(err) {
			return errChangedUnderUs
		}
		return fmt.Errorf("completing the rotation: %w", err)
	}
	committed = true
	cfg.at(HookComplete, key)

	// Rule R3: and only now, the manifest of the version just replaced -- the id
	// read before this write landed, and nothing else.
	if meta.Multipart && meta.ManifestID != next.meta.ManifestID {
		if err := cfg.Upstream.DeleteObject(ctx, cfg.Bucket,
			meta.ManifestID.ObjectKey(key)); err != nil {
			cfg.Log.Warn("could not remove the replaced manifest; gc will collect it",
				"key", key, "err", err)
		}
	}
	return nil
}

// copyParts fills the upload from the object itself, without moving any bytes
// through this process.
func copyParts(ctx context.Context, cfg Config, key string, info *upstream.ObjectInfo,
	layout []manifest.Part, log2C uint8, uploadID string,
) ([]upstream.CompletedPart, error) {
	// A single-part object is copied whole as part 1.
	if layout == nil {
		etag, err := cfg.Upstream.UploadPartCopy(ctx, upstream.UploadPartCopyInput{
			SourceBucket: cfg.Bucket, SourceKey: key,
			Bucket: cfg.Bucket, Key: key, UploadID: uploadID,
			PartNumber: 1, WholeObject: true, SourceIfMatch: info.ETag,
		})
		if err != nil {
			return nil, fmt.Errorf("copying the object: %w", err)
		}
		return []upstream.CompletedPart{{PartNumber: 1, ETag: etag}}, nil
	}

	// A multipart object keeps its part boundaries: the copy has to be the same
	// shape as the original, or the manifest would describe a different object.
	out := make([]upstream.CompletedPart, 0, len(layout))
	var offset int64
	for _, part := range layout {
		sealed, err := stream.SealedSize(part.PlainSize, log2C)
		if err != nil {
			return nil, fmt.Errorf("part %d has an impossible size: %w", part.Number, err)
		}
		etag, err := cfg.Upstream.UploadPartCopy(ctx, upstream.UploadPartCopyInput{
			SourceBucket: cfg.Bucket, SourceKey: key,
			Bucket: cfg.Bucket, Key: key, UploadID: uploadID,
			//nolint:gosec // part numbers come from a verified manifest, 1..10000.
			PartNumber: int(part.Number),
			First:      offset, Last: offset + sealed - 1,
			SourceIfMatch: info.ETag,
		})
		if err != nil {
			return nil, fmt.Errorf("copying part %d: %w", part.Number, err)
		}
		//nolint:gosec // bounded by the manifest.
		out = append(out, upstream.CompletedPart{PartNumber: int(part.Number), ETag: etag})
		offset += sealed
	}
	return out, nil
}

// loadParts fetches and verifies the manifest of a multipart object.
func loadParts(ctx context.Context, cfg Config, key string,
	meta objectmeta.Meta, dek []byte,
) ([]manifest.Part, error) {
	out, err := cfg.Upstream.GetObject(ctx, upstream.GetObjectInput{
		Bucket: cfg.Bucket, Key: meta.ManifestID.ObjectKey(key),
	})
	if err != nil {
		return nil, fmt.Errorf("reading the manifest: %w", err)
	}
	defer func() { _ = out.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(out.Body, maxManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading the manifest: %w", err)
	}
	if len(raw) > maxManifestBytes {
		return nil, fmt.Errorf("%w: manifest exceeds %d bytes", manifest.ErrVerify, maxManifestBytes)
	}
	m, err := manifest.Unmarshal(raw, dek, cfg.Bucket, key, meta.ManifestID)
	if err != nil {
		return nil, err
	}
	return m.Parts, nil
}

// writeManifest stores the manifest of the rotated object.
func writeManifest(ctx context.Context, cfg Config, m *manifest.Manifest, dek []byte) error {
	raw, err := m.Marshal(dek)
	if err != nil {
		return fmt.Errorf("building the manifest: %w", err)
	}
	_, err = cfg.Upstream.PutObject(ctx, upstream.PutObjectInput{
		Bucket: m.Bucket, Key: m.ID.ObjectKey(m.Key),
		Body: strings.NewReader(string(raw)), ContentLength: int64(len(raw)),
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return fmt.Errorf("storing the manifest: %w", err)
	}
	return nil
}

// Duration is a convenience for the CLI's summary.
func (r *Result) Duration(started time.Time) time.Duration {
	return time.Since(started).Round(time.Millisecond)
}
