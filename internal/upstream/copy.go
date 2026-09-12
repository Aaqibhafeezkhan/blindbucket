package upstream

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// copySource renders the x-amz-copy-source header.
//
// The value is a path, so it is encoded like one: SigV4 signs the header
// verbatim, and a key containing a space or a '+' has to arrive as the provider
// expects to see it or the signature will not match.
func copySource(bucket, key string) string {
	return "/" + uriEncodePath(bucket) + "/" + uriEncodePath(key)
}

// CopyObjectInput describes a server-side copy.
//
// The metadata always replaces the source's rather than being copied with it:
// blindbucket's own bb-* fields bind the data key to the object's bucket and
// key, so an object that moved must carry a re-wrapped key and new metadata.
type CopyObjectInput struct {
	SourceBucket string
	SourceKey    string
	Bucket       string
	Key          string

	ContentType        string
	CacheControl       string
	ContentDisposition string
	ContentEncoding    string
	ContentLanguage    string

	// Metadata holds user metadata without the x-amz-meta- prefix.
	Metadata map[string]string

	// SourceIfMatch makes the copy conditional on the source's ETag, so that an
	// object overwritten between the HEAD and the copy is not copied with the
	// metadata of the version that was read.
	SourceIfMatch string
}

// CopyObjectOutput reports what the provider recorded.
type CopyObjectOutput struct {
	ETag      string
	VersionID string
}

type copyObjectResult struct {
	XMLName xml.Name `xml:"CopyObjectResult"`
	ETag    string   `xml:"ETag"`
}

// CopyObject copies one object at the provider, without moving its bytes.
//
// Like CompleteMultipartUpload, this call can answer 200 and then report a
// failure in the body, because a copy of several gigabytes takes long enough
// that the provider commits to a status first. The body is parsed before the
// result is believed.
func (c *Client) CopyObject(ctx context.Context, in CopyObjectInput) (*CopyObjectOutput, error) {
	u := c.objectURL(in.Bucket, in.Key)

	req, err := c.newRequestURL(ctx, http.MethodPut, u)
	if err != nil {
		return nil, err
	}
	req.Body = http.NoBody
	req.ContentLength = 0
	req.Header.Set("X-Amz-Copy-Source", copySource(in.SourceBucket, in.SourceKey))
	req.Header.Set("X-Amz-Metadata-Directive", "REPLACE")
	setIfNotEmpty(req.Header, "X-Amz-Copy-Source-If-Match", in.SourceIfMatch)
	applyObjectHeaders(req.Header, PutObjectInput{
		ContentType:        in.ContentType,
		CacheControl:       in.CacheControl,
		ContentDisposition: in.ContentDisposition,
		ContentEncoding:    in.ContentEncoding,
		ContentLanguage:    in.ContentLanguage,
		Metadata:           in.Metadata,
	})

	//nolint:bodyclose // closed by drainAndClose below.
	resp, err := c.do(ctx, req, false)
	if err != nil {
		return nil, err
	}
	defer drainAndClose(resp.Body)

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxMultipartBody))
	if err != nil {
		return nil, fmt.Errorf("upstream: reading the copy result: %w", err)
	}
	if apiErr := errorInBody(resp, raw); apiErr != nil {
		return nil, apiErr
	}

	var out copyObjectResult
	if err := xml.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("upstream: the copy result is not valid XML: %w", err)
	}
	return &CopyObjectOutput{
		ETag:      out.ETag,
		VersionID: resp.Header.Get("x-amz-version-id"),
	}, nil
}

// UploadPartCopyInput describes one part copied from another object.
type UploadPartCopyInput struct {
	SourceBucket string
	SourceKey    string
	Bucket       string
	Key          string
	UploadID     string
	// PartNumber is 1..10000.
	PartNumber int

	// First and Last are inclusive ciphertext offsets in the source object.
	// Leave both zero to copy the whole object; see WholeObject.
	First, Last int64
	// WholeObject copies the source entire, with no range header. A range of
	// 0..0 is one byte, not the whole object, so the two cases cannot be told
	// apart by the offsets alone.
	WholeObject bool

	SourceIfMatch string
}

type copyPartResult struct {
	XMLName xml.Name `xml:"CopyPartResult"`
	ETag    string   `xml:"ETag"`
}

// UploadPartCopy fills one part of an open upload from a byte range of another
// object, without the bytes travelling through this process.
//
// This is what makes rotation free of data transfer, and it is also the only
// way to copy a multipart object while preserving its part boundaries: a plain
// CopyObject would flatten it into a single part, losing the -M suffix on the
// ETag that the size arithmetic reads (docs/FORMAT.md section 7.2).
func (c *Client) UploadPartCopy(ctx context.Context, in UploadPartCopyInput) (string, error) {
	if in.PartNumber < 1 || in.PartNumber > 10000 {
		return "", fmt.Errorf("upstream: part number %d outside 1..10000", in.PartNumber)
	}
	if !in.WholeObject && (in.First < 0 || in.Last < in.First) {
		return "", fmt.Errorf("upstream: copy range %d-%d is not a range", in.First, in.Last)
	}

	u := c.objectURL(in.Bucket, in.Key)
	u.RawQuery = url.Values{
		"partNumber": {strconv.Itoa(in.PartNumber)},
		"uploadId":   {in.UploadID},
	}.Encode()

	req, err := c.newRequestURL(ctx, http.MethodPut, u)
	if err != nil {
		return "", err
	}
	req.Body = http.NoBody
	req.ContentLength = 0
	req.Header.Set("X-Amz-Copy-Source", copySource(in.SourceBucket, in.SourceKey))
	if !in.WholeObject {
		req.Header.Set("X-Amz-Copy-Source-Range", fmt.Sprintf("bytes=%d-%d", in.First, in.Last))
	}
	setIfNotEmpty(req.Header, "X-Amz-Copy-Source-If-Match", in.SourceIfMatch)

	//nolint:bodyclose // closed by drainAndClose below.
	resp, err := c.do(ctx, req, false)
	if err != nil {
		return "", err
	}
	defer drainAndClose(resp.Body)

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxMultipartBody))
	if err != nil {
		return "", fmt.Errorf("upstream: reading the part copy result: %w", err)
	}
	if apiErr := errorInBody(resp, raw); apiErr != nil {
		return "", apiErr
	}

	var out copyPartResult
	if err := xml.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("upstream: the part copy result is not valid XML: %w", err)
	}
	if out.ETag == "" {
		return "", errors.New("upstream: the part copy result carries no ETag")
	}
	return out.ETag, nil
}
