package upstream

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// maxErrorBody bounds how much of an error response is read. The upstream is
// untrusted, and an error path must not become a way to make the proxy allocate.
const maxErrorBody = 64 << 10

// APIError is an error response from the storage provider.
//
// The S3 error code is preserved verbatim so the proxy can pass through the
// distinctions clients act on -- NoSuchKey, NoSuchBucket, PreconditionFailed --
// rather than collapsing everything into a 500.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	RequestID  string
	Resource   string
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("upstream: HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("upstream: %s (HTTP %d): %s", e.Code, e.StatusCode, e.Message)
}

// AsAPIError reports whether err is or wraps an *APIError.
func AsAPIError(err error) (*APIError, bool) {
	var ae *APIError
	ok := errors.As(err, &ae)
	return ae, ok
}

// NotFound reports whether err is an upstream 404.
func NotFound(err error) bool {
	ae, ok := AsAPIError(err)
	return ok && ae.StatusCode == http.StatusNotFound
}

// errorXML is the shape S3 uses for error responses.
type errorXML struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	RequestID string   `xml:"RequestId"`
	Resource  string   `xml:"Resource"`
}

// newAPIError builds an APIError from a response, consuming its body.
//
// A provider that returns a body which is not the documented XML -- an HTML
// error page from a proxy in front of it, say -- still produces a usable error
// rather than a parse failure that hides the status code.
func newAPIError(resp *http.Response) *APIError {
	out := &APIError{
		StatusCode: resp.StatusCode,
		RequestID:  resp.Header.Get("x-amz-request-id"),
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	if err == nil && len(body) > 0 {
		var parsed errorXML
		if xml.Unmarshal(body, &parsed) == nil && parsed.Code != "" {
			out.Code = parsed.Code
			out.Message = parsed.Message
			out.Resource = parsed.Resource
			if parsed.RequestID != "" {
				out.RequestID = parsed.RequestID
			}
			return out
		}
	}

	out.Code = statusCode(resp.StatusCode)
	out.Message = http.StatusText(resp.StatusCode)
	return out
}

// statusCode maps a bare HTTP status to the S3 error code a client expects,
// for providers that answer without a body.
func statusCode(status int) string {
	switch status {
	case http.StatusNotFound:
		return "NoSuchKey"
	case http.StatusForbidden:
		return "AccessDenied"
	case http.StatusPreconditionFailed:
		return "PreconditionFailed"
	case http.StatusRequestedRangeNotSatisfiable:
		return "InvalidRange"
	case http.StatusNotModified:
		return "NotModified"
	default:
		return "InternalError"
	}
}
