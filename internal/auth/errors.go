package auth

import "errors"

// Verification failures. They are distinct so the proxy can map each to the S3
// error code a client expects, and so the metrics can tell a misconfigured
// client apart from an attack.
var (
	// ErrMissingAuth reports a request with no Authorization header at all.
	ErrMissingAuth = errors.New("auth: request is not signed")
	// ErrMalformedAuth reports an Authorization header that does not parse.
	ErrMalformedAuth = errors.New("auth: malformed Authorization header")
	// ErrUnknownAccessKey reports an access key id that is not configured.
	ErrUnknownAccessKey = errors.New("auth: unknown access key id")
	// ErrSignatureMismatch reports a signature that does not match. It carries
	// no detail: telling a caller which part was wrong helps only the caller
	// that should not be there.
	ErrSignatureMismatch = errors.New("auth: signature does not match")
	// ErrRequestTimeTooSkewed reports a timestamp outside MaxClockSkew, which is
	// what bounds how long a captured signature stays usable.
	ErrRequestTimeTooSkewed = errors.New("auth: request time is too far from the server clock")
	// ErrBucketNotAllowed reports a credential used for a bucket it is not
	// scoped to.
	ErrBucketNotAllowed = errors.New("auth: credential is not allowed for this bucket")
	// ErrUnsupportedPayload reports a payload mode this build cannot verify.
	ErrUnsupportedPayload = errors.New("auth: unsupported payload signing mode")
)
