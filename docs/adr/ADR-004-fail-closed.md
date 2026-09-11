# ADR-004 — Fail-closed by aborting the connection after response headers are sent

**Status:** Accepted
**Date:** 2026-09-11
**Milestone:** M2
**Implements:** `internal/proxy` (`getObject`)

## Context

The governing rule is that no byte of unauthenticated plaintext leaves the proxy.
Chunk authentication gives that within the format: a chunk's plaintext is
released only after its tag verifies.

HTTP makes the *reporting* of a failure harder than the detection of one. A
download is a single response: status line, then `Content-Length`, then the body.
Those first two are a promise, and they have to be made before the body is
produced — which for a 5 TiB object means long before the last chunk is
authenticated.

So there are two distinct situations:

1. Something is wrong **before** the promise is made: the data key does not
   unwrap, the metadata is malformed, the segment header is not what it should be,
   the first chunk does not verify.
2. Something is wrong **after** it: chunk 4,000 of 60,000 fails authentication,
   with 250 MB of authentic plaintext already delivered.

In the second case there is no legal way to say so. Appending an XML error
document to the body would hand the client bytes it would read as object content —
producing a file that is corrupt in a way nothing detects. That is strictly worse
than the corruption being defended against.

## Decision

Split the two cases, and make the first as large as possible.

**Before the status line**, `getObject` does everything that can fail:

1. parse the object metadata,
2. unwrap the data key, with bucket and key as associated data,
3. read and validate the segment header,
4. **decrypt and verify the first chunk** (`DecryptReader.VerifyFirst`),
5. check the recorded chunk size against the authenticated one,
6. compute the plaintext length from the ciphertext length.

Only then are `200 OK` and `Content-Length` written. Everything above produces an
ordinary S3 error response with the code `IntegrityCheckFailed` and status 502.

**After the status line**, a failing chunk causes `panic(http.ErrAbortHandler)`.
Go's server recovers it without logging a stack trace and drops the connection:
on HTTP/1.1 it closes, on HTTP/2 it resets the stream. The client sees fewer bytes
than the declared `Content-Length`, which every correct HTTP client treats as a
failed transfer.

Each failure is logged with bucket, key, chunk index and kind, and never with key
material. M5 turns the same event into
`blindbucket_integrity_failures_total{kind}`.

## Alternatives considered

**Buffer the whole object, verify it, then respond.** Gives a clean error in every
case. Rejected outright: it is the opposite of goal G3, and impossible above a few
gigabytes.

**Send an error document appended to the partial body.** Rejected: it corrupts the
object silently, which is the failure mode being defended against.

**Use HTTP trailers to signal failure.** Correct in principle, and HTTP/1.1 chunked
encoding supports them. Rejected: almost no S3 client reads response trailers, so
the signal would be ignored by the software that needs it, while `Content-Length`
would have to be dropped — removing the short-read detection that actually works.

**Respond with `Content-Length` omitted and chunked encoding, terminating the
stream early.** Equivalent in effect to the abort, but weaker: without a declared
length a client cannot distinguish a truncated transfer from a complete one, so
the very signal being relied upon disappears.

**Buffer only small objects** (say, under 1 MiB) so they always get a clean error.
Genuinely attractive, since most objects are small and the memory cost is bounded.
Deferred rather than rejected: it is an open question in `CONCEPT.md` section 21,
and it interacts with the range-request design in M3. Doing it now would mean two
code paths before the second one exists.

## Consequences

**Positive.**

- Every failure that can be reported cleanly is: wrong key, tampered metadata,
  forged header, corrupted first chunk, impossible ciphertext length.
- A failure that cannot be reported cleanly is at least unmistakable — a short
  read against a declared length, never a plausible-looking file.
- No plaintext is ever released unverified, in either case.

**Negative.**

- A client that ignores short reads keeps a truncated file. That is a client
  defect, but a real consequence, and it is written down in
  `docs/THREAT_MODEL.md` section 5.3 rather than left implicit.
- The error a client sees for a late failure is a transport error, not an S3 one,
  so the reason lives only in the proxy's logs. The request id is echoed in
  `x-amz-request-id` so the two can be tied together.
- `VerifyFirst` costs one chunk of latency before the first byte. At the default
  chunk size that is 64 KiB and one GCM operation.
- Verifying the first chunk before responding means a `GET` of an object whose
  *body* is fine but whose *provider* is slow will block until at least one chunk
  has arrived. That is inherent: there is nothing to authenticate until then.
