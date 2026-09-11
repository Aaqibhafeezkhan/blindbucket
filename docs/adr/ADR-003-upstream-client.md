# ADR-003 — A custom upstream client on `net/http` instead of the SDK's S3 client

**Status:** Accepted
**Date:** 2026-09-11
**Milestone:** M2
**Implements:** `internal/upstream`

## Context

The proxy has to talk S3 to the storage provider. The obvious choice is
`aws-sdk-go-v2/service/s3`, which is maintained by the vendor, handles every
provider quirk, and is what any reviewer would expect.

It also fights the one property this project exists to have. The SDK client is a
middleware stack, and several of its stages assume a request body is a thing you
can hold:

- **Payload signing.** By default the S3 client computes the SHA-256 of the body
  to sign it, which means reading the body to the end before sending the first
  byte. For a 5 TiB object that is not a slow path, it is an impossible one.
- **Automatic checksums.** Recent SDK versions attach a CRC of the body. Ours is
  ciphertext; the client's checksum covers plaintext. Two different checksums for
  two different byte streams, one of which the provider would then also verify.
- **Retries.** The retry middleware wants to rewind and resend a body. A body
  that came from a client socket cannot be rewound, and re-encrypting it would
  draw a new salt and produce different bytes than the Content-Length promised.
- **Opacity.** What actually goes over the wire is the sum of a dozen middleware
  stages. For a component whose entire job is controlling exactly which bytes
  reach the provider, that is the wrong property.

Working around each of these means disabling middleware until what is left is a
signer and an HTTP client.

## Decision

Use `net/http` directly, plus **only** the SigV4 signer from
`aws-sdk-go-v2/aws/signer/v4`.

- Requests are signed with `UNSIGNED-PAYLOAD`. Transport integrity comes from
  TLS; content integrity comes from the segment format, which authenticates every
  chunk independently of the transport.
- The signer runs with `DisableURIPathEscaping`, because S3 — alone among AWS
  services — does not double-encode the canonical path.
- The URL's escaped path is built by hand with the AWS `UriEncode` rules rather
  than `net/url`'s path escaping, which leaves `+`, `:`, `@`, `$`, `&` and `=`
  unescaped. SigV4 signs the escaped path, so relying on Go's rules produces
  signature failures for ordinary object names.
- Uploads carry `Expect: 100-continue`, so an authentication or bucket error is
  seen before a body is streamed.
- Retries are limited to requests without a body.

The signer is kept rather than hand-rolled for a reason beyond convenience: M3
has to *verify* inbound SigV4 signatures, and having a known-good implementation
of the same canonicalisation in the same binary makes it possible to test the
verifier against it directly.

## Alternatives considered

**The full SDK S3 client with middleware removed.** Achievable — the stack is
configurable — but the result is a client configured mostly by subtraction, where
an SDK upgrade can reintroduce a stage and quietly start buffering. The failure
mode is a memory regression under load, which is the hardest kind to notice.

**MinIO's `minio-go`.** Lighter than the AWS SDK and streaming-friendly. Rejected
because it still owns request construction, and because it targets MinIO's dialect
first; the provider matrix here includes AWS, R2 and B2.

**Hand-rolled SigV4 signing as well.** Tempting, since M3 needs the
canonicalisation anyway and it would drop the last AWS dependency. Rejected for
now: a reference implementation to test the verifier against is worth more than
one fewer module, and signing bugs against real providers are loud but tedious.
Revisit once the verifier exists and is covered by the AWS test-suite vectors.

**Signing the payload properly instead of `UNSIGNED-PAYLOAD`.** Would let the
provider reject a corrupted body itself. Rejected: it requires the hash before the
first byte, so it requires buffering. The chunked variant
(`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`) avoids buffering but adds per-chunk
framing on top of the segment format's own, for integrity the format already
provides end to end.

## Consequences

**Positive.**

- Memory per upload stays at one chunk, whatever the object size.
- What goes over the wire is visible in one file and testable directly.
- Only the signer is a third-party dependency on the request path.
- Path encoding is explicit, and covered by integration tests with keys
  containing spaces, plus signs, hashes, question marks, brackets, umlauts and
  emoji — the cases where an encoding mistake actually surfaces.

**Negative.**

- Every operation the proxy needs has to be written by hand. Today that is four;
  multipart in M4 adds five more.
- Provider quirks the SDK absorbs silently now have to be discovered and handled
  here. `docs/COMPATIBILITY.md` is where they get recorded.
- The signer remains an AWS dependency, so its API is not entirely ours to pin.
- `UNSIGNED-PAYLOAD` means the provider cannot detect a body corrupted in
  transit. TLS covers the wire, and the format covers the rest: a corrupted body
  fails authentication on the way out. The provider simply stores garbage it
  cannot tell from ciphertext — which is true of every byte it stores anyway.
