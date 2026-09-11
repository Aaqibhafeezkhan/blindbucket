# ADR-005 — Checksums: verify locally, never forward, withhold the final chunk

**Status:** Accepted
**Date:** 2026-09-11
**Milestone:** M3
**Implements:** `internal/auth` (`BodyReader`, `ChunkedReader`), `internal/proxy` (`putObject`)

## Context

Current AWS SDKs and the AWS CLI attach a checksum to every upload without being
asked. Depending on version it is CRC32 or CRC64NVME, sent either as an
`x-amz-checksum-*` header or — more often now — in an aws-chunked trailer after
the body. The client computes it over the bytes it sends, and expects the service
to verify it and echo it back.

Through this gateway those bytes are plaintext, and what reaches the provider is
ciphertext. So the checksum cannot simply be forwarded: the provider would
compute a completely different value and reject every upload. There are three
options and they are not equally honest.

The second problem is timing. A checksum is only known once the body has ended,
and by then the proxy has already streamed almost all of the ciphertext upstream.
Verifying it "before uploading" would require buffering the object, which is the
one thing this design refuses.

## Decision

**Verify at the proxy, never forward, and use the encoder's lookahead as the
commit point.**

1. Every checksum a client supplies — `x-amz-checksum-*` in headers or trailers,
   `Content-MD5`, and the hex `x-amz-content-sha256` — is computed over the
   plaintext as it streams through, and settled the moment the body ends.
2. None of them are sent upstream. The provider receives no checksum header at
   all, so it applies none.
3. The verified values are echoed back to the client in the response, because the
   provider's own checksum headers describe ciphertext and are stripped.
4. The failure lands in the window the format already creates. `EncryptWriter`
   withholds its final chunk until `Close`, so at the moment the checksum is
   settled the upstream request is still incomplete. A mismatch aborts it before
   a complete body is ever sent: no object is created, nothing was buffered, and
   the client gets `BadDigest`.

A checksum announced in `X-Amz-Trailer` starts hashing from the first byte. One
that arrives in the trailer *without* having been announced is refused, not
ignored — see the consequences below.

## Alternatives considered

**Forward the client's checksum upstream.** Fails immediately and always: it
describes plaintext and the provider sees ciphertext. Not viable.

**Compute a fresh checksum over the ciphertext and send that.** The provider
would then verify the transfer between proxy and provider, which is real value.
Rejected for now because it requires the ciphertext hash before the body is sent,
which means buffering — and the segment format already authenticates every chunk
end to end, so a corrupted transfer is caught on the way out regardless. The
provider would only be detecting corruption the format detects anyway.

**Ignore client checksums entirely.** Simplest, and tempting because a client
that gets no error assumes success. Rejected outright: it turns a detectable
corruption into an undetectable one. A client that computes a checksum has
declared it cares; silently dropping that is worse than refusing the request.
This is also why an unannounced trailer checksum is an error rather than a
no-op — the proxy has no hash running for it, so it cannot honour the check, and
pretending otherwise would be a lie about what was verified.

**Buffer the object and verify before uploading.** Gives a clean error in every
case with no ordering subtleties. Rejected: it is goal G3 inverted, and
impossible above a few gigabytes.

**Verify after upload and delete the object on mismatch.** Avoids buffering.
Rejected: it creates a window in which a corrupt object is readable, and the
cleanup can fail — leaving exactly the bad object the checksum was meant to
prevent.

## Consequences

**Positive.**

- A client's integrity check is honoured end to end, against the bytes it
  actually sent.
- A failed checksum leaves nothing behind: the upstream request never completes,
  so there is no half-written object and no cleanup to get wrong.
- No buffering. Memory stays at one chunk regardless of object size.
- The response carries checksums that describe the plaintext, which is what the
  client can actually compare against.

**Negative.**

- The provider performs no integrity check of its own on the transfer between
  proxy and provider. TLS covers the wire and the format covers the content, but
  the provider is storing bytes it cannot distinguish from noise — which is true
  of everything it stores here.
- Checksum verification is CPU work on the proxy, on top of encryption. CRC32 and
  CRC64 are cheap; SHA-256 for `x-amz-content-sha256` is not free, and a client
  that signs its payload pays for hashing it twice, once on each side.
- A trailer checksum that was not announced in `X-Amz-Trailer` is rejected. If a
  client is found that sends one that way, this becomes a compatibility bug to
  fix in `docs/COMPATIBILITY.md` rather than a policy to relax.
- Composite checksums for multipart uploads are not addressed here. They belong
  with M4, where the parts that make them up exist.
