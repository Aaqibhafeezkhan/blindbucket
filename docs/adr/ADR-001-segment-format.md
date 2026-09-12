# ADR-001 — Segment format: STREAM with AES-256-GCM, 64 KiB chunks, authenticated header

**Status:** Accepted
**Date:** 2026-09-11
**Milestone:** M0
**Normative output:** [`docs/FORMAT.md`](../FORMAT.md) §4–§8

## Context

blindbucket must encrypt object bodies that range from zero bytes to the S3 maximum of
5 TiB, under three constraints that pull against each other:

1. **Constant memory** (goal G3): memory per stream must be `O(chunk size)`, not
   `O(object size)`.
2. **Authenticated encryption** (goal G2): no byte of unauthenticated plaintext may ever
   reach a client.
3. **Range requests** (goal G4): clients read arbitrary byte ranges, and standard S3
   clients do this constantly.

Go's `cipher.AEAD` operates on complete byte slices — `Seal` and `Open` both require the
entire message in memory. That alone rules out encrypting an object as a single AEAD
message. Two further problems make it unsalvageable:

- GCM permits at most `2^39 - 256` bits (~64 GiB) of plaintext per message. S3 objects
  can be 5 TiB.
- Even a hand-rolled streaming GCM would have to withhold all plaintext until the tag at
  the very end verified. Releasing plaintext earlier breaks the AEAD guarantee; releasing
  it later means buffering the whole object. And a range request could never be
  authenticated at all, because the tag covers the whole message.

## Decision

Encrypt each stream as a **segment**: a 32-byte cleartext header followed by a sequence of
independently sealed chunks, following the STREAM construction (Hoang–Reyhanitabar–Rogaway–Vizár,
CRYPTO 2015).

- **Chunk cipher:** AES-256-GCM, 96-bit nonce, 128-bit tag.
- **Default chunk size:** 64 KiB (`log2C = 16`), configurable from 4 KiB to 1 MiB.
- **Nonce:** `uint88_be(chunk index) || final flag`. The final flag makes truncation and
  extension detectable.
- **Per-segment subkey:** `HKDF-SHA256(DEK, salt = 20 random bytes from the header,
  info = "blindbucket/v1/segment")`.
- **Header as associated data:** the full 32-byte header is passed as AAD to every chunk
  in the segment, which authenticates the chunk size, the multipart flag and the segment
  index.

The 64 KiB default is chosen because: the tag overhead is `16/65536 ≈ 0.024%`; a range
request over-reads at most 64 KiB; the per-stream buffer stays small enough for goal G3;
and every common S3 client part size (5, 8, 16 MiB) is a multiple of 64 KiB, which is the
precondition for the multipart size arithmetic in `FORMAT.md` §7.

## Alternatives considered

**One AES-GCM message per object.** Rejected: violates all three constraints above, and
exceeds GCM's per-message plaintext limit for large objects.

**AES-CTR over the whole object plus a separate HMAC.** Allows seeking cheaply, and range
requests are trivial. Rejected: the MAC covers the entire object, so a range read cannot be
authenticated without fetching everything. It also reintroduces encrypt-then-MAC composition
by hand, which is exactly the kind of bespoke construction this project wants to avoid.

**AES-GCM-SIV per chunk.** Nonce-misuse resistant, so a salt-per-segment would not be
strictly necessary. Rejected: not in the Go standard library, and the fresh-salt-per-segment
design already removes nonce reuse as a concern (see ADR context in `FORMAT.md` §11).

**Tink Streaming AEAD (`AES256_GCM_HKDF_4KB`) as a dependency.** A well-reviewed
implementation of essentially this construction. Rejected: it would put a third-party
dependency in the security-critical core, its segment header is not designed to carry the
multipart part number that blindbucket needs in the AAD, and an explicit, documented format
is a deliverable of this project rather than an implementation detail.

**Larger chunks (1 MiB).** Lower relative overhead (0.0015%) and fewer GCM invocations.
Rejected as the default: it multiplies per-stream memory by 16 and makes small range
requests over-read up to 1 MiB. It remains available via `log2C = 20`.

## Consequences

**Positive.**

- Memory per stream is `C + 16` bytes plus small fixed overhead, regardless of object size.
- Range requests decrypt only the chunks they touch.
- Truncation, extension, chunk reordering, chunk duplication, chunk-size reinterpretation
  and part reordering are all detected, because index and final flag are in the nonce and
  the header is in the AAD.
- The format is small enough to specify normatively and to pin down with known-answer test
  vectors, which makes independent review realistic.

**Negative.**

- Ciphertext is larger than plaintext by `32 + 16*ceil(P/C)` bytes. At the default chunk
  size this is under 0.025%, but it is not zero, and it makes the ETag differ from the MD5
  of the plaintext — visible to clients such as rclone (`docs/COMPATIBILITY.md`).
- The exact plaintext size is recoverable from the ciphertext size. This is required for
  computing `Content-Length` and for listings, and it is an accepted metadata leak
  (`THREAT_MODEL.md`).
- The encoder must hold back the last completed chunk until close, because it cannot know
  in advance whether more plaintext follows. This lookahead is a real complication — but it
  is also what makes the checksum-before-commit behaviour possible.
- A decoder must validate the header *before* allocating buffers sized from it, since the
  header is only authenticated once the first chunk verifies. This ordering requirement is
  easy to get wrong and is called out explicitly in `FORMAT.md` §5.2.
