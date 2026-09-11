# Threat Model

**Status:** Draft (M0). Revised at every milestone that adds an attack surface.
**Last updated:** 2026-09-11

This document states precisely what blindbucket protects against and what it does not.
It is deliberately explicit about residual risk. A security tool that overstates its
guarantees is worse than one that states modest guarantees accurately.

For the same reason this project does not describe itself as "zero trust": that term
denotes an access architecture as defined in NIST SP 800-207, not an encryption scheme.

---

## 1. Assets

| Asset | Where it lives |
|---|---|
| Object plaintext | in flight between client and proxy; transiently in proxy memory |
| Key material — root key, KEKs, DEKs, token keys | KMS/Vault/passphrase; proxy memory; wrapped DEKs in object metadata |
| Client credentials for the proxy | proxy configuration |
| Upstream credentials for the storage provider | proxy configuration; never disclosed to clients |

---

## 2. Actors

| ID | Actor | Capabilities | In scope |
|---|---|---|---|
| A1 | Storage provider, passive | Reads everything stored or transmitted to it | Yes |
| A2 | Storage provider, active | Modifies, truncates, reorders, swaps and deletes objects and metadata; replays old data; lies in listings and response headers | Yes, with the limits in §5 |
| A3 | Network attacker between proxy and provider | As A1/A2, on the wire | Yes — TLS reduces this to A1/A2 |
| A4 | Unauthorised client | Sends requests to the proxy without valid credentials, or with credentials scoped to other buckets | Yes |
| A5 | Attacker on the proxy host, or with access to the KEK or root key | Reads memory, configuration, keys | **No** |
| A6 | Network attacker between client and proxy | Reads and modifies plaintext requests | Only insofar as TLS or sidecar deployment covers it |

A5 is the fundamental boundary: the proxy holds keys and sees plaintext by design. It
must reside in the same trust domain as the clients it serves.

---

## 3. Guarantees

| Property | Guaranteed | Mechanism |
|---|---|---|
| Confidentiality of object content against A1–A3 | **Yes** | AES-256-GCM; keys never leave the trust boundary in the clear |
| Integrity of each chunk | **Yes** | One GCM tag per chunk |
| Chunk ordering | **Yes** | Chunk counter in the nonce |
| Detection of truncation and extension | **Yes** | Final flag in the nonce; for multipart also the manifest |
| Binding of content to bucket and key | **Yes** | Bucket and key as associated data when wrapping the DEK |
| Detection of reordered or missing parts | **Yes** | Part number in the authenticated segment header; MAC-protected manifest |
| Client authentication | **Yes** | SigV4 with proxy-specific credentials, constant-time comparison |
| Rollback to an older genuine version of the same key | **No** | Residual risk, §5.1 |
| Confidentiality of names, sizes, timestamps | **No** | §4 |
| Authenticity of sizes reported in listings | **No** | Computed from unauthenticated upstream data, §5.4 |
| Availability | **No** | The provider can delete or refuse access |

---

## 4. What the storage provider still sees

- Bucket names and object keys in cleartext.
- The **exact** plaintext size. The format is length-deterministic, so plaintext size is
  computable from ciphertext size (`FORMAT.md` §7). This is not an oversight; it is the
  property that makes a streaming `Content-Length` and listing sizes possible without
  buffering or extra requests. Size padding is a deferred M6 option.
- `Content-Type`, `Cache-Control` and the client's own user metadata.
- Timestamps of uploads, downloads and deletions.
- Access patterns: which objects, which byte ranges, how often.
- The number of parts of a multipart object.
- The id of the KEK in use — not the KEK itself.

Content *is* hidden. Metadata is not. For workloads where the object names themselves are
sensitive, this matters, and M6 lists deterministic name encryption as a stretch goal.

---

## 5. Residual risks

### 5.1 Rollback

If the provider serves an older but genuine version of the same object — from its own
versioning, for instance — that version is cryptographically valid: the proxy produced it,
and it is bound to the same bucket and key. Nothing in the format distinguishes "current"
from "previous".

Detecting this requires an external, authenticated index of versions, which would
reintroduce the shared mutable state that the stateless design avoids (ADR-002). Mitigation
is deferred to M6 and is currently **accepted risk**.

### 5.2 Retry substitution within a multipart upload

Within one upload, an active provider could substitute part *n* with the bytes of an earlier
transmission attempt of the same part *n*. Both are valid segments produced by the proxy.
In practice clients resend identical content on retry, so this is usually inconsequential.
Planned mitigation (M6): record part ETags in the manifest and verify the ciphertext MD5 per
part on full reads.

### 5.3 Partially delivered plaintext

If a corrupted chunk is detected *after* the response status and `Content-Length` have been
sent, the proxy aborts the connection (`http.ErrAbortHandler`). By then the client has
already received authentic plaintext for the preceding chunks. Because `Content-Length` was
set, a correct client detects a short read and discards the result. A client that ignores
short reads keeps a truncated file — that is a client defect, but it is a real consequence
and is documented rather than hidden.

An open design question (`CONCEPT.md` §21) is whether small ranges should be fully decrypted
into a buffer before the status is sent, trading up to 1 MiB per stream for a clean error
response instead of a connection abort.

### 5.4 Unauthenticated listing sizes

`ListObjectsV2` sizes are converted from the sizes the provider reports. Authenticating them
would cost one request per object. Listings are therefore a hint, not a guarantee; the
authenticated size is established when the object is actually read.

### 5.5 Key material in memory

Go does not guarantee that a buffer can be reliably overwritten — the garbage collector may
copy it. Keys therefore cannot be scrubbed with confidence. Operational mitigations: disable
core dumps, disable or encrypt swap, restrict keyring file permissions to the service user.

### 5.6 DEK compromise

Rotation replaces the KEK, not the DEK. A compromised DEK exposes its object until that
object is re-encrypted. "Key rotation" in this project means KEK rotation, and the README
must not imply more.

### 5.7 Side channels on the proxy host

Timing and cache attacks against the proxy host are out of scope (they fall under A5).
AES-GCM uses hardware acceleration with constant-time behaviour on the platforms Go targets
(AES-NI, ARMv8 Crypto Extensions), and signature comparisons use `hmac.Equal`.

---

## 6. Non-goals

- Hiding metadata (names, sizes, timestamps, access patterns).
- Protecting against a compromised proxy host or leaked KEK (A5).
- Emulating S3 beyond the documented operation set — IAM, bucket policies, object lock,
  lifecycle and replication remain the provider's concern.
- Compression or deduplication. Compressing before encrypting makes ciphertext length
  content-dependent and opens the CRIME/BREACH class of side channels; cross-object
  deduplication is incompatible with a random key per object.
- Availability.

---

## 7. Verification

Each guarantee in §3 is backed by tests that simulate an active provider (A2) and require an
error rather than plaintext. The catalogue is in `CONCEPT.md` §16.2 and covers chunk-level
tampering, header manipulation, object and metadata swapping, multipart reordering, token
forgery, checksum mismatch and authentication failures.

`blindbucket_integrity_failures_total` is exported as a metric. A sustained increase means
either a bug or an actively misbehaving provider, and should alert.
