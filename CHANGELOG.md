# Changelog

Notable changes per release. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [semantic versioning](https://semver.org/spec/v2.0.0.html) —
with the caveat that before `1.0.0` the wire format is the thing held stable, not
the Go API.

The **wire format** is versioned separately and independently: the segment format
is version `1` and is specified in [docs/FORMAT.md](docs/FORMAT.md). A change to
it would be a change to that number, announced here, and objects written under
version 1 would keep being readable.

## [Unreleased]

### Added

**Server-side copy.** `CopyObject` and `UploadPartCopy`, the two operations
`v0.1.0` refused, which between them are what `aws s3 cp s3://a s3://b` and
`aws s3 mv` are made of. A copy does not move the object: the data key is
unwrapped under the source's identity and wrapped again under the
destination's — the wrap is bound to bucket and key (FORMAT §6.1) — while the
ciphertext is copied inside the provider. 1.2 KB crosses the wire for a 600 KB
object. Multipart objects keep their part boundaries and get their own manifest
under a new id, by the same rules rotation follows.

`UploadPartCopy` is the exception, and necessarily so: a part is a segment with
its own salt, so the destination's part shares no bytes with the source's
ciphertext even over identical plaintext. That range is decrypted and
re-encrypted on the way through, at `O(chunk size)` memory. It is the path the
AWS CLI takes above its 8 MiB threshold, and a 1 GiB copy through 128 part
copies returns an identical SHA-256.
[ADR-012](docs/adr/ADR-012-copy-semantics.md) records both decisions, including
why a shared data key is not nonce reuse in the sense that matters.

**`GetObjectTagging`**, forwarded to the provider, because the AWS CLI asks for
the source's tags before a server-side copy.

### Changed

**Object tags are refused rather than ignored.** `PutObjectTagging`,
`DeleteObjectTagging` and `x-amz-tagging` on an upload answer `NotImplemented`
and say why: the provider would store them in plaintext. Previously
`x-amz-tagging` was accepted and silently dropped, which left a client believing
its object carried tags it did not.

**`internal/objcopy`** now holds the republish logic that `internal/rotate` had
its own copy of. The manifest lifecycle rules R1-R3 are an ordering of three
writes that `spec/tla/Multipart.tla` checks; two implementations would
eventually be two orderings, and only one of them was the one the model checked.

## [0.1.0] — 2026-09-12

The first release. A transparent S3 encryption gateway: point a client at it
instead of the storage provider, and the provider only ever sees ciphertext.

### Added

**The format and the crypto core.** AES-256-GCM in a STREAM-style segment format
with 64 KiB chunks and an authenticated header, one data key per object, and a
three-level key hierarchy with an external root key. Tampering, truncation,
reordering and part substitution are all detected. Specified in
[docs/FORMAT.md](docs/FORMAT.md) before it was implemented, and pinned by ten
known-answer vectors that are a normative part of the specification.

**The gateway.** `PutObject`, `GetObject`, `HeadObject`, `DeleteObject`,
`ListObjects`/`V2`, `DeleteObjects` and the bucket operations, with SigV4
verification in both directions, `aws-chunked` bodies with and without trailers,
checksum verification, range requests over ciphertext, and virtual-hosted-style
addressing. Sizes reported to clients are plaintext sizes.

**Multipart uploads.** Parts arrive in parallel, in any order, on any instance,
and are retried freely. The gateway keeps no state for any of it: the upload id a
client receives is a sealed token carrying the data key and the manifest id
([ADR-006](docs/adr/ADR-006-upload-token.md)). A signed manifest binds the parts
into one object ([ADR-007](docs/adr/ADR-007-manifest-sidecar.md)), and
`blindbucket gc` collects the orphans that ordinary operation leaves behind.

**Key rotation.** `blindbucket rotate` re-wraps data keys under a new KEK without
moving ciphertext: a thousand 64 KiB objects rotate in about 1.5 seconds while
1.4 MiB crosses the wire, against 62.5 MiB of payload. Writes are conditional, so
a client write that lands mid-rotation wins ([ADR-009](docs/adr/ADR-009-rotation-by-copy.md)).

**Operations.** Metrics, `/healthz`, `/readyz` and optional pprof on a separate
admin listener that defaults to loopback. Graceful shutdown. A distroless,
nonroot image and a Kubernetes sidecar example in [deploy/](deploy/).

Transfers have no fixed time limit and no unbounded one either: there is no
global `WriteTimeout`, because it would cut off a large download regardless of
progress, and instead the connection's deadlines are renewed as bytes move. A
5 TiB download may take hours; a connection that has moved nothing for a minute
is closed.

### Verified

**A formal model.** Concept version 0.1 contained two race conditions in the
manifest lifecycle, both ending in an unreadable object. The rules that replace
them are checked in TLA+ before the code implemented them: 38.5 million states,
no counterexample, and four configurations that are *required* to produce one.
Each counterexample is an integration test. The model found a third problem
nobody was looking for — the order of two read-only steps in `gc` is
load-bearing ([ADR-010](docs/adr/ADR-010-manifest-lifecycle-under-concurrency.md)).

**An independent decoder.** [ref/python/](ref/python/) is a second decoder written
from the format specification, agreeing with the Go one on every vector and on
100 000 mutated inputs. Writing it found one ambiguity in the specification,
which is now fixed.

**Measurements, not claims.** 10 MiB objects move at 92–97 % of what the provider
manages without the gateway in the way; 1 KiB objects cost about half a
millisecond per request. 10 GiB streams through at 82 MiB peak resident. Scripts,
figures and the methodology are in [bench/](bench/).

### Known limitations

- **Key providers:** the file-backed keyring only. The `KeyProvider` interface is
  what AWS KMS and Vault implementations will slot into; neither exists yet.
- **`CopyObject`** is refused. The copy machinery is in the upstream client
  because rotation needs it, but the S3 operation is not wired up.
- **`ListMultipartUploads`** is refused, and will stay that way: the upload ids
  this gateway issues cannot be reconstructed from the provider's listing.
- **`UploadPartCopy`** is refused.
- **Object names are not encrypted**, and object sizes are visible to the
  provider. Both are recorded in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) as
  accepted, with the M6 options that would change them.
- **rclone and `mc`** need `allow_unsigned_payload` on the proxy; `mc` needs it
  only for multipart. See [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).
- **One benchmark cell** — 10 MiB uploads at 64 concurrent clients — runs at 18 %
  of the direct path. The gateway's share is measured at 0.13 ms per request out
  of ten seconds, so the time is the provider's; why it behaves that way under
  this access pattern is not established.

[Unreleased]: https://github.com/LennardGeissler/blindbucket/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/LennardGeissler/blindbucket/releases/tag/v0.1.0
