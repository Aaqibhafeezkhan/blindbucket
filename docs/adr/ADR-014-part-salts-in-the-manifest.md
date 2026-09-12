# ADR-014 — Part salts in the manifest, carried there by the part ETag

**Status:** Accepted
**Date:** 2026-09-12
**Milestone:** post-M5 (THREAT_MODEL §5.2)
**Implements:** `internal/manifest` (`BBM2`), `internal/upload/parttag.go`, `internal/proxy`

## Context

A client may upload the same part number twice — a retry after a timeout, a
resumed transfer, a tool that changed its mind. Each attempt is a complete,
authentic segment: the part number is authenticated in its header, the sizes are
equal, every chunk tag verifies under the object's data key.

The manifest recorded a part number and a plaintext size. Nothing in it, and
nothing in the segments, distinguished one attempt from another. An active
provider could therefore serve either, and the object would read back as
perfectly valid with one part's contents silently replaced by a version the
client had abandoned.

`THREAT_MODEL` §5.2 recorded this as accepted, with a planned mitigation:
record part ETags in the manifest and verify the ciphertext MD5 per part on
full reads. This decision replaces that plan.

## Decision

### The manifest records each part's segment salt

`FORMAT.md` §4.1 already requires a fresh salt per segment, *including for every
retried attempt at the same part number* — that requirement exists to make nonce
reuse impossible across retries. It therefore already identifies the attempt,
and the manifest only has to write it down.

A reader compares the manifest's salt against the segment header when it opens
that part, **before releasing any of its plaintext**. The salt is associated
data of every chunk in the segment, so a provider cannot forge one without
breaking every tag; it can only substitute a whole genuine segment, which is
precisely what the comparison catches.

Chosen over the planned ETag verification for two reasons. It costs nothing on
the read path — a 20-byte comparison per part against a header that is parsed
anyway — where hashing the ciphertext would put MD5 in series with AES-GCM and
take the measured 7.2 GB/s of the crypto core to somewhere under 1 GB/s. And it
detects *before* the part is delivered rather than after: an MD5 completes at
the end of the part, by which time the plaintext is out and the only remedy is
the connection abort of §5.3.

### The salt reaches the completion inside the part ETag

This is the part that decides whether the above is implementable at all.

The gateway is stateless. The instance that completes an upload may never have
seen the part, and **a part of an open multipart upload cannot be read back** —
it is not an object until the upload completes, which was verified against MinIO
rather than assumed. The manifest must exist before the object does (rule R2).
So at the moment the manifest is written, the salts are not obtainable from the
provider by any means.

They are obtainable from the client. S3 has the client echo each part's ETag
back at completion; that is the one channel connecting the upload of a part to
the completion of the upload. The gateway therefore answers an `UploadPart` with
the provider's ETag followed by `.` and the salt sealed under a key derived from
the KEK, bound to the part number as associated data. At completion it opens the
suffix and records the salt.

The sealing is not confidentiality — the salt sits in the segment header the
provider already holds. It is integrity: a garbled or transplanted tag becomes a
clean `InvalidPart` at completion, rather than a manifest naming a segment that
does not exist and an object that fails at its first read.

Part ETags are consequently no longer plain hex. Measured before committing to
it: the AWS CLI, boto3, `mc` and rclone all treat a part ETag as opaque and echo
it unchanged, each verified with a full multipart round trip and an identical
SHA-256. The object's own ETag is untouched.

### `BBM1` manifests are still read, and upgraded when rewritten

The format moves to `BBM2`. A `BBM1` manifest has no salts, is accepted, and its
parts carry none — a reader must not compare against an absent salt, which would
reject every object an older build wrote. Those objects keep the original risk.

Copying or rotating such an object rewrites its manifest as `BBM2`, and there the
salts *are* recoverable: a finished object's part headers can be read, unlike an
open upload's. So the upgrade path exists and is the one operators already have.

## Alternatives considered

**Part ETags verified as a ciphertext MD5 on read**, the planned mitigation.
Rejected on the two grounds above: an order-of-magnitude cost on the read path,
and detection only after delivery.

**Fetch the part headers at completion.** The obvious implementation, and the
one this ADR originally set out to write. It cannot be built: the parts are not
readable before the upload completes, and the manifest cannot be written after.
Recorded here because it is the first thing anyone will propose.

**Write the manifest without salts, complete, then rewrite it with them.** Makes
the parts readable by completing first. Rejected: it makes a manifest mutable,
which rules R1–R3 and the model in `spec/tla/` treat as immutable, and it leaves
a window in which the object names a manifest that cannot detect substitution.
A correctness property that holds except briefly is not the property.

**A sidecar object per part holding its salt**, written at `UploadPart` and read
at completion. Stateless and workable. Rejected: it doubles the request count of
every multipart upload, and it introduces a new class of object under the
reserved prefix, which means `gc`'s rules — model-checked in `spec/tla/` — would
have to grow a second kind of orphan. A large cost in the part of the system
that is most expensive to change.

**Derive the salt from the part number and the DEK** so that any instance can
recompute it. Rejected outright: two attempts at one part number would then
share a salt *and* a key *and* chunk counters, over different plaintext. That is
the catastrophic nonce reuse the fresh-salt rule exists to prevent, and it would
trade a substitution risk for a confidentiality break.

## Consequences

- Retry substitution is detected. The attack test uploads part 1 twice with
  different content, completes on the second, then has the provider substitute
  a re-encryption of the first — bytes this gateway would itself have written —
  and requires a refusal. With the salt comparison removed, that test serves the
  substituted object, so it is testing the mechanism and not its own setup.
- Part ETags gain a suffix. In `docs/COMPATIBILITY.md`, with the four clients it
  was measured against.
- The manifest grows 20 bytes per part: 300 KB at the 10000-part maximum, inside
  the 1 MiB bound a manifest is read under.
- `internal/upload` gains a second sealed value alongside the upload token,
  keyed by HKDF from the token key so the two cannot collide.
- The reference decoder and the known-answer vectors are untouched: both cover
  the segment format, and the manifest is not part of it.
