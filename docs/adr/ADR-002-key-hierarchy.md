# ADR-002 — Key hierarchy: external root key, in-memory KEK ring, one DEK per object

**Status:** Accepted
**Date:** 2026-09-11
**Milestone:** M0
**Normative output:** [`docs/FORMAT.md`](../FORMAT.md) §3, §6

## Context

Every encrypted object needs a key, and that key has to be recoverable later by any proxy
instance, without a shared database and without the storage provider ever seeing it. Three
requirements shape the design:

1. **Per-object key separation.** Reusing one key across all objects would put an unbounded
   amount of data under a single AES-GCM key and make compromise total rather than local.
2. **Rotation without re-uploading data** (goal G6). Rotating the key material of a 10 TB
   bucket must not move 10 TB over the network.
3. **No per-object KMS call.** A KMS round trip per `PutObject` adds network latency to
   every request and is billed per call. At small object sizes it would dominate.

## Decision

Three levels:

```
Root key   external: AWS KMS, Vault Transit, or Argon2id over a passphrase
 └─ KEK    32 bytes, several versions in a keyring, each with an id such as "2026-09"
     └─ DEK  32 bytes from the CSPRNG, one per object or per multipart upload
```

- The **keyring** holds all KEK versions. It is decrypted once at process start via the
  configured `KeyProvider` and held in memory. The root key never wraps individual objects.
- A fresh **DEK** is generated per object and wrapped locally with AES-256-GCM under the
  active KEK. The wrapped DEK (60 bytes) is stored in the object's own metadata as
  `x-amz-meta-bb-dek`, alongside the KEK id in `x-amz-meta-bb-kid`.
- The **wrapping AAD binds the object's identity**:
  `"blindbucket/v1/dek" || lp(kid) || lp(bucket) || lp(key)`.
- Two further keys are derived from material already present rather than stored: the
  per-segment subkey from the DEK and the segment salt, and the upload-token key from the
  KEK via HKDF.

## Alternatives considered

**One KMS `GenerateDataKey` call per object.** The canonical AWS envelope-encryption
pattern. Rejected: latency and cost per request, and it makes the proxy hard-depend on KMS
availability for every single upload. The keyring achieves the same separation with one
call at startup.

**A single global key with no hierarchy.** Simplest possible design. Rejected: no rotation
story that does not rewrite every object, and it places the entire bucket under one GCM key.

**Storing wrapped DEKs in a sidecar index object or a database.** Would allow rotating DEKs
(not just KEKs) and would enable a rollback-detecting version index. Rejected for now: it
reintroduces shared mutable state, which is exactly what goal G5 (stateless horizontal
scaling) avoids, and it creates a consistency problem between index and object. Object
metadata is atomic with the object it describes. The rollback mitigation is deferred to M6.

**Deriving the DEK from the object key via a KDF** (`DEK = HKDF(KEK, key)`). Removes the
need to store anything per object. Rejected: overwriting an object would reuse the same DEK
for different plaintext, and while the fresh per-segment salt would still prevent nonce
reuse, it collapses the separation between object versions for no real benefit. It also
breaks copy and rename, which would have to re-encrypt rather than re-wrap.

**Binding only the bucket, not the key, into the wrapping AAD.** Cheaper on rename.
Rejected: it would let an active provider swap two objects within a bucket, together with
their metadata, undetected.

## Consequences

**Positive.**

- One KMS or Vault call per process start, not per request.
- KEK rotation touches only metadata: re-wrap the DEK and write it back with a
  server-side copy. No object bytes move.
- Compromise of one DEK exposes one object.
- Because bucket and key are in the AAD, swapping objects together with their metadata is
  detected at unwrap time, before any plaintext is produced.
- Proxy instances share only the keyring, so multipart uploads need no sticky sessions.

**Negative.**

- KEKs live in process memory for the lifetime of the process. Go offers no reliable memory
  zeroisation, so the proxy host must be trusted; this is actor A5 in
  [`THREAT_MODEL.md`](../THREAT_MODEL.md) and explicitly out of scope.
- Rotation rotates the KEK, not the DEK. A leaked DEK can only be addressed by re-encrypting
  the affected object. This must be stated plainly in the README rather than letting
  "key rotation" imply more than it delivers.
- Renaming or copying an object requires unwrapping and re-wrapping the DEK, because the AAD
  changes. Copies can therefore not be pure server-side metadata passthrough; the proxy must
  be in the path with `x-amz-metadata-directive: REPLACE`.
- Roughly 150 bytes of the 2 KB S3 user-metadata budget are consumed by `bb-` headers.
- Argon2id at the RFC 9106 parameters allocates 64 MiB while the keyring is
  unlocked, which dominates the process's peak resident memory. Measured: peak RSS
  is ~70 MiB whether the CLI processes 64 MiB or 4 GiB, so the cost is entirely
  the KDF and entirely one-time. The streaming path's own heap stays at roughly
  0.5 MiB for a 10 GiB object.

  This conflicts with the literal reading of goal G3's 20 MiB CLI budget, and the
  conflict is resolved in favour of the KDF: memory hardness is the whole point of
  Argon2id, and lowering it to fit a number would trade real resistance against a
  stolen keyring for a cosmetic figure. G3's claim is what it was always about --
  memory that does not grow with the object -- and that is measured directly on the
  Go heap rather than inferred from RSS. The proxy unlocks its keyring once at
  startup, where the spike is irrelevant.
