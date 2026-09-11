# ADR-006 — Statelessness via an encrypted upload token

**Status:** Accepted
**Date:** 2026-09-11
**Milestone:** M4
**Implements:** `internal/upload` (`Seal`, `Open`)

## Context

A multipart upload is not one request. It is a `CreateMultipartUpload`, up to
10000 `UploadPart` calls that arrive in any order and are retried freely, and a
`CompleteMultipartUpload` — spread over minutes or hours. Between them something
has to remember three things: which upstream upload this is, which data key
encrypts its parts, and which manifest id the finished object will name.

The obvious place to keep that is the gateway. It is also the place that breaks
every property worth having. A proxy holding per-upload state needs sticky
sessions, cannot be restarted while an upload is in flight, and cannot be scaled
by adding instances — which is the entire operational argument for a gateway that
is otherwise a pure function of its input.

The one thing the protocol does give us is a string the client must hand back
with every subsequent call, unchanged and uninterpreted: the `UploadId`. S3
clients treat it as opaque. That is a channel through which the gateway can send
state to itself.

## Decision

Do not return the provider's `UploadId`. Return a sealed token that carries the
whole state of the upload:

```
Token = base64url( 0x01 || lp(kid) || Nonce(12) || AES-256-GCM.Seal(TokenKey[kid], Nonce, Body, AAD) )
Body  = lp(UpstreamUploadId) || WrappedDEK(60) || ManifestID(16)
AAD   = "blindbucket/v1/upload-token" || lp(bucket) || lp(key)
```

`TokenKey[kid] = HKDF-SHA256(ikm=KEK, info="blindbucket/v1/upload-token")`.

Three properties follow from the shape:

**Any instance can serve any call.** The token key hangs off the KEK, which every
instance has in memory already. Nothing is looked up, nothing is shared, and an
instance that has never seen the upload being created can process its parts and
its completion. Instances can be added, removed and restarted mid-upload; the
load balancer needs no affinity.

**A token is bound to one object.** Bucket and key are authenticated as associated
data, not stored. A token obtained for a key the client may write does not open
against any other key, so it cannot be used to widen access. Length prefixes make
the binding unambiguous: without them, bucket `photos` with key `2026/x` and
bucket `photos2` with key `026/x` would produce identical associated data.

**A KEK rotation does not orphan running uploads.** The `kid` travels in clear
text at the front, so a token sealed under the previous KEK is still openable
after the active key changes. This is why the kid is outside the sealed part.

Failures are uniform. A forged token, a token for another object, a truncated one
and one sealed under a KEK that has since been retired all produce `NoSuchUpload`
and nothing else.

### Why the data key is not derived from the UploadId

It would be simpler: no token, derive everything from a value the client already
carries. It is also unsafe, and the reason is worth stating because it is the kind
of thing that looks paranoid until it isn't. The `UploadId` is chosen by the
storage provider. A provider that returned the same `UploadId` for two different
uploads would give them the same data key — and with the same key, two parts
numbered 1 would be sealed under the same (key, nonce) pair. Under GCM that
reveals the XOR of the plaintexts and lets the authentication key be recovered,
which makes tags forgeable. The data key is drawn from the CSPRNG precisely so
that nothing the provider chooses can influence it.

## Alternatives considered

**Keep the state in the gateway, in memory.** Simplest to write, and it ends the
multi-instance story before it starts: sticky sessions, no rolling restarts, and
an upload lost whenever a process dies. The whole design is built on the proxy
being replaceable at any moment.

**Keep it in a shared store — Redis, a database.** Works, scales, and adds a
stateful dependency to a component that otherwise has none, plus a new failure
mode (the store is down, so uploads fail even though both the client and the
provider are healthy) and an operational burden for every deployment. It buys
nothing the token does not already provide, because the state is small, bounded,
and known to exactly one party that is guaranteed to hand it back.

**Store it at the provider, in a sidecar object.** No extra dependency, but it
costs a round trip per part to read it, and it puts the data key in the bucket
under a key derived from something the provider can see — which weakens the
separation the whole design rests on. The manifest is a sidecar object for
reasons of its own (ADR-007); the *key material* is not.

**Encrypt the token with a per-object key instead of one derived from the KEK.**
Circular: the per-object key is inside the token.

**Sign the token instead of encrypting it.** A MAC would stop tampering but leave
the wrapped data key and the provider's upload id legible to anyone who sees a
request. The wrapped key is not usable without the KEK, but there is no reason to
publish it, and the upstream upload id is an internal detail that a client has no
business learning.

## Consequences

- The gateway keeps no upload state. `internal/proxy` has no map, no TTL, no
  cleanup goroutine, and nothing to lose on restart.
- `ListMultipartUploads` cannot be implemented and returns 501 with that reason.
  The provider's listing reports its own upload ids, and a token cannot be
  reconstructed from one: the data key and the manifest id exist only inside the
  token that `CreateMultipartUpload` handed out. Listing ids a client cannot use
  would be worse than refusing.
- `KeyProvider` grows `TokenKey`. A future KMS or Vault provider has to derive it
  the same way, which is why it is in the interface rather than a type assertion
  on `*Keyring`.
- Tokens are longer than a provider's upload id — around 200 characters. They go
  in a query parameter, well inside every limit that matters.
- An upload whose token is lost cannot be aborted through this gateway, because
  the client is the only holder. The bucket's lifecycle rule for incomplete
  multipart uploads is what cleans those up, and the README asks for one.
