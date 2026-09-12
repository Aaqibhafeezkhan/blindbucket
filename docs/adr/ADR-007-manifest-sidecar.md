# ADR-007 — The manifest as a sidecar object, with its id in the object metadata

**Status:** Accepted
**Date:** 2026-09-11
**Milestone:** M4
**Implements:** `internal/manifest`, `internal/proxy` (`manifeststore.go`)

## Context

A multipart object is stored as one segment per part, concatenated. Each segment
is authenticated on its own: its header is associated data for every chunk, so
the chunk size, the multipart flag and the part number cannot be changed without
decryption failing.

What no segment says is how many others there are. A provider that served parts 1
and 2 of a three-part object would hand the client a shorter file in which every
byte verifies. The same goes for serving the parts of a *different* upload of the
same key, or for presenting the first part alone as a complete object. Chunk
authentication answers "is this byte what was written"; it cannot answer "is this
all of it".

So something has to bind the parts into a whole, and that something has to be
written before the object becomes visible — because the moment it is visible,
clients may read it.

## Decision

Write a signed part list as a separate object, and point at it from the object's
own metadata.

```
Manifest = "BBM1" || lp(bucket) || lp(key) || ManifestID(16) || uint16_be(M)
           || { uint16_be(part number) || uint64_be(plaintext size) } × M
           || HMAC-SHA256(ManifestKey, all preceding bytes)
```

`ManifestKey = HKDF-SHA256(ikm=DEK, info="blindbucket/v1/manifest")`, and the
manifest lives at `.blindbucket/m/<hex(SHA-256(key))>/<ManifestID>`. The id also
goes into `x-amz-meta-bb-mid` on the object itself.

**Why the MAC covers bucket, key and manifest id.** Authenticity alone is not
enough — a manifest has to be authentic *for this object version*. The MAC key is
derived from the data key, which is fresh per upload, so a manifest from an
earlier upload of the same key fails immediately. Bucket and key stop a manifest
being replayed from a different object, and the manifest id ties it to the one
object version whose metadata names it. All three are checked against what the
caller expected, never against what the manifest claims.

**Why the object key is hashed into the path.** S3 keys may be 1024 bytes, and the
manifest's own key would have to carry one whole plus a prefix and an id — over
the same limit. A fixed-width hash keeps every manifest path the same length
whatever the object is called. It also gives `blindbucket gc` a check it would
not otherwise have: gc must read the object key out of a manifest it cannot
authenticate (it has no data key), and a key that does not hash back to the
directory the manifest was found in is a forgery. SHA-256's collision resistance
is what makes an unauthenticated field safe to act on there.

**Why the id is in the metadata and not the path.** Rule R1 (ADR-010) requires a
fresh manifest id for every operation that makes an object visible, so that a
request can delete exactly the manifest it replaced without racing anything. That
only works if the id belongs to the object *version*, which is what metadata is.
Because the id is minted at `CreateMultipartUpload` and the metadata of a
multipart object is fixed by that call, the new manifest can be written before
completion without disturbing the object that is visible meanwhile — it names a
different id.

**Why `bb-mid` need not be authenticated.** It is a pointer. A tampered one points
at a manifest that does not verify, because the manifest's own MAC covers the id.
Removing it entirely is the more interesting attack — it would present a multipart
object as single-part and skip the manifest check — and that fails on the first
segment header, where the multipart flag is set and authenticated.

## Alternatives considered

**Put the part list in the object's metadata.** No extra object, no extra request,
and it does not fit: S3 caps user metadata at 2 KB, while 10000 parts need about
100 KB. It would also have to be a metadata field the provider can rewrite, so it
would need its own MAC regardless — the sidecar's only real cost with none of its
room.

**Prepend a header segment to the object.** Self-contained, and it breaks the size
arithmetic that makes listings work: the plaintext size would no longer follow
from the ciphertext size and the part count. It also cannot be written before the
parts, since it is part of the same object, so there would be no way to have the
manifest exist before the object is visible (rule R2).

**Put the part count and sizes in each segment header.** Each part would have to
know the total, which is not known until completion — and parts are written
before that. Only the last part could carry it, which reintroduces "a provider
serves fewer parts" as an undetectable attack.

**Derive the manifest key from the KEK rather than the DEK.** It would let `gc`
verify manifests. It would also make a manifest from an earlier upload of the
same key verify perfectly, which is exactly the confusion the fresh DEK prevents.
gc does not need to verify manifests; it needs to know which object they belong
to, and the path hash answers that.

**One manifest per key, overwritten on each upload.** Far simpler, and it is the
version 0.1 design whose race conditions prompted M3.5. A shared manifest means
two concurrent uploads write the same object, and the loser's object is left
pointing at the winner's part list. Rule R1 exists to forbid exactly this.

## Consequences

- A multipart `GetObject` costs one extra request for the manifest. A ranged read
  costs the same one, and both are small.
- `HeadObject` and listings do *not* read the manifest. They recover the plaintext
  size from the ciphertext size and the part count in the ETag suffix (FORMAT §7.2),
  which keeps a listing at one request. Those sizes are hints, exactly as they are
  for single-part objects; the authenticated size is established on read.
- Orphaned manifests are normal. A single-part PUT over a multipart object leaves
  one behind deliberately — the alternative is a HEAD on the most common write
  path — and so does every crashed upload. They hold no plaintext.
  `blindbucket gc` is what removes them, under the rules of ADR-010.
- The `.blindbucket/` prefix has to be unreachable for clients, or a client could
  delete a manifest and make its own object unreadable. The router refuses it for
  every operation, and listings filter it out in both directions.
- A manifest is 10 bytes per part plus a fixed header, so about 100 KB at the
  10000-part maximum and a few hundred bytes for ordinary objects.
