# blindbucket Wire Format — Version 1

**Status:** Draft, normative for format version `1`.
**Last updated:** 2026-09-11 (M0)

This document is the authoritative specification of the bytes blindbucket writes to
object storage. It is written so that an independent implementation can interoperate
with blindbucket using only this document and the test vectors in
[`testdata/vectors/`](../testdata/vectors/).

The design rationale lives in [`CONCEPT.md`](../CONCEPT.md) §8 and in
[ADR-001](adr/ADR-001-segment-format.md) / [ADR-002](adr/ADR-002-key-hierarchy.md).
Where this document and `CONCEPT.md` disagree, **this document wins**.

---

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as
described in RFC 2119.

| Notation | Meaning |
|---|---|
| `a \|\| b` | concatenation of byte strings `a` and `b` |
| `uintN_be(x)` | `x` encoded as an unsigned big-endian integer in exactly `N` bits |
| `lp(x)` | length-prefixed byte string: `uint16_be(len(x)) \|\| x` |
| `C` | chunk size in bytes, `C = 2^log2C` |
| `P` | plaintext length in bytes |
| `S` | ciphertext (sealed) length in bytes |
| `N` | number of chunks in a segment |
| `M` | number of parts in a multipart object |

All multi-byte integers are big-endian. All lengths are in bytes. Byte offsets are
zero-based and ranges are inclusive, matching HTTP `Range` semantics.

`lp()` is used wherever two or more variable-length fields are concatenated into an
authenticated input. Its purpose is unambiguity: without length prefixes,
`bucket="ab", key="c"` and `bucket="a", key="bc"` would produce identical associated
data. Implementations MUST reject inputs longer than 65535 bytes to `lp()`.

---

## 2. Cryptographic primitives

| Purpose | Primitive |
|---|---|
| Content encryption | AES-256-GCM (NIST SP 800-38D), 12-byte nonce, 16-byte tag |
| Key derivation | HKDF-SHA256 (RFC 5869) |
| DEK wrapping | AES-256-GCM |
| Manifest authentication | HMAC-SHA256 |
| Randomness | operating-system CSPRNG |

All AES-256-GCM invocations in this format use a 96-bit nonce and a 128-bit tag.
No other tag or nonce length is permitted.

---

## 3. Key hierarchy

```
Root key            external: AWS KMS | Vault Transit | Argon2id(passphrase)
 └─ KEK             32 bytes, identified by a key id (kid), several versions per keyring
     ├─ Token key   = HKDF-SHA256(ikm=KEK, salt="", info="blindbucket/v1/upload-token", L=32)
     └─ DEK         32 bytes, uniformly random, one per object or multipart upload
         ├─ Subkey  = HKDF-SHA256(ikm=DEK, salt=Salt, info="blindbucket/v1/segment",  L=32)
         └─ MacKey  = HKDF-SHA256(ikm=DEK, salt="",   info="blindbucket/v1/manifest", L=32)
```

A DEK MUST be generated with a CSPRNG and MUST NOT be derived from any value chosen
by the storage provider (notably not from the upstream `UploadId`; see `CONCEPT.md`
§10.3).

### 3.1 Key identifiers

A `kid` MUST be 1 to 64 bytes long and MUST consist only of the characters
`A-Z a-z 0-9 . _ -`. The upper bound is normative: it is what makes the associated
data encodings in §6 unambiguous with respect to each other.

---

## 4. Segment

A **segment** is the unit that encrypts one plaintext stream under one subkey.
A single-part object consists of exactly one segment. A multipart object consists of
one segment per part, concatenated in part-number order by the storage provider.

```
Segment = Header(32) || Chunk_0 || Chunk_1 || ... || Chunk_(N-1)
```

### 4.1 Header

The header is exactly 32 bytes and is **not** encrypted. It is authenticated: it is
supplied verbatim as the associated data of every chunk in the segment (§4.3).

| Offset | Length | Field | Value |
|---|---|---|---|
| 0 | 4 | Magic | `"BLBK"` = `0x42 0x4C 0x42 0x4B` |
| 4 | 1 | Version | `0x01` |
| 5 | 1 | `log2C` | `12`..`20`; default `16` (64 KiB) |
| 6 | 1 | Flags | bit 0 (`0x01`): segment belongs to a multipart object. All other bits MUST be `0` |
| 7 | 1 | Reserved | MUST be `0x00` |
| 8 | 4 | Segment index | `uint32_be`; `0` for single-part, otherwise the S3 part number `1`..`10000` |
| 12 | 20 | Salt | 160 uniformly random bits, freshly generated per segment |

Consistency constraints, which a decoder MUST enforce (§5.2):

- If flag bit 0 is clear, the segment index MUST be `0`.
- If flag bit 0 is set, the segment index MUST be in `1..10000`.

The salt MUST be freshly generated for every segment, including for every retried
attempt at the same part number. This is what makes nonce reuse impossible across
retries; see §8.2.

### 4.2 Subkey derivation

```
Subkey = HKDF-SHA256(ikm = DEK, salt = Header[12..32], info = "blindbucket/v1/segment", L = 32)
```

The `info` string is ASCII, 22 bytes, without a trailing NUL.

### 4.3 Chunks

```
C        = 2^log2C
f_i      = 0x01 if i == N-1, else 0x00
Nonce_i  = uint88_be(i) || f_i                                          (12 bytes)
Chunk_i  = AES-256-GCM-Seal(key = Subkey, nonce = Nonce_i,
                            plaintext = Plain_i, aad = Header)          (|Plain_i| + 16 bytes)
```

`i` is the zero-based chunk index within the segment. The counter is 88 bits, so
`i` MUST be less than `2^88`; at the maximum chunk size this bound is far beyond the
5 TiB S3 object limit and can never be reached in practice.

### 4.4 Chunk length rules

1. Every chunk except the last MUST carry exactly `C` bytes of plaintext.
2. The last chunk MUST carry 1 to `C` bytes of plaintext, **except** that a segment
   encrypting zero bytes of plaintext consists of exactly one chunk carrying zero
   bytes of plaintext (a bare 16-byte tag).
3. No bytes MUST follow the chunk whose nonce carries `f = 1`.

Consequently `N = max(1, ceil(P / C))` and a segment always contains at least one
chunk.

---

## 5. Encoder and decoder requirements

### 5.1 Encoder

An encoder MUST NOT emit a chunk with `f = 1` until it knows the plaintext stream has
ended. Because a writer cannot distinguish "buffer full" from "stream finished", the
encoder MUST hold back the most recently completed chunk until either more plaintext
arrives or the stream is explicitly closed.

This means **`Close` is the commit point of a segment.** A segment whose encoder was
never closed is truncated and MUST fail to decrypt. blindbucket relies on this
property in the proxy: the final chunk is withheld until the client's end-to-end
checksum has been verified (`CONCEPT.md` §9.3), so a failed checksum can abort the
upstream request before a complete body is ever written.

### 5.2 Decoder

A decoder MUST, in this order:

1. Read exactly 32 bytes of header.
2. Validate the magic, the version, `12 <= log2C <= 20`, that the reserved byte is
   `0x00`, that no undefined flag bits are set, and the flag/index consistency
   constraints of §4.1 — **before allocating any buffer whose size derives from
   `log2C`.** The header is attacker-controlled and is not yet authenticated at this
   point. Without this check, a header claiming `log2C = 30` would coerce a 1 GiB
   allocation from a single 32-byte read.
3. Compare the header's flag and index fields against what the caller expected for
   this segment (part number, multipart flag). A mismatch MUST be an error.
4. Derive the subkey and decrypt chunk 0. Only after chunk 0 verifies is the header
   authentic.
5. For each chunk, determine `f` by looking ahead exactly one byte past the chunk's
   ciphertext: if any byte follows, `f` MUST be `0`; if the stream ends, `f` MUST
   be `1`.

A decoder MUST NOT release the plaintext of a chunk to its caller before that chunk's
authentication tag has been fully verified. A decoder MUST treat every deviation —
bad tag, bad header field, truncation, trailing bytes, wrong key — as a hard error,
and MUST NOT return partial or unauthenticated plaintext for the failing chunk.

Truncation at a chunk boundary is detected by rule 5: the chunk that becomes last
was sealed with `f = 0` but must now verify under `f = 1`, which fails. Appending
bytes after the final chunk is detected the same way, in reverse.

---

## 6. DEK wrapping

A DEK is stored next to the data it protects, wrapped under a KEK.

```
WrappedDEK = Nonce(12) || AES-256-GCM-Seal(key = KEK[kid], nonce = Nonce,
                                           plaintext = DEK, aad = AAD)
```

The result is exactly `12 + 32 + 16 = 60` bytes, which is 80 characters of
unpadded base64url.

### 6.1 Associated data for objects

```
AAD = "blindbucket/v1/dek" || lp(kid) || lp(bucket) || lp(key)
```

Binding bucket and key into the AAD means unwrapping fails if the storage provider
swaps two objects together with their metadata.

### 6.2 Associated data for the local file format

```
AAD = "blindbucket/v1/dek-file" || lp(kid)
```

The two encodings cannot be confused: they share the 18-byte prefix
`"blindbucket/v1/dek"`, after which the object form has `uint16_be(len(kid))` while
the file form has the ASCII bytes `-fi` (`0x2D 0x66 0x69`). A collision would require
`len(kid) == 0x2D66 == 11622`, which §3.1 forbids.

### 6.3 Object metadata

| Header | Content | Size |
|---|---|---|
| `x-amz-meta-bb-v` | format version, decimal ASCII | `1` |
| `x-amz-meta-bb-kid` | KEK id | 1..64 bytes |
| `x-amz-meta-bb-dek` | wrapped DEK, unpadded base64url | 80 chars |
| `x-amz-meta-bb-mid` | manifest id, 16 bytes unpadded base64url (multipart only) | 22 chars |

A proxy MUST strip all `bb-`-prefixed metadata from responses to clients, and MUST
reject client requests that attempt to set metadata with the `bb-` prefix.

---

## 7. Size arithmetic

The format is deterministic in length: the ciphertext size is a function of the
plaintext size alone. This is what lets the proxy compute an exact upstream
`Content-Length` before reading a single byte, and report plaintext sizes in
`HEAD` and `ListObjectsV2` without extra requests. It also means the exact plaintext
size is visible to the storage provider; this is a deliberate trade-off recorded in
[`THREAT_MODEL.md`](THREAT_MODEL.md).

### 7.1 Forward: plaintext to ciphertext

For a single segment:

```
N(P) = max(1, ceil(P / C))
S(P) = 32 + P + 16 * N(P)
```

For a multipart object of `M` parts whose per-part plaintext sizes are `P_1..P_M`,
with `P = sum(P_i)`:

```
S = 32*M + P + 16 * ceil(P / C)
```

This identity holds **only if every part except the last is an exact multiple of
`C`**, which is why §7.3 makes that a requirement.

### 7.2 Inverse: ciphertext to plaintext

Given `S` and the number of segments `M` (`M = 1` for single-part objects; for
multipart objects `M` is read from the `-M` suffix of the S3 ETag):

```
D = S - 32*M
N = ceil(D / (C + 16))
P = D - 16*N
```

`D` is valid if and only if:

- `D >= 16`, and
- `D == 16` (the empty object, `P = 0`), or
- `D mod (C + 16)` is **not** in the range `1..16`.

The excluded remainders are exactly those no encoder can produce: a plaintext of
`q*C + r` bytes yields `D mod (C+16) = r + 16` for `1 <= r <= C-1`, and `D mod (C+16) = 0`
for `r = 0, q >= 1`. A remainder of `1..16` therefore indicates a corrupted or
forged size and MUST be reported as an error rather than decoded.

**Worked example.** `P = 100 MiB = 104857600`, `C = 65536`, `M = 1`:
`N = 1600`, `S = 32 + 104857600 + 25600 = 104883232`. Inverting:
`D = 104883200`, `D / 65552 = 1600` exactly, so `N = 1600` and
`P = 104883200 - 25600 = 104857600`. ✓

### 7.3 Part size rules for multipart objects

- Every part except the last MUST have a plaintext size that is an exact multiple
  of `C`. The default part sizes of the AWS CLI, boto3, rclone and `mc` (5, 8 and
  16 MiB) all satisfy this for every permitted `C`, since `C <= 1 MiB`.
- The last part MUST NOT be empty.
- The ciphertext of a single part MUST NOT exceed 5 GiB, which caps the plaintext of
  a part at roughly `5 GiB - 1.25 MiB`.

A proxy MUST reject a `CompleteMultipartUpload` that violates these rules rather
than storing an object whose size cannot be recovered.

---

## 8. Range mapping

For a single segment, a plaintext range `a..b` (inclusive, `0 <= a <= b < P`) maps to
ciphertext as:

```
i       = floor(a / C)                              first chunk touched
j       = floor(b / C)                              last chunk touched
c_start = 32 + i * (C + 16)
c_end   = min(32 + (j + 1) * (C + 16), S) - 1
skip    = a - i * C                                 bytes to discard from chunk i
```

The reader decrypts chunks `i..j`, discards `skip` leading bytes and emits exactly
`b - a + 1` bytes. Chunk `j` is decrypted with `f = 1` if and only if `j == N - 1`,
where `N` is derived from the object's total size `S`.

Because `f` is part of the nonce, a storage provider that misreports `S` causes the
final chunk's authentication to fail in both directions: understating `S` makes a
non-final chunk be opened as final, and overstating it makes the final chunk be
opened as non-final. Neither verifies.

For multipart objects the prefix sums of the per-part plaintext sizes from the
manifest locate the part containing offset `a`; within that part the mapping above
applies with `32` replaced by that part's ciphertext start offset.

---

## 9. Local file format (`BBF1`)

`blindbucket encrypt` and `blindbucket decrypt` produce and consume a self-contained
file consisting of a small envelope followed by exactly one segment.

```
File = "BBF1" || uint8(version = 1) || lp(kid) || WrappedDEK(60) || Segment
```

The wrapped DEK uses the associated data of §6.2. The segment MUST have the multipart
flag clear and segment index `0`.

---

## 10. Reserved

The following structures are part of the design but their normative text lands with
the milestone that implements them. Until then, `CONCEPT.md` is the reference.

| Structure | Magic | Specified in | Milestone |
|---|---|---|---|
| Multipart manifest | `"BBM1"` | `CONCEPT.md` §10.6 | M4 |
| Upload token | version byte `0x01` | `CONCEPT.md` §10.3 | M4 |

---

## 11. Security notes (informative)

**Why the nonce construction is safe.** Within a segment, `i` is unique by
construction. Across segments the subkey differs, because each segment draws a fresh
160-bit salt; by the birthday bound a salt collision requires on the order of `2^80`
segments. A (key, nonce) pair is therefore never reused. Fresh per-segment subkeys
additionally keep the amount of data under any single GCM key small.

**Why retries are safe.** A client that retries `UploadPart` for part `n` produces a
second, independent segment with a fresh salt and therefore a fresh subkey. Had the
nonce depended only on the part number and the chunk counter, a retry carrying
different bytes would have reused a (key, nonce) pair, which for GCM leaks the XOR of
the plaintexts and allows recovery of the authentication subkey.

**What the header in the AAD buys.** Chunk size, multipart flag and segment index are
authenticated with every single chunk. A storage provider can therefore not
reinterpret the chunk size, present a multipart object as a single-part object, or
reorder parts, without authentication failing.

**What this format does not protect.** Object names, sizes, timestamps, access
patterns and part counts remain visible. Rollback to an older but genuine version of
the same key is not detectable at the format level. See
[`THREAT_MODEL.md`](THREAT_MODEL.md).

---

## 12. Test vectors

Known-answer test vectors live in
[`testdata/vectors/segment_v1.json`](../testdata/vectors/segment_v1.json) and are a
normative part of this specification. Each vector fixes the DEK, the salt and every
header field, so the expected ciphertext is fully determined. An independent
implementation that reproduces every vector byte for byte is format-compatible.

Each entry is hex-encoded and carries:

| Field | Meaning |
|---|---|
| `dek` | the 32-byte data encryption key |
| `salt` | the 20-byte segment salt, which goes into the header at offset 12 |
| `log2_chunk_size`, `multipart`, `index` | the remaining header fields |
| `plaintext` | the input |
| `ciphertext` | the complete segment, header included |

The ten vectors cover the sizes where an encoder's final-chunk handling either
works or does not -- empty, one byte, one short of a chunk, exactly a chunk, one
past a chunk, and a multi-chunk case -- plus the smallest, default and largest
chunk sizes and both multipart boundaries (part 1 and part 10000).

Regenerate them after a deliberate format change with:

```sh
go test ./internal/crypto/stream -run TestKnownAnswerVectors -update
```

A change that was *not* deliberate shows up as a failure of that same test.

---

## 13. Version history

| Format version | Status | Change |
|---|---|---|
| `1` | draft | Initial specification. |
