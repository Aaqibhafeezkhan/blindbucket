# Client Compatibility

What actually works, measured by pointing each client at the gateway and running
it. Every result below came from a real client against a real MinIO, not from
reading a specification.

**Measured:** 2026-09-12, against `v0.1.0`.
**Setup:** `docker compose up -d`, `blindbucket serve`, path-style, 64 KiB chunks.

---

## Summary

| Client | Version tested | Status | Required settings |
|---|---|---|---|
| AWS CLI v2 | 2.36.43 | **Works** | none |
| boto3 | 1.43.92 | **Works** | none |
| MinIO client (`mc`) | RELEASE.2025-08-13 | **Works** | `allow_unsigned_payload: true` on the proxy, for multipart only |
| rclone | 1.75.1 | **Works with settings** | `allow_unsigned_payload: true` on the proxy; `--ignore-checksum`; `--size-only` for `check` |

Multipart included since M4: each client was run with a file over its own
threshold, so the parts, the manifest and the size arithmetic are all exercised by
the client's own code path rather than by a hand-built request.

---

## AWS CLI v2

```sh
export AWS_ENDPOINT_URL=http://127.0.0.1:9000
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_DEFAULT_REGION=us-east-1
```

| Command | Result |
|---|---|
| `aws s3 cp <file> s3://bucket/key` | works — uses aws-chunked with a CRC64NVME trailer |
| `aws s3 cp s3://bucket/key <file>` | works — identical SHA-256 |
| `aws s3 ls s3://bucket/prefix/` | works — reports **plaintext** sizes |
| `aws s3 sync <dir> s3://bucket/p/` | works, both directions, nested directories |
| `aws s3 rm s3://bucket/key` | works |
| `aws s3 rm s3://bucket/p/ --recursive` | works — `DeleteObjects` |
| `aws s3api put-object` | works — returns the verified `ChecksumCRC64NVME` |
| `aws s3api get-object --range` | works |
| `aws s3api head-object` | works — plaintext size, gateway metadata hidden |
| `aws s3 cp` of 40 MiB and 5 GiB | works — multipart, 8 MiB parts, identical SHA-256 |
| `aws s3 ls` of a multipart object | works — plaintext size, 5368709120 for the 5 GiB file |
| `aws s3 cp` across two proxy instances | works — parts spread over both, no affinity needed |
| restarting an instance mid-upload | the upload completes; the client retries the part it lost |

The CLI's default checksum is CRC64NVME, which is verified against the plaintext
at the gateway and echoed back. That the echoed value matches what the CLI
computed is itself a check on the CRC-64/NVME implementation.

## boto3

Scenarios live in
[`test/integration/clients/boto3/scenarios.py`](../test/integration/clients/boto3/scenarios.py)
and are runnable:

```sh
BLINDBUCKET_ENDPOINT=http://127.0.0.1:9000 BLINDBUCKET_BUCKET=blindbucket-dev \
  python3 test/integration/clients/boto3/scenarios.py
```

| Scenario | Result |
|---|---|
| `put_object` / `get_object` round trip at 0, 1, 65535, 65536, 65537, 300000 bytes | works |
| `head_object` and `list_objects_v2` sizes | plaintext sizes |
| `get_object` with `Range`, including suffix and open-ended | works |
| User metadata, `ContentType`, `CacheControl` | preserved; `bb-*` never visible |
| `ChecksumAlgorithm="CRC32"` | verified and echoed |
| A deliberately wrong checksum | refused with `BadDigest`, nothing stored |
| Paginator with `PageSize=3`, `Delimiter="/"` | works |
| `delete_objects` | works |
| Missing object | `NoSuchKey` |
| `upload_file` / `download_file` at 30 MiB, 8 MiB parts | works — multipart, identical SHA-256 |
| `head_object` and `list_objects_v2` on a multipart object | plaintext sizes; the ETag carries the part count |
| `get_object` with `Range` across a part boundary | works |
| `abort_multipart_upload` | works — no object appears |
| A part that is not a multiple of the chunk size | refused with `InvalidRequest`, nothing stored |
| `list_multipart_uploads` | `NotImplemented` — see [Known limits](#known-limits) |
| `delete_object` / `list_objects_v2` on `.blindbucket/` | `AccessDenied`; the prefix is invisible in listings |

## MinIO client (`mc`)

```sh
mc alias set bb http://127.0.0.1:9000 <key> <secret> --api S3v4
```

| Command | Result |
|---|---|
| `mc cp <file> bb/bucket/key` | works |
| `mc cp bb/bucket/key <file>` | works — identical bytes |
| `mc ls bb/bucket/prefix/` | works — plaintext sizes |
| `mc mirror <dir> bb/bucket/p/` | works, nested |
| `mc cat bb/bucket/key` | works |
| `mc cp` of 64 MiB | works with `allow_unsigned_payload`, identical SHA-256 |

`mc` sends `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`: aws-chunked with a signature per
chunk and **no trailer section at all**. That shape is what found the bug fixed
in `internal/auth/chunked.go` — the decoder expected a trailer block and rejected
every `mc` upload until a real client was pointed at it.

Its multipart path is different again: `mc` signs single-part bodies but sends
`UNSIGNED-PAYLOAD` for the parts of a multipart upload, so a large `mc cp` fails
with *"unsupported payload signing mode"* unless `allow_unsigned_payload: true` is
set on the proxy. The same caveat as for rclone applies — enable it only behind TLS
or on loopback. Below the threshold `mc` still needs nothing, which is why the
summary row names multipart specifically.

## rclone

rclone works, but needs three things said out loud.

```ini
[bb]
type = s3
provider = Other
access_key_id = ...
secret_access_key = ...
endpoint = http://127.0.0.1:9000
region = us-east-1
force_path_style = true
```

```sh
rclone copy --ignore-checksum <dir> bb:bucket/prefix/
rclone check --size-only <dir> bb:bucket/prefix/
```

| Requirement | Why |
|---|---|
| `allow_unsigned_payload: true` on the proxy | rclone cannot seek its upload body, so it cannot hash it to sign it, and it sends `UNSIGNED-PAYLOAD`. Setting `use_unsigned_payload = false` makes rclone fail with *"failed to seek body to start"* instead. Enable this only behind TLS or on loopback: without it the body between client and proxy is not covered by the signature. |
| `--ignore-checksum` on copy and sync | rclone compares the ETag against the local MD5. The ETag is the MD5 of **ciphertext**, so they never match, and rclone reports *"corrupted on transfer"* for a perfectly good object. |
| `--size-only` for `check` | Same reason. Sizes match exactly, because listings report plaintext sizes. |

With those, `copy`, `sync`, `ls` and `check --size-only` all pass, both
directions, on nested directories.

---

## Known limits

These apply to every client.

| Limit | Detail | Arrives |
|---|---|---|
| **`ListMultipartUploads`** | Returns `NotImplemented`, and will keep doing so. The upload ids this gateway issues are sealed tokens carrying the data key and the manifest id (ADR-006); neither can be reconstructed from the provider's listing, so the call could only return ids no client is able to use. Clients that abort their own uploads are unaffected — they hold the token already. | — |
| **`UploadPartCopy`** | Returns `NotImplemented`. The copy machinery is in the upstream client, because rotation needs it, but the S3 operation is not wired up. Deferred with `CopyObject`. | — |
| **Part sizes** | Every part but the last must be a multiple of the chunk size (FORMAT §7.3). The defaults of every client above satisfy this; a client configured with, say, 5.5 MiB parts is refused at completion with a message naming the fix. | — |

### Conditional writes, for rotation

`blindbucket rotate` needs the provider to honour two preconditions, and
CONCEPT.md §11.2 left it open whether MinIO does. Measured:

| Precondition | MinIO | Used for |
|---|---|---|
| `x-amz-copy-source-if-match` on `UploadPartCopy` | **enforced** | the source changing between the HEAD and the copy |
| `If-Match` on `CompleteMultipartUpload` | **enforced** | the target changing between the copy and the completion |

Both answer `412 PreconditionFailed`, and in practice the copy refuses first —
the rotation never gets as far as the completion. Either way the object is
counted as skipped rather than overwritten, which is invariant I2 holding.

A provider that silently *ignored* these headers would be worse than one that
rejected them, because rotation would look safe while losing writes. That is what
`--allow-unconditional` exists for: it makes dropping the guard an explicit
decision with a warning, rather than something a provider does quietly. Whether
R2 and Backblaze B2 enforce them is still untested.

### A note on reverse proxies in front of the gateway

The gateway emits user metadata with lower-case header names on purpose, because
SDKs surface metadata keys exactly as they arrive and boto3 hands the caller
`response["Metadata"]["origin"]`. A reverse proxy that re-canonicalises headers
turns that back into `Origin` and breaks every lookup — Go's own
`httputil.ReverseProxy` does this, and it is worth checking on whatever sits in
front of a deployment. nginx passes them through unchanged, which is what the CI
job uses. The symptom is metadata that round-trips with the wrong casing while
everything else works.
| **ETag ≠ MD5 of plaintext** | The ETag is the provider's, so it is the MD5 of the ciphertext. Anything comparing it against a local hash sees a mismatch. Sizes are fine. | by design |
| **Presigned URLs** | Query-signed requests are refused. | M6 |
| **Listing sizes use the configured chunk size** | A listing carries no per-object metadata, so the conversion assumes the chunk size this deployment is configured with. Correct for everything this deployment wrote; an object written under a different setting is listed with its raw ciphertext size rather than a wrong plaintext one. Not authenticated in any case — see [THREAT_MODEL.md](THREAT_MODEL.md) section 5.4. | by design |
| **Objects not written by the gateway** | Refused with `ObjectNotEncrypted` rather than served. Mixing encrypted and unencrypted objects behind one endpoint would leave a client unable to tell which it got. | by design |
| **Bucket sub-resources** | `?acl`, `?policy`, `?versioning`, `?lifecycle`, `?tagging` all return `NotImplemented`. | not planned |
| **Server-side encryption headers** | Refused. The gateway encrypts already; accepting them would suggest a second layer that is not there. | by design |

## How to reproduce

```sh
docker compose up -d
make build
export BLINDBUCKET_PASSPHRASE=...
./bin/blindbucket keygen --out keyring.json
# fill in blindbucket.yaml, then:
./bin/blindbucket serve --config blindbucket.yaml
```

The Go integration tests cover the same ground without external clients:

```sh
BLINDBUCKET_TEST_S3_ENDPOINT=http://localhost:9002 go test ./internal/proxy ./internal/upstream
```
