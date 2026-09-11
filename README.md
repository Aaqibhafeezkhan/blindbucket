# blindbucket

**A transparent S3 encryption gateway, written in Go.**
Clients speak ordinary S3. The storage provider only ever sees ciphertext — never plaintext, never keys.

[![CI](https://github.com/LennardGeissler/blindbucket/actions/workflows/ci.yml/badge.svg)](https://github.com/LennardGeissler/blindbucket/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> **Status: M3 done — standard S3 clients work, below the multipart threshold.**
> AWS CLI, boto3, `mc` and rclone all round-trip through the gateway. Client
> requests are authenticated with SigV4; ranges, listings and checksums work.
> Multipart uploads arrive with M4, so `aws s3 cp` of a file over 8 MiB still
> fails — cleanly. See [Roadmap](#roadmap) and
> [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

---

## What it is

blindbucket is a reverse proxy that speaks the S3 API. It sits between any S3 client — AWS
CLI, boto3, rclone, `mc`, your own backend — and any S3-compatible store (AWS S3,
Cloudflare R2, MinIO, Backblaze B2). Uploads are encrypted in the stream, downloads are
decrypted in the stream. For the client, only the endpoint changes:

```
aws s3 cp big.tar.zst s3://backups/ --endpoint-url http://localhost:9000
```

The interesting part is not "AES around S3". It is what breaks when you try: authenticated
encryption for objects up to 5 TiB at constant memory, range requests over ciphertext,
parallel multipart uploads across several stateless instances, SigV4 in both directions, and
the checksum machinery of modern SDKs. Solving those cleanly is the substance of this
project.

| Property | How |
|---|---|
| Confidentiality | AES-256-GCM, a fresh data key per object |
| Integrity | Authenticated per chunk; tampering, truncation, reordering and swapping are detected |
| Constant memory | `O(chunk size)` per active stream, independent of object size |
| Statelessness | No local state; multipart state travels in an encrypted token |
| Drop-in compatibility | Standard clients unchanged, only `--endpoint-url` |
| Key rotation | KEK rotation via server-side copy, no data transfer |

## Why not just use…

| Approach | Why it is not enough |
|---|---|
| SSE-S3 / SSE-KMS | The provider holds the keys and sees plaintext |
| SSE-C | Key and plaintext go to the provider on every request |
| AWS S3 Encryption Client | Must be built into every application; language-bound; no CLI support |
| rclone crypt | Built for single-user sync, not a stateless multi-instance gateway |

A gateway centralises encryption at one point inside your own trust boundary. Applications
stay unchanged, and the security level does not depend on every team configuring a library
correctly.

## Security posture

The trust boundary is the proxy. Between client and proxy, data is plaintext — so the proxy
must run in the same trust domain as its clients (sidecar, or behind TLS on an internal
network). Anyone who controls the proxy host or the KEK has everything.

Metadata is **not** hidden: object names, exact sizes, timestamps and access patterns remain
visible to the provider. Rollback to an older genuine version of an object is not currently
detectable.

These are stated up front on purpose. The full analysis, including every residual risk, is
in **[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)**.

## Try it today

```sh
docker compose up -d                         # MinIO on :9002, as a stand-in provider
make build

export BLINDBUCKET_PASSPHRASE='...'          # or --passphrase-file, or you are prompted
./bin/blindbucket keygen --out keyring.json --kid 2026-09

cp blindbucket.example.yaml blindbucket.yaml
export UPSTREAM_ACCESS_KEY_ID=minioadmin UPSTREAM_SECRET_ACCESS_KEY=minioadmin
./bin/blindbucket serve --config blindbucket.yaml
```

Then point any S3 client at it. Nothing about the client changes except the
endpoint:

```sh
export AWS_ENDPOINT_URL=http://127.0.0.1:9000
aws s3 cp big.tar.zst s3://blindbucket-dev/
aws s3 ls s3://blindbucket-dev/
aws s3 sync ./backups s3://blindbucket-dev/backups/
```

`HEAD` reports the plaintext size, while the provider is holding something else
entirely:

```
$ curl -sI http://127.0.0.1:9000/blindbucket-dev/big.tar.zst | grep -i content-length
Content-Length: 3000000

$ mc stat local/blindbucket-dev/big.tar.zst
Size: 3000768                                # 32 + 3000000 + 16 x 46, exactly
X-Amz-Meta-Bb-Kid: 2026-09
X-Amz-Meta-Bb-Dek: SV7GTp0qCaXps-fpNUvKpsAOltVyKIHHscz6Dpmx14_i...

$ mc cat local/blindbucket-dev/big.tar.zst | head -c 16 | xxd
00000000: 424c 424b 0110 0000 0000 0000 ecd4 7291  BLBK..........r.
```

Change one bit of the stored object and the download stops at that chunk rather
than handing over a plausible-looking file.

### Without a server

The crypto core is also usable on its own, which is the point of having shipped it
first: the format can be reviewed, fuzzed and measured before any HTTP is involved.

```sh
./bin/blindbucket encrypt --keyring keyring.json -i big.tar.zst -o big.tar.zst.bb
./bin/blindbucket decrypt --keyring keyring.json -i big.tar.zst.bb -o restored.tar.zst
```

## Numbers

Measured on an Apple M4 with Go 1.27.1. Reproduce with `make bench`; the scripts
and the caveats are in [bench/](bench/).

| Measurement | Result |
|---|---|
| Encrypt, 64 KiB chunks | 7.2 GB/s |
| Decrypt, 64 KiB chunks | 7.0 GB/s |
| Allocations per chunk, steady state | **0** |
| Allocations per 8 MiB stream | 22 encrypting, 26 decrypting — constant, not per chunk |
| 10 GiB encrypt + decrypt | identical SHA-256, **0.5 MiB peak Go heap** |
| 5 GiB through the gateway to MinIO | identical SHA-256, **12 MiB resident** while streaming |

## Clients

Measured by pointing each client at the gateway and running it, not by reading a
specification. Full detail and the exact commands are in
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

| Client | Status | Needs |
|---|---|---|
| AWS CLI v2 | works — `cp`, `ls`, `rm`, `sync`, ranges | nothing |
| boto3 | works — including paginators and delimiters | nothing |
| MinIO `mc` | works — `cp`, `ls`, `mirror`, `cat` | nothing |
| rclone | works | `--ignore-checksum`, and `allow_unsigned_payload` on the proxy |

Two of those needed a fix that only a real client could have found: `mc` sends an
aws-chunked body with no trailer section at all, and rclone attaches an `?x-id=`
parameter that the router was refusing as an unknown sub-resource. boto3 found a
third — user metadata was arriving with Go's canonical header casing, so
`response["Metadata"]["origin"]` came back as `"Origin"` and every lookup missed.

The allocation figures are the interesting ones. They do not change with the
number of chunks, which is the whole of goal G3: memory is a function of how many
streams are in flight, never of how large they are. AES-GCM runs well ahead of any
network the proxy will sit behind, so the expected bottleneck is the upstream, not
the cipher — an expectation M5 will confirm or refute with `warp` rather than
assert.

One honest asterisk: the CLI's peak resident memory is about 70 MiB, essentially
all of it the 64 MiB Argon2id arena used once to unlock the keyring. That is a
deliberate trade — memory hardness is the point of Argon2id — and it is why the
constant-memory claim is measured on the Go heap rather than inferred from RSS.
[ADR-002](docs/adr/ADR-002-key-hierarchy.md) records the reasoning.

## Documentation

| Document | What it is |
|---|---|
| [docs/FORMAT.md](docs/FORMAT.md) | Normative wire format. An independent implementation should be able to interoperate from this document alone. |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | What is protected, what is not, and what the residual risks are. |
| [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) | Which clients work, which settings they need, and what does not work yet. Measured, not assumed. |
| [docs/adr/](docs/adr/) | Architecture decisions, with the alternatives that were rejected and why. |
| [testdata/vectors/](testdata/vectors/) | Known-answer vectors, normative alongside the format spec. |
| [CONCEPT.md](CONCEPT.md) | The full design document the project is being built from (German). |

## Roadmap

| Milestone | Scope | Status |
|---|---|---|
| M0 | Repo, CI, format specification, threat model, ADR-001/002/011 | **done** |
| M1 | Crypto core (segment encoder/decoder), file keyring, `keygen`/`encrypt`/`decrypt` | **done** |
| M2 | Local proxy: `PutObject`, `GetObject`, `HeadObject`, `DeleteObject` | **done** |
| M3 | S3 compatibility: SigV4 verification, checksums, ranges, listings | **done** |
| M3.5 | TLA+ model of the manifest and rotation coordination, checked with TLC | next |
| M4 | Multipart uploads: upload token, manifest, multi-instance operation | planned |
| — | Independent Python reference decoder, differential fuzzing | optional |
| M5 | Production: KMS/Vault providers, `CopyObject`, rotation, metrics, benchmarks | planned |
| M6 | Stretch: name encryption, presigned URLs, rollback protection | open |

Concept version 0.2 found two race conditions in the original manifest lifecycle, both
ending in a visible multipart object with no manifest — readable by nobody. The fix is a set
of rules derived by reasoning, which is exactly the kind of argument that tends to be wrong.
M3.5 exists to check them with a model checker before M4 turns them into code, and the same
model must reproduce the original bug as a negative test.

## Development

Requires Go 1.24 or newer (for `crypto/hkdf`) and Docker for the integration tests.

```sh
make build          # build ./bin/blindbucket
make test           # go test -race
make lint           # golangci-lint
make fuzz           # 30s per fuzz target
make bench          # micro-benchmarks
make vuln           # govulncheck

docker compose up -d   # local MinIO on :9002, console on :9091
```

The integration tests need a provider and skip without one:

```sh
docker compose up -d
BLINDBUCKET_TEST_S3_ENDPOINT=http://localhost:9002 go test ./internal/upstream ./internal/proxy

# and against a running gateway, with a real client:
python3 test/integration/clients/boto3/scenarios.py
```

Production code is Go, without exception. Anything else in this repository has a written
reason in [ADR-011](docs/adr/ADR-011-languages-outside-the-go-core.md).

## Reviews welcome

The format was specified before it was implemented precisely so that it can be reviewed,
and [testdata/vectors/segment_v1.json](testdata/vectors/segment_v1.json) fixes every input
so an independent implementation can check itself against it.

Every guarantee is backed by tests that play an actively hostile storage provider and
require an error rather than plaintext: every single-bit flip across all 32 header bytes,
tampered chunk data and tags, swapped and duplicated chunks, truncation at and inside chunk
boundaries, appended bytes, forged chunk sizes, and multipart segments served under the
wrong part number. A fuzz target additionally requires that anything the decoder accepts
re-encrypts to the identical bytes, which rules out two ciphertexts decoding to one
plaintext.

The same applies end to end. Integration tests against a real MinIO rewrite stored objects
behind the gateway's back — corrupting a chunk, truncating the ciphertext, swapping two
objects' bodies, forging a wrapped key — and require an error rather than plaintext in
every case.

If you find a weakness in [docs/FORMAT.md](docs/FORMAT.md), in the reasoning in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), or an attack the tests miss, please open an
issue — that is the most valuable contribution this project can receive.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
