# blindbucket

**A transparent S3 encryption gateway, written in Go.**
Clients speak ordinary S3. The storage provider only ever sees ciphertext — never plaintext, never keys.

[![CI](https://github.com/LennardGeissler/blindbucket/actions/workflows/ci.yml/badge.svg)](https://github.com/LennardGeissler/blindbucket/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> **Status: pre-M1 — not usable yet.**
> The repository skeleton, CI and the normative specifications are in place. The crypto
> core is next. See [Roadmap](#roadmap) for exactly what does and does not exist.

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

## Documentation

| Document | What it is |
|---|---|
| [docs/FORMAT.md](docs/FORMAT.md) | Normative wire format. An independent implementation should be able to interoperate from this document alone. |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | What is protected, what is not, and what the residual risks are. |
| [docs/adr/](docs/adr/) | Architecture decisions, with the alternatives that were rejected and why. |
| [CONCEPT.md](CONCEPT.md) | The full design document the project is being built from (German). |

## Roadmap

| Milestone | Scope | Status |
|---|---|---|
| M0 | Repo, CI, format specification, threat model, ADR-001/002/011 | **done** |
| M1 | Crypto core (segment encoder/decoder), file keyring, `keygen`/`encrypt`/`decrypt` | next |
| M2 | Local proxy: `PutObject`, `GetObject`, `HeadObject`, `DeleteObject` | planned |
| M3 | S3 compatibility: SigV4 verification, checksums, ranges, listings | planned |
| M3.5 | TLA+ model of the manifest and rotation coordination, checked with TLC | planned |
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

Production code is Go, without exception. Anything else in this repository has a written
reason in [ADR-011](docs/adr/ADR-011-languages-outside-the-go-core.md).

## Reviews welcome

The format is specified before it is implemented precisely so that it can be reviewed. If
you find a weakness in [docs/FORMAT.md](docs/FORMAT.md) or in the reasoning in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), please open an issue — that is the most
valuable contribution this project can receive.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
