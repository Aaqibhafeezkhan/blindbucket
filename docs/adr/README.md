# Architecture Decision Records

Each ADR follows the same shape: **context**, **decision**, **alternatives considered**,
**consequences**. The alternatives section is the point of the exercise — a decision without
rejected options is not a decision, it is a default.

| Nr. | Title | Status | Milestone |
|---|---|---|---|
| [001](ADR-001-segment-format.md) | Segment format: STREAM with AES-256-GCM, 64 KiB chunks, authenticated header | Accepted | M0 |
| [002](ADR-002-key-hierarchy.md) | Key hierarchy: external root key, in-memory KEK ring, one DEK per object | Accepted | M0 |

## Planned

| Nr. | Title | Milestone |
|---|---|---|
| 003 | Custom upstream client on `net/http` instead of the SDK S3 client | M2 |
| 004 | Fail-closed by connection abort after response headers are sent | M2 |
| 005 | Checksums: verify locally, do not forward, withhold the final chunk | M3 |
| 006 | Statelessness via an encrypted upload token | M4 |
| 007 | Manifest as a sidecar object, manifest id in object metadata | M4 |
| 008 | Part sizes as multiples of the chunk size | M4 |
| 009 | Rotation by copy, preserving part structure | M5 |
