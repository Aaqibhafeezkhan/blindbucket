# Architecture Decision Records

Each ADR follows the same shape: **context**, **decision**, **alternatives considered**,
**consequences**. The alternatives section is the point of the exercise — a decision without
rejected options is not a decision, it is a default.

| Nr. | Title | Status | Milestone |
|---|---|---|---|
| [001](ADR-001-segment-format.md) | Segment format: STREAM with AES-256-GCM, 64 KiB chunks, authenticated header | Accepted | M0 |
| [002](ADR-002-key-hierarchy.md) | Key hierarchy: external root key, in-memory KEK ring, one DEK per object | Accepted | M0 |
| [003](ADR-003-upstream-client.md) | A custom upstream client on `net/http` instead of the SDK's S3 client | Accepted | M2 |
| [004](ADR-004-fail-closed.md) | Fail-closed by aborting the connection after response headers are sent | Accepted | M2 |
| [005](ADR-005-checksums.md) | Checksums: verify locally, never forward, withhold the final chunk | Accepted | M3 |
| [006](ADR-006-upload-token.md) | Statelessness via an encrypted upload token | Accepted | M4 |
| [007](ADR-007-manifest-sidecar.md) | The manifest as a sidecar object, with its id in the object metadata | Accepted | M4 |
| [008](ADR-008-part-sizes.md) | Part sizes as multiples of the chunk size | Accepted | M4 |
| [009](ADR-009-rotation-by-copy.md) | Rotation by copy, preserving part structure, with conditional writes | Accepted | M5 |
| [010](ADR-010-manifest-lifecycle-under-concurrency.md) | Manifest lifecycle under concurrency (R1–R4, checked with TLA+) | Accepted | M3.5 |
| [011](ADR-011-languages-outside-the-go-core.md) | Languages and tools outside the Go core | Accepted | M0 |
| [012](ADR-012-copy-semantics.md) | Copy semantics: re-wrap and keep the ciphertext, re-encrypt for part copies | Accepted | post-M5 |

ADR numbers reflect the order the decisions were identified, not the order they are made.
010 and 011 were added in concept version 0.2; 011 was decided in M0 because it governs what
may enter the repository from the start, while 010 waited for the model checker in M3.5.
