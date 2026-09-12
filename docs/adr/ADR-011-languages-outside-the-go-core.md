# ADR-011 — Languages and tools outside the Go core

**Status:** Accepted
**Date:** 2026-09-11
**Milestone:** M0
**Reference:** [`CONCEPT.md`](../../CONCEPT.md) §15.2

## Context

blindbucket is a portfolio project, which creates a specific temptation: adding a second
language because it looks impressive rather than because it solves a problem. The opposite
failure is just as real — refusing every non-Go tool on principle, and then verifying
concurrent protocols with integration tests that cannot actually cover the interleavings,
or claiming client compatibility without ever running the client.

Three concrete needs surfaced while writing the concept:

1. The compatibility matrix claims boto3 works. Only boto3 can substantiate that.
2. §10.8 describes coordination rules (R1–R4) whose correctness depends on how operations
   on several instances interleave, including crashes at every step. Version 0.1 of the
   concept contained two races in exactly this area that ordinary review did not catch.
3. `FORMAT.md` claims to be implementable from the document alone. Nothing tests that claim
   as long as the only implementation is the one the document was written from.

## Decision

**Production code is 100% Go.** A second language enters the repository only if at least one
of these holds:

1. **The ecosystem forces it.** A compatibility statement about a client can only be
   substantiated with that client.
2. **Independence is the point.** A second implementation must not inherit the first one's
   misconceptions.
3. **A special-purpose language solves a task Go is not built for** — notably exhaustive
   checking of concurrent behaviour.
4. **A measured bottleneck Go cannot address.** This does not currently apply and is only
   reopened with profiling data.

| Purpose | Language / tool | Criterion | Location | Milestone |
|---|---|---|---|---|
| boto3 compatibility tests | Python | 1 | `test/integration/clients/boto3/` | M3 |
| Model of manifest and rotation coordination | TLA+ (PlusCal), TLC | 3 | `spec/tla/` | M3.5 |
| Independent reference decoder, differential fuzzing | Python (`cryptography`) | 2 | `ref/python/` | after M4 |
| Benchmark plots and summaries | Python (standard library only) | 1 | `bench/plot/` | M5 |
| Machine-readable format description | Kaitai Struct | 3 | `docs/format.ksy` | M6, optional |

Makefiles, Dockerfiles, Compose files, GitHub Actions and deployment examples are
configuration, not a language choice.

**One row changed when it was built.** The benchmark plots were planned as Python with
matplotlib, under a fifth reason this ADR does not actually grant: convenience. When the
figures were written it turned out that two charts are a few hundred lines of SVG, so they
are emitted by the standard library alone. The criterion becomes 1 rather than an exception:
the same Python the boto3 tests already require, with nothing to install and no version to
pin, which is the argument the rest of the project makes about dependencies. A third chart
form, or anything wanting statistics, would be the point to revisit it -- and to say so here.

## Alternatives considered

**Rust or C for the crypto core, via cgo.** The usual argument is performance. It does not
apply: Go's AES-GCM uses hand-written assembly with hardware acceleration on amd64 and
arm64, and §12.4 expects the network, not the cipher, to be the bottleneck — an expectation
the benchmarks in M5 will confirm or refute with numbers. The costs are concrete: cgo gives
up the static binary, straightforward cross-compilation and the `distroless/static` image;
it places an FFI boundary with unsafe code inside the most security-critical component; and
the cryptography would run outside the Go standard library's FIPS 140-3 mode (`GOFIPS140`).

**Rust for the reference decoder instead of Python.** Equally valid as a proof that the
specification is independently implementable, and it would be the right choice if learning
Rust were also a goal. It is not, and Python is already in the repository for the boto3
tests. If that motivation ever changes, the README should say so plainly rather than dress
up language tourism as engineering.

**No formal methods; cover the races with integration tests.** Rejected: the two races in
concept 0.1 only appear in specific interleavings across instances with crashes at specific
points. Tests can reproduce an interleaving once it is known, but they are a poor instrument
for discovering it. TLC enumerates the state space instead. Integration tests remain — they
just get their scenarios from the counterexamples.

**A full model of the whole system in TLA+.** Rejected as scope: the model covers
coordination only (objects, manifests, open uploads, process steps), not cryptography.
Roughly 150–250 lines of PlusCal, capped deliberately.

**Adding a language purely as a portfolio signal.** Rejected explicitly, and this ADR exists
partly to make that refusal reviewable. The signal a reviewer values is a defensible reason,
not a count of languages.

## Consequences

**Positive.**

- The security-critical path stays in one memory-safe language with no FFI boundary, one
  toolchain and one build.
- Each non-Go artefact has a written reason and an owner milestone, so the repository does
  not accumulate languages by drift.
- The TLA+ model makes a class of bug checkable that neither the race detector nor
  integration tests reach.
- The reference decoder turns "the spec is implementable on its own" from a claim into a
  test.

**Negative.**

- CI gains tool chains beyond Go: Python for the client tests, a JVM for TLC. Both run in
  containers, but they are additional failure modes in the pipeline.
- TLA+ carries real learning cost, which is why M3.5 budgets 2–3 days and sits at position 7
  of the cut list in `CONCEPT.md` §19.
- A model can drift away from the code it describes. Mitigations: the Go functions for
  Complete, Delete, rotation and `gc` name the corresponding model actions in comments,
  counterexamples become tests, and TLC runs whenever `spec/tla/` or the coordination logic
  changes.
- The model proves properties of the *model*, not of the implementation. This must be stated
  in the README; it is a strong argument, not a proof of the Go code.
