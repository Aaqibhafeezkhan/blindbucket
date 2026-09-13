# ADR-016 — A hash-chained, signed audit log, one chain per instance

**Status:** Accepted
**Date:** 2026-09-13
**Milestone:** post-M5
**Implements:** `internal/audit`, `internal/crypto/keys` (audit key), `internal/proxy`, `blindbucket audit`

## Context

The gateway is the one place where plaintext and identity meet. It knows which
credential asked for which object, whether the request was allowed, and what came
back — and it is the only component that knows, because the storage provider sees
ciphertext under names it cannot read and the client sees only its own traffic.
That makes the gateway the natural place to record what happened, and the only
one that *can*.

It also makes the record worth attacking. A log that an intruder can edit after
the fact answers no question worth asking: "nothing in the log" and "nothing
happened" are the same sentence only if the log cannot be quietly shortened. So
the requirement is not logging, which `slog` already does, but **tamper
evidence**: any edit, reorder, splice or removal must be detectable afterwards,
by someone who was not there at the time and who does not hold the keys.

Two things this project has already decided constrain the shape of the answer.

**There is no shared state.** Goal G5 is stateless horizontal scaling; ADR-002
rejected a shared index for exactly this reason, and ADR-006 put multipart state
in an encrypted token rather than a database. A single global log with a total
order across instances would be that database, arriving through the back door.

**Names are not the provider's business, and are becoming not anyone's.**
ADR-015 encrypts object names per path segment. An audit log that writes
`photos/2026/payroll.xlsx` in clear next to it would hand back, in a file that is
easier to steal than a bucket, precisely what that work hides.

## What this is not

**This does not close the rollback risk of `THREAT_MODEL` §5.1.** A log of what
the gateway did is not an authority on what the current version of an object is,
and nothing here makes a read consult it. Turning this log into a version index
that reads verify against is a different feature with a different cost — it
reintroduces the shared mutable state above, and ADR-002 has the argument
against. The two share machinery and are separate decisions; §5.1 stays
**accepted risk** and is not quietly downgraded because a log now exists.

Saying so here is the point. A feature called "audit log" invites a reader to
assume rollback is handled, and an unstated assumption in the direction of more
security is the kind this project has to avoid.

## Decision

### One chain per instance, not one log per deployment

Each gateway process appends to its own file and hashes its own chain. Nothing is
shared, no instance waits for another, and the property being claimed is per
chain: *this instance's record of its own requests is complete and unedited*.

The alternative — one totally ordered log across instances — is strictly more
informative and would need a consensus protocol or a serialising writer in front
of every request. That is the shared-state design G5 exists to avoid, and it
would put a network round trip on a path measured at 0.13 ms. Per-instance chains
give up a global order, which no S3 client can observe anyway: two requests to
two instances have no order in the API either.

### Hash chain over canonical, length-prefixed fields

Each entry carries the hash of the one before it:

```
h₀ = SHA-256("blindbucket/v1/audit-head"       || lp(chain) || lp(opened) || lp(pubkey) || lp(prev))
hₙ = SHA-256("blindbucket/v1/audit-entry"      || uint64_be(seq) || lp(chain) || fields… || hₙ₋₁)
```

The fields are length-prefixed and the record types are domain-separated, for the
reason `FORMAT.md` §1 already gives: without it, adjacent variable-length fields
concatenate ambiguously and two different entries can hash the same. `lp()` here
is the same `lp()` as everywhere else in the project.

The genesis hash binds the chain's own id and its public key, so an entry cannot
be lifted from one chain and replayed into another: its hash covers a `seq` and a
`chain` that would have to match.

### Signed checkpoints, not signed entries

Every *N* entries, every *T* seconds, and on clean shutdown, the writer appends a
checkpoint: the current `seq`, the current chain hash, and an Ed25519 signature
over both. Entries themselves are not signed.

This is the transparency-log idiom — Certificate Transparency's signed tree heads
are the same move — and the reasoning is the same. The chain already makes every
entry before a checkpoint immutable: changing one changes every hash after it,
including the one the checkpoint signed. Signing each entry would add 64 bytes
and a signature to every request while proving nothing the chain does not already
prove.

What this does not close is stated under **Consequences**, because it is the
limit of the whole design: entries written after the last checkpoint are chained
but not signed, and whoever holds the file can drop them.

### The signing key lives in the keyring, and only its private half is wrapped

The keyring gains one optional entry: a 32-byte audit secret, wrapped under the
root key exactly as a KEK is and bound by its own associated-data prefix, plus
**the Ed25519 public key in clear**.

Two keys are derived from that secret by HKDF-SHA256 with separate `info`
strings: the Ed25519 seed that signs checkpoints, and a name key for the field
below. One wrapped secret, two uses, no possibility of one being used as the
other.

The public key being unwrapped is the feature, not an oversight. It means
**verifying a log needs no secret at all** — the check is a signature check, and
anyone handed the log and the public key can run it, including an auditor who
should not have the keyring and an operator whose host has burned down. Reading
the *names* in that log is a separate privilege that does need the keyring. This
split is the reason to use a signature here rather than an HMAC, which would have
required handing over a key that can also forge.

The keyring file format stays at version 1 and the field is optional. A keyring
written before this existed loads unchanged; a gateway configured to audit with
such a keyring refuses to start and names the command that fixes it, rather than
starting with auditing silently off.

### Object names in the log are encrypted, not written in clear

Bucket and key are stored through `internal/crypto/names` — the deterministic
per-segment SIV construction of ADR-015 — under the name key derived above.

This is ADR-015's primitive finding a second caller before its first one ships,
and it inherits that ADR's properties exactly, including the one that is a cost:
determinism does not hide equality, so an attacker holding the log can confirm a
guessed name, and repeated access to one object is visible as repeated access to
*something*. `THREAT_MODEL` §4 says this in the same words for stored names and
now says it for logged ones.

Encryption rather than a keyed hash, deliberately: a hash would be irreversible,
and an audit log that cannot be read during an actual incident is an audit log
that fails at the one moment it exists for. `blindbucket audit verify --keyring`
decrypts; `--public-key` does not and does not need to.

The name key is derived from the audit secret and is **not** ADR-015's name key.
The two are independent, so a log entry and a stored object name are different
opaque strings for the same object. That is a deliberate loss of correlation for
anyone holding both without the keyring, and a small cost in forensics for
anyone holding it.

### Fail-closed means the *next* request, and the log says which one was lost

An entry records an outcome — status, bytes, error code — so it can only be
written once the request is over. There is nothing left to withhold by then, and
a design that pretended otherwise would have to buffer the response, which is
ADR-004's rejected alternative wearing a different hat.

So: an append failure marks the writer broken, and a broken writer makes the
gateway refuse **subsequent** requests with `503 ServiceUnavailable` until it is
fixed. Exactly one request can be served unrecorded, and that is visible in the
log as the place the chain stops.

Fail-closed is the default because the failure it guards against is an attacker
filling a disk to turn auditing off, which is a cheap attack against a log that
degrades quietly. `audit.fail_closed: false` is available and documented as what
it is: a choice to keep serving with an incomplete record.

## Alternatives considered

**A Merkle tree with inclusion and consistency proofs**, as Certificate
Transparency proper. Strictly stronger: a client could be handed a proof that its
own operation is in the log without being handed the log. Rejected for now on
honest grounds — there is no second party here to hand a proof to. The gateway's
clients are the operator's own workloads, inside the trust boundary, and a proof
system with no verifier on the other end is machinery for its own sake. The
linear chain is the same tamper evidence for the questions actually asked, and
`h_n` is a tree head over a degenerate tree if it is ever worth generalising.

**HMAC under a KEK instead of Ed25519.** No new key type, no new primitive, and
the keyring already does AES-GCM under a KEK. Rejected: verification would need
the same key that writes, so an auditor could forge what they verify and an
operator could not delegate the check. "Verifiable by whoever already has the
power to rewrite it" is not the property the feature is for.

**Signing every entry.** Removes the truncation window below entirely. Rejected
on cost and on effect. The cost is 64 bytes per entry plus an Ed25519 signature,
measured at **11.9 µs**, against an append measured at **3.6 µs** — it more than
quadruples the serialised section of every request. The effect is nil against the
attacker it would be for: someone holding the file can drop signed entries as
easily as unsigned ones, so truncation is not what a per-entry signature fixes.

**The log as an upstream object.** Survives the loss of an instance, which a
local file does not. Rejected as the default: it puts the record of what the
provider was asked to do into the provider's hands, where it can be truncated by
exactly the actor a chain is meant to catch — and with no externally published
checkpoint, truncation to a checkpoint boundary is undetectable. Shipping the
file elsewhere is an operator's decision and works with any tool, because the
format is append-only lines.

**Writing audit records through `slog` with the chain fields attached.** Would
reuse the handler, the formatting and whatever ships logs today. Rejected: a
handler can be reconfigured, sampled, rate-limited or pointed at a socket that
drops, and a chain with a hole in it fails verification without saying whether a
request was hidden or a log line was dropped. The audit writer owns its file.

**An in-process queue with a background writer.** Keeps the hashing and the write
off the request goroutine. Rejected as premature: the append is **3.6 µs**
against a gateway overhead measured at 0.13 ms per request — under 3 % — on a
path that has already made at least one network round trip. A queue would add a
bounded channel whose full state is either a stall or a silently dropped audit
record, and both are worse than the mutex. If the append ever becomes the
bottleneck, the number to beat is in `internal/audit/bench_test.go`.

## What it costs, measured

Apple M4, APFS, Go 1.27, from `internal/audit/bench_test.go`:

| | |
|---|---|
| One append (name encryption, chain hash, buffered write) | **3.6 µs**, 8.5 kB, 100 allocs |
| One checkpoint (Ed25519 signature and `fsync`) | **≈ 4.7 ms**, almost all of it the fsync |
| Verifying a log | **210 MB/s**, so the 128 MiB rotation default is ≈ 0.6 s at startup |
| An Ed25519 signature on its own | 11.9 µs |

The two that matter are the first and the last. The append is what every request
pays and is small against the 0.13 ms the gateway already costs; the signature is
what the rejected "sign every entry" alternative would have added to it.

The checkpoint cost is an fsync and is therefore a property of the disk rather
than of this code. It is paid once per `checkpoint_every` entries, so at the
default of 256 it is ≈ 18 µs per request — and lowering that setting to narrow
the truncation window is the same knob as raising the per-request cost. That
trade is the operator's, and this is the number to make it with.

## Consequences

**Positive.**

- Any edit, reorder or splice of a chain before its last checkpoint is detectable
  with the public key alone, by someone who holds neither the keyring nor the
  host.
- Verification needs no secret. Handing an auditor the log and the public key
  hands them nothing that lets them write to it.
- Object names in the log are no more readable than the object names in the
  bucket, so shipping the log off-host does not undo ADR-015.
- Statelessness is untouched: no coordination, no shared writer, no round trip.
  Adding an instance adds a chain.

**Negative.**

- **Truncation past the last checkpoint is undetectable from the file alone.**
  Whoever holds the file can drop entries written since, and nothing in it
  disagrees. That window is bounded by the checkpoint interval and no smaller;
  closing it needs a checkpoint published somewhere the attacker does not
  control, which is why `audit verify --expect` takes one and why the verifier
  prints the latest checkpoint rather than only a verdict.
- **The host holds the signing key.** An attacker with the running process can
  write entries that verify — the threat model already says anyone who controls
  the proxy host has everything, and this does not change it. The property is
  against an attacker who reaches the *log*, not one who reaches the gateway.
- No global order across instances, and no way to prove one instance's chain is
  complete with respect to another's. Per-chain completeness is all that is
  claimed.
- Opening a log verifies it from the beginning, so startup is linear in the size
  of the file being continued. Rotation bounds it, and the head of each new file
  records the previous file's final hash so a rotated sequence is still one
  chain.
- One request per breakage can be served without a record, as above.
- `fail_closed` turns a full disk into an outage. That is the intended reading of
  the word, and the operational cost of it is the reason the setting exists.
