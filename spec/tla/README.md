# Formal model of the manifest coordination

[`Multipart.tla`](Multipart.tla) models the coordination described in
[CONCEPT.md](../../CONCEPT.md) §10.6, §10.8 and §11.2: what order the proxy makes its
upstream calls in when several requests work on the same key at the same time, possibly on
different instances, and any of them may die at any point.

It exists because those rules — R1 to R4 — were derived by *reasoning*. Version 0.1 of the
concept contained two race conditions that were also derived by reasoning, and they survived
being written down, read again, and reviewed. Argument is not evidence, so the rules are
checked here before M4 turns them into Go.

## What is modelled, and what is not

| In the model | Not in the model |
|---|---|
| The visible object version for one key | Anything cryptographic: data keys, segments, chunk tags |
| The set of manifest sidecar objects | Part contents, part sizes, `ListParts` |
| Open multipart uploads at the upstream | More than one key — manifests and gc are per key |
| Two to three concurrent uploads, a single-part PUT, a `DeleteObject`, a rotation, one `gc` pass | The minimum-age condition in R4 step 4 (see below) |
| A crash of any process after any step, losing that process's local state | Network retries: a retried call is a repeat of the same step |
| The bucket lifecycle rule aborting an open upload at any time | |

**Why the minimum age is left out.** R4 step 4 only deletes manifests older than the
lifecycle window plus 24 hours. That threshold is a guard against the *upstream assumptions*
failing — it does nothing if they hold, and the model assumes they hold. Modelling it would
therefore make R4 look safe for a reason that has nothing to do with its ordering, which is
the part that was never checked. The ordering argument stands on its own here, and the
threshold remains a second line of defence rather than the first.

**The upstream assumptions themselves** (§10.8) are assumptions of the model, not results of
it: read-after-write consistency for HEAD, LIST and `ListMultipartUploads`, and a completed
or aborted upload id never making an object visible again. For AWS S3 these are guaranteed;
for MinIO and R2 they belong in the compatibility matrix, not in TLC.

## Invariants

- **I1** — every visible multipart object has a manifest with its manifest id. An object
  that fails I1 is not lost (the ciphertext and the data key are still there) but every GET
  against it fails.
- **I2** — rotation never replaces a newer version of an object with an older one.

The liveness property §15.2 lists as optional — that orphaned manifests eventually disappear
under fairness — is **not** modelled. It would need a `gc` that loops rather than making one
pass, plus fairness on the lifecycle rule, and liveness checking costs far more than the
safety run. Both invariants above are safety properties, and orphaned manifests are a
cleanup concern rather than a correctness one: they hold no plaintext, and an object that
keeps one around is still perfectly readable.

## Configurations

Four of the five configurations are expected to **fail**. A model that cannot reproduce the
two races the concept already knows about is too coarse to be evidence about the races it
does not know about, so "no counterexample" is a failing result for those four.

| Configuration | Rules | Expected |
|---|---|---|
| `MCFixed` | R1–R4, conditional rotation, 3 uploads | no counterexample |
| `MCLegacyCleanup` | completion deletes *every other* manifest of the key (v0.1) | **I1 violated** |
| `MCLegacyGc` | `gc` never checks for open uploads (v0.1) | **I1 violated** |
| `MCGcOrder` | R4 with steps 1 and 2 swapped | **I1 violated** |
| `MCUnconditionalRotate` | `rotate --allow-unconditional` | **I2 violated** |

The three I1 configurations run with `RotateMode = "off"`, so their counterexamples contain
only operations that M4 itself implements and can replay as integration tests.

## Running it

```sh
make tla-tools     # downloads tla2tools.jar into .tools/ (not committed)
make tla           # translates the PlusCal and runs all five configurations
make tla-translate # re-run the PlusCal translator after editing the algorithm
```

`check.sh` takes configuration names if only some are wanted:

```sh
./check.sh MCLegacyGc MCGcOrder
```

`MCFixed` explores about 38.5 million distinct states — roughly 21 CPU-minutes, so about
three minutes on eight cores. The other four finish in seconds. The CI job runs on changes to
`spec/tla/` or to the coordination code rather than on every push.

One caveat worth stating plainly, since "exhaustive" is doing a lot of work above: TLC
recognises a state it has already seen by a 64-bit fingerprint, so at tens of millions of
states there is a small chance two distinct states collide and one subtree goes unexplored.
TLC estimates that probability itself and `check.sh` prints it — for `MCFixed` it lands
between 1e-4 and 3e-3 depending on the run. That is a property of the hash width, not of the
machine, so more memory does not move it; rerunning with a different `-fp` seed and getting
the same answer is what buys extra confidence. The four counterexample runs are unaffected: a
trace TLC prints is a trace that exists.

The checked-in `Multipart.tla` contains both the PlusCal algorithm and its translation. CI
re-runs the translator and fails if the result differs, so the two can never drift apart.

## The counterexamples

Each trace below is what TLC prints, with the incidental steps of uninvolved processes left
out; `./check.sh` regenerates them in full. Each is a scenario for the M4 integration tests,
where test hooks hold a request at a named point until another request has passed its own.

### 1. Cleanup against a concurrent upload — `MCLegacyCleanup`

The version 0.1 rule for step 5 of the completion order was "delete the other manifests of
this key". TLC reaches an unreadable object in eleven states.

| # | Who | Step | Result |
|---|---|---|---|
| 1 | client | `PutObject` — a single-part object is visible | |
| 2 | u1, u2 | `CreateMultipartUpload` on the same key | two uploads open |
| 3 | u1 | HEAD — the visible object is single-part | observed: none |
| 4 | u1 | write manifest `u1` | manifests: `{u1}` |
| 5 | u1 | `CompleteMultipartUpload` | **visible: multipart `u1`** |
| 6 | u2 | HEAD — sees `u1` | observed: `u1` |
| 7 | u2 | write manifest `u2` | manifests: `{u1, u2}` |
| 8 | u1 | cleanup: delete every *other* manifest | manifests: `{u1}` ← **`u2` is gone** |
| 9 | u2 | `CompleteMultipartUpload` | **visible: multipart `u2`**, manifest missing |

Step 8 is the bug: u1's own completion finished three steps earlier, but the request had not
got around to its cleanup yet, and by then u2 had written a manifest that u1 knows nothing
about. R3 fixes it by licensing a request to delete exactly one id — the one it observed at
step 2 — and nothing else.

**M4 integration test:** hold u1 between `CompleteMultipartUpload` and the manifest delete;
let u2 run HEAD and write its manifest; release u1; complete u2; `GetObject` must succeed.

### 2. `gc` against an upload in flight — `MCLegacyGc`

Version 0.1's `gc` listed the manifests, read the current manifest id, and deleted the rest.

| # | Who | Step | Result |
|---|---|---|---|
| 1 | client | `PutObject` — a single-part object is visible | current manifest id: none |
| 2 | u1 | `CreateMultipartUpload`, HEAD, write manifest `u1` | manifests: `{u1}`, upload open |
| 3 | gc | list manifests | listed: `{u1}` |
| 4 | gc | HEAD — the visible object is single-part | current: none |
| 5 | gc | delete every listed manifest that is not current | manifests: `{}` ← **`u1` is gone** |
| 6 | u1 | `CompleteMultipartUpload` | **visible: multipart `u1`**, manifest missing |

`gc` was right about every fact it observed. `u1` really was not the current manifest id at
step 4 — it just was not current *yet*. R4 step 2 closes this by asking
`ListMultipartUploads` first and skipping the key entirely while an upload is in flight.

**M4 integration test:** hold a `CompleteMultipartUpload` after its manifest write; run
`blindbucket gc` to completion; release the upload; `GetObject` must succeed. With R4 the
`gc` run must report the key as skipped.

### 3. R4 with its first two steps swapped — `MCGcOrder`

This one is not a bug from version 0.1. It is a check on R4 itself, and it is the reason R4
fixes an order for two steps that only *read*.

| # | Who | Step | Result |
|---|---|---|---|
| 1 | client | `PutObject` — a single-part object is visible | |
| 2 | gc | `ListMultipartUploads` — **nothing open**, carry on | |
| 3 | u1 | `CreateMultipartUpload`, HEAD, write manifest `u1` | manifests: `{u1}`, upload open |
| 4 | gc | list manifests | listed: `{u1}` |
| 5 | gc | HEAD — still single-part | current: none |
| 6 | gc | delete the listed non-current manifests | manifests: `{}` |
| 7 | u1 | `CompleteMultipartUpload` | **visible: multipart `u1`**, manifest missing |

Swapping two read-only steps is the kind of edit that passes review, because neither step
changes anything. It is still wrong. Listing *first* is what makes the open-upload check
mean something: every manifest in the listing was written before the check ran, so an upload
that could still publish one of them would have been open at the time of the check. Check
first and the listing picks up manifests written afterwards, about which the check said
nothing.

This is the result that pays for the milestone. The argument for R4 in §10.8 is correct, but
nothing in it announces that the order of steps 1 and 2 is load-bearing, and nobody reading
the finished Go code would either.

**M4 integration test:** the same hooks as scenario 2, releasing the upload creation between
`gc`'s first and second upstream call.

### 4. Rotation without a conditional write — `MCUnconditionalRotate`

`blindbucket rotate --allow-unconditional`, the mode §11.2 permits on upstreams that have no
conditional writes. Six states:

| # | Who | Step | Result |
|---|---|---|---|
| 1 | rotate | HEAD the object, note its etag | |
| 2 | client | `PutObject` — overwrites the object | **the client's data is the visible version** |
| 3 | rotate | create upload, copy parts, write manifest | |
| 4 | rotate | `CompleteMultipartUpload`, no `If-Match` | **visible: the pre-rotation version** |

The client's write is gone. With `If-Match` the completion fails with 412, rotation reports
the object as skipped, and the client's write stands. I2 holds in every other configuration
because of that one header.

This is not a defect to fix — it is the documented price of the flag, and the model is what
makes the warning in the documentation a measured statement rather than a hedge.
