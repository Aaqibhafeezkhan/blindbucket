#!/usr/bin/env python3
"""Differential test: the Python reference decoder against the Go one.

Two implementations of the same specification are only worth having if they are
compared. Every input goes to both, and the only thing they have to agree on is
the verdict: accepted with this plaintext, or rejected. Error *messages* are not
part of the format and are not compared.

A disagreement is always a finding. If one accepts what the other rejects, the
specification is ambiguous or one of them is wrong; if both accept and the
plaintexts differ, one of them is very wrong.

The corpus is valid segments from the Go encoder, plus mutations of them:
bit flips, truncations, extensions, and targeted edits to the header fields that
docs/FORMAT.md section 5.2 requires a decoder to validate. Untargeted mutation
alone would spend almost all of its budget on inputs that fail at the magic.

    python3 ref/python/difftest.py --count 100000
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import random
import subprocess
import sys

from blindbucket_ref import FormatError, decode_segment

REPO = pathlib.Path(__file__).resolve().parents[2]
HEADER_SIZE = 32


def go_seeds(count: int) -> list[dict]:
    """Ask the Go encoder for valid segments to mutate."""
    result = subprocess.run(
        ["go", "run", "./test/difftool", "-gen", str(count)],
        cwd=REPO, capture_output=True, check=True,
    )
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def mutate(rng: random.Random, seed: dict) -> dict:
    """Produce one input from a valid segment.

    The weights matter more than the mutations. Most of the budget goes to edits
    that leave the input *nearly* valid, because those are where two decoders
    are most likely to disagree -- a truncation at a chunk boundary, a flipped
    flag bit, an index that no longer matches the expectation. A uniformly
    random byte string is rejected by both at the magic and proves nothing.
    """
    data = bytearray(bytes.fromhex(seed["data"]))
    out = dict(seed)
    choice = rng.random()

    if choice < 0.30:
        # A single bit anywhere. Inside the header this tests validation;
        # inside a chunk it tests the tag.
        if data:
            position = rng.randrange(len(data))
            data[position] ^= 1 << rng.randrange(8)

    elif choice < 0.45:
        # Truncation, biased towards chunk and tag boundaries, which is where
        # the final-flag rule of section 5.2 does its work.
        if len(data) > HEADER_SIZE:
            cuts = [len(data) - 1, len(data) - 16, len(data) - 17, HEADER_SIZE,
                    HEADER_SIZE + 16, rng.randrange(len(data) + 1)]
            data = data[: max(0, min(len(data), rng.choice(cuts)))]

    elif choice < 0.58:
        # Extension past the final chunk: the mirror image of truncation.
        data += bytes(rng.randrange(256) for _ in range(rng.choice([1, 16, 17, 32])))

    elif choice < 0.72:
        # Targeted header edits, one field at a time. These are the fields
        # section 5.2 step 2 names, so a decoder that skipped one shows up here.
        if len(data) >= HEADER_SIZE:
            field = rng.choice(["magic", "version", "log2c", "flags", "reserved", "index", "salt"])
            if field == "magic":
                data[rng.randrange(4)] = rng.randrange(256)
            elif field == "version":
                data[4] = rng.choice([0, 2, 255, rng.randrange(256)])
            elif field == "log2c":
                data[5] = rng.choice([0, 11, 21, 30, 255, rng.randrange(256)])
            elif field == "flags":
                data[6] = rng.choice([0x00, 0x01, 0x02, 0x80, 0xFF, rng.randrange(256)])
            elif field == "reserved":
                data[7] = rng.randrange(1, 256)
            elif field == "index":
                # Both ends of the legal part range and both sides of them, so
                # the flag/index consistency rule is exercised from either side.
                data[8:12] = rng.choice(
                    [0, 1, 10000, 10001, 0xFFFFFFFF, rng.randrange(1 << 32)]
                ).to_bytes(4, "big")
            else:
                data[12 + rng.randrange(20)] ^= 1 << rng.randrange(8)

    elif choice < 0.80:
        # A different key: both must reject, and neither may leak plaintext.
        out["dek"] = bytes(rng.randrange(256) for _ in range(32)).hex()

    elif choice < 0.88:
        # A different expectation than the segment was written with.
        out["multipart"] = not out["multipart"]
        out["index"] = rng.choice([0, 1, 2, 10000, 10001])

    elif choice < 0.94:
        # Splice two chunks' worth of bytes around: a provider reordering the
        # body without touching the header.
        if len(data) > HEADER_SIZE + 64:
            a = rng.randrange(HEADER_SIZE, len(data) - 32)
            b = rng.randrange(HEADER_SIZE, len(data) - 32)
            width = rng.choice([1, 16, 32])
            data[a:a + width], data[b:b + width] = data[b:b + width], data[a:a + width]

    # The remaining ~6% are left exactly as generated, so every run also checks
    # that both decoders still accept valid input.

    out["data"] = bytes(data).hex()
    return out


def run_go(inputs: list[dict]) -> list[dict]:
    """Feed every input to the Go decoder in one process."""
    payload = "\n".join(json.dumps(item) for item in inputs) + "\n"
    result = subprocess.run(
        ["go", "run", "./test/difftool"],
        cwd=REPO, input=payload.encode(), capture_output=True, check=True,
    )
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def run_python(item: dict) -> dict:
    """The same input through the reference decoder."""
    try:
        plain = decode_segment(
            bytes.fromhex(item["data"]),
            bytes.fromhex(item["dek"]),
            multipart=item["multipart"],
            index=item["index"],
        )
    except FormatError as err:
        return {"ok": False, "err": str(err)}
    except Exception as err:  # noqa: BLE001 - an unexpected crash is a finding too
        return {"ok": False, "err": f"UNEXPECTED {type(err).__name__}: {err}"}
    return {"ok": True, "sha256": hashlib.sha256(plain).hexdigest()}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--count", type=int, default=100_000, help="inputs to compare")
    parser.add_argument("--seeds", type=int, default=240, help="valid segments to mutate")
    parser.add_argument("--seed", type=int, default=1, help="RNG seed, for reproducibility")
    parser.add_argument("--batch", type=int, default=2000, help="inputs per Go invocation")
    args = parser.parse_args(argv[1:])

    rng = random.Random(args.seed)
    print(f"generating {args.seeds} valid segments with the Go encoder")
    seeds = go_seeds(args.seeds)
    print(f"comparing {args.count} inputs (rng seed {args.seed})")

    agreed = accepted = disagreements = 0
    examples: list[str] = []

    done = 0
    while done < args.count:
        size = min(args.batch, args.count - done)
        batch = [mutate(rng, rng.choice(seeds)) for _ in range(size)]
        go_verdicts = run_go(batch)
        if len(go_verdicts) != len(batch):
            print(f"the Go decoder answered {len(go_verdicts)} of {len(batch)} inputs")
            return 1

        for item, go in zip(batch, go_verdicts):
            py = run_python(item)
            same = go["ok"] == py["ok"] and (
                not go["ok"] or go.get("sha256") == py.get("sha256")
            )
            if same:
                agreed += 1
                accepted += 1 if go["ok"] else 0
                continue

            disagreements += 1
            if len(examples) < 5:
                examples.append(
                    f"    go: ok={go['ok']} {go.get('sha256', go.get('err', ''))[:60]}\n"
                    f"    py: ok={py['ok']} {py.get('sha256', py.get('err', ''))[:60]}\n"
                    f"    input: dek={item['dek'][:16]}... "
                    f"multipart={item['multipart']} index={item['index']} "
                    f"data={item['data'][:80]}..."
                )

        done += size
        print(f"  {done}/{args.count} compared, {disagreements} disagreements", end="\r", flush=True)

    print()
    print(f"compared     {done}")
    print(f"agreed       {agreed}")
    print(f"  accepted   {accepted}  (both decoded, identical plaintext)")
    print(f"  rejected   {agreed - accepted}  (both refused)")
    print(f"disagreed    {disagreements}")

    if disagreements:
        print("\nfirst disagreements:")
        for example in examples:
            print(example)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
