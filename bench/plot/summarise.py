#!/usr/bin/env python3
"""Turn a directory of warp output into a CSV and a Markdown table.

`warp` prints its report as text. Parsing that is less pleasant than reading a
machine-readable file, but `--analyze.out` needs a writable bind mount into the
container, which is one more thing to get wrong on a machine where Docker does
not share the directory in question. The text is stable and carries everything
CONCEPT.md section 12.5 asks for: throughput, p50, p90 and p99.

Usage:
    python3 bench/plot/summarise.py <results-dir>

Writes <results-dir>/results.csv and <results-dir>/results.md.
"""

from __future__ import annotations

import csv
import re
import statistics
import sys
from pathlib import Path

# " * Average: 212.83 MiB/s, 212.83 obj/s" -- or, for tiny objects, only obj/s.
AVERAGE = re.compile(
    r"^\s*\*\s*Average:\s*(?:([\d.]+)\s*([KMG]?i?B)/s,\s*)?([\d.]+)\s*obj/s", re.M)
# " * Reqs: Avg: 18.7ms, 50%: 18.4ms, 90%: 22.5ms, 99%: 28.0ms, ..."
REQS = re.compile(
    r"^\s*\*\s*Reqs:\s*Avg:\s*([\d.]+)(m?s),.*?50%:\s*([\d.]+)(m?s),"
    r".*?90%:\s*([\d.]+)(m?s),.*?99%:\s*([\d.]+)(m?s)", re.M)

UNIT_BYTES = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}


def to_mib_s(value: str | None, unit: str | None) -> float | None:
    if value is None or unit is None:
        return None
    return float(value) * UNIT_BYTES.get(unit, 1) / UNIT_BYTES["MiB"]


def to_ms(value: str, unit: str) -> float:
    return float(value) * (1000.0 if unit == "s" else 1.0)


def parse(path: Path) -> dict | None:
    """Read one warp report. A run that produced no report is skipped, loudly."""
    text = path.read_text(errors="replace")
    average = AVERAGE.search(text)
    reqs = REQS.search(text)
    if not average or not reqs:
        print(f"  no usable report in {path.name}", file=sys.stderr)
        return None

    # direct-put-10MiB-c16-r2.txt, or the older direct-put-10MiB-c16.txt
    stem = path.stem.split("-")
    if len(stem) not in (4, 5) or not stem[3].startswith("c"):
        print(f"  unexpected file name {path.name}", file=sys.stderr)
        return None

    return {
        "path": stem[0],
        "op": stem[1],
        "size": stem[2],
        "concurrency": int(stem[3][1:]),
        "repeat": int(stem[4][1:]) if len(stem) == 5 else 1,
        "mib_s": to_mib_s(average.group(1), average.group(2)),
        "obj_s": float(average.group(3)),
        "avg_ms": to_ms(reqs.group(1), reqs.group(2)),
        "p50_ms": to_ms(reqs.group(3), reqs.group(4)),
        "p90_ms": to_ms(reqs.group(5), reqs.group(6)),
        "p99_ms": to_ms(reqs.group(7), reqs.group(8)),
    }


SIZE = re.compile(r"^([\d.]+)\s*([KMG]?i?B)$")


def size_order(size: str) -> int:
    """Sort 1KiB before 10MiB before 1GiB, rather than lexically."""
    match = SIZE.match(size)
    if not match:
        return 0
    return int(float(match.group(1)) * UNIT_BYTES.get(match.group(2), 1))


def collapse(raw: list[dict]) -> list[dict]:
    """Reduce the repetitions of each cell to a median, and record the spread.

    The spread is the point. A cell measured once is a number; a cell measured
    three times with a 6x range between them is a warning that the rig, not the
    code, is what is being observed.
    """
    cells: dict[tuple, list[dict]] = {}
    for row in raw:
        cells.setdefault((row["path"], row["op"], row["size"], row["concurrency"]),
                         []).append(row)

    out = []
    for (path, op, size, concurrency), runs in cells.items():
        rate_key = "mib_s" if runs[0]["mib_s"] is not None else "obj_s"
        rates = sorted(float(r[rate_key]) for r in runs)
        median_rate = statistics.median(rates)
        # The run nearest the median rate supplies the latency figures, so that
        # throughput and latency describe the same run rather than two different
        # ones.
        representative = min(runs, key=lambda r: abs(float(r[rate_key]) - median_rate))
        out.append({
            "path": path, "op": op, "size": size, "concurrency": concurrency,
            "runs": len(runs),
            "mib_s": representative["mib_s"],
            "obj_s": representative["obj_s"],
            "avg_ms": representative["avg_ms"],
            "p50_ms": representative["p50_ms"],
            "p90_ms": representative["p90_ms"],
            "p99_ms": representative["p99_ms"],
            # How far apart the fastest and slowest repetitions were, as a
            # fraction of the median.
            "spread": (rates[-1] - rates[0]) / median_rate if median_rate else 0.0,
        })
    out.sort(key=lambda r: (size_order(r["size"]), r["op"], r["concurrency"], r["path"]))
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    results_dir = Path(argv[1])

    raw = [r for r in (parse(p) for p in sorted(results_dir.glob("*-*-*-c*.txt"))) if r]
    if not raw:
        print("no results parsed", file=sys.stderr)
        return 1
    raw.sort(key=lambda r: (size_order(r["size"]), r["op"], r["concurrency"],
                            r["path"], r["repeat"]))

    csv_path = results_dir / "results-raw.csv"
    with csv_path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(raw[0]))
        writer.writeheader()
        writer.writerows(raw)

    rows = collapse(raw)
    summary_path = results_dir / "results.csv"
    with summary_path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    # Pair each proxy run with the direct run it should be compared against.
    direct = {(r["op"], r["size"], r["concurrency"]): r for r in rows if r["path"] == "direct"}
    lines = [
        "| Size | Op | Clients | Direct | Through the proxy | Ratio | "
        "p50 direct → proxy | p99 direct → proxy |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        if row["path"] != "proxy":
            continue
        base = direct.get((row["op"], row["size"], row["concurrency"]))
        if not base:
            continue

        # Small objects are a request-rate story: 0.9 MiB/s says nothing a reader
        # can use, while 900 obj/s is the number the size was chosen to expose.
        small = size_order(row["size"]) < UNIT_BYTES["MiB"]

        def rate(r: dict) -> str:
            if small or not r["mib_s"]:
                return f"{float(r['obj_s']):,.0f} obj/s"
            return f"{float(r['mib_s']):.1f} MiB/s"

        metric = "obj_s" if small else ("mib_s" if row["mib_s"] else "obj_s")
        a, b = float(base[metric]), float(row[metric])
        # A cell whose repetitions disagree by more than a quarter is reporting
        # the test rig, not the gateway. Say so in the row rather than letting
        # the ratio stand unqualified.
        spread = max(float(base.get("spread", 0)), float(row.get("spread", 0)))
        ratio = f"{b / a * 100:.0f}%"
        if spread > 0.25:
            ratio += f" ±{spread * 100:.0f}%"
        lines.append(
            f"| {row['size']} | {row['op'].upper()} | {row['concurrency']} | "
            f"{rate(base)} | {rate(row)} | {ratio} | "
            f"{base['p50_ms']:.1f} → {row['p50_ms']:.1f} ms | "
            f"{base['p99_ms']:.1f} → {row['p99_ms']:.1f} ms |"
        )

    md_path = results_dir / "results.md"
    environment = results_dir / "environment.txt"
    header = ""
    if environment.exists():
        header = "```\n" + environment.read_text().rstrip() + "\n```\n\n"
    md_path.write_text(header + "\n".join(lines) + "\n")

    print("\n".join(lines))
    print(f"\nwrote {csv_path} and {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
