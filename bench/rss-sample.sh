#!/usr/bin/env bash
#
# Sample the resident set size of a command while it runs.
#
# The point is to separate two very different costs that a single high-water
# figure conflates:
#
#   * a one-time spike while Argon2id unlocks the keyring, which is fixed by the
#     KDF parameters and has nothing to do with the data being processed, and
#   * the steady state while bytes are streamed, which is the number that has to
#     stay flat as the object grows.
#
# Usage: bench/rss-sample.sh <csv-output> <command> [args...]
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <csv-output> <command> [args...]" >&2
  exit 2
fi

csv=$1
shift

"$@" &
pid=$!

echo "elapsed_ms,rss_kib" > "$csv"
start=$(date +%s%N)
while kill -0 "$pid" 2>/dev/null; do
  rss=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || true)
  if [[ -n "${rss:-}" ]]; then
    now=$(date +%s%N)
    echo "$(( (now - start) / 1000000 )),$rss" >> "$csv"
  fi
  sleep 0.02
done
wait "$pid"

python3 - "$csv" "$(uname -s)" <<'PY'
import csv, statistics, sys

rows = list(csv.DictReader(open(sys.argv[1])))
platform = sys.argv[2] if len(sys.argv) > 2 else ""
if not rows:
    print("no samples collected (the command finished too quickly)")
    raise SystemExit(0)

rss = [int(r["rss_kib"]) for r in rows]
peak = max(rss)

# The KDF spike is at the start, before any streaming. Drop the leading samples
# up to and including the peak, then describe what remains: that is the steady
# state while data actually moves.
peak_at = rss.index(peak)
tail = rss[peak_at + 1:]

print(f"samples            {len(rss)}")
print(f"peak RSS           {peak / 1024:.1f} MiB   (includes the Argon2id allocation)")
if tail:
    print(f"steady-state RSS   {statistics.median(tail) / 1024:.1f} MiB   (median while streaming)")
    print(f"steady-state max   {max(tail) / 1024:.1f} MiB")
else:
    print("steady-state RSS   not observed; the run was too short to sample after the peak")

if platform == "Darwin":
    print()
    print("note: on macOS this figure is not authoritative. Go returns freed pages with")
    print("      MADV_FREE_REUSABLE, which marks them reclaimable without lowering the RSS")
    print("      that ps reports until the system is actually under pressure. Go's own")
    print("      HeapReleased confirms the pages were handed back. The portable evidence for")
    print("      constant memory is TestLargeStreamRoundTrip, which measures the Go heap")
    print("      directly; run this script on Linux for a meaningful RSS number.")
PY
