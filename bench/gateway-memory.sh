#!/usr/bin/env bash
#
# The memory row of the benchmark plan: push a large object through a
# running gateway and sample the gateway's resident set while it happens.
#
# This is the claim the whole streaming design exists for -- memory is a function
# of how many streams are in flight, never of how large they are -- so it is
# measured against a real object, through real HTTP, rather than inferred from a
# unit test. The unit test exists too (TestLargeStreamRoundTrip, which samples
# the Go heap directly and is the portable evidence); this is the end-to-end one.
#
# Usage:
#   bench/gateway-memory.sh <results-dir> [size]
#
# Environment:
#   BENCH_ENDPOINT   gateway endpoint          (default http://127.0.0.1:9000)
#   BENCH_BUCKET     bucket to write into      (required)
#   BENCH_KEY        object key                (default bench/memory.bin)
#   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY  credentials for the gateway
#   BENCH_PATTERN    pgrep pattern for the gateway (default 'blindbucket serve')
#
# The default size is 10GiB, which needs that much free space on the provider and
# on this machine. Pass a smaller size to rehearse.
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <results-dir> [size]" >&2
    exit 2
fi
out=$1
size=${2:-10GiB}
mkdir -p "$out"

BENCH_ENDPOINT=${BENCH_ENDPOINT:-http://127.0.0.1:9000}
BENCH_KEY=${BENCH_KEY:-bench/memory.bin}
BENCH_PATTERN=${BENCH_PATTERN:-blindbucket serve}
: "${BENCH_BUCKET:?set BENCH_BUCKET to a bucket the gateway client may write}"

case $size in
    *GiB) bytes=$(( ${size%GiB} * 1024 * 1024 * 1024 )) ;;
    *MiB) bytes=$(( ${size%MiB} * 1024 * 1024 )) ;;
    *)    echo "size must look like 10GiB or 512MiB" >&2; exit 2 ;;
esac

pid=$(pgrep -f "$BENCH_PATTERN" | head -1 || true)
if [[ -z $pid ]]; then
    echo "no process matching '$BENCH_PATTERN'; start the gateway first" >&2
    exit 1
fi
echo "sampling gateway pid $pid while $size moves through it"

payload=$(mktemp -t blindbucket-bench)
restored=$(mktemp -t blindbucket-bench)
trap 'rm -f "$payload" "$restored"' EXIT

echo "generating $size of random data"
dd if=/dev/urandom of="$payload" bs=1048576 count=$(( bytes / 1048576 )) status=none
want=$(shasum -a 256 "$payload" | cut -d' ' -f1)

csv="$out/gateway-rss.csv"
echo "elapsed_ms,rss_kib,phase" > "$csv"
phase=idle
sample() {
    local start now rss
    start=$(date +%s%N)
    while kill -0 "$pid" 2>/dev/null; do
        rss=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || true)
        if [[ -n ${rss:-} ]]; then
            now=$(date +%s%N)
            echo "$(( (now - start) / 1000000 )),$rss,$(cat "$out/.phase")" >> "$csv"
        fi
        sleep 0.1
    done
}

echo "$phase" > "$out/.phase"
sample &
sampler=$!
trap 'kill $sampler 2>/dev/null; rm -f "$payload" "$restored" "$out/.phase"' EXIT

export AWS_ENDPOINT_URL=$BENCH_ENDPOINT
sleep 2   # a little idle baseline before the work starts

echo upload > "$out/.phase"
echo "uploading"
time aws s3 cp --quiet "$payload" "s3://$BENCH_BUCKET/$BENCH_KEY"

echo between > "$out/.phase"
sleep 2

echo download > "$out/.phase"
echo "downloading"
time aws s3 cp --quiet "s3://$BENCH_BUCKET/$BENCH_KEY" "$restored"

echo idle > "$out/.phase"
sleep 2
kill $sampler 2>/dev/null || true

got=$(shasum -a 256 "$restored" | cut -d' ' -f1)
if [[ $want != "$got" ]]; then
    echo "MISMATCH: $want != $got" >&2
    exit 1
fi
echo "round trip is byte-identical ($want)"

python3 - "$csv" "$(uname -s)" "$size" <<'PY'
import csv, statistics, sys

rows = list(csv.DictReader(open(sys.argv[1])))
platform, size = sys.argv[2], sys.argv[3]
if not rows:
    print("no samples collected")
    raise SystemExit(0)

by_phase = {}
for row in rows:
    by_phase.setdefault(row["phase"], []).append(int(row["rss_kib"]))

print()
print(f"gateway resident set while {size} moved through it")
for phase in ("idle", "upload", "between", "download"):
    values = by_phase.get(phase)
    if not values:
        continue
    print(f"  {phase:<9} median {statistics.median(values) / 1024:7.1f} MiB   "
          f"peak {max(values) / 1024:7.1f} MiB   ({len(values)} samples)")

streaming = by_phase.get("upload", []) + by_phase.get("download", [])
if streaming:
    print()
    print(f"peak while streaming: {max(streaming) / 1024:.1f} MiB for {size} of payload")

if platform == "Darwin":
    print()
    print("note: on macOS RSS does not fall when Go releases pages -- the runtime uses")
    print("      MADV_FREE_REUSABLE, which marks them reclaimable without lowering what ps")
    print("      reports. The figure above is therefore an upper bound. Run on Linux for a")
    print("      number that also falls again.")
PY
