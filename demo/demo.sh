#!/usr/bin/env bash
#
# The recorded session: the thirty-second case for the project, as CONCEPT.md
# section 20 describes it. A standard client uploads a large file through the
# gateway; the provider is then shown holding ciphertext and a wrapped key; the
# download comes back with an identical hash; and a provider that changes one bit
# gets an error instead of plaintext.
#
# Everything here is a real command against a real MinIO. Run demo/setup.sh first.
#
# Usage:
#   demo/demo.sh                              # run it, with typing pacing
#   DEMO_FAST=1 demo/demo.sh                  # no pacing, for checking it still works
#
# Recording it is demo/README.md: the terminal has to be 100x30, which is what the
# line lengths below are written for.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
state="$root/demo/.state"
[[ -f "$state/env.sh" ]] || { echo "run demo/setup.sh first" >&2; exit 1; }
# shellcheck disable=SC1091
source "$state/env.sh"
cd "$root"

if [[ -n ${DEMO_FAST:-} ]]; then TYPE_DELAY=0; BEAT=0; PAUSE=0
else TYPE_DELAY=${TYPE_DELAY:-0.012}; BEAT=${BEAT:-1.1}; PAUSE=${PAUSE:-2.0}; fi

DIM=$'\033[2m'; BOLD=$'\033[1m'; GREEN=$'\033[32m'; RED=$'\033[31m'; OFF=$'\033[0m'

# The real command name, so that what the recording shows is what a viewer can paste.
if command -v sha256sum >/dev/null 2>&1; then SHA="sha256sum"; else SHA="shasum -a 256"; fi

# A comment line, the way a narrator would drop it into a session.
say() { printf '%s# %s%s\n' "$DIM" "$*" "$OFF"; sleep "$BEAT"; }

# Print a command as if typed, then run it. With -k the status is ignored, which
# is for pipelines into `head`: the producer is killed by SIGPIPE, which pipefail
# reports as a failure and an interactive shell would not.
run() {
  local keep=0
  if [[ ${1:-} == -k ]]; then keep=1; shift; fi
  local cmd=$1 i
  printf '%s$%s ' "$GREEN" "$OFF"
  for ((i = 0; i < ${#cmd}; i++)); do
    printf '%s' "${cmd:i:1}"
    if [[ $TYPE_DELAY != 0 ]]; then sleep "$TYPE_DELAY"; fi
  done
  printf '\n'
  if (( keep )); then eval "$cmd" || true; else eval "$cmd" || return $?; fi
  printf '\n'
  sleep "$BEAT"
}

payload=demo/.state/demo-payload.bin
restored=demo/.state/restored.bin
[[ -s $payload ]] || { echo "$payload is missing or empty; run demo/setup.sh" >&2; exit 1; }
rm -f "$restored"

# Leftovers from an earlier run, removed through the gateway so that the manifest
# goes with them. Quietly: a listing with yesterday's objects in it is noise, and
# the first listing below should be the one this run produced.
for key in demo-payload.bin secret.txt; do
  aws s3 rm "s3://$DEMO_BUCKET/$key" >/dev/null 2>&1 || true
done

# Stated rather than assumed: the caption below should not claim a size the file
# does not have, and the payload size is configurable.
payload_size=$(ls -lh "$payload" | awk '{print $5}')
# ls -lh counts in powers of two, so its suffix is the binary one; a size small
# enough to be printed as plain bytes has no suffix to correct.
case $payload_size in *[0-9]) payload_size="$payload_size bytes" ;; *) payload_size="${payload_size}iB" ;; esac

# No `clear` first: in a recording the very first frame is the poster frame, and a
# blank terminal is a poor one. The title goes out before anything else instead.
printf '%sblindbucket%s -- a transparent S3 encryption gateway\n\n' "$BOLD" "$OFF"
say "The client is plain AWS CLI. The only thing that is different is the endpoint."
run "echo \$AWS_ENDPOINT_URL"

say "Here is the file, and its hash. Remember the first eight characters."
run "ls -lh $payload"
run "$SHA $payload"

say "Upload it through the gateway. $payload_size, so the CLI splits it into parts by itself."
run "aws s3 cp $payload s3://\$DEMO_BUCKET/demo-payload.bin"

say "The client sees what it put there: the plaintext size, to the byte."
run "aws s3 ls s3://\$DEMO_BUCKET/"

sleep "$PAUSE"
say "Now the other side. 'mc' below talks to MinIO directly, not through the gateway."
run "mc ls \$DEMO_ALIAS/\$DEMO_BUCKET/"

say "Same offset, two views. First the file on this disk:"
run -k "head -c 48 $payload | xxd"
say "...and then what the provider is storing at that offset:"
run -k "mc cat \$DEMO_ALIAS/\$DEMO_BUCKET/demo-payload.bin | head -c 48 | xxd"

say "BLBK, the format version, the salt. The data key is in the metadata -- wrapped."
run -k "mc stat \$DEMO_ALIAS/\$DEMO_BUCKET/demo-payload.bin | grep -iE 'size|bb-' | cut -c1-88"

sleep "$PAUSE"
say "Download it back through the gateway and compare the hashes."
run "aws s3 cp s3://\$DEMO_BUCKET/demo-payload.bin $restored"
run "$SHA $payload $restored"

sleep "$PAUSE"
say "One more thing: the provider is not trusted, so let it misbehave."
run "printf 'the provider never sees this sentence\\n' > demo/.state/secret.txt"
run "aws s3 cp --quiet demo/.state/secret.txt s3://\$DEMO_BUCKET/secret.txt"
run "aws s3 cp s3://\$DEMO_BUCKET/secret.txt -"

say "Now flip a single bit of the stored ciphertext, in place, metadata untouched."
run "demo/tamper.sh secret.txt"

say "The same download again. It must fail -- not return something plausible."
if run "aws s3 cp s3://\$DEMO_BUCKET/secret.txt -"; then
  printf '%sThe tampered object was served. That is a bug -- see demo/README.md.%s\n' "$RED" "$OFF"
  exit 1
fi
printf '%s^ fail-closed: an error, never plaintext.%s\n\n' "$DIM" "$OFF"
sleep "$BEAT"

say "Nothing about the client changed. The provider never held plaintext or a key."
printf '\n'
