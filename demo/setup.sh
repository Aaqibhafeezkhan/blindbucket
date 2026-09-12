#!/usr/bin/env bash
#
# Prepare this machine for the demo recording in demo/demo.sh.
#
# The recording is the thirty-second argument for
# the whole project: a standard client uploads a large file through the gateway,
# the provider is then shown holding ciphertext, and the download comes back with
# an identical hash. None of that is interesting to watch being set up, so the
# setup lives here and the recorded session assumes it has run.
#
# Everything this creates lands in demo/.state/ and is removed by `stop clean`.
# The credentials below are demo credentials in an ignored directory; nothing here
# is a secret and nothing here should be reused.
#
# Usage:
#   demo/setup.sh           # bring everything up, leave it running
#   demo/setup.sh stop      # stop the gateway and MinIO, keep the state
#   demo/setup.sh stop clean # and delete demo/.state/
#
# Environment:
#   DEMO_SIZE      payload size, e.g. 512MiB, 1GiB, 2G        (default 1GiB)
#   DEMO_BUCKET    bucket to use                            (default blindbucket-dev)
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
state="$root/demo/.state"

DEMO_SIZE=${DEMO_SIZE:-1GiB}
DEMO_BUCKET=${DEMO_BUCKET:-blindbucket-dev}

say() { printf '\033[2m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

port_free() { ! (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null; }

# BSD head -c takes a plain byte count and nothing else, so the suffixes are
# resolved here rather than handed on.
to_bytes() {
  local v=${1//i/} n unit
  n=${v%%[KMGkmg]*}; unit=${v#"$n"}
  case ${unit%B} in
    K|k) echo $((n * 1024)) ;;
    M|m) echo $((n * 1024 * 1024)) ;;
    G|g) echo $((n * 1024 * 1024 * 1024)) ;;
    "")  echo "$n" ;;
    *)   die "cannot read size '$1'" ;;
  esac
}

# The gateway port is fixed, because the recording shows it and a viewer should see
# the port the quickstart uses. The admin port is only used here, to wait for
# readiness, so it moves out of the way of whatever else is listening.
DEMO_PORT=${DEMO_PORT:-9000}
DEMO_ADMIN_PORT=${DEMO_ADMIN_PORT:-9100}
while ! port_free "$DEMO_ADMIN_PORT"; do DEMO_ADMIN_PORT=$((DEMO_ADMIN_PORT + 1)); done

readonly GATEWAY=http://127.0.0.1:$DEMO_PORT
readonly ADMIN=http://127.0.0.1:$DEMO_ADMIN_PORT
readonly UPSTREAM=http://127.0.0.1:9002
readonly DEMO_KEY_ID=BLINDBUCKETDEMOKEY
readonly DEMO_SECRET=demo-secret-not-a-secret
readonly DEMO_PASSPHRASE=demo-passphrase-not-a-secret

stop() {
  if [[ -f "$state/gateway.pid" ]]; then
    local pid
    pid=$(cat "$state/gateway.pid")
    if kill -0 "$pid" 2>/dev/null; then
      say "stopping the gateway (pid $pid)"
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
    rm -f "$state/gateway.pid"
  fi
  say "stopping MinIO"
  (cd "$root" && docker compose down -v >/dev/null 2>&1) || true
  if [[ ${1:-} == clean ]]; then
    say "removing $state"
    rm -rf "$state"
  fi
  say "stopped"
}

if [[ ${1:-} == stop ]]; then
  stop "${2:-}"
  exit 0
fi

for tool in docker aws mc go; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required and was not found"
done
docker info >/dev/null 2>&1 || die "the Docker daemon is not running"

mkdir -p "$state"

# A gateway this script started earlier goes first, so that re-running it is the
# normal way to pick up a changed binary rather than an error about the port.
if [[ -f "$state/gateway.pid" ]] && kill -0 "$(cat "$state/gateway.pid")" 2>/dev/null; then
  say "stopping the gateway from an earlier run (pid $(cat "$state/gateway.pid"))"
  kill "$(cat "$state/gateway.pid")" 2>/dev/null || true
  for _ in $(seq 1 20); do port_free "$DEMO_PORT" && break; sleep 0.5; done
  rm -f "$state/gateway.pid"
fi
port_free "$DEMO_PORT" || die "port $DEMO_PORT is in use; stop whatever holds it, or set DEMO_PORT"

say "starting MinIO on ${UPSTREAM#http://} (docker compose)"
(cd "$root" && docker compose up -d >/dev/null)

say "waiting for MinIO"
for _ in $(seq 1 60); do
  curl -sf "$UPSTREAM/minio/health/live" >/dev/null && break
  sleep 1
done
curl -sf "$UPSTREAM/minio/health/live" >/dev/null || die "MinIO did not become healthy"

say "registering the mc alias 'bbdemo' against the provider directly"
mc alias set bbdemo "$UPSTREAM" minioadmin minioadmin >/dev/null
mc mb --ignore-existing "bbdemo/$DEMO_BUCKET" >/dev/null

say "building the gateway"
(cd "$root" && go build -o bin/blindbucket ./cmd/blindbucket)

if [[ ! -f "$state/keyring.json" ]]; then
  say "generating a keyring"
  BLINDBUCKET_PASSPHRASE="$DEMO_PASSPHRASE" \
    "$root/bin/blindbucket" keygen --out "$state/keyring.json" --kid demo-2026-09 >/dev/null
fi

# Literal credentials rather than ${VAR} references: the file lives in an ignored
# directory, is regenerated on every run, and a reader of the recording should be
# able to see exactly what the gateway was configured with.
say "writing $state/blindbucket.yaml"
cat > "$state/blindbucket.yaml" <<YAML
server:
  listen: "127.0.0.1:$DEMO_PORT"
admin:
  listen: "127.0.0.1:$DEMO_ADMIN_PORT"
upstream:
  endpoint: $UPSTREAM
  region: us-east-1
  path_style: true
  access_key_id: minioadmin
  secret_access_key: minioadmin
clients:
  - name: demo
    access_key_id: $DEMO_KEY_ID
    secret_access_key: $DEMO_SECRET
    buckets: ["$DEMO_BUCKET"]
keys:
  provider: file
  keyring: $state/keyring.json
crypto:
  log2_chunk_size: 16
YAML

say "starting the gateway on ${GATEWAY#http://}"
BLINDBUCKET_PASSPHRASE="$DEMO_PASSPHRASE" \
  nohup "$root/bin/blindbucket" serve --config "$state/blindbucket.yaml" \
  > "$state/gateway.log" 2>&1 &
echo $! > "$state/gateway.pid"

say "waiting for the gateway"
for _ in $(seq 1 30); do
  curl -sf "$ADMIN/readyz" >/dev/null && break
  sleep 1
done
curl -sf "$ADMIN/readyz" >/dev/null || {
  cat "$state/gateway.log" >&2
  die "the gateway did not become ready"
}

# A recognisable, repeating payload rather than random bytes: the point of one shot
# in the recording is that the same offset reads as text locally and as ciphertext
# on the provider, and random plaintext would make that contrast invisible.
want_bytes=$(to_bytes "$DEMO_SIZE")
have_bytes=0
[[ -f "$state/demo-payload.bin" ]] && have_bytes=$(wc -c < "$state/demo-payload.bin" | tr -d ' ')
if [[ $have_bytes != "$want_bytes" ]]; then
  say "generating a $DEMO_SIZE payload ($want_bytes bytes)"
  (yes "blindbucket demo payload -- this line is plaintext, and the provider never sees it" 2>/dev/null || true) \
    | head -c "$want_bytes" > "$state/demo-payload.bin"
  [[ $(wc -c < "$state/demo-payload.bin" | tr -d ' ') == "$want_bytes" ]] \
    || die "the payload came out the wrong size; check DEMO_SIZE=$DEMO_SIZE"
fi
printf 'the provider never sees this sentence\n' > "$state/secret.txt"

cat > "$state/env.sh" <<ENV
# Sourced by demo/demo.sh.
export AWS_ACCESS_KEY_ID=$DEMO_KEY_ID
export AWS_SECRET_ACCESS_KEY=$DEMO_SECRET
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=$GATEWAY
export DEMO_BUCKET=$DEMO_BUCKET
export DEMO_STATE=$state
export DEMO_ROOT=$root
export DEMO_ALIAS=bbdemo
export BLINDBUCKET_PASSPHRASE=$DEMO_PASSPHRASE
export DEMO_ADMIN=$ADMIN
ENV

say "ready"
printf '\n'
printf '  gateway   %s   (admin %s)\n' "$GATEWAY" "$ADMIN"
printf '  provider  %s   (mc alias bbdemo, console http://127.0.0.1:9091)\n' "$UPSTREAM"
printf '  payload   %s\n' "$state/demo-payload.bin"
printf '\n'
printf '  run the demo:   demo/demo.sh\n'
printf '  record it:      see demo/README.md\n'
printf '  tear down:      demo/setup.sh stop clean\n'
