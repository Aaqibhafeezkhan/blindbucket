# Benchmarks

Reproducible measurements for the claims the README makes. Hardware and versions
are recorded alongside every result, because a throughput number without them is
decoration.

## What is here

| Script | Measures |
|---|---|
| `rss-sample.sh` | Resident set size of a command over time, separating the one-time Argon2id spike from the steady state while data streams |

Micro-benchmarks live with the code and run through `make bench`:

```sh
make bench                                   # all packages
go test ./internal/crypto/stream -bench . -benchmem
```

## Measuring memory

```sh
BLINDBUCKET_PASSPHRASE=... bench/rss-sample.sh out.csv \
  ./bin/blindbucket encrypt --keyring keyring.json -i big.bin -o big.bb
```

**Read the platform note the script prints.** On macOS, RSS as reported by `ps`
does not fall when Go releases pages: the runtime uses `MADV_FREE_REUSABLE`,
which marks pages reclaimable without lowering RSS until the system is under
pressure. Go's own `HeapReleased` shows the memory was handed back. On Linux the
figure is meaningful.

The portable evidence for constant memory is `TestLargeStreamRoundTrip`, which
samples the Go heap directly rather than asking the operating system:

```sh
BLINDBUCKET_STREAM_SIZE=10GiB go test ./internal/crypto/stream \
  -run TestLargeStreamRoundTrip -v -timeout 30m
```

## Still to come (M5)

`warp` scenarios against MinIO with and without the proxy, latency percentiles at
1, 16 and 64 concurrent clients, and the RSS-over-time plot for the README. See
CONCEPT.md section 12.5.
