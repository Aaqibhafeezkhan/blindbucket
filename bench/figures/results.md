# Macro benchmark results

`warp` against MinIO directly, and the same load through the gateway, on the same
machine minutes apart. Each cell is the median of three runs; the two paths
alternate order between runs so that the cost of the provider reclaiming the
previous run cannot land on the same path every time.

```
date:        2026-09-11
host:        Darwin 25.5.0 arm64, Apple M4, 10 cores, 16 GiB
go:          go1.27.1 darwin/arm64
warp:        1.3.1
provider:    quay.io/minio/minio:latest, in a 10-core colima VM on the same host
chunk size:  64 KiB
runs:        3 per cell, 72 runs total, 0 failures
duration:    20s per run at 1 KiB, 10s at 10 MiB
```

Everything -- client, gateway and provider -- runs on one laptop. That is the
honest description of the rig and the main caveat on every number below: the
three compete for the same ten cores and the same disk, so absolute throughput is
lower than a real deployment would see. The *ratio* is what the setup is for, and
it is measured under identical conditions for both paths.

## Results

| Size | Op | Clients | Direct | Through the proxy | Ratio | p50 direct → proxy | p99 direct → proxy |
|---|---|---:|---:|---:|---:|---:|---:|
| 1KiB | GET | 1 | 1,526 obj/s | 1,202 obj/s | 79% | 0.7 → 0.9 ms | 0.8 → 1.1 ms |
| 1KiB | GET | 16 | 6,321 obj/s | 5,353 obj/s | 85% | 2.3 → 2.8 ms | 6.4 → 7.3 ms |
| 1KiB | GET | 64 | 6,200 obj/s | 5,734 obj/s | 92% | 9.5 → 10.3 ms | 33.2 → 33.2 ms |
| 1KiB | PUT | 1 | 911 obj/s | 637 obj/s | 70% | 1.1 → 1.6 ms | 1.9 → 2.3 ms |
| 1KiB | PUT | 16 | 2,759 obj/s | 2,350 obj/s | 85% | 5.5 → 6.5 ms | 13.2 → 12.8 ms |
| 1KiB | PUT | 64 | 2,669 obj/s | 2,367 obj/s | 89% | 23.6 → 26.1 ms | 54.4 → 54.3 ms |
| 10MiB | GET | 1 | 278.5 MiB/s | 267.9 MiB/s | 96% | 36.4 → 38.0 ms | 40.0 → 41.7 ms |
| 10MiB | GET | 16 | 263.1 MiB/s | 242.0 MiB/s | 92% | 590.5 → 666.2 ms | 653.4 → 714.3 ms |
| 10MiB | GET | 64 | 247.3 MiB/s | 234.5 MiB/s | 95% | 2513.0 → 2680.2 ms | 3064.9 → 3252.7 ms |
| 10MiB | PUT | 1 | 208.7 MiB/s | 202.1 MiB/s | 97% | 49.7 → 49.6 ms | 55.0 → 59.1 ms |
| 10MiB | PUT | 16 | 253.3 MiB/s | 241.0 MiB/s | 95% | 620.9 → 688.5 ms | 912.7 → 1184.0 ms |
| 10MiB | PUT | 64 | 218.0 MiB/s | 39.5 MiB/s | 18% | 2643.1 → 13775.8 ms | 4283.3 → 15877.1 ms |

## The one result that is not a ratio

`10MiB PUT` at 64 concurrent clients is the outlier: 39.5 MiB/s against the
provider's 218, with p50 latency of 13.8 seconds against 2.6. It is not noise --
all three repetitions landed between 37.5 and 44.9 MiB/s, and the alternating
order rules out the run before it being responsible. It is specific to PUT: GET
at the same size and concurrency runs at 95%, and PUT at 16 clients at 95%.

**The cause is not yet identified, and nothing here should be read as if it
were.** What is known: the gateway process sits at near-zero CPU throughout, no
request fails, and no file descriptors or memory accumulate. So it is waiting on
something rather than doing work.

One hypothesis was the `Expect: 100-continue` handshake the upstream client sends
with every body, which makes a request wait out `ExpectContinueTimeout` when the
provider does not answer promptly. A build without it measured 221 MiB/s once --
and then, on a controlled repeat, 33.9 MiB/s, while the unmodified build measured
157. Those single measurements were not measurements; the repetition and the
alternating order in `warp.sh` exist because of them. The hypothesis is neither
confirmed nor ruled out, and the code is unchanged.

The next step is the pprof endpoint that M5 puts behind a flag: a goroutine dump
taken during the slow run answers "waiting on what" directly, which no amount of
black-box timing will.
