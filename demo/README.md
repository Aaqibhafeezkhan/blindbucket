# Demo recording

The terminal recording [`CONCEPT.md`](../CONCEPT.md) section 20 asks for, and the
scripts that produce it. It is the thirty-second version of the whole argument:

1. A standard client — plain AWS CLI, only `--endpoint-url` changed — uploads a
   large file through the gateway, which the client splits into parts by itself.
2. The client's listing shows the plaintext size, to the byte.
3. `mc`, talking to MinIO **directly**, shows the stored object at the same offset:
   `BLBK`, a version, a salt, and from there ciphertext. The data key is in the
   object's metadata, wrapped.
4. The download through the gateway returns an identical SHA-256.
5. The provider then flips one bit of a stored object, in place, with the metadata
   untouched — and the download fails rather than returning something plausible.

Every command is real, against a real MinIO. Nothing is staged or re-enacted.

## Running it

```sh
demo/setup.sh            # MinIO, a keyring, a config, a gateway, a payload
demo/demo.sh             # the session itself
demo/setup.sh stop clean # tear it all down again
```

Or `make demo-setup`, `make demo`, `make demo-stop`.

| Script | What it does |
|---|---|
| `setup.sh` | Everything that is not worth watching: brings up the MinIO from `docker-compose.yml`, builds the binary, generates a keyring, writes a config, starts the gateway, generates the payload. Idempotent — re-running it restarts the gateway against a freshly built binary. |
| `demo.sh` | The recorded session. Prints each command as if typed, then runs it. Requires `setup.sh` to have run. |
| `tamper.sh` | Plays the hostile provider: flips one bit of a stored object's ciphertext, in place, preserving its metadata so that the download hits the authentication tag rather than a missing key. Useful on its own, not only in the demo. |

Everything `setup.sh` creates lands in `demo/.state/`, which is not committed. The
credentials in it are demo credentials in an ignored directory; none of it is a
secret and none of it should be reused.

| Variable | Default | |
|---|---|---|
| `DEMO_SIZE` | `1GiB` | Payload size. 64 MiB is enough to be multipart (the AWS CLI's threshold is 8 MiB) and much quicker to rehearse with. |
| `DEMO_PORT` | `9000` | Gateway port. Fixed by default because the recording shows it. |
| `DEMO_ADMIN_PORT` | `9100` | Admin listener. Only used to wait for readiness, so it moves upward if something already holds that port. |
| `DEMO_FAST` | unset | Set it to drop the typing pacing. For checking the demo still works without sitting through it. |
| `TYPE_DELAY`, `BEAT`, `PAUSE` | `0.012`, `1.1`, `2.0` | Typing speed and the pauses between commands and acts, in seconds. |

`demo.sh` exits non-zero if the tampered object is served instead of rejected. It
is a demo, but it is also a test.

## Recording it

Needs [asciinema](https://docs.asciinema.org/) for the cast and
[agg](https://github.com/asciinema/agg) to turn it into a GIF:

```sh
brew install asciinema agg
```

```sh
demo/setup.sh
asciinema rec demo/demo.cast --overwrite --headless --window-size 100x30 \
  --idle-time-limit 2 -c demo/demo.sh
agg --font-size 16 demo/demo.cast demo/demo.gif
```

The flags are asciinema 3; version 2 spelled the size `--cols`/`--rows`.

- `--window-size 100x30` because a cast embeds the size it was made at, and a wider
  one scales down to unreadable in a README. The script keeps its lines inside 100
  columns on purpose — the `cut -c1-88` on the `mc stat` output is there for that.
- `--headless` runs the command against a pty without taking over the terminal, which
  is what makes the recording scriptable. The AWS CLI's progress bar rewrites one line
  with carriage returns and needs that pty: a cast with hundreds of `Completed …`
  lines in it was recorded through a pipe, not a terminal.
- `--idle-time-limit 2` caps any pause at two seconds at playback time without
  altering the captured timing.

The committed recording is 1 GiB of payload, 67 seconds, and a 2.7 MB GIF. Both the
cast and the GIF are committed: the cast is a quarter of the size, it is diffable, and
`asciinema play demo/demo.cast` replays it locally.

Re-record it whenever the output it shows changes — an error message, a metadata key,
a command name. A recording that disagrees with the code is worse than none.
