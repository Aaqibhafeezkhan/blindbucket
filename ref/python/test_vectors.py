#!/usr/bin/env python3
"""Check the reference decoder against the known-answer vectors.

docs/FORMAT.md section 13 calls the vectors a normative part of the
specification: "An independent implementation that reproduces every vector byte
for byte is format-compatible." This is that check, from the decoding side --
every vector's ciphertext must open to exactly its plaintext.

    python3 ref/python/test_vectors.py
"""

from __future__ import annotations

import json
import pathlib
import sys

from blindbucket_ref import FormatError, decode_segment

VECTORS = pathlib.Path(__file__).resolve().parents[2] / "testdata" / "vectors" / "segment_v1.json"


def main() -> int:
    document = json.loads(VECTORS.read_text())
    print(f"{VECTORS.name}: format version {document['format_version']}, "
          f"{len(document['vectors'])} vectors")

    failures = 0
    for vector in document["vectors"]:
        name = vector["name"]
        want = bytes.fromhex(vector["plaintext"])
        sealed = bytes.fromhex(vector["ciphertext"])
        try:
            got = decode_segment(
                sealed,
                bytes.fromhex(vector["dek"]),
                multipart=vector["multipart"],
                index=vector["index"],
            )
        except FormatError as err:
            print(f"  FAIL  {name}: {err}")
            failures += 1
            continue

        if got != want:
            print(f"  FAIL  {name}: decoded {len(got)} bytes, expected {len(want)}")
            failures += 1
            continue

        # The header fields the vector fixes must be what the decoder read back,
        # or the agreement on plaintext would be luck.
        if sealed[5] != vector["log2_chunk_size"]:
            print(f"  FAIL  {name}: header log2C {sealed[5]} != {vector['log2_chunk_size']}")
            failures += 1
            continue

        print(f"  ok    {name}: {len(want)} bytes, log2C {vector['log2_chunk_size']}, "
              f"index {vector['index']}")

    if failures:
        print(f"\n{failures} of {len(document['vectors'])} vectors failed")
        return 1
    print(f"\nall {len(document['vectors'])} vectors decode as specified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
