"""An independent decoder for the blindbucket wire format.

Written from `docs/FORMAT.md` and nothing else. Its job is not to be fast or to
be used in production; it is to answer one question that the Go implementation
cannot answer about itself: **is the specification sufficient to implement
from?** A second implementation that agrees with the first on every known-answer
vector and on a large body of mutated inputs is evidence that the format is
pinned down by the document rather than by one codebase's habits.

The rules implemented here are, section by section:

  §1    big-endian integers, lp(x) = uint16_be(len(x)) || x
  §2    AES-256-GCM with a 12-byte nonce and a 16-byte tag, HKDF-SHA256
  §4.1  the 32-byte header and its consistency constraints
  §4.2  Subkey = HKDF-SHA256(DEK, salt = header[12:32], info = ".../segment")
  §4.3  Nonce_i = uint88_be(i) || f_i, with the header as associated data
  §4.4  chunk length rules
  §5.2  the order a decoder must work in, including the one-byte lookahead
  §6    DEK unwrapping and its associated data
  §9    the local BBF1 file envelope

Usage:
    python3 blindbucket_ref.py segment --dek <hex> <file>
    python3 blindbucket_ref.py file    --kek <hex> <file>
"""

from __future__ import annotations

import argparse
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# §4.1, §2: the fixed sizes of the format.
HEADER_SIZE = 32
MAGIC = b"BLBK"
VERSION = 1
TAG_SIZE = 16
NONCE_SIZE = 12
SALT_SIZE = 20
KEY_SIZE = 32
WRAPPED_DEK_SIZE = NONCE_SIZE + KEY_SIZE + TAG_SIZE  # §6: exactly 60 bytes

# §4.1: log2C is bounded so that a header cannot coerce a large allocation.
MIN_LOG2C = 12
MAX_LOG2C = 20

# §4.1: the only defined flag bit.
FLAG_MULTIPART = 0x01

# §4.1: an S3 part number.
MAX_PART_NUMBER = 10000

# §3, §4.2, §6.1, §6.2: the domain-separation strings, ASCII, no trailing NUL.
INFO_SEGMENT = b"blindbucket/v1/segment"
AAD_OBJECT_PREFIX = b"blindbucket/v1/dek"
AAD_FILE_PREFIX = b"blindbucket/v1/dek-file"

# §9: the local file envelope.
FILE_MAGIC = b"BBF1"
FILE_VERSION = 1


class FormatError(Exception):
    """Any deviation from docs/FORMAT.md.

    §5.2 requires a decoder to treat every deviation -- bad tag, bad header
    field, truncation, trailing bytes, wrong key -- as a hard error, so they all
    land here rather than being distinguished by type.
    """


def lp(value: bytes) -> bytes:
    """§1: length-prefixed byte string."""
    if len(value) > 0xFFFF:
        raise FormatError(f"lp() input of {len(value)} bytes exceeds 65535")
    return len(value).to_bytes(2, "big") + value


class Header:
    """§4.1: the parsed 32-byte segment header."""

    __slots__ = ("log2c", "multipart", "index", "salt", "raw")

    def __init__(self, log2c: int, multipart: bool, index: int, salt: bytes, raw: bytes):
        self.log2c = log2c
        self.multipart = multipart
        self.index = index
        self.salt = salt
        # §4.1: the header is supplied *verbatim* as associated data, so the
        # bytes as read are kept rather than re-encoded from the fields.
        self.raw = raw

    @property
    def chunk_size(self) -> int:
        return 1 << self.log2c


def parse_header(raw: bytes) -> Header:
    """§5.2 steps 1 and 2: read and validate the header before anything else.

    Every field is checked here because at this point the header is
    attacker-controlled and not yet authenticated; §5.2 is explicit that the
    bounds on log2C must hold before any buffer is sized from it.
    """
    if len(raw) < HEADER_SIZE:
        raise FormatError(f"segment is {len(raw)} bytes, shorter than its {HEADER_SIZE}-byte header")
    head = raw[:HEADER_SIZE]

    if head[0:4] != MAGIC:
        raise FormatError(f"bad magic {head[0:4]!r}, want {MAGIC!r}")
    if head[4] != VERSION:
        raise FormatError(f"format version {head[4]}, this decoder reads {VERSION}")

    log2c = head[5]
    if not MIN_LOG2C <= log2c <= MAX_LOG2C:
        raise FormatError(f"log2C {log2c} outside {MIN_LOG2C}..{MAX_LOG2C}")

    flags = head[6]
    if flags & ~FLAG_MULTIPART:
        raise FormatError(f"undefined flag bits set: 0x{flags:02x}")
    if head[7] != 0x00:
        raise FormatError(f"reserved byte is 0x{head[7]:02x}, must be 0x00")

    multipart = bool(flags & FLAG_MULTIPART)
    index = int.from_bytes(head[8:12], "big")
    # §4.1: the flag and the index must agree, or the header denotes nothing.
    if multipart:
        if not 1 <= index <= MAX_PART_NUMBER:
            raise FormatError(f"multipart segment index {index} outside 1..{MAX_PART_NUMBER}")
    elif index != 0:
        raise FormatError(f"single-part segment must have index 0, got {index}")

    return Header(log2c, multipart, index, head[12:HEADER_SIZE], head)


def derive_subkey(dek: bytes, salt: bytes) -> bytes:
    """§4.2: Subkey = HKDF-SHA256(ikm=DEK, salt=Header[12..32], info, L=32)."""
    if len(dek) != KEY_SIZE:
        raise FormatError(f"DEK is {len(dek)} bytes, want {KEY_SIZE}")
    if len(salt) != SALT_SIZE:
        raise FormatError(f"salt is {len(salt)} bytes, want {SALT_SIZE}")
    return HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=salt,
                info=INFO_SEGMENT).derive(dek)


def chunk_nonce(index: int, final: bool) -> bytes:
    """§4.3: Nonce_i = uint88_be(i) || f_i, twelve bytes in total."""
    if not 0 <= index < (1 << 88):
        raise FormatError(f"chunk index {index} does not fit in 88 bits")
    return index.to_bytes(11, "big") + (b"\x01" if final else b"\x00")


def decode_segment(data: bytes, dek: bytes, *, multipart: bool | None = None,
                   index: int | None = None) -> bytes:
    """Decrypt one segment and return its plaintext.

    `multipart` and `index` are what the caller expects this segment to be.
    §5.2 step 3 requires a mismatch to be an error: it is what stops a provider
    from serving part 7 where part 3 belongs. Passing None skips that check,
    which is only appropriate when the caller genuinely has no expectation.
    """
    header = parse_header(data)
    if multipart is not None and header.multipart != multipart:
        raise FormatError(f"segment multipart flag is {header.multipart}, expected {multipart}")
    if index is not None and header.index != index:
        raise FormatError(f"segment index is {header.index}, expected {index}")

    subkey = derive_subkey(dek, header.salt)
    aead = AESGCM(subkey)
    body = data[HEADER_SIZE:]

    # §4.4: a segment always contains at least one chunk, and the smallest legal
    # chunk is a bare tag (the single chunk of an empty segment).
    if len(body) < TAG_SIZE:
        raise FormatError(f"segment body is {len(body)} bytes, below one bare {TAG_SIZE}-byte tag")

    full_chunk = header.chunk_size + TAG_SIZE
    plaintext = bytearray()
    offset = 0
    i = 0

    while True:
        remaining = len(body) - offset
        # §5.2 rule 5: the one-byte lookahead, expressed over a complete buffer.
        # A chunk is the last one exactly when nothing follows it, and a
        # non-final chunk carries exactly C bytes of plaintext (§4.4 rule 1), so
        # "nothing follows" is "no more than one full chunk remains".
        final = remaining <= full_chunk
        take = remaining if final else full_chunk

        if take < TAG_SIZE:
            raise FormatError(f"chunk {i} is {take} bytes, shorter than its tag")
        # §4.4 rule 2: only the single chunk of an empty segment may carry zero
        # bytes of plaintext.
        if take == TAG_SIZE and i > 0:
            raise FormatError(f"chunk {i} carries no plaintext; only a lone chunk may")

        try:
            opened = aead.decrypt(chunk_nonce(i, final), body[offset:offset + take], header.raw)
        except InvalidTag as exc:
            # The nonce carries the final flag, so this is also what a truncated
            # or extended segment looks like: the chunk that became last was
            # sealed under f = 0 and cannot verify under f = 1 (§5.2).
            raise FormatError(f"chunk {i} failed authentication") from exc

        plaintext += opened
        offset += take
        i += 1
        if final:
            break

    if offset != len(body):
        raise FormatError(f"{len(body) - offset} bytes follow the final chunk")
    return bytes(plaintext)


def object_aad(kid: str, bucket: str, key: str) -> bytes:
    """§6.1: AAD = "blindbucket/v1/dek" || lp(kid) || lp(bucket) || lp(key)."""
    return (AAD_OBJECT_PREFIX + lp(kid.encode()) + lp(bucket.encode()) + lp(key.encode()))


def file_aad(kid: str) -> bytes:
    """§6.2: AAD = "blindbucket/v1/dek-file" || lp(kid)."""
    return AAD_FILE_PREFIX + lp(kid.encode())


def unwrap_dek(wrapped: bytes, kek: bytes, aad: bytes) -> bytes:
    """§6: WrappedDEK = Nonce(12) || AES-256-GCM-Seal(KEK, Nonce, DEK, AAD)."""
    if len(wrapped) != WRAPPED_DEK_SIZE:
        raise FormatError(f"wrapped DEK is {len(wrapped)} bytes, want {WRAPPED_DEK_SIZE}")
    if len(kek) != KEY_SIZE:
        raise FormatError(f"KEK is {len(kek)} bytes, want {KEY_SIZE}")
    try:
        dek = AESGCM(kek).decrypt(wrapped[:NONCE_SIZE], wrapped[NONCE_SIZE:], aad)
    except InvalidTag as exc:
        raise FormatError("wrapped DEK failed authentication") from exc
    if len(dek) != KEY_SIZE:
        raise FormatError(f"unwrapped DEK is {len(dek)} bytes, want {KEY_SIZE}")
    return dek


def decode_file(data: bytes, kek: bytes) -> bytes:
    """§9: File = "BBF1" || uint8(version) || lp(kid) || WrappedDEK(60) || Segment."""
    if len(data) < len(FILE_MAGIC) + 1 + 2:
        raise FormatError(f"file is {len(data)} bytes, too short for its envelope")
    if data[:4] != FILE_MAGIC:
        raise FormatError(f"bad file magic {data[:4]!r}, want {FILE_MAGIC!r}")
    if data[4] != FILE_VERSION:
        raise FormatError(f"file version {data[4]}, this decoder reads {FILE_VERSION}")

    kid_len = int.from_bytes(data[5:7], "big")
    at = 7 + kid_len
    if len(data) < at + WRAPPED_DEK_SIZE:
        raise FormatError("file is truncated inside its envelope")
    kid = data[7:at].decode("ascii", errors="strict")

    dek = unwrap_dek(data[at:at + WRAPPED_DEK_SIZE], kek, file_aad(kid))
    # §9: the segment of a local file is single-part with index 0.
    return decode_segment(data[at + WRAPPED_DEK_SIZE:], dek, multipart=False, index=0)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="mode", required=True)

    seg = sub.add_parser("segment", help="decode a bare segment")
    seg.add_argument("--dek", required=True, help="32-byte data key, hex")
    seg.add_argument("--index", type=int, default=None, help="expected segment index")
    seg.add_argument("--multipart", action="store_true", help="expect the multipart flag")
    seg.add_argument("path")

    fil = sub.add_parser("file", help="decode a BBF1 file")
    fil.add_argument("--kek", required=True, help="32-byte key-encryption key, hex")
    fil.add_argument("path")

    args = parser.parse_args(argv[1:])
    data = sys.stdin.buffer.read() if args.path == "-" else open(args.path, "rb").read()

    try:
        if args.mode == "segment":
            out = decode_segment(data, bytes.fromhex(args.dek),
                                 multipart=args.multipart or None, index=args.index)
        else:
            out = decode_file(data, bytes.fromhex(args.kek))
    except FormatError as err:
        print(f"blindbucket-ref: {err}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
