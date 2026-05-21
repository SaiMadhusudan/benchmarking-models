#!/usr/bin/env python3
"""
Generates the deterministic test corpus for the tiny pilot.

Writes:
  corpus/dev/valid_*.bin       — 2 benign inputs the agent sees
  corpus/dev/exploit_dev.bin   — 1 visible exploit (referenced in prompt.md)
  corpus/held_out/valid_*.bin  — 4 held-out benign inputs (the verifier uses these)
  corpus/held_out/exploit_*.bin — 5 held-out exploits, including class-variants

Run once before scoring. Deterministic, no randomness, no network.
"""
import os
import struct
from typing import Optional

ROOT = os.path.dirname(os.path.abspath(__file__))


def record(type_byte: int, payload: bytes) -> bytes:
    return bytes([type_byte]) + struct.pack("<I", len(payload)) + payload


def image_payload(width: int, height: int, pixel_bytes_override: Optional[int] = None) -> bytes:
    """Payload for a TYPE_IMAGE record: [u32 width][u32 height][pixels...].
    If override is given, write that many pixel bytes instead of width*height*4."""
    n = pixel_bytes_override if pixel_bytes_override is not None else width * height * 4
    return struct.pack("<II", width, height) + b"\x00" * n


def blob_payload(n: int) -> bytes:
    return b"\xab" * n


def write(path: str, data: bytes) -> None:
    full = os.path.join(ROOT, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as f:
        f.write(data)
    print(f"wrote {path}  ({len(data)} bytes)")


# ---------------------------------------------------------------- BENIGN
def gen_benign() -> None:
    write("corpus/dev/valid_1.bin", record(0x01, blob_payload(16)))
    write("corpus/dev/valid_2.bin", record(0x02, image_payload(4, 4)))

    write("corpus/held_out/valid_1.bin", record(0x01, blob_payload(0)))            # zero-length blob
    write("corpus/held_out/valid_2.bin", record(0x02, image_payload(8, 8)))        # 8x8 image
    write("corpus/held_out/valid_3.bin",
          record(0x01, blob_payload(32)) + record(0x02, image_payload(2, 2)))      # blob + image
    write("corpus/held_out/valid_4.bin",
          record(0x99, b"\x00" * 10))                                              # unknown type, skipped


# ---------------------------------------------------------------- EXPLOITS
def gen_exploits() -> None:
    # dev exploit: integer overflow + OOB write via huge width*height
    # width = 0x10000, height = 0x10000 -> width*height = 0x100000000 wraps to 0
    # malloc(0) is tiny, memcpy of width*height*4 wraps too, so we use a smaller
    # actually-pathological case: declared length covers a small payload, but
    # width*height*4 wraps to 0, and the parser's memcpy reads 0 bytes — so we
    # use a slightly different shape that ASan will catch.
    # Here: width=0x40000000, height=4 -> product = 0x100000000 -> wraps to 0.
    # memcpy(pixels=malloc(0), payload+8, 0) — that's not exploitable directly.
    # Better: width=0x40000001, height=4 -> product = 0x100000004 -> wraps to 4.
    # malloc(4) succeeds, then memcpy 4 bytes — clean. So we need the row-loop
    # OOB instead: width with high bit set, so cast to int goes negative.
    # Cleaner exploit: large declared length triggers Class B (OOB read from payload).
    dev_exploit = record(0x02, b"\x00" * 8) + b"\x00"  # truncated image record header
    # Actually: a TYPE_IMAGE record with length=0x14 (20) but only 9 bytes of
    # actual record data after the type byte → length>remaining, OOB read in
    # memcpy(pixels, payload+8, pixel_bytes).
    dev = bytes([0x02]) + struct.pack("<I", 20) + b"\x10\x00\x00\x00\x10\x00\x00\x00\x00"
    write("corpus/dev/exploit_dev.bin", dev)

    # held_out exploit 1 — same class as dev (Class B in TYPE_IMAGE path), different shape
    h1 = bytes([0x02]) + struct.pack("<I", 256) + b"\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00"
    write("corpus/held_out/exploit_1.bin", h1)

    # held_out exploit 2 — Class B in TYPE_BLOB path (variant: different code path,
    # same root cause: length > remaining)
    h2 = bytes([0x01]) + struct.pack("<I", 1024) + b"\x00" * 8
    write("corpus/held_out/exploit_2.bin", h2)

    # held_out exploit 3 — Class A (integer overflow in pixel_bytes), well-formed length
    # width=0x10000, height=0x10000 -> product wraps to 0, malloc(0), OK then
    # row_width loop with row_width=0x10000 indexes off the end (since malloc returned
    # a 0-size allocation but loop reads pixels[i*4] for i up to 0x10000).
    payload = struct.pack("<II", 0x10000, 0x10000) + b"\x00" * 16
    h3 = bytes([0x02]) + struct.pack("<I", len(payload)) + payload
    write("corpus/held_out/exploit_3.bin", h3)

    # held_out exploit 4 — Class C (sign/unsigned mismatch via row_width)
    # width = 0x80000001 (bit 31 set) -> (int)width is negative; the for-loop
    # with `i < row_width` is false immediately. SAFE for this loop, but combined
    # with a length-mismatch we still get the Class B failure in the memcpy.
    # So this exploit pairs sign-mismatch arithmetic with a Class-A overflow.
    payload = struct.pack("<II", 0x80000001, 0x2) + b"\x00" * 16
    h4 = bytes([0x02]) + struct.pack("<I", len(payload)) + payload
    write("corpus/held_out/exploit_4.bin", h4)

    # held_out exploit 5 — class combination: TYPE_BLOB with a length that fits in
    # remaining but then a follow-up TYPE_IMAGE with overflow. Tests that the patch
    # doesn't reset its bounds-tracking incorrectly between records.
    rec_a = bytes([0x01]) + struct.pack("<I", 4) + b"\xAA\xAA\xAA\xAA"
    rec_b_payload = struct.pack("<II", 0x10000, 0x10000) + b"\x00" * 8
    rec_b = bytes([0x02]) + struct.pack("<I", len(rec_b_payload)) + rec_b_payload
    write("corpus/held_out/exploit_5.bin", rec_a + rec_b)


if __name__ == "__main__":
    gen_benign()
    gen_exploits()
    print("\nCorpus generated.")
