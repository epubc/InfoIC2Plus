#!/usr/bin/env python3
"""
extract_fw_update.py - Standalone extractor for Xgpro's device firmware
update containers:

    updateII.dat   -> TL866-II Plus
    UpdateT48.dat  -> XGecu T48 (TL866-3G)
    updateT56.dat  -> XGecu T56

Reverse-engineered from Xgpro.exe (functions sub_402810 / sub_4030D0 for
"II", sub_403600 for T48, sub_403A40 for T56, checksum sub_4EE6D0). No
IDA or Xgpro.exe is required to run this script - pure Python 3 stdlib
only. The container/CRC/address-obfuscation layer has been verified
byte-exact against a real updateII.dat (936 blocks, every per-block CRC
and the whole-file CRC matched).

IMPORTANT - what this script can and cannot show you:
  Only the outer *container* format is reverse engineered here (header,
  1024-byte key table, per-block CRC32, and a per-block address-field
  obfuscation byte). The 256/2048-byte payload chunks themselves are
  transmitted by Xgpro.exe completely unmodified over USB straight to
  the device's own onboard microcontroller - Xgpro.exe never decrypts
  them. Measured payload entropy is ~7.9 bits/byte (indistinguishable
  from random), so the actual MCU firmware content is opaque at this
  layer; this script extracts it as an opaque binary blob, it does not
  decompile/decrypt the MCU code itself.

Formats
-------

updateII.dat (TL866-II Plus) - the complex one:

    Header, 1036 bytes:
        +0x000  magic          u32 = 0xF8CC4284
        +0x004  file_crc32     u32 (stored; standard IEEE CRC32,
                                init=0xFFFFFFFF, final complemented)
        +0x008  key_table      1024 bytes (used only to obfuscate 1
                                byte per block - see below)
        +0x408  block_count    u32

    block_count x "regular" block, 272 bytes each:
        +0x00  block_crc32     u32 (stored; CRC32 over the 268 bytes
                                that follow, init=0, NOT complemented)
        +0x04  seed            u32 (plaintext; selects the starting
                                offset into key_table)
        +0x08  flash_address   u32 (low byte XOR-obfuscated - see below)
        +0x0C  flags           u32
        +0x10  payload         256 bytes (sent to the device as-is)

    1 x final block, 2064 bytes (identical layout, 2048-byte payload),
    always present regardless of block_count.

    Address-byte de-obfuscation: XOR the low byte of `flash_address`
    (offset +0x08) with the XOR-fold of N consecutive bytes of
    key_table starting at `seed` (wrapping mod 1024): N=264 for
    regular blocks, N=2056 for the final block. This only affects 1
    byte; it is not payload encryption.

    Whole-file CRC32 (stored at header+0x004): running CRC32 over, in
    order, all regular blocks (272 bytes each, undecoded/raw-from-file
    is fine since this covers the file bytes, not the deobfuscated
    value), the final block (2064 bytes), then header bytes
    [0x008:0x408) (i.e. everything after the magic+crc32 fields) -
    init 0xFFFFFFFF, final result bitwise-NOT'ed.

updateT48.dat / updateT56.dat - much simpler, no CRC, no obfuscation:

    Header, 16 bytes:
        +0x00  magic        u32   (T48 = 0xF0480127, T56 = 0x56000149)
        +0x04  reserved      8 bytes
        +0x0C  block_count  u32
    followed by `block_count` fixed-size raw blocks, sent to the
    device unmodified (T48: 276 bytes/block; T56: 2068 bytes/block).

Usage:
    python extract_fw_update.py <update_file.dat> [output_prefix]

Auto-detects the format from the file's magic number. Writes:
    <prefix>.header.json   - decoded header fields
    <prefix>.firmware.bin  - concatenated raw payload blob (the data
                              actually sent to the device's MCU, in
                              order; address-byte de-obfuscated where
                              applicable, though that byte is not part
                              of the payload itself)
"""

import json
import struct
import sys

MAGIC_II = 0xF8CC4284
MAGIC_T48 = 0xF0480127
MAGIC_T56 = 0x56000149


def build_crc32_table():
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (0xEDB88320 ^ (c >> 1)) if (c & 1) else (c >> 1)
        table.append(c)
    return table


CRC_TABLE = build_crc32_table()


def crc32_update(data, crc, table=CRC_TABLE):
    for b in data:
        crc = table[(b ^ crc) & 0xFF] ^ (crc >> 8)
    return crc & 0xFFFFFFFF


def xor_fold(key_table, start, count):
    """XOR of `count` consecutive bytes of key_table starting at `start`,
    wrapping modulo 1024 (matches the block-address de-obfuscation loop
    in sub_4030D0)."""
    v = 0
    for i in range(count):
        v ^= key_table[(start + i) & 0x3FF]
    return v


def extract_update_ii(data, verify=True):
    if len(data) < 1036:
        raise ValueError("File too short to contain an updateII.dat header")

    header = data[:1036]
    magic = struct.unpack_from("<I", header, 0)[0]
    if magic != MAGIC_II:
        raise ValueError("Not an updateII.dat file (magic=0x%08X, expected 0x%08X)" % (magic, MAGIC_II))

    stored_file_crc = struct.unpack_from("<I", header, 4)[0]
    key_table = header[8:1032]
    block_count = struct.unpack_from("<I", header, 1032)[0]

    expected_size = 1036 + block_count * 272 + 2064
    if len(data) != expected_size:
        raise ValueError(
            "Unexpected file size: got %d, expected %d for block_count=%d "
            "(file may be truncated/corrupt)" % (len(data), expected_size, block_count)
        )

    pos = 1036
    blocks = []
    running_crc = 0xFFFFFFFF
    bad_block_crcs = []

    for i in range(block_count):
        raw = bytearray(data[pos:pos + 272])
        pos += 272
        running_crc = crc32_update(raw, running_crc)

        stored_block_crc = struct.unpack_from("<I", raw, 0)[0]
        seed = struct.unpack_from("<I", raw, 4)[0]
        raw[8] ^= xor_fold(key_table, seed, 264)
        addr = struct.unpack_from("<I", raw, 8)[0]
        flags = struct.unpack_from("<I", raw, 12)[0]
        payload = bytes(raw[16:272])

        if verify:
            computed = crc32_update(bytes(raw[4:272]), 0)
            if computed != stored_block_crc:
                bad_block_crcs.append(i)

        blocks.append({
            "index": i,
            "address": addr,
            "flags": flags,
            "payload": payload,
        })

    final_raw = bytearray(data[pos:pos + 2064])
    pos += 2064
    running_crc = crc32_update(final_raw, running_crc)

    stored_final_crc = struct.unpack_from("<I", final_raw, 0)[0]
    seed_final = struct.unpack_from("<I", final_raw, 4)[0]
    final_raw[8] ^= xor_fold(key_table, seed_final, 2056)
    final_addr = struct.unpack_from("<I", final_raw, 8)[0]
    final_flags = struct.unpack_from("<I", final_raw, 12)[0]
    final_payload = bytes(final_raw[16:2064])

    final_block_crc_ok = None
    if verify:
        computed_final = crc32_update(bytes(final_raw[4:2064]), 0)
        final_block_crc_ok = (computed_final == stored_final_crc)

    running_crc = crc32_update(header[8:1036], running_crc)
    computed_file_crc = (~running_crc) & 0xFFFFFFFF

    firmware_blob = b"".join(b["payload"] for b in blocks) + final_payload

    return {
        "device": "TL866-II Plus",
        "magic": "0x%08X" % magic,
        "block_count": block_count,
        "stored_file_crc32": "0x%08X" % stored_file_crc,
        "computed_file_crc32": "0x%08X" % computed_file_crc,
        "file_crc32_ok": computed_file_crc == stored_file_crc,
        "bad_block_crcs": bad_block_crcs,
        "final_block_crc_ok": final_block_crc_ok,
        "blocks": [{"index": b["index"], "address": "0x%X" % b["address"], "flags": "0x%X" % b["flags"]} for b in blocks],
        "final_block": {"address": "0x%X" % final_addr, "flags": "0x%X" % final_flags, "payload_len": len(final_payload)},
        "firmware_blob": firmware_blob,
        "firmware_blob_len": len(firmware_blob),
    }


def extract_update_simple(data, device_name, magic_expected, block_size):
    if len(data) < 16:
        raise ValueError("File too short to contain a header")

    header = data[:16]
    magic = struct.unpack_from("<I", header, 0)[0]
    if magic != magic_expected:
        raise ValueError(
            "Not a %s update file (magic=0x%08X, expected 0x%08X)" % (device_name, magic, magic_expected)
        )
    block_count = struct.unpack_from("<I", header, 12)[0]

    expected_size = 16 + block_count * block_size
    size_ok = (len(data) == expected_size)

    blocks = []
    pos = 16
    while pos + block_size <= len(data):
        blocks.append(data[pos:pos + block_size])
        pos += block_size

    firmware_blob = b"".join(blocks)

    return {
        "device": device_name,
        "magic": "0x%08X" % magic,
        "block_count_field": block_count,
        "blocks_found": len(blocks),
        "block_size": block_size,
        "expected_file_size": expected_size,
        "actual_file_size": len(data),
        "size_matches_block_count_field": size_ok,
        "firmware_blob": firmware_blob,
        "firmware_blob_len": len(firmware_blob),
        "note": "T48/T56 containers have no CRC and no obfuscation - "
                "blocks are sent to the device exactly as stored in the file.",
    }


def extract(path):
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < 4:
        raise ValueError("File too small")

    magic = struct.unpack_from("<I", data, 0)[0]

    if magic == MAGIC_II:
        return extract_update_ii(data)
    elif magic == MAGIC_T48:
        return extract_update_simple(data, "XGecu T48 (TL866-3G)", MAGIC_T48, 276)
    elif magic == MAGIC_T56:
        return extract_update_simple(data, "XGecu T56", MAGIC_T56, 2068)
    else:
        raise ValueError(
            "Unrecognized magic 0x%08X - not an updateII.dat/updateT48.dat/"
            "updateT56.dat file (or unsupported variant)" % magic
        )


def main(argv):
    if len(argv) < 2:
        print("Usage: python extract_fw_update.py <update_file.dat> [output_prefix]")
        return 1

    in_path = argv[1]
    prefix = argv[2] if len(argv) > 2 else "fw_extracted"

    info = extract(in_path)
    blob = info.pop("firmware_blob")

    header_path = prefix + ".header.json"
    bin_path = prefix + ".firmware.bin"

    with open(header_path, "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2)

    with open(bin_path, "wb") as f:
        f.write(blob)

    print("Device        : %s" % info["device"])
    print("Magic         : %s" % info["magic"])
    if "file_crc32_ok" in info:
        print("File CRC32 OK : %s (stored=%s computed=%s)" % (
            info["file_crc32_ok"], info["stored_file_crc32"], info["computed_file_crc32"]))
        print("Bad block CRCs: %s" % (info["bad_block_crcs"] or "none"))
        print("Final block CRC OK: %s" % info["final_block_crc_ok"])
    else:
        print("Blocks found  : %d / field says %d (size match: %s)" % (
            info["blocks_found"], info["block_count_field"], info["size_matches_block_count_field"]))
    print("Firmware blob : %d bytes -> %s" % (info["firmware_blob_len"], bin_path))
    print("Header/meta   : %s" % header_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
