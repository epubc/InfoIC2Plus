#!/usr/bin/env python3
"""
extract_infoic2plus.py - Standalone extractor for Xgpro's InfoIC2Plus.dll chip database.

Reverse-engineered from InfoIC2Plus.dll (opened directly in IDA Pro; no
data is read from any external file at runtime by the DLL itself - the
entire chip database is compiled as static C structs inside the DLL's
.rdata/.data sections). This script parses the raw PE file directly -
no IDA required, pure Python 3 stdlib only.

Data model (empirically verified against real records):

  - A fixed array of 173 "ChipFamily" records, 76 bytes each, at VA
    0x101C9330 (image base 0x10000000 -> RVA 0x1C9330):

        struct ChipFamily {            // 76 bytes (0x4C)
            DWORD  family_index;        // +0x00 (== array index)
            DWORD  category_id;         // +0x04
            char   short_name[20];      // +0x08  e.g. "ABLIC"
            char   display_name[40];    // +0x1C  e.g. "ABLIC Inc"
            DWORD  variants_va;         // +0x44  pointer to variant array
            DWORD  variant_count;       // +0x48
        };

  - Each family points to `variant_count` "ChipVariant" records, 116
    bytes each (0x74), stored contiguously starting at variants_va:

        struct ChipVariant {           // 116 bytes (0x74)
            DWORD algo_id;               // +0x00  shared per family (programming
                                          //        algorithm / package class id)
            DWORD flags;                 // +0x04  category bitmask (top byte
                                          //        checked by GetIcList/GetIcMFC)
            DWORD sub_id;                 // +0x08
            char  name_suffix[64];        // +0x0C  null-terminated chip name suffix
            // bytes +0x24..+0x4B unaccounted for (unused/reserved for most chips)
            DWORD bus_width;              // +0x4C (76)  NAND: data bus width in bits
            DWORD page_size;              // +0x50 (80)  NAND: page size in bytes
            DWORD total_blocks;           // +0x54 (84)  NAND: total block count
            BYTE  spare_size;              // +0x58 (88)  NAND: spare/OOB bytes per page
            BYTE  unknown89;               // +0x59 (89)
            BYTE  nce_pin;                 // +0x5A (90)  NAND: nCE# pin number
            BYTE  nrb_pin;                 // +0x5B (91)  NAND: nRB# pin number
            // bytes +0x5C..+0x67 unaccounted for
            DWORD pages_per_block;        // +0x68 (104) NAND: pages per block
            // (remaining bytes hold further binary fields not decoded here)
        };

    NOTE: the bus_width/page_size/total_blocks/spare_size/nce_pin/nrb_pin/
    pages_per_block fields are only meaningful for NAND-flash-style chips
    (verified against Xgpro's own "Chip Info" popup for two different
    Toshiba/Kioxia NAND parts). For non-NAND chips (EEPROM, NOR flash,
    etc.) these bytes are frequently 0 or hold unrelated values - Xgpro's
    UI decides what to display based on algo_id/flags, which this script
    does not attempt to decode.

    Xgpro's own "Blocks Size" and "Device Size" figures are NOT stored
    directly - they are computed on the fly:
        block_size_bytes  = pages_per_block * (page_size + spare_size)
        device_size_bytes = total_blocks * block_size_bytes

  - The full chip name shown in Xgpro's UI is simply
    `short_name + name_suffix` (plain string concatenation, exactly as
    the DLL's own GetIcList/GetIcMFC functions do it internally).

Usage:
    python extract_infoic2plus.py InfoIC2Plus.dll [output_prefix]

Writes <output_prefix>.json (full nested data) and <output_prefix>.csv
(flat: one row per chip variant). Defaults to "infoic2plus_chiplist".
"""

import csv
import json
import struct
import sys

FAMILY_COUNT = 173
FAMILY_STRUCT_SIZE = 76
VARIANT_STRUCT_SIZE = 116
FAMILY_ARRAY_VA = 0x101C9330


def parse_pe(data):
    """Return (image_base, sections) where sections is a list of
    (name, virtual_address, virtual_size, raw_ptr, raw_size)."""
    if data[:2] != b"MZ":
        raise ValueError("Not a PE file (missing MZ header)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("Not a PE file (missing PE signature)")

    coff_offset = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff_offset + 2)[0]
    opt_header_size = struct.unpack_from("<H", data, coff_offset + 16)[0]
    opt_header_offset = coff_offset + 20

    magic = struct.unpack_from("<H", data, opt_header_offset)[0]
    if magic == 0x10B:      # PE32
        image_base = struct.unpack_from("<I", data, opt_header_offset + 28)[0]
    elif magic == 0x20B:    # PE32+
        image_base = struct.unpack_from("<Q", data, opt_header_offset + 24)[0]
    else:
        raise ValueError("Unknown optional header magic: 0x%x" % magic)

    section_table_offset = opt_header_offset + opt_header_size
    sections = []
    for i in range(num_sections):
        off = section_table_offset + i * 40
        name = data[off:off + 8].rstrip(b"\x00").decode(errors="replace")
        virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append((name, virtual_address, virtual_size, raw_ptr, raw_size))
    return image_base, sections


def rva_to_offset(sections, rva):
    for name, va, vsize, raw_ptr, raw_size in sections:
        span = max(vsize, raw_size)
        if va <= rva < va + span:
            return raw_ptr + (rva - va)
    raise ValueError("RVA 0x%x not found in any section" % rva)


def read_cstr(data, offset, maxlen):
    end = data.find(b"\x00", offset, offset + maxlen)
    if end == -1:
        end = offset + maxlen
    return data[offset:end].decode("latin-1", errors="replace")


def extract(dll_path):
    with open(dll_path, "rb") as f:
        data = f.read()

    image_base, sections = parse_pe(data)

    family_file_off = rva_to_offset(sections, FAMILY_ARRAY_VA - image_base)

    families = []
    for fi in range(FAMILY_COUNT):
        rec_off = family_file_off + fi * FAMILY_STRUCT_SIZE
        family_index, category_id = struct.unpack_from("<II", data, rec_off)
        short_name = read_cstr(data, rec_off + 0x08, 20)
        display_name = read_cstr(data, rec_off + 0x1C, 40)
        variants_va, variant_count = struct.unpack_from("<II", data, rec_off + 0x44)

        variants = []
        if variants_va and variant_count > 0:
            var_file_off = rva_to_offset(sections, variants_va - image_base)
            for vi in range(variant_count):
                vrec_off = var_file_off + vi * VARIANT_STRUCT_SIZE
                algo_id, flags, sub_id = struct.unpack_from("<III", data, vrec_off)
                name_suffix = read_cstr(data, vrec_off + 0x0C, VARIANT_STRUCT_SIZE - 0x0C)

                bus_width = struct.unpack_from("<I", data, vrec_off + 76)[0]
                page_size = struct.unpack_from("<I", data, vrec_off + 80)[0]
                total_blocks = struct.unpack_from("<I", data, vrec_off + 84)[0]
                spare_size = data[vrec_off + 88]
                nce_pin = data[vrec_off + 90]
                nrb_pin = data[vrec_off + 91]
                pages_per_block = struct.unpack_from("<I", data, vrec_off + 104)[0]

                block_size = None
                device_size = None
                if page_size and pages_per_block:
                    block_size = pages_per_block * (page_size + spare_size)
                    device_size = total_blocks * block_size if total_blocks else None

                variants.append({
                    "variant_index": vi,
                    "algo_id": algo_id,
                    "flags": flags,
                    "sub_id": sub_id,
                    "name_suffix": name_suffix,
                    "full_name": short_name + name_suffix,
                    "bus_width": bus_width,
                    "page_size": page_size,
                    "total_blocks": total_blocks,
                    "spare_size": spare_size,
                    "nce_pin": nce_pin,
                    "nrb_pin": nrb_pin,
                    "pages_per_block": pages_per_block,
                    "block_size_bytes": block_size,
                    "device_size_bytes": device_size,
                })

        families.append({
            "family_index": family_index,
            "category_id": category_id,
            "short_name": short_name,
            "display_name": display_name,
            "variant_count": variant_count,
            "variants": variants,
        })

    return families


def write_outputs(families, prefix):
    json_path = prefix + ".json"
    csv_path = prefix + ".csv"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(families, f, ensure_ascii=False, indent=2)

    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["family_index", "family_short_name", "family_display_name",
                    "variant_index", "algo_id", "flags", "sub_id",
                    "name_suffix", "full_chip_name",
                    "bus_width", "page_size", "total_blocks", "spare_size",
                    "nce_pin", "nrb_pin", "pages_per_block",
                    "block_size_bytes", "device_size_bytes"])
        for fam in families:
            for v in fam["variants"]:
                w.writerow([
                    fam["family_index"], fam["short_name"], fam["display_name"],
                    v["variant_index"], v["algo_id"], v["flags"], v["sub_id"],
                    v["name_suffix"], v["full_name"],
                    v["bus_width"], v["page_size"], v["total_blocks"], v["spare_size"],
                    v["nce_pin"], v["nrb_pin"], v["pages_per_block"],
                    v["block_size_bytes"], v["device_size_bytes"],
                ])

    return json_path, csv_path


def main(argv):
    if len(argv) < 2:
        print("Usage: python extract_infoic2plus.py <InfoIC2Plus.dll> [output_prefix]")
        return 1

    dll_path = argv[1]
    prefix = argv[2] if len(argv) > 2 else "infoic2plus_chiplist"

    families = extract(dll_path)
    total_variants = sum(f["variant_count"] for f in families)
    json_path, csv_path = write_outputs(families, prefix)

    print("OK: %d chip families, %d total chip variants" % (len(families), total_variants))
    print("Written: %s" % json_path)
    print("Written: %s" % csv_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
