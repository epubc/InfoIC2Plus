#!/usr/bin/env python3
"""
infoic2plus_lib.py - Core read/write library for Xgpro's InfoIC2Plus.dll
chip database.

Reverse-engineered by static analysis in IDA Pro (see extract_infoic2plus.py
for the read-only version and its docstring for the full struct writeup).
This module additionally supports SAFE in-place editing:

  - edit an existing chip variant's fields
  - delete an existing chip variant (swap-with-last + shrink count)
  - add a new chip variant to an EXISTING family (clone-based, recommended)

INTENTIONALLY NOT SUPPORTED: adding a brand-new top-level family. The
family count (173) is a hard-coded immediate constant baked into the
compiled machine code of GetDllInfo/GetIcList/GetIcMFC/GetMfcStru/GetIcStru
inside the DLL - not a value read from the data array. Changing it would
require patching x86 instructions in multiple functions, which is a much
higher-risk operation this tool deliberately does not attempt. Two
families already exist as user-customization slots you can freely add
variants to: family index 0 ("MY FAVORITES-User") and family index 172
("Customize").

SAFETY MODEL
------------
- Every field EXCEPT name_suffix and the 7 known NAND-geometry fields is
  treated as opaque/unknown and is only ever copied byte-for-byte from an
  existing record - never zeroed, never guessed. This is why `add_variant`
  requires cloning an existing similar variant rather than building one
  from scratch: the trailing ~20 bytes of a variant record are still
  undeciphered and may hold real programming-algorithm parameters. Zeroing
  them for a brand new entry could make Xgpro mis-program a real chip.
- New variants are never spliced into the middle of the file. All writes
  that need extra space go into a brand-new PE section appended at the end
  of the file (added via a fresh IMAGE_SECTION_HEADER), so nothing already
  in the file ever has to move. This keeps every other RVA/pointer in the
  DLL valid.
- save() always writes a NEW file by default (never silently overwrites
  your original), and even in overwrite mode it makes a timestamped
  ".bak" copy of the original first.

Struct layout: see extract_infoic2plus.py's module docstring.
"""

import copy
import shutil
import struct
import time

FAMILY_COUNT = 173
FAMILY_STRUCT_SIZE = 76
VARIANT_STRUCT_SIZE = 116
FAMILY_ARRAY_VA = 0x101C9330

NAME_OFFSET = 0x0C
NAME_MAX_BYTES = 0x4C - 0x0C  # 64 bytes incl. null terminator -> 63 usable chars
# (0x4C / 76 is where the first known NAND field, bus_width, begins - name
#  text must never be allowed to grow into that region)

FIELD_OFFSETS = {
    "algo_id": (0x00, "<I"),
    "flags": (0x04, "<I"),
    "sub_id": (0x08, "<I"),
    "bus_width": (0x4C, "<I"),
    "page_size": (0x50, "<I"),
    "total_blocks": (0x54, "<I"),
    "spare_size": (0x58, "<B"),
    "nce_pin": (0x5A, "<B"),
    "nrb_pin": (0x5B, "<B"),
    "pages_per_block": (0x68, "<I"),
}


class PEError(Exception):
    pass


class InfoIC2PlusDB:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = bytearray(f.read())
        self._parse_pe()
        self._dirty_families = {}   # family_index -> list[dict] (decoded variants, editable copy)
        self._new_section_added = False

    # ---------------------------------------------------------------- PE --
    def _parse_pe(self):
        data = self.data
        if data[:2] != b"MZ":
            raise PEError("Not a PE file (missing MZ header)")
        self.e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if bytes(data[self.e_lfanew:self.e_lfanew + 4]) != b"PE\x00\x00":
            raise PEError("Not a PE file (missing PE signature)")

        self.coff_offset = self.e_lfanew + 4
        self.num_sections = struct.unpack_from("<H", data, self.coff_offset + 2)[0]
        self.opt_header_size = struct.unpack_from("<H", data, self.coff_offset + 16)[0]
        self.opt_header_offset = self.coff_offset + 20

        magic = struct.unpack_from("<H", data, self.opt_header_offset)[0]
        if magic != 0x10B:
            raise PEError("Only PE32 (32-bit) images are supported (got magic 0x%x)" % magic)
        self.is_pe32 = True
        self.image_base = struct.unpack_from("<I", data, self.opt_header_offset + 28)[0]
        self.section_alignment = struct.unpack_from("<I", data, self.opt_header_offset + 32)[0]
        self.file_alignment = struct.unpack_from("<I", data, self.opt_header_offset + 36)[0]
        self.size_of_image_off = self.opt_header_offset + 56

        self.section_table_offset = self.opt_header_offset + self.opt_header_size
        self._read_sections()

    def _read_sections(self):
        data = self.data
        self.sections = []
        for i in range(self.num_sections):
            off = self.section_table_offset + i * 40
            name = bytes(data[off:off + 8]).rstrip(b"\x00").decode(errors="replace")
            vsize, va, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
            self.sections.append({
                "header_off": off, "name": name, "virtual_size": vsize,
                "virtual_address": va, "raw_size": rsize, "raw_ptr": rptr,
            })

    def rva_to_offset(self, rva):
        for s in self.sections:
            span = max(s["virtual_size"], s["raw_size"])
            if s["virtual_address"] <= rva < s["virtual_address"] + span:
                return s["raw_ptr"] + (rva - s["virtual_address"])
        raise PEError("RVA 0x%x not found in any section" % rva)

    def va_to_offset(self, va):
        return self.rva_to_offset(va - self.image_base)

    @staticmethod
    def _align(value, alignment):
        if alignment <= 1:
            return value
        return (value + alignment - 1) // alignment * alignment

    def _ensure_growth_section(self):
        """Add (once) a brand-new RW data section at the end of the file
        for anything this session needs to append. Returns nothing; sets
        self._growth_section (dict) and self._growth_cursor (file offset
        where the next appended blob should go)."""
        if self._new_section_added:
            return

        # Room check: need one more 40-byte header before first section's raw data.
        last_header_end = self.section_table_offset + (self.num_sections + 1) * 40
        first_raw_ptr = min(s["raw_ptr"] for s in self.sections if s["raw_ptr"])
        if last_header_end > first_raw_ptr:
            raise PEError(
                "Not enough room in the PE header area to add a new section "
                "(need %d bytes, only %d available before first section's raw data). "
                "This DLL cannot be safely extended by this tool." % (
                    last_header_end - self.section_table_offset, first_raw_ptr - self.section_table_offset)
            )

        # New section's VA starts right after the current highest section (aligned).
        highest_va_end = max(s["virtual_address"] + max(s["virtual_size"], s["raw_size"]) for s in self.sections)
        new_va = self._align(highest_va_end, self.section_alignment)

        # New section's raw data starts at end of current file (aligned).
        new_raw_ptr = self._align(len(self.data), self.file_alignment)
        if new_raw_ptr > len(self.data):
            self.data.extend(b"\x00" * (new_raw_ptr - len(self.data)))

        new_header = {
            "header_off": self.section_table_offset + self.num_sections * 40,
            "name": ".xgpat0",
            "virtual_size": 0,      # filled in on save/finalize
            "virtual_address": new_va,
            "raw_size": 0,          # filled in on save/finalize
            "raw_ptr": new_raw_ptr,
        }

        self.num_sections += 1
        struct.pack_into("<H", self.data, self.coff_offset + 2, self.num_sections)

        self.sections.append(new_header)
        self._growth_section = new_header
        self._new_section_added = True

    def _append_bytes(self, blob):
        """Append blob to the growth section, return its VA."""
        self._ensure_growth_section()
        offset_in_file = len(self.data)
        rva = self._growth_section["virtual_address"] + (offset_in_file - self._growth_section["raw_ptr"])
        self.data.extend(blob)
        self._growth_section["virtual_size"] = offset_in_file + len(blob) - self._growth_section["raw_ptr"]
        return self.image_base + rva

    def _finalize_growth_section(self):
        if not self._new_section_added:
            return
        gs = self._growth_section
        raw_end = self._align(gs["raw_ptr"] + gs["virtual_size"], self.file_alignment)
        if raw_end > len(self.data):
            self.data.extend(b"\x00" * (raw_end - len(self.data)))
        gs["raw_size"] = raw_end - gs["raw_ptr"]

        name_bytes = gs["name"].encode()[:8].ljust(8, b"\x00")
        struct.pack_into(
            "<8sIIIIIIHHI", self.data, gs["header_off"],
            name_bytes,
            gs["virtual_size"], gs["virtual_address"],
            gs["raw_size"], gs["raw_ptr"],
            0, 0, 0, 0,
            0xC0000040,  # IMAGE_SCN_CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE
        )

        new_size_of_image = self._align(gs["virtual_address"] + gs["virtual_size"], self.section_alignment)
        struct.pack_into("<I", self.data, self.size_of_image_off, new_size_of_image)

    # ------------------------------------------------------------- read --
    def _read_cstr(self, offset, maxlen):
        data = self.data
        end = data.find(b"\x00", offset, offset + maxlen)
        if end == -1:
            end = offset + maxlen
        return bytes(data[offset:end]).decode("latin-1", errors="replace")

    def _read_variant_raw(self, rec_off):
        rec = bytes(self.data[rec_off:rec_off + VARIANT_STRUCT_SIZE])
        d = {"_raw": rec}
        for name, (off, fmt) in FIELD_OFFSETS.items():
            d[name] = struct.unpack_from(fmt, rec, off)[0]
        d["name_suffix"] = self._read_cstr(rec_off + NAME_OFFSET, NAME_MAX_BYTES)
        return d

    def get_family(self, family_index):
        if not (0 <= family_index < FAMILY_COUNT):
            raise ValueError("family_index must be 0..%d" % (FAMILY_COUNT - 1))
        rec_off = self.va_to_offset(FAMILY_ARRAY_VA) + family_index * FAMILY_STRUCT_SIZE
        raw = bytes(self.data[rec_off:rec_off + FAMILY_STRUCT_SIZE])
        short_name = raw[8:28].split(b"\x00")[0].decode(errors="replace")
        display_name = raw[28:68].split(b"\x00")[0].decode(errors="replace")
        variants_va, variant_count = struct.unpack_from("<II", raw, 0x44)
        return {
            "family_index": family_index, "rec_off": rec_off,
            "short_name": short_name, "display_name": display_name,
            "variants_va": variants_va, "variant_count": variant_count,
        }

    def get_variants(self, family_index):
        if family_index in self._dirty_families:
            return copy.deepcopy(self._dirty_families[family_index])
        fam = self.get_family(family_index)
        out = []
        if fam["variants_va"] and fam["variant_count"] > 0:
            base_off = self.va_to_offset(fam["variants_va"])
            for vi in range(fam["variant_count"]):
                out.append(self._read_variant_raw(base_off + vi * VARIANT_STRUCT_SIZE))
        return out

    def find_families(self, name_substr):
        name_substr = name_substr.lower()
        hits = []
        for fi in range(FAMILY_COUNT):
            fam = self.get_family(fi)
            if name_substr in fam["short_name"].lower() or name_substr in fam["display_name"].lower():
                hits.append(fam)
        return hits

    def search_variants(self, name_substr):
        """Search across ALL families for chips whose full displayed name
        (short_name + name_suffix) contains name_substr (case-insensitive).
        Returns list of (family_index, family_short_name, variant_index, variant_dict)."""
        needle = name_substr.lower()
        hits = []
        for fi in range(FAMILY_COUNT):
            fam = self.get_family(fi)
            for vi, v in enumerate(self.get_variants(fi)):
                full = fam["short_name"] + v["name_suffix"]
                if needle in full.lower():
                    hits.append((fi, fam["short_name"], vi, v))
        return hits

    # ------------------------------------------------------------ write --
    def _touch(self, family_index):
        if family_index not in self._dirty_families:
            self._dirty_families[family_index] = self.get_variants(family_index)
        return self._dirty_families[family_index]

    def edit_variant(self, family_index, variant_index, **fields):
        """Edit one or more fields of an existing variant.
        Allowed keys: name_suffix, algo_id, flags, sub_id, bus_width,
        page_size, total_blocks, spare_size, nce_pin, nrb_pin,
        pages_per_block. Any field not passed is left unchanged."""
        variants = self._touch(family_index)
        if not (0 <= variant_index < len(variants)):
            raise ValueError("variant_index out of range (0..%d)" % (len(variants) - 1))
        v = variants[variant_index]

        for key, val in fields.items():
            if key == "name_suffix":
                encoded = val.encode("latin-1", errors="replace")
                if len(encoded) + 1 > NAME_MAX_BYTES:
                    raise ValueError(
                        "name_suffix too long: %d bytes (max %d incl. null terminator) - "
                        "longer names would overwrite the chip's NAND geometry fields" % (
                            len(encoded) + 1, NAME_MAX_BYTES))
                v["name_suffix"] = val
            elif key in FIELD_OFFSETS:
                v[key] = val
            else:
                raise ValueError("Unknown/unsafe field: %r" % key)
        return v

    def delete_variant(self, family_index, variant_index):
        """Delete a variant by swapping it with the last one in the array
        and shrinking the count. O(1), never needs to move file data."""
        variants = self._touch(family_index)
        if not (0 <= variant_index < len(variants)):
            raise ValueError("variant_index out of range (0..%d)" % (len(variants) - 1))
        removed = variants.pop(variant_index)
        return removed

    def add_variant_cloned(self, family_index, source_variant_index, name_suffix, **overrides):
        """Add a new variant by cloning an EXISTING variant's full 116-byte
        record (preserving all still-undeciphered fields) and then only
        overriding the fields you explicitly pass (always overrides
        name_suffix; optionally any key from FIELD_OFFSETS too).
        This is the SAFE, recommended way to add a chip."""
        variants = self._touch(family_index)
        if not (0 <= source_variant_index < len(variants)):
            raise ValueError("source_variant_index out of range (0..%d)" % (len(variants) - 1))
        new_v = copy.deepcopy(variants[source_variant_index])

        encoded = name_suffix.encode("latin-1", errors="replace")
        if len(encoded) + 1 > NAME_MAX_BYTES:
            raise ValueError("name_suffix too long: %d bytes (max %d)" % (len(encoded) + 1, NAME_MAX_BYTES))
        new_v["name_suffix"] = name_suffix

        for key, val in overrides.items():
            if key not in FIELD_OFFSETS:
                raise ValueError("Unknown/unsafe field: %r" % key)
            new_v[key] = val

        variants.append(new_v)
        return new_v

    def add_variant_blank(self, family_index, name_suffix, **fields):
        """Add a brand new variant with all unknown/undeciphered bytes
        zeroed. NOT recommended for chips you intend to actually use for
        real programming - prefer add_variant_cloned(). Provided for
        completeness (e.g. the 'Customize'/'MY FAVORITES-User' slots where
        Xgpro's own UI is expected to fill in details afterwards)."""
        variants = self._touch(family_index)
        encoded = name_suffix.encode("latin-1", errors="replace")
        if len(encoded) + 1 > NAME_MAX_BYTES:
            raise ValueError("name_suffix too long: %d bytes (max %d)" % (len(encoded) + 1, NAME_MAX_BYTES))
        new_v = {"_raw": b"\x00" * VARIANT_STRUCT_SIZE, "name_suffix": name_suffix}
        for key in FIELD_OFFSETS:
            new_v[key] = fields.get(key, 0)
        variants.append(new_v)
        return new_v

    # -------------------------------------------------------- serialize --
    def _serialize_variant(self, v):
        rec = bytearray(v.get("_raw") or (b"\x00" * VARIANT_STRUCT_SIZE))
        if len(rec) != VARIANT_STRUCT_SIZE:
            rec = bytearray(VARIANT_STRUCT_SIZE)
        for name, (off, fmt) in FIELD_OFFSETS.items():
            struct.pack_into(fmt, rec, off, v[name])
        name_bytes = v["name_suffix"].encode("latin-1", errors="replace")[:NAME_MAX_BYTES - 1] + b"\x00"
        rec[NAME_OFFSET:NAME_OFFSET + len(name_bytes)] = name_bytes
        # zero any leftover bytes between the new terminator and the next known field
        pad_start = NAME_OFFSET + len(name_bytes)
        pad_end = FIELD_OFFSETS["bus_width"][0]
        if pad_start < pad_end:
            rec[pad_start:pad_end] = b"\x00" * (pad_end - pad_start)
        return bytes(rec)

    def _apply_dirty_families(self):
        for family_index, variants in self._dirty_families.items():
            fam = self.get_family(family_index)
            blob = b"".join(self._serialize_variant(v) for v in variants)
            if len(variants) == 0:
                new_va, new_count = 0, 0
            else:
                new_va = self._append_bytes(blob)
                new_count = len(variants)
            struct.pack_into("<II", self.data, fam["rec_off"] + 0x44, new_va, new_count)

    # ------------------------------------------------------------- save --
    def save(self, output_path=None, overwrite=False, make_backup=True):
        """Write the modified database.

        - If output_path is given, always writes there (original untouched).
        - If output_path is None and overwrite=True, writes back to the
          original path (after making a timestamped .bak copy unless
          make_backup=False).
        - If output_path is None and overwrite=False (default), writes to
          "<original>.edited.dll" next to the original.
        """
        self._apply_dirty_families()
        self._finalize_growth_section()

        if output_path is None:
            if overwrite:
                output_path = self.path
                if make_backup:
                    backup_path = self.path + ".%d.bak" % int(time.time())
                    shutil.copy2(self.path, backup_path)
            else:
                if self.path.lower().endswith(".dll"):
                    output_path = self.path[:-4] + ".edited.dll"
                else:
                    output_path = self.path + ".edited"

        with open(output_path, "wb") as f:
            f.write(self.data)
        return output_path
