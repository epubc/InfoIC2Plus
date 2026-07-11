#!/usr/bin/env python3
"""
edit_infoic2plus_cli.py - Command-line editor for Xgpro's InfoIC2Plus.dll
chip database. Requires infoic2plus_lib.py in the same folder.

Only edits/adds/deletes chip *variants* inside EXISTING families - see
infoic2plus_lib.py's module docstring for why adding brand-new families
is intentionally not supported.

Examples:

  # List all families
  python edit_infoic2plus_cli.py InfoIC2Plus.dll list-families

  # List every chip variant in family 154 (TOSHIBA/KIOXIA)
  python edit_infoic2plus_cli.py InfoIC2Plus.dll list-variants --family 154

  # Search by chip name across all families
  python edit_infoic2plus_cli.py InfoIC2Plus.dll search "TC58DVM72A1FT00"

  # Show full decoded record for one variant
  python edit_infoic2plus_cli.py InfoIC2Plus.dll show --family 154 --variant 26

  # Edit a field (writes InfoIC2Plus.edited.dll by default)
  python edit_infoic2plus_cli.py InfoIC2Plus.dll edit --family 154 --variant 26 --page-size 1024 --out MyEdited.dll

  # Delete a variant
  python edit_infoic2plus_cli.py InfoIC2Plus.dll delete --family 154 --variant 26 --out MyEdited.dll

  # Add a new chip by cloning an existing similar one, only overriding name/fields
  python edit_infoic2plus_cli.py InfoIC2Plus.dll clone-add --family 154 --source-variant 26 \\
      --name "MYNEWCHIP01 @TSOP48" --page-size 2048 --spare-size 128 --out MyEdited.dll
"""

import argparse
import sys

from infoic2plus_lib import InfoIC2PlusDB, FAMILY_COUNT


def cmd_list_families(db, args):
    for fi in range(FAMILY_COUNT):
        fam = db.get_family(fi)
        print("%3d  %-20s %-40s (%d variants)" % (
            fam["family_index"], fam["short_name"], fam["display_name"], fam["variant_count"]))


def cmd_list_variants(db, args):
    fam = db.get_family(args.family)
    print("Family %d: %s (%s)" % (fam["family_index"], fam["short_name"], fam["display_name"]))
    for vi, v in enumerate(db.get_variants(args.family)):
        print("  [%4d] %s%s" % (vi, fam["short_name"], v["name_suffix"]))


def cmd_search(db, args):
    hits = db.search_variants(args.text)
    if not hits:
        print("No matches.")
        return
    for fi, short_name, vi, v in hits:
        print("family=%d (%s)  variant=%d  name=%s%s" % (fi, short_name, vi, short_name, v["name_suffix"]))


def _print_variant(fam, vi, v):
    print("family=%d (%s)  variant=%d" % (fam["family_index"], fam["short_name"], vi))
    print("  full_name       : %s%s" % (fam["short_name"], v["name_suffix"]))
    print("  algo_id         : %d" % v["algo_id"])
    print("  flags           : 0x%X" % v["flags"])
    print("  sub_id          : %d" % v["sub_id"])
    print("  bus_width       : %d" % v["bus_width"])
    print("  page_size       : %d" % v["page_size"])
    print("  total_blocks    : %d" % v["total_blocks"])
    print("  spare_size      : %d" % v["spare_size"])
    print("  nce_pin         : %d" % v["nce_pin"])
    print("  nrb_pin         : %d" % v["nrb_pin"])
    print("  pages_per_block : %d" % v["pages_per_block"])
    if v["page_size"] and v["pages_per_block"]:
        block_size = v["pages_per_block"] * (v["page_size"] + v["spare_size"])
        device_size = v["total_blocks"] * block_size
        print("  block_size_bytes  (computed): %d" % block_size)
        print("  device_size_bytes (computed): %d" % device_size)


def cmd_show(db, args):
    fam = db.get_family(args.family)
    variants = db.get_variants(args.family)
    if not (0 <= args.variant < len(variants)):
        print("variant index out of range (0..%d)" % (len(variants) - 1))
        sys.exit(1)
    _print_variant(fam, args.variant, variants[args.variant])


NUMERIC_FIELD_ARGS = [
    ("algo_id", "--algo-id", int),
    ("flags", "--flags", lambda s: int(s, 0)),
    ("sub_id", "--sub-id", int),
    ("bus_width", "--bus-width", int),
    ("page_size", "--page-size", int),
    ("total_blocks", "--total-blocks", int),
    ("spare_size", "--spare-size", int),
    ("nce_pin", "--nce-pin", int),
    ("nrb_pin", "--nrb-pin", int),
    ("pages_per_block", "--pages-per-block", int),
]


def _add_field_args(p):
    p.add_argument("--name", dest="name_suffix", help="new name suffix (after family short name)")
    for key, flag, _ in NUMERIC_FIELD_ARGS:
        p.add_argument(flag, dest=key, type=int if _ is int else str)


def _collect_fields(args):
    fields = {}
    if getattr(args, "name_suffix", None) is not None:
        fields["name_suffix"] = args.name_suffix
    for key, flag, conv in NUMERIC_FIELD_ARGS:
        val = getattr(args, key, None)
        if val is not None:
            fields[key] = conv(val) if not isinstance(val, int) else val
    return fields


def cmd_edit(db, args):
    fields = _collect_fields(args)
    if not fields:
        print("Nothing to edit - pass at least one of --name/--page-size/... ")
        sys.exit(1)
    v = db.edit_variant(args.family, args.variant, **fields)
    fam = db.get_family(args.family)
    print("Edited. New values:")
    _print_variant(fam, args.variant, v)
    out = db.save(output_path=args.out, overwrite=args.overwrite)
    print("Saved: %s" % out)


def cmd_delete(db, args):
    fam = db.get_family(args.family)
    removed = db.delete_variant(args.family, args.variant)
    print("Deleted: %s%s" % (fam["short_name"], removed["name_suffix"]))
    out = db.save(output_path=args.out, overwrite=args.overwrite)
    print("Saved: %s" % out)


def cmd_clone_add(db, args):
    if not args.name_suffix:
        print("--name is required for clone-add")
        sys.exit(1)
    fields = _collect_fields(args)
    fields.pop("name_suffix", None)
    v = db.add_variant_cloned(args.family, args.source_variant, args.name_suffix, **fields)
    fam = db.get_family(args.family)
    print("Added (cloned from variant %d):" % args.source_variant)
    _print_variant(fam, "new", v)
    out = db.save(output_path=args.out, overwrite=args.overwrite)
    print("Saved: %s" % out)


def cmd_blank_add(db, args):
    if not args.name_suffix:
        print("--name is required for blank-add")
        sys.exit(1)
    fields = _collect_fields(args)
    fields.pop("name_suffix", None)
    print("WARNING: blank-add zeroes ~20 bytes of still-undeciphered fields. "
          "Prefer clone-add for chips you intend to actually program with.")
    v = db.add_variant_blank(args.family, args.name_suffix, **fields)
    fam = db.get_family(args.family)
    print("Added (blank):")
    _print_variant(fam, "new", v)
    out = db.save(output_path=args.out, overwrite=args.overwrite)
    print("Saved: %s" % out)


def main(argv):
    p = argparse.ArgumentParser(description="Edit Xgpro's InfoIC2Plus.dll chip database")
    p.add_argument("dll_path")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("list-families")
    sp.set_defaults(func=cmd_list_families)

    sp = sub.add_parser("list-variants")
    sp.add_argument("--family", type=int, required=True)
    sp.set_defaults(func=cmd_list_variants)

    sp = sub.add_parser("search")
    sp.add_argument("text")
    sp.set_defaults(func=cmd_search)

    sp = sub.add_parser("show")
    sp.add_argument("--family", type=int, required=True)
    sp.add_argument("--variant", type=int, required=True)
    sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("edit")
    sp.add_argument("--family", type=int, required=True)
    sp.add_argument("--variant", type=int, required=True)
    sp.add_argument("--out", default=None)
    sp.add_argument("--overwrite", action="store_true")
    _add_field_args(sp)
    sp.set_defaults(func=cmd_edit)

    sp = sub.add_parser("delete")
    sp.add_argument("--family", type=int, required=True)
    sp.add_argument("--variant", type=int, required=True)
    sp.add_argument("--out", default=None)
    sp.add_argument("--overwrite", action="store_true")
    sp.set_defaults(func=cmd_delete)

    sp = sub.add_parser("clone-add", help="RECOMMENDED way to add a new chip")
    sp.add_argument("--family", type=int, required=True)
    sp.add_argument("--source-variant", type=int, required=True,
                     help="index of an existing similar variant to clone unknown fields from")
    sp.add_argument("--out", default=None)
    sp.add_argument("--overwrite", action="store_true")
    _add_field_args(sp)
    sp.set_defaults(func=cmd_clone_add)

    sp = sub.add_parser("blank-add", help="Add with unknown fields zeroed (not recommended)")
    sp.add_argument("--family", type=int, required=True)
    sp.add_argument("--out", default=None)
    sp.add_argument("--overwrite", action="store_true")
    _add_field_args(sp)
    sp.set_defaults(func=cmd_blank_add)

    args = p.parse_args(argv[1:])
    db = InfoIC2PlusDB(args.dll_path)
    args.func(db, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
