#!/usr/bin/env python3
"""
emi_dump.py — READ-ONLY parser/dumper for emi_base.db3 EMI records in Pandora Tool.

This script does NOT decrypt, modify, or patch anything. It only reads the
emi_base.db3 SQLite database that ships with Pandora and pretty-prints the
header fields it can interpret for educational/forensic use.

Usage:
    python3 emi_dump.py [--db path/to/emi_base.db3] [--id N] [--brand X]
                       [--model Y] [--limit N] [--hex-dump]
"""
import argparse
import os
import sqlite3
import struct
import sys

# ---------------- DRAM type decoding ----------------
# Observed little-endian word values at offset 0x04
DRAM_TYPES = {
    0x0000: "Unknown/generic",
    0x0202: "DDR2",
    0x0203: "DDR3",
    0x0204: "DDR3/LPDDR2 variant",
    0x0205: "LPDDR3",
    0x0206: "LPDDR4/LPDDR4X",
    0x0207: "LPDDR4X variant",
    0x0208: "LPDDR5",
}

# ---------------- MediaTek m_type decoding ----------------
# Codes observed in the database, mapped to the MediaTek enum (from preloader/emi.h).
MTYPE_MAP = {
    -2147483648: "Invalid/reserved",
    -2004318072: "Reserved/legacy",
    0: "Generic/unknown",
    1: "MCP (legacy)",
    2: "MCP combo NAND+RAM",
    3: "Discrete DRAM (early)",
    4: "LPDDR2",
    6: "DDR2/LPDDR2",
    8: "Reserved",
    9: "LPDDR3",
    11: "DDR3",
    12: "DDR3L",
    16: "LPDDR3-advanced",
    50: "LPDDR3 variant",
    52: "LPDDR3 variant 2",
    55: "LPDDR3 alt",
    66: "DDR3 variant",
    257: "LPDDR3 dual-channel",
    258: "LPDDR3 alt dual-channel",
    513: "LPDDR4",
    514: "LPDDR4X (Helio G/P)",
    515: "LPDDR4X (largest bucket)",
    516: "LPDDR4 dual",
    518: "LPDDR4X + UFS combo (2020+ phones)",
    774: "UFS + LPDDR5",
    776: "UFS + LPDDR5 variant",
    777: "UFS + LPDDR5 alt",
    779: "UFS + LPDDR5 alt2",
    4266: "LPDDR5T",
    458752: "UFS 4.0 special",
    352669780: "Custom/unknown",
    1073741824: "Reserved",
}


def decode_header(blob, id_len):
    """Return a dict of decoded fields. blob is raw bytes; id_len from column."""
    out = {}
    if len(blob) < 0x30:
        out["error"] = f"blob too short: {len(blob)}"
        return out
    out["rec_version"] = struct.unpack("<I", blob[0:4])[0]
    dram_code = struct.unpack("<H", blob[4:6])[0]
    out["dram_code"] = f"0x{dram_code:04x}"
    out["dram_type"] = DRAM_TYPES.get(dram_code, "unknown")
    topo = struct.unpack("<H", blob[6:8])[0]
    out["rank_topo"] = {0: "single-rank/cs", 2: "dual-rank/cs"}.get(topo, f"0x{topo:04x}")
    out["hdr_id_len"] = struct.unpack("<H", blob[8:10])[0]
    out["flags"] = struct.unpack("<H", blob[0x10:0x12])[0]
    # CID prefix at 0x14 for id_len bytes (binary). Column emmc_id stores this
    # as ASCII hex with a 3-byte prefix 15 01 00.
    cid_raw = blob[0x14:0x14 + id_len]
    out["cid_raw_hex"] = cid_raw.hex()
    out["cid_raw_ascii"] = "".join(chr(b) if 32 <= b < 127 else "." for b in cid_raw)
    # RAM vendor tag at 0x24 (up to 8 ASCII bytes)
    tag_bin = blob[0x24:0x2C]
    tag_ascii = "".join(chr(b) if 32 <= b < 127 else "." for b in tag_bin).rstrip("\x00").rstrip(".")
    out["ram_tag"] = tag_ascii
    return out


def hexdump(blob, start=0, length=None, width=16):
    if length is None:
        length = len(blob) - start
    lines = []
    for i in range(0, min(length, len(blob) - start), width):
        chunk = blob[start + i : start + i + width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {start+i:04x}: {hx:<{width*3}} {asc}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Read-only Pandora emi_base.db3 dumper")
    ap.add_argument("--db", default="emi_base.db3")
    ap.add_argument("--id", type=int, help="Dump a specific record id")
    ap.add_argument("--brand", help="Filter by brand (fuzzy, case-insensitive)")
    ap.add_argument("--model", help="Filter by model (fuzzy, case-insensitive)")
    ap.add_argument("--limit", type=int, default=10, help="Number of records to show")
    ap.add_argument("--hex-dump", action="store_true", help="Print hex dump of blob")
    ap.add_argument("--stats", action="store_true", help="Print database statistics")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f"error: cannot open {args.db}", file=sys.stderr)
        sys.exit(1)

    c = sqlite3.connect(args.db)
    cur = c.cursor()

    if args.stats:
        print("=== emi_base.db3 statistics ===")
        total = cur.execute("SELECT COUNT(*) FROM EmiInfo").fetchone()[0]
        print(f"Total EMI records: {total}")
        print("Top 20 brands by record count:")
        for brand, n in cur.execute(
            "SELECT brand, COUNT(*) FROM EmiInfo GROUP BY brand ORDER BY COUNT(*) DESC LIMIT 20"
        ):
            print(f"  {brand}: {n}")
        print()
        print("m_type distribution (MediaTek memory type code):")
        for mt, n in cur.execute(
            "SELECT m_type, COUNT(*) FROM EmiInfo GROUP BY m_type ORDER BY COUNT(*) DESC"
        ):
            print(f"  {mt:>12}  {MTYPE_MAP.get(mt,'?'):<40s}  {n}")
        print()
        print("data_size distribution:")
        for sz, n in cur.execute(
            "SELECT data_size, COUNT(*) FROM EmiInfo GROUP BY data_size ORDER BY COUNT(*) DESC"
        ):
            print(f"  {sz} bytes: {n}")
        return

    q = "SELECT id,version,brand,model,emmc_id,sub_ver,m_type,id_len,emi_crc,data,data_size,src_name FROM EmiInfo WHERE 1=1"
    params = []
    if args.id is not None:
        q += " AND id=?"; params.append(args.id)
    if args.brand:
        q += " AND LOWER(brand) LIKE ?"; params.append(f"%{args.brand.lower()}%")
    if args.model:
        q += " AND LOWER(model) LIKE ?"; params.append(f"%{args.model.lower()}%")
    q += " ORDER BY id LIMIT ?"
    params.append(args.limit)

    rows = cur.execute(q, params).fetchall()
    for r in rows:
        (iid, ver, brand, model, emmc_id, sub, mtype, idlen, crc, data,
         dsz, src) = r
        hdr = decode_header(data, idlen)
        print(f"=== EMI record id={iid} ===")
        print(f"  brand/model : {brand} / {model}")
        print(f"  version/sub : {ver} / {sub}")
        print(f"  source pre  : {src}")
        print(f"  emmc_id     : {emmc_id}  (id_len={idlen})")
        print(f"  m_type      : {mtype}  ({MTYPE_MAP.get(mtype,'?')})")
        print(f"  emi_crc     : 0x{crc:08x}" if crc is not None else "  emi_crc     : null")
        print(f"  blob size   : {dsz}")
        for k, v in hdr.items():
            print(f"  {k:12s}: {v}")
        if args.hex_dump:
            print("  hex dump:")
            print(hexdump(data))
        print()


if __name__ == "__main__":
    main()
