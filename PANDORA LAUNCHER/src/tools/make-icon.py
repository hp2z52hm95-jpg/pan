#!/usr/bin/env python3
"""
Builds src/icon.ico for PandoraLauncher.exe out of the icon resources that were
extracted from PandoraTool.exe (RE_work/rsrc/main), so the launcher shows the
same icon as the tool.

Inputs : RE_work/rsrc/main/GRPICON.MAINICON.L1033.bin  (RT_GROUP_ICON)
         RE_work/rsrc/main/ICON.<id>.L1033.bin         (RT_ICON)
Output : PANDORA LAUNCHER/src/icon.ico
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)                       # PANDORA LAUNCHER/src
LAUNCHER = os.path.dirname(SRC)                   # PANDORA LAUNCHER
REPO = os.path.dirname(LAUNCHER)                  # repository root
RSRC = os.path.join(REPO, "RE_work", "rsrc", "main")


def read_group(path):
    data = open(path, "rb").read()
    reserved, rtype, count = struct.unpack_from("<HHH", data, 0)
    entries = []
    for i in range(count):
        off = 6 + i * 14
        w, h, cc, rsv, planes, bpp, size, idx = struct.unpack_from("<BBBBHHIH", data, off)
        entries.append({"w": w or 256, "h": h or 256, "cc": cc, "planes": planes,
                        "bpp": bpp, "size": size, "id": idx})
    return entries


def main():
    group = os.path.join(RSRC, "GRPICON.MAINICON.L1033.bin")
    if not os.path.exists(group):
        print("missing", group, file=sys.stderr)
        return 1
    raw = read_group(group)
    blobs = []
    for e in sorted(raw, key=lambda x: (x["w"], x["bpp"])):
        blob_path = os.path.join(RSRC, "ICON.%d.L1033.bin" % e["id"])
        if not os.path.exists(blob_path):
            continue
        blob = open(blob_path, "rb").read()
        if len(blob) != e["size"]:
            continue
        blobs.append((e, blob))

    out_path = os.path.join(SRC, "icon.ico")
    header = struct.pack("<HHH", 0, 1, len(blobs))
    offset = len(header) + 16 * len(blobs)
    directory = b""
    body = b""
    for e, blob in blobs:
        directory += struct.pack("<BBBBHHII",
                                 0 if e["w"] >= 256 else e["w"],
                                 0 if e["h"] >= 256 else e["h"],
                                 e["cc"], 0, e["planes"] or 1, e["bpp"],
                                 len(blob), offset)
        body += blob
        offset += len(blob)
    with open(out_path, "wb") as f:
        f.write(header + directory + body)
    print("wrote %s (%d images: %s)"
          % (out_path, len(blobs), ", ".join("%dx%d/%dbpp" % (e["w"], e["h"], e["bpp"])
                                             for e, _ in blobs)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
