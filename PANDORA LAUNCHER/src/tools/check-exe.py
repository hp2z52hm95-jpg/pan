#!/usr/bin/env python3
"""
Sanity check for a built PandoraLauncher.exe (used by CI and locally):

  python3 tools/check-exe.py PandoraLauncher.exe

Checks that the file really is a 32-bit Windows GUI executable, that the icon
group / version info / manifest resources are in it, and that it is statically
linked except for the Windows system DLLs.
"""
import struct
import sys

EXPECTED_IMPORTS = {
    "WINHTTP.dll", "COMCTL32.dll", "SHELL32.dll", "VERSION.dll", "ADVAPI32.dll",
    "USER32.dll", "GDI32.dll", "KERNEL32.dll", "ole32.dll", "OLE32.dll",
}


def sections(d, pe, nsec, optsz):
    opt = pe + 24
    sec = opt + optsz
    out = []
    for i in range(nsec):
        off = sec + i * 40
        name = d[off:off + 8].rstrip(b"\0").decode(errors="replace")
        vsz, va, rsz, ra = struct.unpack_from("<IIII", d, off + 8)
        out.append((name, va, max(vsz, rsz), ra))
    return out


def main(path):
    d = open(path, "rb").read()
    if d[:2] != b"MZ":
        print("not a PE file", file=sys.stderr)
        return 1
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    if d[pe:pe + 4] != b"PE\0\0":
        print("no PE header", file=sys.stderr)
        return 1
    machine, nsec = struct.unpack_from("<HH", d, pe + 4)
    optsz = struct.unpack_from("<H", d, pe + 20)[0]
    subsystem = struct.unpack_from("<H", d, pe + 0x5C)[0]
    secs = sections(d, pe, nsec, optsz)

    def rva2off(rva):
        for _, va, sz, ra in secs:
            if va <= rva < va + sz:
                return ra + (rva - va)
        raise KeyError(hex(rva))

    problems = []
    if machine != 0x14C:
        problems.append("machine is not i386 (32-bit)")
    if subsystem != 2:
        problems.append("subsystem is not GUI")

    # resources: RT_ICON(3) / RT_GROUP_ICON(14) / RT_VERSION(16) / RT_MANIFEST(24)
    rsrc_rva, rsrc_sz = struct.unpack_from("<II", d, pe + 24 + 96 + 2 * 8)
    if not rsrc_rva:
        problems.append("no resources at all")
    else:
        base = rva2off(rsrc_rva)
        def count_entries(off):
            nname, nid = struct.unpack_from("<HH", d, off + 12)
            return nname + nid

        def walk(off, level, found):
            nname, nid = struct.unpack_from("<HH", d, off + 12)
            for i in range(nname + nid):
                name_or_id, child = struct.unpack_from("<II", d, off + 16 + i * 8)
                if not (child & 0x80000000):
                    continue
                sub = base + (child & 0x7FFFFFFF)
                if level == 0:
                    found[name_or_id] = count_entries(sub)
                else:
                    walk(sub, level + 1, found)
            return found

        res = walk(base, 0, {})
        for want, label in ((3, "RT_ICON"), (14, "RT_GROUP_ICON"),
                            (16, "RT_VERSION"), (24, "RT_MANIFEST")):
            if not res.get(want):
                problems.append("missing resource %s" % label)
        print("resources: %s" % ", ".join("%d=%d" % (k, v) for k, v in sorted(res.items())))

    # imports
    imp_rva = struct.unpack_from("<I", d, pe + 24 + 96 + 8)[0]
    imports = []
    if imp_rva:
        off = rva2off(imp_rva)
        while off and d[off:off + 20] != b"\0" * 20:
            namerva = struct.unpack_from("<I", d, off + 12)[0]
            if namerva == 0:
                break
            o = rva2off(namerva)
            e = d.index(b"\0", o)
            imports.append(d[o:e].decode())
            off += 20
    extra = [i for i in imports
             if i not in EXPECTED_IMPORTS and not i.startswith("api-ms-win-crt-")]
    if extra:
        problems.append("unexpected imports: %s" % ", ".join(extra))
    print("imports: %s" % ", ".join(imports))

    if b"P\x00a\x00n\x00d\x00o\x00r\x00a\x00 \x00L\x00a\x00u\x00n\x00c\x00h\x00e\x00r\x00" not in d:
        problems.append("no Pandora Launcher version string")
    print("size: %d bytes" % len(d))

    if problems:
        for p in problems:
            print("FAIL: %s" % p, file=sys.stderr)
        return 1
    print("OK: %s is a valid 32-bit Pandora Launcher GUI executable" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "PandoraLauncher.exe"))
