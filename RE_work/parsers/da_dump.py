#!/usr/bin/env python3
"""
da_dump.py — inspect MediaTek/Spreadtrum download agent & preloader payloads in Data/.

Does not decrypt anything; only prints file header, inner tag (ASCII name),
and size. For educational identification of which loader targets which chip.
"""
import os, struct, sys, glob

# Map of known tag prefix -> chip / purpose
TAG_MAP = [
    ('MTK_DOWNLOAD_AGENT', 'MediaTek Download Agent (generic, encrypted or plain)'),
    ('MTK_AllInOne_DA.bin','MediaTek All-in-One DA (generic)'),
    ('SC7731E',            'Spreadtrum/Unisoc SC7731E FDL (primary/secondary loader)'),
    ('SC-53F',             'Spreadtrum SC-53F DA (for Samsung SPRD-based models)'),
]

def read_hdr(path, n=64):
    with open(path,'rb') as f: return f.read(n)

def find_ascii_tag(blob):
    # Take all runs of 4+ printable ASCII chars within first 64 bytes
    best = (0, b'')
    cur = b''
    for b in blob:
        if 32 <= b < 127:
            cur += bytes([b])
        else:
            if len(cur) > len(best[1]):
                best = (len(cur), cur)
            cur = b''
    if len(cur) > len(best[1]): best = (len(cur), cur)
    return best[1].decode('latin-1','replace') if best[1] else ''

def is_arm_vector(blob):
    # ARM reset vector: first 3 bytes often are 0x?? 0x00 0x00 0xEA (B opcode) or 0x00 0x00 0xA0 E1 (NOP) or similar
    if blob[3] == 0xEA: return 'ARM B (reset vector)'
    if blob[0:4]==b'\x1F\x8B\x08\x00': return 'GZIP compressed'
    if blob[0:4]==b'\x7fELF': return 'ELF executable'
    if blob[0:2]==b'MZ': return 'PE/Windows EXE'
    return None

def inspect_dir(dirpath):
    rows=[]
    for root,_,files in os.walk(dirpath):
        for fn in files:
            p=os.path.join(root,fn)
            sz=os.path.getsize(p)
            h=read_hdr(p)
            tag=find_ascii_tag(h)
            arm=is_arm_vector(h)
            kind='?'
            for prefix,desc in TAG_MAP:
                if tag.startswith(prefix): kind=desc; break
            if fn.endswith('.crp'): kind=(kind+' ' if kind!='?' else '')+'(encrypted container .crp)'
            if arm: kind=(kind+' · '+arm) if kind!='?' else arm
            rows.append((p, sz, tag, kind))
    return rows

def main():
    rows=inspect_dir('Data')
    print(f"{'File':40s} {'Size':>10}  Tag                         Kind")
    print('-'*120)
    for p,sz,tag,kind in sorted(rows):
        short=p.replace('Data/','')
        print(f'{short:40s} {sz:>10}  {tag[:28]:28s} {kind}')

if __name__=='__main__': main()
