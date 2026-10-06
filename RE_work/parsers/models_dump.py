#!/usr/bin/env python3
"""
models_dump.py — READ-ONLY inspector for PandoraTool's models.mdb (SQLite).

Does NOT decrypt payloads; only inspects metadata (brand/model/platform/cpu/
payload length/flag byte and catalog timestamp). For education/forensics.

Usage:
    python3 models_dump.py [--db models.mdb] [--platform X] [--brand X] [--limit N] [--stats]
"""
import argparse, os, sqlite3, sys
from datetime import datetime, timezone

def ts(secs):
    if secs is None: return '?'
    try: return datetime.fromtimestamp(int(secs), tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    except: return str(secs)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--db',default='models.mdb')
    ap.add_argument('--platform')
    ap.add_argument('--brand')
    ap.add_argument('--model')
    ap.add_argument('--limit',type=int,default=20)
    ap.add_argument('--stats',action='store_true')
    args=ap.parse_args()

    if not os.path.exists(args.db):
        print(f'error: missing {args.db}',file=sys.stderr); sys.exit(1)
    c=sqlite3.connect(args.db); cur=c.cursor()

    if args.stats:
        print('=== models.mdb metadata ===')
        for k,v in cur.execute('SELECT key,value FROM db_meta'):
            extra=''
            if k.endswith('_at') or k=='created_at':
                try: extra='  ('+ts(v)+')'
                except: pass
            print(f'  {k:25s} = {v}{extra}')
        print()
        print('=== platform coverage ===')
        for plat,n in cur.execute('SELECT platform,COUNT(*) FROM models GROUP BY platform ORDER BY COUNT(*) DESC'):
            print(f'  {plat:12s} {n}')
        print()
        print('=== catalogs (PNDCAT01 encrypted) ===')
        for plat,data,mtime in cur.execute('SELECT platform,data,json_mtime FROM catalogs'):
            print(f'  {plat:12s} size={len(data):>6} bytes  mtime={ts(mtime)}')
        print()
        print('=== top 20 brands overall ===')
        for b,n in cur.execute('SELECT brand,COUNT(*) FROM models GROUP BY brand ORDER BY COUNT(*) DESC LIMIT 20'):
            print(f'  {b:20s} {n}')
        print()
        print('=== payload length distribution ===')
        for ln,n in cur.execute('SELECT length(payload),COUNT(*) FROM models GROUP BY length(payload) ORDER BY COUNT(*) DESC LIMIT 15'):
            print(f'  {ln} bytes: {n}')
        return

    q="SELECT id,brand,name,code_name,platform,cpu,length(payload),hex(substr(payload,1,10)),updated_at FROM models WHERE 1=1"
    p=[]
    if args.platform:
        q+=" AND platform=?"; p.append(args.platform.upper())
    if args.brand:
        q+=" AND LOWER(brand) LIKE ?"; p.append(f"%{args.brand.lower()}%")
    if args.model:
        q+=" AND (LOWER(name) LIKE ? OR LOWER(code_name) LIKE ?)"; p += [f"%{args.model.lower()}%"]*2
    q+=" ORDER BY id LIMIT ?"; p.append(args.limit)

    print(f'{"id":>5} {"plat":<10} {"brand":<15} {"model":<25} {"codename":<20} {"cpu":<20} {"plen":>5}  flag  updated')
    print('-'*130)
    for iid,br,nm,cod,plat,cpu,plen,hdr,upd in cur.execute(q,p):
        # hdr is hex like '504E444D4F44454C313E' -> last byte is the flag byte (payload type)
        flag_byte = hdr[-2:] if hdr else '??'
        print(f'{iid:>5} {plat:<10} {(br or "")[:15]:<15} {(nm or "")[:25]:<25} {(cod or "")[:20]:<20} {(cpu or "")[:20]:<20} {plen or 0:>5}  0x{flag_byte}  {ts(upd)}')

if __name__=='__main__': main()
