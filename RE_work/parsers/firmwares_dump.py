#!/usr/bin/env python3
"""
firmwares_dump.py — READ-ONLY inspector for PandoraTool's Firmwares.db3.

The Firmwares.db3 is a local index/cache of firmware archives available on
Pandora's download server. This script lists, filters, and summarizes it.

Usage:
    python3 firmwares_dump.py [--db Firmwares.db3] [--brand X] [--limit N] [--stats]
"""
import argparse, os, sqlite3, sys

def fmt_size(n):
    if n is None: return "?"
    for u in ('B','KB','MB','GB','TB'):
        if n<1024 or u=='TB': return f"{n:.1f} {u}" if u!='B' else f"{n} B"
        n/=1024
    return f"{n} PB"

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--db',default='Firmwares.db3')
    ap.add_argument('--brand',help='Filter by path prefix brand (folder name after "2. Firmwares/")')
    ap.add_argument('--limit',type=int,default=20)
    ap.add_argument('--stats',action='store_true')
    ap.add_argument('--new',action='store_true',help='Show only "new" firmwares')
    args=ap.parse_args()

    if not os.path.exists(args.db):
        print(f'error: missing {args.db}',file=sys.stderr); sys.exit(1)
    c=sqlite3.connect(args.db); cur=c.cursor()
    ver=cur.execute('SELECT ver FROM Version').fetchone()[0]
    if args.stats:
        total=cur.execute('SELECT COUNT(*) FROM Files').fetchone()[0]
        active=cur.execute('SELECT COUNT(*) FROM Files WHERE active=1').fetchone()[0]
        new=cur.execute('SELECT COUNT(*) FROM Files WHERE new=1').fetchone()[0]
        total_hits=cur.execute('SELECT SUM(hits) FROM Files').fetchone()[0] or 0
        total_size=cur.execute('SELECT SUM(file_size) FROM Files').fetchone()[0] or 0
        print('=== Firmwares.db3 statistics ===')
        print(f'  DB version tag : {ver}')
        print(f'  Total entries  : {total}')
        print(f'  Active         : {active}')
        print(f'  Flagged "new"  : {new}')
        print(f'  Total hits     : {total_hits}')
        print(f'  Total size     : {fmt_size(total_size)}')
        print()
        print('Top 15 brands by number of entries:')
        for name,count in cur.execute("""
            SELECT substr(file_name, length('2. Firmwares/')+1,
                instr(substr(file_name, length('2. Firmwares/')+1),'/')-1) AS brand,
                   COUNT(*)
            FROM Files
            WHERE file_name LIKE '2. Firmwares/%'
            GROUP BY brand ORDER BY COUNT(*) DESC LIMIT 15"""):
            print(f'  {name}: {count}')
        print()
        print('Top 15 brands by total firmware size:')
        for name,sz in cur.execute("""
            SELECT substr(file_name, length('2. Firmwares/')+1,
                instr(substr(file_name, length('2. Firmwares/')+1),'/')-1) AS brand,
                   SUM(file_size)
            FROM Files
            WHERE file_name LIKE '2. Firmwares/%'
            GROUP BY brand ORDER BY SUM(file_size) DESC LIMIT 15"""):
            print(f'  {name}: {fmt_size(sz)}')
        return

    q="SELECT file_name,file_size,hits,active,new,created_at,updated_at FROM Files WHERE 1=1"
    p=[]
    if args.brand:
        q+=" AND file_name LIKE ?"; p.append(f'%/{args.brand}/%')
    if args.new:
        q+=" AND new=1"
    q+=" ORDER BY updated_at DESC LIMIT ?"; p.append(args.limit)
    print(f'DB version: {ver}')
    print(f'{"Size":>10}  {"Hits":>5}  {"Updated":<19}  A N  Path')
    print('-'*100)
    for fn,sz,hits,active,new,ca,ua in cur.execute(q,p):
        flag=('Y' if active else '-')+(' ')+('Y' if new else '-')
        # trim leading "2. Firmwares/"
        short=fn.replace('2. Firmwares/','',1) if fn.startswith('2. Firmwares/') else fn
        print(f'{fmt_size(sz):>10}  {hits:>5}  {ua or ""[:19]:<19}  {flag}  {short}')

if __name__=='__main__': main()
