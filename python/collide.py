import sys
import json

from hash2077 import Hash2077
import mangle

SEG_CODE = '0001' # .text (code)
SEG_RDATA = '0002' # .rdata (read-only data)
SEG_DATA = '0003' # .data (read-write data)

with open('cyberpunk2077_addresses.json') as f:
    addresses = json.load(f)

all_hashes = []

for x in addresses['Addresses']:
    seg, off = x['offset'].split(':')
    all_hashes.append((seg, int(off, 16), int(x['hash']), bytes.fromhex(x['secondary hash'])))

hasher = Hash2077()

def segment(*seg_id):
    return [ (adler, sha) for seg, off, adler, sha in all_hashes if seg in seg_id ]

def collide(hashes, *parts, num_threads=0, batch_size=2**28, lookup_size=2**31):
    part_lists = []
    for part in parts:
        if isinstance(part, str):
            part_lists.append([part])
        else:
            part_lists.append(list(sorted(set(part))))

    return hasher.collide(hashes, part_lists, num_threads, batch_size, lookup_size)

def loadlines(path):
    with open(path, "r") as f:
        return f.read().splitlines()

def rep(value, n):
    return (value for _ in range(n))

def dynamic_ctor_dtors():
    collide(segment(SEG_CODE), ["??__E", "??__F"], hasher.known.values(), "@@YAXXZ")

def unwinds():
    collide(segment(SEG_RDATA), [ "$unwind$" ] + [ f"$chain${i}$" for i in range(16) ], hasher.known.values())

def strlits():
    import csv
    strings = []
    with open('strings.csv', newline='', encoding='ascii', errors='replace') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            value = row['String Value']
            strings.append(mangle.strlit(value.encode('ascii', errors='replace')))
    collide(segment(SEG_RDATA), strings)

def vftables():
    collide(segment(SEG_RDATA), "??_7", ['', 'C', 'I'], *rep(set(v.title() for v in loadlines('dictionary.txt')), 3), loadlines('data/ns.txt'), "@@6B@")

vftables()

hasher.save()