import sys
import json

from hash2077 import Hash2077

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

def collide(segments, *parts, num_threads=0, prefix_size=2**28, suffix_size=2**30):
    hashes = [ (adler, sha) for seg, off, adler, sha in all_hashes if ((not segments) or (seg in segments)) ]
    return hasher.collide(hashes, parts, num_threads, prefix_size, suffix_size)

def loadlines(path):
    with open(path, "r") as f:
        return f.read().splitlines()

def rep(value, n):
    return (value for _ in range(n))

def dynamic_ctor_dtors():
    collide({ SEG_CODE }, ["??__E", "??__F"], hasher.known.values(), "@@YAXXZ")

def unwinds():
    collide({ SEG_RDATA }, [ "$unwind$" ] + [ f"$chain${i}$" for i in range(16) ], hasher.known.values())

def lns():
    collide({ SEG_CODE }, [ f'$LN{i}' for i in range(9999) ])

def reals32():
    collide({ SEG_RDATA }, "__real@", *rep(list("0123456789abcdef"), 8))

reals32()

hasher.save()