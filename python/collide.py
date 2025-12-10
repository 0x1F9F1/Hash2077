import sys
import mangle

from hash2077 import Hash2077, load_addresses

SEG_CODE = '0001' # .text (code)
SEG_RDATA = '0002' # .rdata (read-only data)
SEG_DATA = '0003' # .data (read-write data)

hasher = Hash2077()
addrs = load_addresses()

def segs(*seg_id):
	return [ (adler, sha) for seg, off, adler, sha in addrs if seg in seg_id ]

def adlers(*adler_ids):
	return [ (adler, sha) for seg, off, adler, sha in addrs if adler in adler_ids ]

def collide(hashes, *parts, num_threads=0, batch_size=2**28, lookup_size=2**31):
	part_lists = []
	for part in parts:
		if isinstance(part, str):
			part_lists.append([part])
		else:
			part_lists.append(list(sorted(set(part))))
	return hasher.collide(hashes, part_lists, num_threads, batch_size, lookup_size)

def loadlines(path):
	with open(path, 'r') as f:
		return f.read().splitlines()

def rep(value, n):
	return (value for _ in range(n))

def dynamic_ctor_dtors():
	collide(segs(SEG_CODE), ['??__E', '??__F'], hasher.known.values(), '@@YAXXZ')

def unwinds():
	collide(segs(SEG_RDATA), [ '$unwind$' ] + [ f'$chain${i}$' for i in range(32) ], hasher.known.values())

def strlits():
	import csv
	with open('strings.csv', newline='', encoding='ascii', errors='replace') as f:
		strings = [mangle.strlit(row['String Value'].encode('ascii', errors='replace')) for row in csv.DictReader(f)]
	collide(segs(SEG_RDATA), strings)

def vftables():
	names = set(v if v.isupper() else v.title() for v in loadlines('cp2077-dictionary-ndb.txt')) | set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_@")
	collide(segs(SEG_RDATA), '??_7', ['', 'C', 'I', 'S'], *rep(names, 3), loadlines('data/ns.txt'), '@@6B@')

def ctor_dtors():
	class_names = [ v[4:-5] for v in hasher.known.values() if v.startswith('??_7') ]
	collide(segs(SEG_CODE), ['??0', '??1'], class_names, '@@', list('AIQEMU'), 'EAA@XZ')
	collide(segs(SEG_CODE), '??_G', class_names, '@@', list('EMU'), 'EAAPEAXI@Z')

collide(segs(SEG_RDATA), '__real@', *rep(list('0123456789abcdef'), 8))

hasher.save()