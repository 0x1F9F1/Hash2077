import sys
import mangle

from hash2077 import Hash2077, load_addresses

SEG_CODE = '0001' # .text (code)
SEG_RDATA = '0002' # .rdata (read-only data)
SEG_DATA = '0003' # .data (read-write data)

hasher = Hash2077()
addrs = load_addresses()

def segs(*seg_ids):
	return [ (adler, sha) for seg, off, adler, sha in addrs if seg in seg_ids ]

def adlers(*adler_ids):
	return [ (adler, sha) for seg, off, adler, sha in addrs if adler in adler_ids ]

def collide(hashes, *parts, num_threads=0, batch_size=2**26, lookup_size=2**30):
	hashes = list(set(hashes))
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
	inits = [ v[1:-11].replace('$initializer$', '') for v in hasher.known.values() if v.endswith('@@3P6AXXZEA') ]
	collide(segs(SEG_CODE), ['??__E', '??__F'], set(hasher.known.values()) | set(inits), '@@YAXXZ')

def unwinds():
	collide(segs(SEG_RDATA), [ '$unwind$' ] + [ f'$chain${i}$' for i in range(32) ], hasher.known.values())

def fnv1a_64(data, seed=0xCBF29CE484222325):
	h = seed
	for v in data:
		h = (0x100000001B3 * (h ^ v)) & 0xFFFFFFFFFFFFFFFF
	return h

def strlits():
	import csv
	with open('strings.csv', newline='', encoding='ascii', errors='replace') as f:
		strings = [ row['String Value'].encode('ascii', errors='replace') for row in csv.DictReader(f)]
	collide(segs(SEG_RDATA), [ mangle.strlit(v) for v in strings ])
	const_names = [ mangle.number((fnv1a_64(v) ^ 0x8000000000000000) - 0x8000000000000000) for v in strings ]
	collide(segs(SEG_CODE), '?Build@?$ConstNameBuilder@$0', const_names, '@@SA?AVCName@@QEBD@Z')
	collide(segs(SEG_DATA), '?s_registered@?$ConstNameBuilder@$0', const_names, '@@2_NA')

def vftable_hashes():
	hashes = { bytes.fromhex(v) for v in loadlines('vftables.txt') }
	return [ (adler, sha) for seg, off, adler, sha in addrs if sha in hashes ]

def vftables():
	names = set(v if v.isupper() else v.title() for v in loadlines('cp2077-dictionary-ndb.txt')) | set('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_@')
	collide(vftable_hashes(), '??_7', ['', 'C', 'I', 'S'], *rep(names, 3), loadlines('data/ns.txt'), '@@6B@')

def class_funcs():
	class_names = { v[4:-5] for v in hasher.known.values() if v.startswith('??_7') }
	class_names |= { f'?$DynArray@U{v}@@@red' for v in class_names } | { f'?$DynArray@V{v}@@@red' for v in class_names }
	collide(segs(SEG_CODE), '??0', class_names, '@@', list('AIQ'), 'EAA@XZ')
	collide(segs(SEG_CODE), '??1', class_names, '@@', list('AIQEMU'), 'EAA@XZ')
	collide(segs(SEG_CODE), '??_G', class_names, '@@', list('EMU'), 'EAAPEAXI@Z')
	collide(segs(SEG_CODE), '??_7', class_names, '@@6B@')
	collide(segs(SEG_CODE), '??$GetNativeTypeHash@', list('UV'), class_names, '@@@@YA_KXZ')
	collide(segs(SEG_DATA), '?nativeTypeHash@?1???$GetNativeTypeHash@', list('UV'), class_names, '@@@@YA_KXZ@4IA')
	collide(segs(SEG_DATA), '?$TSS0@?1???$GetNativeTypeHash@', list('UV'), class_names, '@@@@YA_KXZ@4HA')
	collide(segs(SEG_CODE), '??$GetTypeObject@', list('UV'), class_names, '@@@@YAPEBVIType@rtti@@XZ')
	collide(segs(SEG_DATA), '?rttiType@?1???$GetTypeObject@', list('UV'), class_names, '@@@@YAPEBVIType@rtti@@XZ@4PEBV12@EB')
	collide(segs(SEG_DATA), '?$TSS0@?1???$GetTypeObject@', list('UV'), class_names, '@@@@YAPEBVIType@rtti@@XZ@4HA')

hasher.save()