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

	inits = [ '?' + v[5:-5].replace('@', '$initializer$@', count=1) + '3P6AXXZEA' for v in hasher.known.values() if v.startswith('??__E') ]
	collide(segs(SEG_RDATA), inits)

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
		byte_strings = { row['String Value'].encode('ascii', errors='replace') for row in csv.DictReader(f) }

	collide(segs(SEG_RDATA), [ mangle.strlit(v) for v in byte_strings ])

	string_hashes = { mangle.number((fnv1a_64(v) ^ 0x8000000000000000) - 0x8000000000000000) for v in byte_strings }
	collide(segs(SEG_CODE), '?Build@?$ConstNameBuilder@$0', string_hashes, '@@SA?AVCName@@QEBD@Z')
	collide(segs(SEG_DATA), '?s_registered@?$ConstNameBuilder@$0', string_hashes, '@@2_NA')

	strings = { v.decode('ascii') for v in byte_strings }
	collide(segs(SEG_CODE), '??0', strings, '@@', list('AIQ'), 'EAA@XZ')
	collide(segs(SEG_CODE), '??1', strings, '@@', list('AIQEMU'), 'EAA@XZ')
	collide(segs(SEG_CODE), '??_G', strings, '@@', list('EMU'), 'EAAPEAXI@Z')
	collide(segs(SEG_RDATA), '??_7', strings, '@@6B@')

def vftable_hashes():
	hashes = { bytes.fromhex(v) for v in loadlines('vftables.txt') }
	return [ (adler, sha) for seg, off, adler, sha in addrs if sha in hashes ]

def vftables():
	names = set(v if v.isupper() else v.title() for v in loadlines('cp2077-dictionary-ndb.txt')) | set('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_@')
	collide(vftable_hashes(), '??_7', ['', 'C', 'I', 'S'], *rep(names, 3), loadlines('data/ns.txt'), '@@6B@')

def get_class_names():
	class_names = { v[4:-5] for v in hasher.known.values() if v.startswith('??_7') }
	class_names |= { v[22:-10] for v in hasher.known.values() if v.startswith('??$GetNativeTypeHash@') }
	class_names |= { v[16:-7] for v in class_names if v.startswith('?$TNativeClass@') }
	class_names |= { v[21:-7] for v in class_names if v.startswith('?$TNativeClassNoCopy@') }
	return class_names

def class_funcs(class_names):
	extra_names = set()
	extra_names |= { f'?$DynArray@U{v}@@@red' for v in class_names } | { f'?$DynArray@V{v}@@@red' for v in class_names }
	extra_names |= { f'?$THandle@U{v}@@' for v in class_names } | { f'?$THandle@V{v}@@' for v in class_names }
	extra_names |= { f'?$TNativeClass@U{v}@@@rtti' for v in class_names } | { f'?$TNativeClass@V{v}@@@rtti' for v in class_names }
	extra_names |= { f'?$TNativeClassNoCopy@U{v}@@@rtti' for v in class_names } | { f'?$TNativeClassNoCopy@V{v}@@@rtti' for v in class_names }
	class_names |= extra_names

	collide(segs(SEG_CODE), '??0', class_names, '@@', list('AIQ'), [
		'EAA@XZ', # Default
		'EAA@AEBU0@@Z', # Copy
		'EAA@AEBU01@@Z', # Copy
		'EAA@AEBU012@@Z', # Copy
		'EAA@AEBU0123@@Z', # Copy
		'EAA@$$QEAU0@@Z', # Move
		'EAA@$$QEAU01@@Z', # Move
		'EAA@$$QEAU012@@Z', # Move
		'EAA@$$QEAU0123@@Z', # Move
	])
	collide(segs(SEG_CODE), '??1', class_names, '@@', list('AIQEMU'), 'EAA@XZ')
	collide(segs(SEG_CODE), '??_G', class_names, '@@', list('EMU'), 'EAAPEAXI@Z')
	collide(segs(SEG_RDATA), '??_7', class_names, '@@6B@')

	# Based on https://github.com/Mozz3d/CyberpunkGhidraUtils/blob/main/CyberpunkRTTIDeriver.py
	collide(segs(SEG_CODE), ['?OnConstruct@', '?OnDestruct@'], class_names, '@@EEBAXPEAX@Z')
	collide(segs(SEG_CODE), '?RegisterProperties@', class_names, '@@SAXPEAVClassType@rtti@@@Z')
	collide(segs(SEG_CODE), ['?GetClass@', '?GetNativeClass@'], class_names, '@@UEBAPEBVClassType@rtti@@XZ')
	collide(segs(SEG_CODE), '?OnPreSave@', class_names, '@@UEAAXAEBUPreSaveContext@@@Z')
	collide(segs(SEG_CODE), '?OnPostLoad@', class_names, '@@UEAAXAEBUPostLoadContext@@@Z')
	collide(segs(SEG_CODE), '?OnPropertyPreChange@', class_names, '@@UEAA_NAEBVAccessPath@rtti@@AEAV?$SharedStorage@$$CBVValueHolder@rtti@@VAtomicSharedStorage@internal@red@@X@red@@@Z')
	collide(segs(SEG_CODE), '?OnPropertyPostChange@', class_names, '@@UEAAXAEBVAccessPath@rtti@@AEBV?$SharedStorage@VValueHolder@rtti@@VAtomicSharedStorage@internal@red@@X@red@@1@Z')
	collide(segs(SEG_CODE), '?OnPropertyMissing@', class_names, '@@UEAA_NVCName@@AEBVVariant@rtti@@@Z')
	collide(segs(SEG_CODE), '?OnPropertyTypeMismatch@', class_names, '@@UEAA_NVCName@@PEBVProperty@rtti@@AEBVVariant@4@@Z')
	collide(segs(SEG_CODE), '?GetFriendlyName@', class_names, '@@UEBA?AVString@red@@XZ')
	collide(segs(SEG_CODE), '?GetPath@', class_names, '@@UEBA?AVResourcePath@res@@XZ')
	collide(segs(SEG_DATA), '?sm_classDesc@', class_names, '@@0PEBVClassType@rtti@@EB')

	collide(segs(SEG_CODE), '??$GetNativeTypeHash@', list('UV'), class_names, '@@@@YA_KXZ')
	collide(segs(SEG_DATA), '?nativeTypeHash@?1???$GetNativeTypeHash@', list('UV'), class_names, '@@@@YA_KXZ@4IA')
	collide(segs(SEG_DATA), '?$TSS0@?1???$GetNativeTypeHash@', list('UV'), class_names, '@@@@YA_KXZ@4HA')
	collide(segs(SEG_CODE), '??$GetTypeObject@', list('UV'), class_names, '@@@@YAPEBVIType@rtti@@XZ')
	collide(segs(SEG_DATA), '?rttiType@?1???$GetTypeObject@', list('UV'), class_names, '@@@@YAPEBVIType@rtti@@XZ@4PEBV12@EB')
	collide(segs(SEG_DATA), '?$TSS0@?1???$GetTypeObject@', list('UV'), class_names, '@@@@YAPEBVIType@rtti@@XZ@4HA')

def class_funcs_1():
	class_funcs(get_class_names())

def class_funcs_2():
	import json
	import re
	with open('classes.json') as f:
		data = json.load(f)
	namespaces = { ''.join(reversed(v.split('@'))).lower():v for v in loadlines('data/ns.txt') }
	pat = re.compile("[A-Z]")
	skipped = set()
	class_names = set()
	for v in data:
		name = v['b']
		ns = ''
		m = pat.search(name)
		if m is not None:
			start = m.start()
			ns = name[:start]
			if ns in namespaces:
				ns = namespaces[ns]
			else:
				skipped.add(ns)
			name = name[start:]
		class_names.add(name + ns)
	class_funcs(class_names)

def static_locals():
	collide(segs(SEG_DATA), '?$TSS', [str(x) for x in range(16)], '@?', [mangle.number(x) for x in range(1000)], '?', hasher.known.values(), '@4HA')

def member_funcs():
	names = set(v if v.isupper() else v.title() for v in loadlines('cp2077-dictionary-ndb.txt')) | set('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_@')
	mfunc_types = {'CAXXZ', 'KAXXZ', 'SAXXZ'} # static void()
	return_types = [
		'X', # void
		'_N', # bool
		'_J', # i64
		'_K', # u64
		'H', # i32
		'I', # u32
	]
	for access in 'AIQEMU':
		for cv in 'AB':
			for ty in return_types:
				mfunc_types.add(f'{access}E{cv}A{ty}XZ')
	collide(segs(SEG_CODE), '?', *rep(names, 2), '@', get_class_names(), '@@', mfunc_types)

hasher.save()