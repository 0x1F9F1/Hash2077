from hash2077 import load_known, load_addresses
from collections import defaultdict

addrs = load_addresses()
known = load_known()
segs = { k:ida_segment.get_segm_by_name(v).start_ea for k,v in [
	("0001", ".text"),
	("0002", ".idata"), # HACK: IDA creates a fake idata segment at the beginning of .rdata ("0002", ".rdata"),
	("0003", ".data")
]}

addr_hashes = defaultdict(set)

for seg, off, adler, sha in addrs:
	if seg in segs:
		addr_hashes[segs[seg] + off].add((adler, sha, known.get(sha, None)))

def set_anterior_comment(ea, lines):
	for i in range(500):
		index = ida_lines.E_PREV + i
		if i < len(lines):
			ida_lines.update_extra_cmt(ea, index, lines[i])
		else:
			ida_lines.del_extra_cmt(ea, index)

for addr, hashes in addr_hashes.items():
	n = len(hashes)

	names = [ name for adler, sha, name in hashes if name is not None ]
	lines = []

	if n <= 10:
		for adler, sha, name in hashes:
			line = sha.hex().upper()
			if name is not None:
				line += f' {name}'
			lines.append(line)
	else:
		lines.append(f'{n} Hashes')
		lines.append(' '.join(sha.hex().upper()[:16] for adler, sha, name in hashes))

	if names:
		name = names[0]
		if len(names) > 1:
			name = f'MAYBE_{name}'
		idaapi.set_name(addr, name, idaapi.SN_FORCE | ida_name.SN_PUBLIC)

	set_anterior_comment(addr, lines)