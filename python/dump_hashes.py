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
		addr_hashes[segs[seg] + off].add(adler)

target_hashes = set()

for addr in range(0x142B0B6C8, 0x142B0B9E8, 8):
	target = ida_xref.get_first_dref_from(addr)
	if target in addr_hashes:
		hashes = addr_hashes[target]
		if len(hashes) < 5:
			target_hashes |= hashes

print(','.join(str(v) for v in sorted(target_hashes)))