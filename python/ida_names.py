from hash2077 import load_known, load_addresses

addrs = load_addresses()
known = load_known()
segs = { k:ida_segment.get_segm_by_name(v).start_ea for k,v in [
	("0001", ".text"),
	("0002", ".idata"), # HACK: IDA creates a fake idata segment at the beginning of .rdata ("0002", ".rdata"),
	("0003", ".data")
]}

vftables = set()

for seg, off, adler, sha in addrs:
	if seg in segs:
		addr = segs[seg] + off
		idc.set_cmt(addr, f'Adler32: {adler}, SHA256: {sha.hex().upper()}', 0)

		if seg == '0002':
			dref = ida_xref.get_first_dref_from(addr)

			if ida_bytes.is_func(ida_bytes.get_flags(dref)):
				vftables.add(sha)

		if sha in known:
			idaapi.set_name(addr, known[sha], idaapi.SN_FORCE | ida_name.SN_PUBLIC)

with open('vftables.txt', 'w') as f:
	f.write('\n'.join(sorted(v.hex().upper() for v in vftables)))