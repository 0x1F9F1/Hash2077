from hash2077 import load_known, load_addresses

addrs = load_addresses()
known = load_known()
segs = { k:ida_segment.get_segm_by_name(v).start_ea for k,v in [
	("0001", ".text"),
	("0002", ".idata"), # HACK: IDA creates a fake idata segment at the beginning of .rdata ("0002", ".rdata"),
	("0003", ".data")
]}

for seg, off, adler, sha in addrs:
	if (seg in segs) and (sha in known):
		addr = segs[seg] + off
		idaapi.set_name(addr, known[sha], idaapi.SN_FORCE | ida_name.SN_PUBLIC)
		# idc.set_cmt(addr, f'Adler32: {adler}, SHA256: {sha.hex().upper()}', 0)