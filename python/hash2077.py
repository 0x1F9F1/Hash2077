import os
import json
from ctypes import *
from pathlib import Path
from hashlib import sha256

class _Collider(Structure):
	pass

c_collider = POINTER(_Collider)

_script_path = Path(__file__).resolve().parent

def load_known(path=None):
	known = {}
	with open(path or (_script_path / 'data/known.txt'), 'r') as f:
		for line in f.read().splitlines():
			sha, name = line.split(' ')
			sha = bytes.fromhex(sha)
			known[sha] = name
	return known

def load_addresses(path=None):
	addrs = []
	with open(path or (_script_path / 'cyberpunk2077_addresses.json')) as f:
		data = json.load(f)
		for x in data['Addresses']:
			seg, off = x['offset'].split(':')
			addrs.append((seg, int(off, 16), int(x['hash']), bytes.fromhex(x['secondary hash'])))
	return addrs

class Hash2077:
	def __init__(self, dll_path=None):
		if dll_path is None:
			dll_path = _script_path / ('hash2077.dll' if os.name == 'nt' else 'libhash2077.so')

		self.lib = cdll.LoadLibrary(dll_path)

		def load(name, restype, *argtypes):
			func = self.lib[name]
			func.restype = restype
			func.argtypes = argtypes
			return func

		self.Collider_Create = load('Collider_Create', c_collider)
		self.Collider_Destroy = load('Collider_Destroy', None, c_collider)
		self.Collider_AddHash = load('Collider_AddHash', None, c_collider, c_uint32, c_char_p)
		self.Collider_NextPart = load('Collider_NextPart', None, c_collider)
		self.Collider_AddString = load('Collider_AddString', None, c_collider, c_char_p)
		self.Collider_Run = load('Collider_Run', c_size_t, c_collider, c_size_t, c_size_t, c_size_t)
		self.Collider_GetResults = load('Collider_GetResults', None, c_collider, POINTER(c_char_p))
		self.known = load_known()

	def save(self):
		self._save_known(_script_path / 'data/known.txt')

	def _save_known(self, path):
		with open(path, 'w') as f:
			for sha, name in sorted(self.known.items(), key=lambda x:x[1]):
				f.write(f'{sha.hex().upper()} {name}\n')

	def collide(self, hashes, parts, num_threads, batch_size, lookup_size):
		assert batch_size <= 2**32
		assert lookup_size <= 2**32

		collider = self.Collider_Create()
		results = []

		for adler, sha in hashes:
			if sha not in self.known:
				self.Collider_AddHash(collider, adler, sha)

		for part in parts:
			self.Collider_NextPart(collider)
			for value in part:
				self.Collider_AddString(collider, value.encode('ascii'))

		num_results = self.Collider_Run(collider, num_threads, batch_size, lookup_size)
		raw_results = (c_char_p * num_results)()
		self.Collider_GetResults(collider, raw_results)

		results.extend(x.decode('ascii') for x in raw_results)
		self.Collider_Destroy(collider)

		for result in results:
			sha = sha256(result.encode('ascii')).digest()
			self.known[sha] = result

		return results
