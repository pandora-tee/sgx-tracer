#!/usr/bin/python3
import argparse
import ctypes
import json
from enum import Enum

###########################################################################

class MrEnclaveEcreate(ctypes.LittleEndianStructure):
	_pack_ = 1
	_fields_ = [
        	('tag', ctypes.c_uint64),
        	('ssaframesize', ctypes.c_uint32),
        	('size', ctypes.c_uint64),
        	('rsvd', ctypes.c_uint8 * 44),
	]

	def __repr__(self):
		return f'ECREATE size={self.size}; ssaframesize={self.ssaframesize}'

	def __init__(self, ssaframesize, size):
		self.tag = 0x0045544145524345 # "ECREATE\0"
		self.ssaframesize = ssaframesize
		self.size = size
assert(ctypes.sizeof(MrEnclaveEcreate) == 64)

class MrEnclaveEadd(ctypes.LittleEndianStructure):
	_pack_ = 1
	_fields_ = [
        	('tag', ctypes.c_uint64),
        	('offset', ctypes.c_uint64),
        	('secinfo_flags', ctypes.c_uint64),
        	('secinfo_rsvd', ctypes.c_uint8 * 40),
	]

	def __repr__(self):
		t = PageTypes(self.secinfo_flags >> 8)
		r = 'R' if self.secinfo_flags & (0x1 << 0) else '-'
		w = 'W' if self.secinfo_flags & (0x1 << 1) else '-'
		x = 'X' if self.secinfo_flags & (0x1 << 2) else '-'
		return f'EADD    {self.offset:04x}; {t}; {r}{w}{x}'

	def __init__(self, offset, perms, page_type):
		self.tag = 0x0000000044444145 # "EADD\0\0\0\0"
		self.offset = offset
		flags = page_type.value << 8
		if 'R' in perms:
			flags |= 0x1
		if 'W' in perms:
			flags |= 0x2
		if 'X' in perms:
			flags |= 0x4
		self.secinfo_flags = flags
assert(ctypes.sizeof(MrEnclaveEadd) == 64)

class MrEnclaveEextend(ctypes.LittleEndianStructure):
	_pack_ = 1
	_fields_ = [
        	('tag', ctypes.c_uint64),
        	('offset', ctypes.c_uint64),
        	('zeroes', ctypes.c_uint8 * 48),
        	('blob', ctypes.c_uint8 * 256),
	]

	def __repr__(self):
		data = ''.join(f'{b:x}' for b in self.blob)
		short = 'zeroes' if all(b == 0 for b in self.blob) else 'data' 
		return f'EEXTEND {self.offset:04x}:{self.offset+255:04x} {short}'

	def __init__(self, offset, blob):
		self.tag = 0x00444E4554584545 # "EEXTEND\0"
		self.offset = offset
		for i in range(0,256):
			self.blob[i] = blob[i]
assert(ctypes.sizeof(MrEnclaveEextend) == 5*64)

class PageTypes(Enum):
	PT_SECS = 0
	PT_TCS  = 1
	PT_REG  = 2

class JsonTypes(Enum):
	JSON_TYPE_SECS = 0
	JSON_TYPE_TCS  = 1
	JSON_TYPE_PAGE = 2

###########################################################################

parser = argparse.ArgumentParser()
parser.add_argument('dumpfile')
parser.add_argument('jsonfile')
args = parser.parse_args()

sgxsfile = f'{args.dumpfile}.sgxs'
d = open(args.dumpfile, 'rb')
j = open(args.jsonfile, 'r')
json_arr = json.load(j)
o = open(sgxsfile, 'wb')
print(f'.. writing to {sgxsfile}')

def sgxs_append(struct):
	#if type(struct) != MrEnclaveEextend:
	print(f'.. appending {struct}')
	o.write(bytes(struct))

# First emit the ecreate header based on the dumped SECS
json_secs = json_arr[0]
assert(JsonTypes(json_secs['entry_type']) == JsonTypes.JSON_TYPE_SECS)
mec = MrEnclaveEcreate(json_secs['ssa_frame_size'], json_secs['size'])
sgxs_append(mec)

# Now sort all JSON_TYPE_PAGE entries with ascending offset to ensure we
# produce a canonical sgxs stream, even if the original loader (e.g.,
# Gramine) did not.
json_pages = list(filter(lambda p: JsonTypes(p['entry_type']) == JsonTypes.JSON_TYPE_PAGE, json_arr))
pages_sorted = sorted(json_pages, key=lambda x : x['offset'])
if json_pages != pages_sorted:
	print('WARNING: non-canonical SGX loader detected; continuing with sorted page offsets')

for e in pages_sorted:
	for i in range(0, e['length'], 4096):
		mea = MrEnclaveEadd(e['offset'] + i, e['permissions'], PageTypes[(e['type'])])
		sgxs_append(mea)
		if e['measured'] == 1:
			for j in range(0, 4096, 256):
				offset = e['offset'] + i + j
				d.seek(offset, 0)
				blob = d.read(256)
				mee = MrEnclaveEextend(offset, blob)
				sgxs_append(mee)

# Create a copied dump file with all unmeasured areas forced to zero (to
# facilitate comparison with sgxs-created dumps for validation)
dz = open(f'{args.dumpfile}.zero', 'wb')
for e in pages_sorted:
	offset = e['offset']
	length = e['length']
	if e['measured'] == 1:
		d.seek(offset, 0)
		blob = d.read(length)
	else:
		blob = b'\0' * length
	dz.seek(offset, 0)
	dz.write(blob)

