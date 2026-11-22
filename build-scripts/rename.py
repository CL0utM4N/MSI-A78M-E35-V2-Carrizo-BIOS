"""Rename board strings A68HM-E33 V2 -> A78M-E35 V2 (and PCB version 9.0 -> 6.0) inside compressed DXE modules.

For each target FFS: decompress its Tiano COMPRESSION section, apply exact replacements (each must match the
expected number of times), re-encode with tianocomp, verify round-trip, rebuild section/FFS headers and
checksums, then re-lay the DXE volume (pad absorbs size changes; the DMI ROM hole stays at its fixed offset;
the execute-in-place S3Restore image is rebased if it moves).
"""
import sys, os, struct, hashlib, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fvlib import files, fv_header, sections, ffs_header_checksum_ok, ffs_data_checksum_ok
from build import fix_ffs_checksums, make_pad, place_and_rebase, is_xip_flash_image
import efidecomp, tianocomp

src, out_p = sys.argv[1:3]
img = open(src, 'rb').read()
DXE = 0x190000
OLD, NEW = b'A68HM-E33 V2 (MS-7721)', b'A78M-E35 V2 (MS-7721)'
EDITS = {
    'B1DA0ADF-4F77-4070-A88E-BFFE1C60529A': ('AMITSE', [(OLD + b'\0\0', NEW + b'\0\0\0', 1)]),
    '6F017C3F-CEA2-4643-BB0D-2C1A863B2B18': ('OEMDMI', [(OLD + b'\0\x009.0\0', NEW + b'\0\0\x006.0\0', 1)]),
    'DAF4BF89-CE71-4917-B522-C89D32FBC59F': ('SMBIOS template', [(b'\0' + OLD + b'\0', b'\0' + NEW + b'\0', 1),
                                                               (b'\x009.0\x00To ', b'\x006.0\x00To ', 3)]),
}


def sec_hdr(size, typ):
    assert size < 0xFFFFFF
    return size.to_bytes(3, 'little') + bytes([typ])


def rebuild_ffs(raw, name, edits):
    body = raw[0x18:]
    out = bytearray()
    secs = sections(body)
    # the original FFS must be exactly its sections (no trailing bytes) for this rebuild to be faithful
    last = secs[-1]
    assert last['off'] + last['size'] == len(body), f'{name}: unexpected trailing bytes in FFS'
    for idx, s in enumerate(secs):
        if idx > 0:
            while len(out) % 4:
                out += b'\0'
        sb = body[s['off']:s['off'] + s['size']]
        if s['type'] != 0x01:
            out += sb
        else:
            ulen, ct = struct.unpack_from('<IB', sb, s['hdr'])
            assert ct == 1
            comp = sb[s['hdr'] + 5:]
            dec = efidecomp.decompress(comp, 5)
            assert len(dec) == ulen
            new = dec
            for a, b, cnt in edits:
                n = new.count(a)
                assert n == cnt, f'{name}: expected {cnt}x {a!r}, found {n}'
                new = new.replace(a, b)
            # inner sections: fix the size of any section whose length changed
            if len(new) != len(dec):
                inner = sections(dec)
                assert len(inner) == 1, f'{name}: length change with multiple inner sections'
                i0 = inner[0]
                trail = dec[i0['size']:]
                assert i0['hdr'] == 4 and i0['off'] == 0 and len(trail) < 4 and trail.count(0) == len(trail), \
                    f'{name}: unexpected inner layout size {i0["size"]:#x} of {len(dec):#x}'
                delta = len(new) - len(dec)
                newsize = i0['size'] + delta
                core = sec_hdr(newsize, dec[3]) + new[4:newsize]
                new = core + b'\0' * ((-len(core)) % 4)   # same 4-byte padding rule as the original stream
                print(f'  {name}: inner section {i0["size"]:#x} -> {newsize:#x}, stream padding {len(trail)} -> {(-len(core)) % 4}')
            enc = tianocomp.compress(new)
            assert efidecomp.decompress(enc, 5) == new, f'{name}: round-trip failed'
            payload = struct.pack('<IB', len(new), 1) + enc
            out += sec_hdr(4 + len(payload), 0x01) + payload
            print(f'  {name}: uncompressed {ulen:#x} -> {len(new):#x}, compressed {len(comp):#x} -> {len(enc):#x}')
    newraw = bytearray(raw[:0x18]) + out
    return fix_ffs_checksums(bytes(newraw))


fl, fv_end, _ = files(img, DXE)
pad = [f for f in fl if f['type'] == 0xF0][0]
tail = fl[fl.index(pad) + 1:]
head = fl[:fl.index(pad)]
assert [f['guid'] for f in tail] == ['05CA01FC-0FC1-11DC-9011-00173153EBA8']
log = []
pos = head[0]['off']
blob = bytearray()
for f in head:
    raw = f['raw']
    if f['guid'] in EDITS:
        name, edits = EDITS[f['guid']]
        raw = rebuild_ffs(raw, name, edits)
    xip = is_xip_flash_image(f['raw'], f['off'], len(img))
    if xip:
        raw = place_and_rebase(raw, pos, len(img), log, f['name'] or f['guid'])
    blob += raw
    pos += len(raw)
    padlen = (-pos) % 8
    blob += b'\xff' * padlen
    pos += padlen
pad_size = tail[0]['off'] - pos
assert pad_size >= 0x18, f'DXE volume overflow by {0x18 - pad_size:#x}'
blob += make_pad(pad['raw'], pad_size)
new = bytearray(img)
new[head[0]['off']:tail[0]['off']] = blob
new = bytes(new)
print('\n'.join(log))
print(f'  DXE pad {pad["size"]:#x} -> {pad_size:#x}')
open(out_p, 'wb').write(new)
print('sha256', hashlib.sha256(new).hexdigest())
