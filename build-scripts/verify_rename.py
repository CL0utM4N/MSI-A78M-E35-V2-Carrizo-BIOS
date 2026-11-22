"""Verify the renamed image against the previously verified cross-flash image."""
import sys, os, struct, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fvlib import files, fv_header, sections, ffs_header_checksum_ok, ffs_data_checksum_ok
from build import pe32_sections_of, pe32_info, rebase_pe32
import efidecomp

prev_p, new_p, base65_p = sys.argv[1:4]
prev, new, b65 = (open(p, 'rb').read() for p in (prev_p, new_p, base65_p))
FLASH = 0x100000000 - len(new)
fails = []
def check(c, m):
    if not c: fails.append(m)

OLD, NEW = b'A68HM-E33 V2 (MS-7721)', b'A78M-E35 V2 (MS-7721)'
EXPECT = {
    'B1DA0ADF-4F77-4070-A88E-BFFE1C60529A': [(OLD + b'\0\0', NEW + b'\0\0\0')],
    '6F017C3F-CEA2-4643-BB0D-2C1A863B2B18': [(OLD + b'\0\x009.0\0', NEW + b'\0\0\x006.0\0')],
    'DAF4BF89-CE71-4917-B522-C89D32FBC59F': None,  # length-changing; checked separately
}
PHOTO_T, PHOTO_S = 'A746FD64-F0F3-4310-B923-12196A8B3DD7', '337EC55A-14C9-4C93-AF69-9D3A739BD187'

def decomp_stream(raw):
    out = b''
    for s in sections(raw[0x18:]):
        sb = raw[0x18 + s['off']:0x18 + s['off'] + s['size']]
        if s['type'] == 1:
            ulen, ct = struct.unpack_from('<IB', sb, s['hdr'])
            d = efidecomp.decompress(sb[s['hdr'] + 5:], 5)
            assert len(d) == ulen
            out += d
        else:
            out += sb
    return out

def norm(raw, off):
    r = bytearray(raw)
    for pe_off, s in pe32_sections_of(r):
        info = pe32_info(r, pe_off)
        if info and info['base'] is not None and FLASH <= info['base'] < 0x100000000:
            check(info['base'] == FLASH + off + pe_off, f'XIP base wrong in {raw[:16].hex()}')
            rebase_pe32(r, pe_off, 0x10000000 + pe_off)
    r[0x10] = r[0x11] = 0
    return bytes(r)

# regions outside the DXE volume must be byte-identical
check(new[:0x190000] == prev[:0x190000], 'bytes before DXE volume changed')
check(new[0x6C0000:] == prev[0x6C0000:], 'boot-block volume changed')
fp = {f['guid']: f for f in files(prev, 0x190000)[0]}
fn, end, used = files(new, 0x190000)
check(used == end, 'DXE volume parse stopped early')
check([f['guid'] for f in fn] == [f['guid'] for f in files(prev, 0x190000)[0]], 'DXE file order/set changed')
changed = []
for f in fn:
    check(ffs_header_checksum_ok(f['raw']) and ffs_data_checksum_ok(f['raw']), f"{f['guid']} checksum")
    check(f['off'] % 8 == 0, f"{f['guid']} misaligned")
    if f['type'] == 0xF0:
        continue
    p = fp[f['guid']]
    if f['guid'] in EXPECT:
        changed.append(f['guid'])
        a, b = decomp_stream(p['raw']), decomp_stream(f['raw'])
        if EXPECT[f['guid']]:
            exp = a
            for o, n in EXPECT[f['guid']]:
                exp = exp.replace(o, n)
            check(b == exp, f"{f['guid']}: decompressed content != original with intended edits")
        else:  # template: string set shortened by one byte, inner section header -1, version strings 9.0->6.0
            ea = a.replace(b'\0' + OLD + b'\0', b'\0' + NEW + b'\0').replace(b'\x009.0\x00To ', b'\x006.0\x00To ')
            inner_old = int.from_bytes(a[:3], 'little'); inner_new = int.from_bytes(b[:3], 'little')
            check(inner_new == inner_old - 1, 'template inner size not -1')
            check(b[4:inner_new] == ea[4:inner_old - 1], 'template content mismatch')
        check(f['raw'][:0x10] == p['raw'][:0x10] and f['raw'][0x12:0x14] == p['raw'][0x12:0x14], 'FFS GUID/type/attr changed')
    elif f['guid'] == PHOTO_T:
        changed.append(f['guid'])
        ph = [x for x in files(b65, 0x190000)[0] if x['guid'] == PHOTO_S][0]
        check(f['raw'][0x18:] == ph['raw'][0x18:], 'photo sections differ from 6.5 A78M-E35 V2 photo')
    else:
        check(norm(f['raw'], f['off']) == norm(p['raw'], p['off']), f"{f['name'] or f['guid']} changed unexpectedly")
# no A68HM strings left anywhere (decompressed)
left = []
for f in fn:
    if f['type'] == 0xF0:
        continue
    try:
        d = decomp_stream(f['raw'])
    except Exception:
        d = f['raw']
    for pat in (b'A68HM', 'A68HM'.encode('utf-16le')):
        if pat in d:
            left.append(f['name'] or f['guid'])
for fvb in (0x6C0000,):
    for f in files(new, fvb)[0]:
        if b'A68HM' in f['raw']:
            left.append(f['name'] or f['guid'])
check(not left, f'A68HM strings remain in: {left}')
check(b'A68HM' not in new, 'raw A68HM string remains')
print(f'changed files: {len(changed)} (expected 4 incl. photo if applied)')
print('ALL CHECKS PASSED' if not fails else 'FAILURES:\n  ' + '\n  '.join(fails))
sys.exit(1 if fails else 0)
