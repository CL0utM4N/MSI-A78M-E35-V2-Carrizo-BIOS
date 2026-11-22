"""Verify the temperature-patched image against the verified renamed image."""
import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fvlib import files, fv_header, sections, ffs_header_checksum_ok, ffs_data_checksum_ok
from build import pe32_sections_of, pe32_info, rebase_pe32
import efidecomp
from hwm_patch import patch_pe, verify_pe, GUID

prev, new = (open(p, 'rb').read() for p in sys.argv[1:3])
FLASH = 0x100000000 - len(new)
fails = []
def check(c, m):
    if not c: fails.append(m)

def norm(raw, off):
    r = bytearray(raw)
    for po, s in pe32_sections_of(r):
        info = pe32_info(r, po)
        if info and info['base'] is not None and FLASH <= info['base'] < 0x100000000:
            check(info['base'] == FLASH + off + po, f'XIP base wrong')
            rebase_pe32(r, po, 0x10000000 + po)
    r[0x10] = r[0x11] = 0
    return bytes(r)

def inner(raw):
    out = {}
    for s in sections(raw[0x18:]):
        sb = raw[0x18 + s['off']:0x18 + s['off'] + s['size']]
        if s['type'] == 1:
            d = efidecomp.decompress(sb[9:], 5)
            check(len(d) == struct.unpack_from('<I', sb, 4)[0], 'ulen mismatch')
            for t in sections(d):
                out[t['type']] = d[t['off'] + t['hdr']:t['off'] + t['size']]
        else:
            out[s['type']] = sb[s['hdr']:]
    return out

check(new[:0x190000] == prev[:0x190000], 'bytes before DXE volume changed')
check(new[0x6C0000:] == prev[0x6C0000:], 'boot-block volume changed')
fp = {f['guid']: f for f in files(prev, 0x190000)[0]}
fn, end, used = files(new, 0x190000)
check(used == end, 'DXE parse stopped early')
check([f['guid'] for f in fn] == [f['guid'] for f in files(prev, 0x190000)[0]], 'file order changed')
for f in fn:
    check(ffs_header_checksum_ok(f['raw']) and ffs_data_checksum_ok(f['raw']), f"{f['guid']} checksum")
    if f['type'] == 0xF0:
        continue
    p = fp[f['guid']]
    if f['guid'] == GUID:
        a, b = inner(p['raw']), inner(f['raw'])
        check(a[0x13] == b[0x13], 'depex changed')
        check(a[0x15] == b[0x15], 'UI section changed')
        exp, cva, clen = patch_pe(a[0x10], [])
        check(b[0x10] == exp, 'patched PE != original + intended patch')
        errs, _ = verify_pe(a[0x10], b[0x10], cva, clen)
        check(not errs, f'patch verify: {errs}')
        check(f['raw'][:0x10] == p['raw'][:0x10] and f['raw'][0x12:0x14] == p['raw'][0x12:0x14], 'FFS GUID/type/attr changed')
    else:
        check(norm(f['raw'], f['off']) == norm(p['raw'], p['off']), f"{f['name'] or f['guid']} changed unexpectedly")
print('ALL CHECKS PASSED' if not fails else 'FAILURES:\n  ' + '\n  '.join(fails))
sys.exit(1 if fails else 0)
