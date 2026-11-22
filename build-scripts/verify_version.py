import sys, os, struct, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fvlib import files, sections, ffs_header_checksum_ok, ffs_data_checksum_ok, fv_header
from build import pe32_sections_of, pe32_info, rebase_pe32
import efidecomp
from version import COMPRESSED, RAW_DXE, RAW_PEI, apply  # noqa: E402 (module guards on argv)

prev, new = (open(p, 'rb').read() for p in sys.argv[1:3])
FLASH = 0x100000000 - len(new)
fails = []
def check(c, m):
    if not c: fails.append(m)

def stream(raw):
    out = b''
    for s in sections(raw[0x18:]):
        sb = raw[0x18 + s['off']:0x18 + s['off'] + s['size']]
        out += efidecomp.decompress(sb[9:], 5) if s['type'] == 1 else sb
    return out

def norm(raw, off):
    r = bytearray(raw)
    for po, s in pe32_sections_of(r):
        info = pe32_info(r, po)
        if info and info['base'] is not None and FLASH <= info['base'] < 0x100000000:
            check(info['base'] == FLASH + off + po, 'XIP base wrong')
            rebase_pe32(r, po, 0x10000000 + po)
    r[0x10] = r[0x11] = 0
    return bytes(r)

check(new[:0x190000] == prev[:0x190000], 'bytes before DXE volume changed')
changed = []
for fvb in (0x190000, 0x6C0000):
    h = fv_header(new, fvb)
    check(new[fvb:fvb + h['hlen']] == prev[fvb:fvb + h['hlen']], f'FV {fvb:#x} header changed')
    fp = {f['guid']: f for f in files(prev, fvb)[0]}
    fn, end, used = files(new, fvb)
    check(used == end, f'FV {fvb:#x} parse stopped early')
    check([f['guid'] for f in fn] == [f['guid'] for f in files(prev, fvb)[0]], f'FV {fvb:#x} order changed')
    for f in fn:
        check(ffs_header_checksum_ok(f['raw']) and ffs_data_checksum_ok(f['raw']), f"{f['guid']} checksum")
        if f['type'] == 0xF0:
            continue
        p = fp[f['guid']]
        g = f['guid']
        if g in COMPRESSED:
            changed.append(g)
            check(stream(f['raw']) == apply(stream(p['raw']), COMPRESSED[g], g), f'{g} content != original + edits')
        elif g in RAW_DXE or g in RAW_PEI:
            changed.append(g)
            edits = RAW_DXE.get(g) or RAW_PEI.get(g)
            check(f['raw'][0x18:] == apply(p['raw'][0x18:], edits, g), f'{g} raw != original + edits')
            check(f['off'] == p['off'] or fvb == 0x190000, f'{g} moved')
        else:
            check(norm(f['raw'], f['off']) == norm(p['raw'], p['off']), f"{f['name'] or g} changed unexpectedly")
check(len(changed) == 4, f'changed files {len(changed)} != 4')
check(new[0x7FEC20:] != prev[0x7FEC20:] and len(new) == len(prev), 'SEC not updated')
check(b'$MS1E7721AMS660' in new and b'$MS1E7721AMS850' not in new, 'SEC tag')
check(b'$MSESGN$E7721AMS V6.6 11/01/2018' in new and b'E7721AMS V8.5' not in new, 'MSESGN tag')
# SEC is still at the top and the reset vector bytes (last 16 bytes) are unchanged
check(new[-16:] == prev[-16:], 'reset vector area changed')
print(f'changed files: {len(changed)}')
print('ALL CHECKS PASSED' if not fails else 'FAILURES:\n  ' + '\n  '.join(fails))
sys.exit(1 if fails else 0)
