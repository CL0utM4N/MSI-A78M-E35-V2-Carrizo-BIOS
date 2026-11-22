"""Independently verify a built image against base (6.5 dump) and donor, given the build config."""
import json, struct, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fvlib import files, fv_header, ffs_header_checksum_ok, ffs_data_checksum_ok, sections
from build import pe32_info, rebase_pe32, pe32_sections_of

cfg = json.load(open(sys.argv[1]))
base = open(cfg['base'], 'rb').read()
donor = open(cfg['donor'], 'rb').read()
out = open(cfg['out'], 'rb').read()
FLASH = 0x100000000 - len(out)
fails = []
def check(cond, msg):
    if not cond:
        fails.append(msg)
    return cond

check(len(out) == len(base) == 0x800000, 'size')


def normalize(raw, file_off, to_off):
    """Rebase every XIP PE32 in an FFS file from its address at file_off to the address at to_off."""
    r = bytearray(raw)
    for pe_off, s in pe32_sections_of(r):
        info = pe32_info(r, pe_off)
        if info and info['base'] is not None and info['base'] == FLASH + file_off + pe_off:
            rebase_pe32(r, pe_off, FLASH + to_off + pe_off)
    # header checksums excluded from content comparison
    r[0x10] = r[0x11] = 0
    return bytes(r[0x18:]), bytes(r[:0x10]) + bytes(r[0x12:0x14]) + bytes(r[0x17:0x18])


report = []
for fv in cfg['volumes']:
    fvb = int(fv['base'], 16)
    # FV header untouched
    h_out = out[fvb:fvb + fv_header(out, fvb)['hlen']]
    check(h_out == base[fvb:fvb + len(h_out)], f'FV {fvb:#x} header changed')
    hdr_sum = sum(struct.unpack_from(f'<{len(h_out)//2}H', h_out)) & 0xFFFF
    check(hdr_sum == 0, f'FV {fvb:#x} header checksum')
    fo, end, used = files(out, fvb)
    fb = files(base, fvb)[0]
    fd = {f['guid']: f for f in files(donor, fvb)[0]}
    check(used == end, f'FV {fvb:#x} not fully parsed: stopped at {used:#x} of {end:#x}')
    # expected order
    exp = []
    for f in fb:
        exp.append(f['guid'])
        exp += fv.get('insert_after', {}).get(f['guid'], [])
    check([f['guid'] for f in fo] == exp, f'FV {fvb:#x} file order/set differs from expected')
    repl = set(fv.get('replace', [])) | {g for v in fv.get('insert_after', {}).values() for g in v}
    bmap = {f['guid']: f for f in fb}
    n_x = n_b = n_d = 0
    for f in fo:
        check(ffs_header_checksum_ok(f['raw']), f"{f['guid']} header checksum")
        check(ffs_data_checksum_ok(f['raw']), f"{f['guid']} data checksum")
        check(f['state'] == 0xF8, f"{f['guid']} state {f['state']:#x}")
        check(f['off'] % 8 == 0, f"{f['guid']} misaligned")
        # every flash-range PE32 must be linked at exactly its own flash address
        for pe_off, s in pe32_sections_of(f['raw']):
            info = pe32_info(f['raw'], pe_off)
            if info and info['base'] is not None and FLASH <= info['base'] < 0x100000000:
                n_x += 1
                check(info['base'] == FLASH + f['off'] + pe_off,
                      f"{f['name'] or f['guid']} XIP base {info['base']:#x} != {FLASH + f['off'] + pe_off:#x}")
        if f['type'] == 0xF0:
            check(f['raw'][0x18:].count(0xFF) == f['size'] - 0x18, 'pad body not erased')
            check(f['guid'] == [x for x in fb if x['type'] == 0xF0][0]['guid'], 'pad GUID changed')
            continue
        src = fd[f['guid']] if f['guid'] in repl else bmap[f['guid']]
        a_body, a_hdr = normalize(f['raw'], f['off'], src['off'])
        s_body, s_hdr = normalize(src['raw'], src['off'], src['off'])
        ok = check(a_body == s_body and a_hdr == s_hdr,
                   f"{f['name'] or f['guid']} content != {'donor' if f['guid'] in repl else 'base'} (after address normalisation)")
        if f['guid'] in repl:
            n_d += 1
        else:
            n_b += 1
    # fixed tail files byte-identical at identical offsets
    for g in fv['fixed_tail']:
        tb = [f for f in fb if f['guid'] == g][0]
        to = [f for f in fo if f['guid'] == g][0]
        check(tb['off'] == to['off'] and tb['raw'] == to['raw'], f'fixed file {g} moved or changed')
    report.append(f"FV {fvb:#x}: {len(fo)} files ({n_d} from donor, {n_b} from base, 1 pad), "
                  f"{n_x} XIP images all at correct addresses; free pad {[f['size'] for f in fo if f['type']==0xF0][0]:#x}")

# regions
fv_spans = [(int(v['base'], 16), int(v['base'], 16) + fv_header(base, int(v['base'], 16))['len']) for v in cfg['volumes']]
reg = [(int(r['start'], 16), int(r['end'], 16)) for r in cfg.get('regions', [])]
for a, z in reg:
    check(out[a:z] == donor[a:z], f'region {a:#x}-{z:#x} != donor')
# everything not in a rebuilt FV or copied region must equal base exactly
covered = sorted(fv_spans + reg)
pos = 0
untouched = 0
for a, z in covered + [(len(out), len(out))]:
    if pos < a:
        check(out[pos:a] == base[pos:a], f'untouched span {pos:#x}-{a:#x} changed')
        untouched += a - pos
    pos = max(pos, z)
report.append(f"untouched bytes outside rebuilt volumes/regions identical to your dump: {untouched:#x}")

# PSP directory sanity in output
m = out.find(b'$PSP')
cnt = struct.unpack_from('<I', out, m + 8)[0]
words = struct.unpack_from(f'<{(16 * cnt + 8) // 2}H', out, m + 8)
s1 = s2 = 0xFFFF
for w in words:
    s1 = (s1 + w) % 0xFFFF
    s2 = (s2 + s1) % 0xFFFF
fl32 = (s2 << 16) | s1
stored = struct.unpack_from('<I', out, m + 4)[0]
dm = donor.find(b'$PSP')
check(m == dm == 0xA0000, 'PSP directory location')
for i in range(cnt):
    t, sz, loc = struct.unpack_from('<IIQ', out, m + 16 + i * 16)
    if FLASH <= loc < 0x100000000 and sz != 0xFFFFFFFF:
        o = loc - FLASH
        inside = any(a <= o and o + sz <= z for a, z in reg) or o == 0x7FEC20
        check(inside, f'PSP entry {t:#x} at {o:#x} outside copied region')
        if t == 6:
            check(out[o:o + sz] == base[o:o + sz], 'PSP RTM region (SEC) changed')
report.append(f"PSP directory @ {m:#x}: {cnt} entries, stored checksum {stored:#x}, fletcher32 {fl32:#x} "
              f"({'match' if fl32 == stored else 'no match - checksum scheme differs; identical to donor dir anyway'})")
check(out[m:m + 16 + 16 * cnt] == donor[dm:dm + 16 + 16 * cnt], 'PSP directory differs from donor')
# EFS (embedded firmware structure) must still point at the same PSP dir
check(out[0x20000:0x20040] == base[0x20000:0x20040] == donor[0x20000:0x20040], 'EFS differs')

print('\n'.join(report))
print('FAILURES:' if fails else 'ALL CHECKS PASSED')
for f in fails:
    print('  !', f)
sys.exit(1 if fails else 0)
