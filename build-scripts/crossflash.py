"""Build: MSI A68HM-E33 V2 BIOS 8.5 + your board's DMI ROM hole and SMBIOS flash data, then verify.

Only two FFS files change, each replaced in place by your copy of the same GUID and same size:
  05CA01FC-0FC1-11DC-9011-00173153EBA8  DMI ROM hole (DXE volume, fixed offset)
  FD44820B-F1AB-41C0-AE4E-0C55556EB9BD  SMBIOS flash data (boot-block volume, plain data, not executable)
Everything else is MSI's 8.5 image byte-for-byte, including its default NVRAM.
"""
import sys, os, hashlib, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fvlib import files, fv_header, ffs_header_checksum_ok, ffs_data_checksum_ok, sections
from build import pe32_sections_of, pe32_info

donor_p, mine_p, out_p = sys.argv[1:4]
donor = open(donor_p, 'rb').read()
mine = open(mine_p, 'rb').read()
assert len(donor) == len(mine) == 0x800000
FLASH = 0x100000000 - len(donor)
CARRY = [(0x190000, '05CA01FC-0FC1-11DC-9011-00173153EBA8'), (0x6C0000, 'FD44820B-F1AB-41C0-AE4E-0C55556EB9BD')]

out = bytearray(donor)
log = []
for fvb, g in CARRY:
    d = [f for f in files(donor, fvb)[0] if f['guid'] == g]
    m = [f for f in files(mine, fvb)[0] if f['guid'] == g]
    assert len(d) == 1 and len(m) == 1, g
    d, m = d[0], m[0]
    assert d['size'] == m['size'], f'{g}: size differs {d["size"]:#x} vs {m["size"]:#x}'
    assert d['type'] == m['type'] and not any(True for _ in pe32_sections_of(m['raw'])), f'{g}: not plain data'
    assert ffs_header_checksum_ok(m['raw']) and ffs_data_checksum_ok(m['raw'])
    out[d['off']:d['off'] + d['size']] = m['raw']
    log.append(f'carried {g} ({m["size"]:#x} bytes) from your dump @ {m["off"]:#x} -> {d["off"]:#x}')
out = bytes(out)

# ---------------- verification
fails = []
def check(c, msg):
    if not c: fails.append(msg)
# 1. differences vs MSI 8.5 are confined to the two carried files
allowed = []
for fvb, g in CARRY:
    f = [f for f in files(donor, fvb)[0] if f['guid'] == g][0]
    allowed.append((f['off'], f['off'] + f['size']))
diff = [i for i in range(len(out)) if out[i] != donor[i]] if False else None
pos = 0; outside = 0
for a, z in sorted(allowed) + [(len(out), len(out))]:
    if out[pos:a] != donor[pos:a]:
        outside += 1
    pos = z
check(outside == 0, 'bytes changed outside the two carried files')
# 2. every FV parses fully, every FFS checksum valid, XIP images at their own addresses
nfiles = nxip = 0
for fvb in (0x40000, 0x190000, 0x6C0000):
    h = fv_header(out, fvb)
    hdr = out[fvb:fvb + h['hlen']]
    check(sum(struct.unpack_from(f'<{len(hdr)//2}H', hdr)) & 0xFFFF == 0, f'FV {fvb:#x} header checksum')
    if fvb == 0x40000:
        continue  # NVRAM store (not an FFS volume)
    fl, end, used = files(out, fvb)
    check(used == end, f'FV {fvb:#x} parse stopped early')
    for f in fl:
        nfiles += 1
        check(ffs_header_checksum_ok(f['raw']), f"{f['guid']} header checksum")
        check(ffs_data_checksum_ok(f['raw']), f"{f['guid']} data checksum")
        for pe_off, s in pe32_sections_of(f['raw']):
            info = pe32_info(f['raw'], pe_off)
            if info and info['base'] is not None and FLASH <= info['base'] < 0x100000000:
                nxip += 1
                check(info['base'] == FLASH + f['off'] + pe_off, f"{f['name']} XIP base mismatch")
# 3. carried files byte-identical to your dump's copies
for fvb, g in CARRY:
    a = [f for f in files(out, fvb)[0] if f['guid'] == g][0]['raw']
    b = [f for f in files(mine, fvb)[0] if f['guid'] == g][0]['raw']
    check(a == b, f'{g} not identical to your copy')
# 4. identity strings
check(b'A78M-E35 V2 (MS-7721)' in out, 'your board name string missing from DMI data')
check(b'$MS1E7721AMS850' in out and b'AGESACarrizoFM2r2PI  V1.3.0.1X' in out, 'version markers')
check(out[0x20000:0x20040] == donor[0x20000:0x20040] and out.find(b'$PSP') == 0xA0000, 'EFS/PSP pointer')

open(out_p, 'wb').write(out)
print('\n'.join(log))
print(f'files checked {nfiles}, XIP images checked {nxip}')
print(f'sha256 {hashlib.sha256(out).hexdigest()}  {os.path.basename(out_p)}')
print('ALL CHECKS PASSED' if not fails else 'FAILURES:\n  ' + '\n  '.join(fails))
sys.exit(1 if fails else 0)
