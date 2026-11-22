"""Copy YOUR board's DMI data (serial / UUID / model strings) from a backup of your own BIOS chip
into the E7721AMS.660 release image, so the flashed board keeps its own identity.

Usage:
    python add_my_dmi.py E7721AMS.660 my_backup.bin E7721AMS_660_mydmi.bin

my_backup.bin must be a full 8 MB read of YOUR MS-7721 board's chip (CH341A read, or `afuwinx64 backup.bin /O`).

Only two plain-data files are copied, each in place (same GUID, same size, same offset):
  05CA01FC-0FC1-11DC-9011-00173153EBA8  DMI ROM hole        (DXE volume)
  FD44820B-F1AB-41C0-AE4E-0C55556EB9BD  SMBIOS flash data   (boot-block volume)
Nothing executable is touched. The script refuses to write if any check fails.
"""
import sys, os, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fvlib import files, ffs_header_checksum_ok, ffs_data_checksum_ok

RELEASE_SHA256 = '2c057042488261e79c379b27b8833eed23b31bb47a463e81624e4a85b11a51d3'
CARRY = [(0x190000, '05CA01FC-0FC1-11DC-9011-00173153EBA8'), (0x6C0000, 'FD44820B-F1AB-41C0-AE4E-0C55556EB9BD')]


def one(img, fvb, guid, what):
    fl, end, used = files(img, fvb)
    if used != end:
        sys.exit(f'{what}: firmware volume at {fvb:#x} does not parse - is this a full 8 MB MS-7721 image?')
    m = [f for f in fl if f['guid'] == guid]
    if len(m) != 1:
        sys.exit(f'{what}: file {guid} not found')
    return m[0]


def main(rel_p, mine_p, out_p):
    rel, mine = open(rel_p, 'rb').read(), open(mine_p, 'rb').read()
    if hashlib.sha256(rel).hexdigest() != RELEASE_SHA256:
        sys.exit('release image hash mismatch - re-download E7721AMS.660')
    if len(mine) != 0x800000:
        sys.exit(f'your backup is {len(mine)} bytes, expected 8388608 (8 MB)')
    if b'MS-7721' not in mine:
        sys.exit('your backup does not look like an MS-7721 BIOS')
    out = bytearray(rel)
    for fvb, g in CARRY:
        r, m = one(rel, fvb, g, 'release'), one(mine, fvb, g, 'your backup')
        if r['size'] != m['size'] or r['type'] != m['type']:
            sys.exit(f'{g}: size/type differs in your backup ({m["size"]:#x} vs {r["size"]:#x}) - not compatible')
        if not (ffs_header_checksum_ok(m['raw']) and ffs_data_checksum_ok(m['raw'])):
            sys.exit(f'{g}: bad checksum in your backup - re-read the chip')
        out[r['off']:r['off'] + r['size']] = m['raw']
        print(f'copied {g} ({m["size"]:#x} bytes)')
    out = bytes(out)
    # verify: only the two files differ from the release, and everything still parses with valid checksums
    spans = sorted((one(rel, fvb, g, 'release')['off'], one(rel, fvb, g, 'release')['off'] + one(rel, fvb, g, 'release')['size']) for fvb, g in CARRY)
    pos = 0
    for a, z in spans + [(len(out), len(out))]:
        if out[pos:a] != rel[pos:a]:
            sys.exit('internal error: bytes changed outside the DMI files')
        pos = z
    for fvb in (0x190000, 0x6C0000):
        fl, end, used = files(out, fvb)
        if used != end or not all(ffs_header_checksum_ok(f['raw']) and ffs_data_checksum_ok(f['raw']) for f in fl):
            sys.exit('internal error: output does not verify')
    open(out_p, 'wb').write(out)
    print(f'wrote {out_p}\nsha256 {hashlib.sha256(out).hexdigest()}')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:4])
