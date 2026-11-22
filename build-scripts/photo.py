"""Stage 2: put your board's Click BIOS photo (6.5 file 337EC55A = A78M-E35 V2) into 8.5's UI photo file (A746FD64).
The FFS keeps 8.5's GUID/type/attributes; only its sections are replaced by the 6.5 photo file's sections.
The DXE volume is re-laid exactly like rename.py (pad absorbs the change, DMI ROM hole fixed, S3Restore rebased)."""
import sys, os, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fvlib import files, sections
from build import fix_ffs_checksums, make_pad, place_and_rebase, is_xip_flash_image
import efidecomp

src, base65, out_p = sys.argv[1:4]
img = open(src, 'rb').read()
b65 = open(base65, 'rb').read()
DXE = 0x190000
TARGET, PHOTO = 'A746FD64-F0F3-4310-B923-12196A8B3DD7', '337EC55A-14C9-4C93-AF69-9D3A739BD187'

photo = [f for f in files(b65, DXE)[0] if f['guid'] == PHOTO][0]
# confirm what we are copying is the A78M-E35 V2 picture we identified (JPEG inside $MsI$ container)
psecs = photo['raw'][0x18:]
fl, fv_end, _ = files(img, DXE)
pad = [f for f in fl if f['type'] == 0xF0][0]
head, tail = fl[:fl.index(pad)], fl[fl.index(pad) + 1:]
assert [f['guid'] for f in tail] == ['05CA01FC-0FC1-11DC-9011-00173153EBA8']
tgt = [f for f in head if f['guid'] == TARGET]
assert len(tgt) == 1
tgt = tgt[0]
assert tgt['type'] == photo['type'], 'file types differ'
assert [s['type'] for s in sections(tgt['raw'][0x18:])] == [s['type'] for s in sections(psecs)], 'section layout differs'
newraw = fix_ffs_checksums(bytes(tgt['raw'][:0x18]) + psecs)

log = []
pos = head[0]['off']
blob = bytearray()
for f in head:
    raw = newraw if f['guid'] == TARGET else f['raw']
    if is_xip_flash_image(f['raw'], f['off'], len(img)):
        raw = place_and_rebase(raw, pos, len(img), log, f['name'] or f['guid'])
    blob += raw
    pos += len(raw)
    p = (-pos) % 8
    blob += b'\xff' * p
    pos += p
pad_size = tail[0]['off'] - pos
assert pad_size >= 0x18
blob += make_pad(pad['raw'], pad_size)
new = bytearray(img)
new[head[0]['off']:tail[0]['off']] = blob
new = bytes(new)
open(out_p, 'wb').write(new)
print('\n'.join(log))
print(f'photo file {tgt["size"]:#x} -> {len(newraw):#x}; DXE pad {pad["size"]:#x} -> {pad_size:#x}')
print('sha256', hashlib.sha256(new).hexdigest())
