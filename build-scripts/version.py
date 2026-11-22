"""Rebrand visible BIOS version 8.5 -> 6.6 (same-length, exact-count replacements)."""
import sys, os, struct, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fvlib import files, sections
from build import fix_ffs_checksums, make_pad, place_and_rebase, is_xip_flash_image
import efidecomp, tianocomp


COMPRESSED = {  # GUID: [(old, new, count)] inside the decompressed stream
    'B1DA0ADF-4F77-4070-A88E-BFFE1C60529A': [(b'\x00V8.5\x00', b'\x00V6.6\x00', 1),
                                             ('E7721AMS.850'.encode('utf-16le'), 'E7721AMS.660'.encode('utf-16le'), 1)],
    'DAF4BF89-CE71-4917-B522-C89D32FBC59F': [(b'\x00V8.5\x0011/01/2018', b'\x00V6.6\x0011/01/2018', 1)],
}
RAW_DXE = {'D6C141B7-DFE2-4049-991F-898F1D0E45BD': [(b'$MSESGN$E7721AMS V8.5 ', b'$MSESGN$E7721AMS V6.6 ', 1)]}
RAW_PEI = {'1BA0062E-C779-4582-8566-336AE8F78F09': [(b'$MS1E7721AMS850', b'$MS1E7721AMS660', 1)]}


def apply(buf, edits, name):
    for a, b, n in edits:
        assert len(a) == len(b)
        c = buf.count(a)
        assert c == n, f'{name}: expected {n}x {a!r}, found {c}'
        buf = buf.replace(a, b)
    return buf


def recompress_ffs(raw, name, edits):
    body = raw[0x18:]
    secs = sections(body)
    assert secs[-1]['off'] + secs[-1]['size'] == len(body)
    out = bytearray()
    for i, s in enumerate(secs):
        if i:
            out += b'\0' * ((-len(out)) % 4)
        sb = body[s['off']:s['off'] + s['size']]
        if s['type'] != 1:
            out += sb
            continue
        ulen, ct = struct.unpack_from('<IB', sb, 4)
        dec = efidecomp.decompress(sb[9:], 5)
        assert len(dec) == ulen and ct == 1
        new = apply(dec, edits, name)
        enc = tianocomp.compress(new)
        assert efidecomp.decompress(enc, 5) == new
        payload = struct.pack('<IB', len(new), 1) + enc
        out += (4 + len(payload)).to_bytes(3, 'little') + b'\x01' + payload
        print(f'  {name}: compressed {len(sb) - 9:#x} -> {len(enc):#x}')
    return fix_ffs_checksums(bytes(raw[:0x18]) + bytes(out))


def raw_ffs(raw, name, edits):
    new = apply(raw[0x18:], edits, name)
    print(f'  {name}: in-place edit')
    return fix_ffs_checksums(bytes(raw[:0x18]) + new)


def main(src, out_p):
    img = open(src, 'rb').read()
    log = []
    # DXE volume: rebuild with replacements and re-layout
    fl, _, _ = files(img, 0x190000)
    pad = [x for x in fl if x['type'] == 0xF0][0]
    head, tail = fl[:fl.index(pad)], fl[fl.index(pad) + 1:]
    assert [x['guid'] for x in tail] == ['05CA01FC-0FC1-11DC-9011-00173153EBA8']
    pos = head[0]['off']; blob = bytearray()
    for x in head:
        r = x['raw']
        if x['guid'] in COMPRESSED:
            r = recompress_ffs(r, x['name'] or x['guid'][:8], COMPRESSED[x['guid']])
        elif x['guid'] in RAW_DXE:
            r = raw_ffs(r, x['guid'][:8], RAW_DXE[x['guid']])
        if is_xip_flash_image(x['raw'], x['off'], len(img)):
            r = place_and_rebase(r, pos, len(img), log, x['name'] or x['guid'])
        blob += r; pos += len(r)
        p = (-pos) % 8; blob += b'\xff' * p; pos += p
    pad_size = tail[0]['off'] - pos
    assert pad_size >= 0x18
    blob += make_pad(pad['raw'], pad_size)
    new = bytearray(img); new[head[0]['off']:tail[0]['off']] = blob
    # boot-block: in-place same-size edit of the SEC file
    for x in files(bytes(new), 0x6C0000)[0]:
        if x['guid'] in RAW_PEI:
            r = raw_ffs(x['raw'], 'SEC', RAW_PEI[x['guid']])
            assert len(r) == len(x['raw'])
            new[x['off']:x['off'] + len(r)] = r
    new = bytes(new)
    open(out_p, 'wb').write(new)
    print('\n'.join(log))
    print(f'  DXE pad {pad["size"]:#x} -> {pad_size:#x}')
    print('sha256', hashlib.sha256(new).hexdigest())


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
