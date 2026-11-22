"""Build a CPU-only transplant image: base (your 6.5 dump) + selected donor modules/regions.

Everything is copied verbatim from the donor as already-built FFS files (no recompression).
Execute-in-place PE32 images that end up at a different flash address are rebased using their
own relocation tables. The DMI ROM hole and the SEC/reset-vector file keep their exact offsets.
"""
import json, struct, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fvlib import files, fv_header, sections

DXE_FV, PEI_FV = 0x190000, 0x6C0000


def flash_base(img):
    return 0x100000000 - len(img)


# ---------------------------------------------------------------- PE32 rebase
def pe32_info(buf, off):
    if buf[off:off + 2] != b'MZ':
        return None
    pe = off + struct.unpack_from('<I', buf, off + 0x3C)[0]
    assert buf[pe:pe + 4] == b'PE\0\0'
    opt = pe + 24
    magic = struct.unpack_from('<H', buf, opt)[0]
    if magic != 0x10B:
        return dict(magic=magic, base=None)  # PE32+ (x64 DXE): never execute-in-place here
    base = struct.unpack_from('<I', buf, opt + 28)[0]
    chars = struct.unpack_from('<H', buf, pe + 22)[0]
    nsec = struct.unpack_from('<H', buf, pe + 6)[0]
    osz = struct.unpack_from('<H', buf, pe + 20)[0]
    sh = opt + osz
    secs = []
    for i in range(nsec):
        vsz, va, rsz, ro = struct.unpack_from('<IIII', buf, sh + i * 40 + 8)
        secs.append((va, vsz, ro, rsz))
    rr, rs = struct.unpack_from('<II', buf, opt + 96 + 5 * 8)
    return dict(magic=magic, pe=pe, opt=opt, base=base, chars=chars, secs=secs, reloc_rva=rr, reloc_size=rs)


def rva_to_off(info, img_off, rva):
    for va, vsz, ro, rsz in info['secs']:
        if va <= rva < va + max(vsz, rsz):
            return img_off + ro + (rva - va)
    if rva < info['secs'][0][0]:
        return img_off + rva  # headers
    raise ValueError(f'rva {rva:#x} not in any section')


def rebase_pe32(buf, img_off, new_base):
    """Rebase a PE32 image located at buf[img_off:] to new_base, in place. Returns (old_base, fixups)."""
    info = pe32_info(buf, img_off)
    assert info and info['magic'] == 0x10B, 'rebase supports PE32 only'
    delta = (new_base - info['base']) & 0xFFFFFFFF
    if delta == 0:
        return info['base'], 0
    if info['reloc_size'] == 0:
        if info['chars'] & 1:
            raise ValueError('relocations stripped; cannot rebase')
        # no absolute fixups in image; only the header field changes
    n = 0
    o = rva_to_off(info, img_off, info['reloc_rva']) if info['reloc_size'] else 0
    end = o + info['reloc_size']
    while info['reloc_size'] and o < end:
        page, blk = struct.unpack_from('<II', buf, o)
        if blk < 8:
            break
        for j in range((blk - 8) // 2):
            e = struct.unpack_from('<H', buf, o + 8 + j * 2)[0]
            t, r = e >> 12, e & 0xFFF
            if t == 0:
                continue
            if t != 3:
                raise ValueError(f'unsupported reloc type {t}')
            p = rva_to_off(info, img_off, page + r)
            v = struct.unpack_from('<I', buf, p)[0]
            struct.pack_into('<I', buf, p, (v + delta) & 0xFFFFFFFF)
            n += 1
        o += blk
    struct.pack_into('<I', buf, info['opt'] + 28, new_base)
    return info['base'], n


# ---------------------------------------------------------------- FFS helpers
def fix_ffs_checksums(raw):
    raw = bytearray(raw)
    size = len(raw)
    raw[0x14:0x17] = size.to_bytes(3, 'little')
    attr = raw[0x13]
    raw[0x10] = 0
    raw[0x11] = 0
    state = raw[0x17]
    raw[0x17] = 0
    raw[0x10] = (-sum(raw[:0x18])) & 0xFF
    raw[0x17] = state
    if attr & 0x40:
        raw[0x11] = (-sum(raw[0x18:])) & 0xFF
    else:
        raw[0x11] = 0xAA
    return bytes(raw)


def make_pad(template_raw, size):
    assert size >= 0x18 and size % 8 == 0 or size >= 0x18
    raw = bytearray(template_raw[:0x18]) + b'\xff' * (size - 0x18)
    return fix_ffs_checksums(raw)


def pe32_sections_of(ffs_raw):
    """Yield (offset_in_ffs, section) for PE32 sections in an FFS file."""
    for s in sections(ffs_raw[0x18:]):
        if s['type'] == 0x10:
            yield 0x18 + s['off'] + s['hdr'], s


def place_and_rebase(ffs_raw, file_off, img_len, log, name):
    """Return FFS bytes with every XIP PE32 section rebased to its flash address at file_off."""
    raw = bytearray(ffs_raw)
    changed = False
    for pe_off, s in pe32_sections_of(raw):
        info = pe32_info(raw, pe_off)
        if info is None or info['base'] is None:
            continue
        want = (0x100000000 - img_len) + file_off + pe_off
        if info['base'] != want and (0x100000000 - img_len) <= info['base'] < 0x100000000:
            old, n = rebase_pe32(raw, pe_off, want)
            log.append(f'    rebased {name}: {old:#x} -> {want:#x} ({n} fixups)')
            changed = True
    return fix_ffs_checksums(raw) if changed else bytes(raw)


def is_xip_flash_image(ffs_raw, file_off, img_len):
    for pe_off, s in pe32_sections_of(ffs_raw):
        info = pe32_info(ffs_raw, pe_off)
        if info and info['base'] is not None and info['base'] == (0x100000000 - img_len) + file_off + pe_off:
            return True
    return False


# ---------------------------------------------------------------- volume rebuild
def rebuild_fv(base_img, donor_img, fv_base, replace, insert_after, fixed_tail_guids, log):
    """Rebuild one FV: replace files by GUID with donor copies, insert donor files after given GUIDs.
    Files in fixed_tail_guids (and the pad before them) keep their exact offsets."""
    img_len = len(base_img)
    h = fv_header(base_img, fv_base)
    bfiles, fv_end, _ = files(base_img, fv_base)
    dfiles = {f['guid']: f for f in files(donor_img, fv_base)[0]}
    pad_idx = [i for i, f in enumerate(bfiles) if f['type'] == 0xF0]
    assert len(pad_idx) == 1, 'expected exactly one pad file'
    pad = bfiles[pad_idx[0]]
    head, tail = bfiles[:pad_idx[0]], bfiles[pad_idx[0] + 1:]
    assert [f['guid'] for f in tail] == fixed_tail_guids, f'unexpected files after pad: {[f["guid"] for f in tail]}'

    # new ordered list of (guid, raw, source, xip_in_base)
    out = []
    for f in head:
        src = 'base'
        raw = f['raw']
        if f['guid'] in replace:
            raw = dfiles[f['guid']]['raw']
            src = 'donor'
        out.append([f['guid'], raw, src, is_xip_flash_image(f['raw'], f['off'], img_len) if src == 'base' else
                    is_xip_flash_image(raw, dfiles[f['guid']]['off'], img_len), f.get('name')])
        for g in insert_after.get(f['guid'], []):
            d = dfiles[g]
            out.append([g, d['raw'], 'donor-new', is_xip_flash_image(d['raw'], d['off'], img_len), d.get('name')])

    # lay out from the first file offset
    pos = head[0]['off']
    blob = bytearray()
    placed = []
    for guid, raw, src, xip, name in out:
        assert pos % 8 == 0
        if xip:
            raw = place_and_rebase(raw, pos, img_len, log, name or guid)
        placed.append((pos, guid, src, len(raw), name))
        blob += raw
        pos += len(raw)
        padlen = (-pos) % 8
        blob += b'\xff' * padlen
        pos += padlen
    tail_start = tail[0]['off'] if tail else fv_end
    pad_size = tail_start - pos
    if pad_size < 0x18:
        raise ValueError(f'FV {fv_base:#x} overflow: need {-(pad_size - 0x18):#x} more bytes')
    blob += make_pad(pad['raw'], pad_size)
    log.append(f'  FV {fv_base:#x}: pad {pad["size"]:#x} -> {pad_size:#x} ({pad_size - pad["size"]:+#x})')
    new = bytearray(base_img)
    start = head[0]['off']
    assert start + len(blob) == tail_start
    new[start:tail_start] = blob
    return bytes(new), placed


def main(cfg_path):
    cfg = json.load(open(cfg_path))
    base = open(cfg['base'], 'rb').read()
    donor = open(cfg['donor'], 'rb').read()
    assert len(base) == len(donor) == 0x800000
    log = []
    img = base
    for fv in cfg['volumes']:
        fvb = int(fv['base'], 16)
        log.append(f"== volume {fvb:#x}")
        img, placed = rebuild_fv(img, donor, fvb, set(fv.get('replace', [])), fv.get('insert_after', {}),
                                 fv['fixed_tail'], log)
        for p in placed:
            if p[2] != 'base':
                log.append(f"    {p[2]:9} {p[4] or p[1]} @ {p[0]:#x} size {p[3]:#x}")
    for r in cfg.get('regions', []):
        a, z = int(r['start'], 16), int(r['end'], 16)
        img = img[:a] + donor[a:z] + img[z:]
        log.append(f"== region {a:#x}-{z:#x} copied from donor ({r['why']})")
    open(cfg['out'], 'wb').write(img)
    print('\n'.join(log))
    print(f"wrote {cfg['out']} ({len(img):#x} bytes)")


if __name__ == '__main__':
    main(sys.argv[1])
