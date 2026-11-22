"""Firmware-volume helpers: list FFS files with raw bytes, attributes and section layout."""
import struct, uuid

FFS_TYPES = {0x01: 'RAW', 0x02: 'FREEFORM', 0x03: 'SEC', 0x04: 'PEI_CORE', 0x05: 'DXE_CORE', 0x06: 'PEIM',
             0x07: 'DRIVER', 0x08: 'COMBO', 0x09: 'APP', 0x0A: 'SMM', 0x0B: 'FVIMG', 0x0C: 'COMBO_SMM_DXE',
             0x0D: 'SMM_CORE', 0xF0: 'PAD'}
SEC_TYPES = {0x01: 'COMPRESSION', 0x02: 'GUID_DEFINED', 0x10: 'PE32', 0x11: 'PIC', 0x12: 'TE', 0x13: 'DXE_DEPEX',
             0x14: 'VERSION', 0x15: 'UI', 0x17: 'FV_IMAGE', 0x18: 'FREEFORM_SUBTYPE_GUID', 0x19: 'RAW',
             0x1B: 'PEI_DEPEX', 0x1C: 'SMM_DEPEX'}


def g(b, o=0):
    return str(uuid.UUID(bytes_le=bytes(b[o:o + 16]))).upper()


def fv_header(img, base):
    assert img[base + 0x28:base + 0x2C] == b'_FVH', hex(base)
    fs = g(img, base + 0x10)
    fvlen, sig, attr, hlen, csum, ext = struct.unpack_from('<Q4sIHHH', img, base + 0x20)
    rev = img[base + 0x37]
    erase = 0xFF if attr & 0x800 else 0x00  # EFI_FVB2_ERASE_POLARITY
    return dict(fs=fs, len=fvlen, attr=attr, hlen=hlen, csum=csum, ext=ext, rev=rev, erase=erase)


def sections(buf):
    out = []
    o = 0
    while o + 4 <= len(buf):
        size = int.from_bytes(buf[o:o + 3], 'little'); t = buf[o + 3]; h = 4
        if size == 0xFFFFFF:
            size = struct.unpack_from('<I', buf, o + 4)[0]; h = 8
        if size < h or o + size > len(buf):
            break
        out.append(dict(off=o, size=size, type=t, hdr=h))
        o += (size + 3) & ~3
    return out


def files(img, base):
    h = fv_header(img, base)
    end = base + h['len']
    o = base + h['hlen']
    if h['ext']:
        o = base + h['ext'] + struct.unpack_from('<I', img, base + h['ext'] + 16)[0]
    o = (o + 7) & ~7
    out = []
    while o + 0x18 <= end:
        if img[o:o + 0x18] == b'\xff' * 0x18:
            break
        size = int.from_bytes(img[o + 0x14:o + 0x17], 'little')
        if size < 0x18 or o + size > end:
            break
        attr = img[o + 0x13]
        t = img[o + 0x12]
        align = [1, 16, 128, 512, 1024, 4096, 32768, 65536][(attr >> 3) & 7]
        f = dict(off=o, size=size, guid=g(img, o), type=t, tname=FFS_TYPES.get(t, hex(t)), attr=attr,
                 align=align, hchk=img[o + 0x10], dchk=img[o + 0x11], state=img[o + 0x17],
                 raw=bytes(img[o:o + size]))
        f['secs'] = sections(img[o + 0x18:o + size]) if t != 0xF0 else []
        f['name'] = None
        for s in f['secs']:
            if s['type'] == 0x15:
                b = img[o + 0x18 + s['off'] + s['hdr']:o + 0x18 + s['off'] + s['size']]
                f['name'] = bytes(b).decode('utf-16le', 'ignore').rstrip('\x00')
        out.append(f)
        o = (o + size + 7) & ~7
    return out, end, o


def ffs_header_checksum_ok(raw):
    hdr = bytearray(raw[:0x18])
    hdr[0x11] = 0  # data checksum excluded
    hdr[0x17] = 0  # state excluded
    return sum(hdr) & 0xFF == 0


def ffs_data_checksum_ok(raw):
    attr = raw[0x13]
    if attr & 0x40:  # FFS_ATTRIB_CHECKSUM
        return (sum(raw[0x18:]) + raw[0x11]) & 0xFF == 0
    return raw[0x11] == 0xAA
