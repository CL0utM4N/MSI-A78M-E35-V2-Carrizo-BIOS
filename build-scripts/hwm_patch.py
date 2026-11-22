"""Patch HardwareMonitorDxe so the 'CPU' temperature (Fintek index 0x72) is read from the CPU's own sensor.

CPU sensor selection (mirrors Linux k10temp):
  family 15h, model 60h-7Fh (Carrizo/Bristol): SMU index 0xD8200CA4 via D0F0xB8 (index) / D0F0xBC (data)
  anything else (e.g. Kaveri 15h/30h):          PCI D18F3xA4
  temp_C = bits[31:21] / 8  (integer), minus 49 if bit 19 (CurTmpRangeSel) is set; 0xFFFFFFFF or negative -> 0
All other sensors keep the original Super I/O read, byte-for-byte equivalent.
The CF8 address port and the D0F0xB8 index are saved and restored.

Then: re-encode the module, rebuild its FFS, re-lay the DXE volume, write the output image.
"""
import sys, os, struct, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import keystone, capstone
from fvlib import files, sections
from build import fix_ffs_checksums, make_pad, place_and_rebase, is_xip_flash_image
import efidecomp, tianocomp

GUID = '55B66A09-451A-4AB0-BD04-DD27E148B384'
PATCH_AT, PATCH_END, JOIN = 0x87E, 0x8A2, 0x93D
IOWRITE8, IOREAD8 = 0x27A0, 0x2790
ORIG = bytes.fromhex('8a541304' 'b995020000' 'e8141f0000' 'b996020000' 'e8fa1e0000' '440fb6d8' '4c891f' 'e99b000000')

CAVE_ASM = f"""
    mov dl, byte ptr [rbx + rdx + 4]
    cmp dl, 0x72
    jne orig
    push rbx
    mov eax, 1
    cpuid
    pop rbx
    mov r8d, eax
    and r8d, 0x0FF00F00
    cmp r8d, 0x00600F00
    jne d18
    mov r8d, eax
    shr r8d, 4
    and r8d, 0x0F
    mov r9d, eax
    shr r9d, 12
    and r9d, 0xF0
    or r8d, r9d
    and r8d, 0xE0
    cmp r8d, 0x60
    jne d18
    mov dx, 0xCF8
    in eax, dx
    mov r10d, eax
    mov eax, 0x800000B8
    out dx, eax
    mov dx, 0xCFC
    in eax, dx
    mov r11d, eax
    mov eax, 0xD8200CA4
    out dx, eax
    mov dx, 0xCF8
    mov eax, 0x800000BC
    out dx, eax
    mov dx, 0xCFC
    in eax, dx
    mov r9d, eax
    mov dx, 0xCF8
    mov eax, 0x800000B8
    out dx, eax
    mov dx, 0xCFC
    mov eax, r11d
    out dx, eax
    mov dx, 0xCF8
    mov eax, r10d
    out dx, eax
    jmp calc
d18:
    mov dx, 0xCF8
    in eax, dx
    mov r10d, eax
    mov eax, 0x8000C3A4
    out dx, eax
    mov dx, 0xCFC
    in eax, dx
    mov r9d, eax
    mov dx, 0xCF8
    mov eax, r10d
    out dx, eax
calc:
    cmp r9d, 0xFFFFFFFF
    je zero
    mov eax, r9d
    shr eax, 24
    bt r9d, 19
    jnc store
    sub eax, 49
    jns store
zero:
    xor eax, eax
store:
    mov qword ptr [rdi], rax
    jmp {JOIN:#x}
orig:
    mov ecx, 0x295
    call {IOWRITE8:#x}
    mov ecx, 0x296
    call {IOREAD8:#x}
    movzx r11d, al
    mov qword ptr [rdi], r11
    jmp {JOIN:#x}
"""


def patch_pe(pe_bytes, log):
    b = bytearray(pe_bytes)
    peo = struct.unpack_from('<I', b, 0x3C)[0]
    opt = peo + 24
    assert struct.unpack_from('<H', b, opt)[0] == 0x20B
    n = struct.unpack_from('<H', b, peo + 6)[0]
    osz = struct.unpack_from('<H', b, peo + 20)[0]
    sa, fa = struct.unpack_from('<II', b, opt + 32)
    assert sa == fa == 0x20
    secs = []
    for i in range(n):
        sh = opt + osz + i * 40
        secs.append((sh, b[sh:sh + 8].rstrip(b'\0'), *struct.unpack_from('<IIII', b, sh + 8)))
    last = secs[-1]
    assert last[1] == b'.reloc', 'last section is not .reloc'
    sh, nm, vsz, va, rsz, ro = last
    assert ro == va and ro + rsz == len(b), 'unexpected file layout'
    reloc_rva, reloc_size = struct.unpack_from('<II', b, opt + 112 + 5 * 8)
    assert reloc_rva == va and reloc_size <= vsz
    assert bytes(b[PATCH_AT:PATCH_END]) == ORIG, 'original code at patch site does not match'
    cave_va = va + ((rsz + 0x1F) & ~0x1F)
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    enc, _ = ks.asm(CAVE_ASM, cave_va)
    cave = bytes(enc)
    hook, _ = ks.asm(f'jmp {cave_va:#x}', PATCH_AT)
    hook = bytes(hook)
    assert len(hook) == 5
    b[PATCH_AT:PATCH_END] = hook + b'\xCC' * (PATCH_END - PATCH_AT - len(hook))
    # extend .reloc with the cave
    pad = cave_va - (va + rsz)
    b += b'\0' * pad + cave
    new_raw = ((len(b) - ro) + 0x1F) & ~0x1F
    b += b'\0' * (ro + new_raw - len(b))
    struct.pack_into('<IIII', b, sh + 8, new_raw, va, new_raw, ro)
    struct.pack_into('<I', b, sh + 36, 0x60000060)  # code | initialized data | execute | read
    struct.pack_into('<I', b, opt + 56, va + new_raw)  # SizeOfImage
    log.append(f'  hook @ {PATCH_AT:#x} -> cave @ {cave_va:#x} ({len(cave)} bytes); .reloc {rsz:#x} -> {new_raw:#x}; SizeOfImage -> {va + new_raw:#x}')
    return bytes(b), cave_va, len(cave)


def verify_pe(orig, new, cave_va, cave_len):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    errs = []
    # everything except the hook region, the .reloc section header, SizeOfImage and the appended tail is unchanged
    peo = struct.unpack_from('<I', orig, 0x3C)[0]; opt = peo + 24
    n = struct.unpack_from('<H', orig, peo + 6)[0]; osz = struct.unpack_from('<H', orig, peo + 20)[0]
    sh = opt + osz + (n - 1) * 40
    allowed = set(range(PATCH_AT, PATCH_END)) | set(range(sh + 8, sh + 24)) | set(range(sh + 36, sh + 40)) | set(range(opt + 56, opt + 60))
    for i in range(len(orig)):
        if i not in allowed and orig[i] != new[i]:
            errs.append(f'unexpected byte change at {i:#x}')
            break
    hook = list(md.disasm(new[PATCH_AT:PATCH_AT + 5], PATCH_AT))
    if not (len(hook) == 1 and hook[0].mnemonic == 'jmp' and int(hook[0].op_str, 16) == cave_va):
        errs.append('hook jump wrong')
    ins = list(md.disasm(new[cave_va:cave_va + cave_len], cave_va))
    if sum(i.size for i in ins) != cave_len:
        errs.append('cave does not disassemble cleanly')
    tgt = [(i.mnemonic, i.op_str) for i in ins if i.mnemonic in ('jmp', 'call')]
    outs = [t for t in tgt if t[1].startswith('0x') and not (cave_va <= int(t[1], 16) < cave_va + cave_len)]
    expect = [('jmp', hex(JOIN)), ('call', hex(IOWRITE8)), ('call', hex(IOREAD8)), ('jmp', hex(JOIN))]
    if outs != expect:
        errs.append(f'external control transfers {outs} != {expect}')
    return errs, ins


def main(src, out_p):
    img = open(src, 'rb').read()
    fl, _, _ = files(img, 0x190000)
    f = [x for x in fl if x['guid'] == GUID][0]
    raw = f['raw']
    secs = sections(raw[0x18:])
    assert [s['type'] for s in secs] == [0x13, 0x01]
    dep, cmp_ = secs
    sb = raw[0x18 + cmp_['off']:0x18 + cmp_['off'] + cmp_['size']]
    ulen, ct = struct.unpack_from('<IB', sb, 4)
    dec = efidecomp.decompress(sb[9:], 5)
    inner = sections(dec)
    assert [t['type'] for t in inner] == [0x10, 0x15]
    pe_sec, ui_sec = inner
    pe = dec[4:pe_sec['size']]
    log = []
    new_pe, cave_va, cave_len = patch_pe(pe, log)
    errs, ins = verify_pe(pe, new_pe, cave_va, cave_len)
    for i in ins:
        log.append(f'    {i.address:06x}: {i.bytes.hex():24} {i.mnemonic} {i.op_str}')
    if errs:
        print('\n'.join(log)); raise SystemExit('PE verification failed: ' + '; '.join(errs))
    # rebuild inner stream: PE section, pad4, UI section, pad4
    s = bytearray((4 + len(new_pe)).to_bytes(3, 'little') + b'\x10' + new_pe)
    s += b'\0' * ((-len(s)) % 4)
    s += dec[ui_sec['off']:ui_sec['off'] + ui_sec['size']]
    s += b'\0' * ((-len(s)) % 4)
    s = bytes(s)
    enc = tianocomp.compress(s)
    assert efidecomp.decompress(enc, 5) == s
    payload = struct.pack('<IB', len(s), 1) + enc
    csec = (4 + len(payload)).to_bytes(3, 'little') + b'\x01' + payload
    body = raw[0x18 + dep['off']:0x18 + dep['off'] + dep['size']]
    body += b'\0' * ((-len(body)) % 4)
    newraw = fix_ffs_checksums(bytes(raw[:0x18]) + body + csec)
    log.append(f'  FFS {f["size"]:#x} -> {len(newraw):#x}')
    # re-lay DXE volume
    pad = [x for x in fl if x['type'] == 0xF0][0]
    head, tail = fl[:fl.index(pad)], fl[fl.index(pad) + 1:]
    assert [x['guid'] for x in tail] == ['05CA01FC-0FC1-11DC-9011-00173153EBA8']
    pos = head[0]['off']; blob = bytearray()
    for x in head:
        r = newraw if x['guid'] == GUID else x['raw']
        if is_xip_flash_image(x['raw'], x['off'], len(img)):
            r = place_and_rebase(r, pos, len(img), log, x['name'] or x['guid'])
        blob += r; pos += len(r)
        p = (-pos) % 8; blob += b'\xff' * p; pos += p
    pad_size = tail[0]['off'] - pos
    assert pad_size >= 0x18
    blob += make_pad(pad['raw'], pad_size)
    new = bytearray(img); new[head[0]['off']:tail[0]['off']] = blob; new = bytes(new)
    open(out_p, 'wb').write(new)
    log.append(f'  DXE pad {pad["size"]:#x} -> {pad_size:#x}')
    print('\n'.join(log))
    print('sha256', hashlib.sha256(new).hexdigest())


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
