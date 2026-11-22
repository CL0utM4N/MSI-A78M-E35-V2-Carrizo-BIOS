"""Tiano (EFI_STANDARD_COMPRESSION, PBIT=5) encoder compatible with EDK2 BaseUefiDecompressLib / TianoDecompress.

Format (matches efidecomp.decompress(..., pbit=5)):
  u32 compressed_size, u32 original_size, then MSB-first bitstream of blocks:
    16-bit block size (number of codes)
    T tree  (NT=19 symbols, TBIT=5, special skip after index 3)
    C tree  (NC=510 symbols, CBIT=9, lengths coded with the T tree)
    P tree  (NP=20 symbols, PBIT=5)
    codes: C<256 literal, C>=256 match of length C-253 followed by a P code for distance-1
"""
import heapq, struct

NC, NT, NP = 510, 19, 20
CBIT, TBIT, PBIT = 9, 5, 5
MAXLEN = 16
WSIZE = 1 << 19
MAXMATCH, THRESHOLD = 256, 3
BLOCK = 0x3FFF


class BitWriter:
    def __init__(self):
        self.acc = 0
        self.n = 0
        self.out = bytearray()

    def put(self, nbits, val):
        if nbits == 0:
            return
        assert 0 <= val < (1 << nbits), (nbits, val)
        self.acc = (self.acc << nbits) | val
        self.n += nbits
        while self.n >= 8:
            self.n -= 8
            self.out.append((self.acc >> self.n) & 0xFF)
        self.acc &= (1 << self.n) - 1

    def flush(self):
        if self.n:
            self.out.append((self.acc << (8 - self.n)) & 0xFF)
            self.acc = 0
            self.n = 0
        return bytes(self.out)


def package_merge(freqs, limit):
    """Optimal length-limited prefix code lengths (complete when >=2 symbols)."""
    syms = [(f, i) for i, f in enumerate(freqs) if f > 0]
    lens = [0] * len(freqs)
    if len(syms) <= 1:
        return lens
    syms.sort()
    items = [(f, [i]) for f, i in syms]
    cur = items[:]
    for _ in range(limit - 1):
        pk = []
        for k in range(0, len(cur) - 1, 2):
            pk.append((cur[k][0] + cur[k + 1][0], cur[k][1] + cur[k + 1][1]))
        cur = sorted(items + pk, key=lambda x: x[0])
    for f, ids in cur[:2 * len(syms) - 2]:
        for i in ids:
            lens[i] += 1
    return lens


def canonical(lens):
    codes = [0] * len(lens)
    code = 0
    for l in range(1, MAXLEN + 1):
        for s, sl in enumerate(lens):
            if sl == l:
                codes[s] = code
                code += 1
        code <<= 1
    return codes


def kraft_complete(lens):
    used = [l for l in lens if l]
    if len(used) < 2:
        return True
    return sum(1 << (MAXLEN - l) for l in used) == 1 << MAXLEN


def lz77(data):
    """Greedy+lazy LZ77 with hash chains. Returns list of ints (literal) or tuples (len, dist)."""
    n = len(data)
    head = {}
    prev = [-1] * n
    toks = []
    MAXCHAIN = 96

    def insert(i):
        if i + 2 < n:
            h = data[i:i + 3]
            prev[i] = head.get(h, -1)
            head[h] = i

    def best(i):
        if i + 2 >= n:
            return 0, 0
        h = data[i:i + 3]
        j = head.get(h, -1)
        bl, bd = 0, 0
        lim = min(MAXMATCH, n - i)
        chain = 0
        while j >= 0 and i - j < WSIZE and chain < MAXCHAIN:
            if data[j + bl:j + bl + 1] == data[i + bl:i + bl + 1] if bl < lim else False:
                l = 0
                # extend
                while l < lim and data[j + l] == data[i + l]:
                    l += 1
                if l > bl:
                    bl, bd = l, i - j
                    if l == lim:
                        break
            j = prev[j]
            chain += 1
        return bl, bd

    i = 0
    while i < n:
        l, d = best(i)
        if l >= THRESHOLD and i + 1 < n:
            insert(i)
            l2, d2 = best(i + 1)
            if l2 > l + 1:
                toks.append(data[i])
                i += 1
                l, d = l2, d2
            else:
                # undo nothing; continue with current match
                pass
            if l >= THRESHOLD:
                toks.append((l, d))
                # insert covered positions (i already inserted if we didn't move)
                start = i if toks and isinstance(toks[-2] if len(toks) > 1 else None, int) and False else i
                for k in range(i + (0 if head.get(data[i:i+3], -2) != i else 1), i + l):
                    insert(k)
                i += l
                continue
        if l >= THRESHOLD:
            toks.append((l, d))
            for k in range(i, i + l):
                insert(k)
            i += l
        else:
            toks.append(data[i])
            insert(i)
            i += 1
    return toks


def write_pt(bw, lens, nbit, special, freqs):
    n = len(lens)
    while n > 0 and lens[n - 1] == 0:
        n -= 1
    used = [s for s, f in enumerate(freqs) if f]
    if len(used) <= 1:
        bw.put(nbit, 0)
        bw.put(nbit, used[0] if used else 0)
        return
    bw.put(nbit, n)
    i = 0
    while i < n:
        k = lens[i]
        if k <= 6:
            bw.put(3, k)
        else:
            bw.put(3, 7)
            for _ in range(k - 7):
                bw.put(1, 1)
            bw.put(1, 0)
        i += 1
        if i == special:
            z = 0
            while z < 3 and i + z < n and lens[i + z] == 0:
                z += 1
            bw.put(2, z)
            i += z


def c_len_symbols(clens):
    n = NC
    while n > 0 and clens[n - 1] == 0:
        n -= 1
    syms = []
    i = 0
    while i < n:
        k = clens[i]
        i += 1
        if k == 0:
            cnt = 1
            while i < n and clens[i] == 0:
                i += 1
                cnt += 1
            while cnt > 0:
                if cnt <= 2:
                    syms.append((0, None)); cnt -= 1
                elif cnt <= 18:
                    syms.append((1, cnt - 3)); cnt = 0
                elif cnt == 19:
                    syms.append((0, None)); syms.append((1, 15)); cnt = 0
                else:
                    r = min(cnt, 20 + (1 << CBIT) - 1)
                    syms.append((2, r - 20)); cnt -= r
        else:
            syms.append((k + 2, None))
    return n, syms


def encode_block(bw, toks):
    cf = [0] * NC
    pf = [0] * NP
    for t in toks:
        if isinstance(t, int):
            cf[t] += 1
        else:
            l, d = t
            cf[l + 253] += 1
            p = d - 1
            pf[p.bit_length() if p > 1 else p] += 1
    clens = package_merge(cf, MAXLEN)
    plens = package_merge(pf, MAXLEN)
    cused = [s for s in range(NC) if cf[s]]
    bw.put(16, len(toks))
    if len(cused) == 1:
        # degenerate C tree: T tree irrelevant
        bw.put(TBIT, 0); bw.put(TBIT, 0)
        bw.put(CBIT, 0); bw.put(CBIT, cused[0])
        ccodes, clens = [0] * NC, [0] * NC
    else:
        n, syms = c_len_symbols(clens)
        tf = [0] * NT
        for s, _ in syms:
            tf[s] += 1
        tlens = package_merge(tf, MAXLEN)
        assert kraft_complete(tlens) and kraft_complete(clens)
        write_pt(bw, tlens, TBIT, 3, tf)
        tcodes = canonical(tlens)
        tused = [s for s in range(NT) if tf[s]]
        bw.put(CBIT, n)
        for s, extra in syms:
            if len(tused) > 1:
                bw.put(tlens[s], tcodes[s])
            if s == 1:
                bw.put(4, extra)
            elif s == 2:
                bw.put(CBIT, extra)
        ccodes = canonical(clens)
    assert kraft_complete(plens)
    write_pt(bw, plens, PBIT, -1, pf)
    pcodes = canonical(plens)
    pused = [s for s in range(NP) if pf[s]]
    for t in toks:
        if isinstance(t, int):
            if len(cused) > 1:
                bw.put(clens[t], ccodes[t])
        else:
            l, d = t
            c = l + 253
            if len(cused) > 1:
                bw.put(clens[c], ccodes[c])
            p = d - 1
            v = p.bit_length() if p > 1 else p
            if len(pused) > 1:
                bw.put(plens[v], pcodes[v])
            if v > 1:
                bw.put(v - 1, p - (1 << (v - 1)))


def compress(data):
    toks = lz77(data)
    bw = BitWriter()
    for i in range(0, len(toks), BLOCK):
        encode_block(bw, toks[i:i + BLOCK])
    body = bw.flush()
    return struct.pack('<II', len(body), len(data)) + body
