"""Pure-Python EFI 1.1 / Tiano decompressor (LZ77 + Huffman, per EDK2 BaseUefiDecompressLib)."""
import struct

NC = 510
NT = 19
CBIT = 9
TBIT = 5
MAXNP = 31


class BitReader:
    def __init__(self, data):
        self.v = int.from_bytes(data, 'big')
        self.total = len(data) * 8
        self.pos = 0

    def peek(self, n):
        sh = self.total - self.pos - n
        if sh >= 0:
            return (self.v >> sh) & ((1 << n) - 1)
        return (self.v << (-sh)) & ((1 << n) - 1)

    def get(self, n):
        if n == 0:
            return 0
        r = self.peek(n)
        self.pos += n
        return r


def make_table(lens):
    """Return dict (len, code) -> symbol, canonical MSB-first."""
    table = {}
    code = 0
    maxlen = max(lens) if lens else 0
    for l in range(1, maxlen + 1):
        for sym, sl in enumerate(lens):
            if sl == l:
                table[(l, code)] = sym
                code += 1
        code <<= 1
    return table, maxlen


def decode(br, tbl):
    table, maxlen, const = tbl
    if const is not None:
        return const
    for l in range(1, maxlen + 1):
        s = table.get((l, br.peek(l)))
        if s is not None:
            br.pos += l
            return s
    raise ValueError("bad huffman code")


def read_pt_len(br, nn, nbit, special):
    number = br.get(nbit)
    if number == 0:
        c = br.get(nbit)
        return ({}, 0, c)
    lens = [0] * nn
    i = 0
    while i < number and i < nn:
        c = br.peek(3)
        if c == 7:
            br.pos += 3
            while br.get(1):
                c += 1
        else:
            br.pos += 3
        lens[i] = c
        i += 1
        if i == special:
            z = br.get(2)
            i += z
    t, m = make_table(lens)
    return (t, m, None)


def read_c_len(br, pt):
    number = br.get(CBIT)
    if number == 0:
        c = br.get(CBIT)
        return ({}, 0, c)
    lens = [0] * NC
    i = 0
    while i < number and i < NC:
        c = decode(br, pt)
        if c <= 2:
            if c == 0:
                c = 1
            elif c == 1:
                c = br.get(4) + 3
            else:
                c = br.get(CBIT) + 20
            i += c
        else:
            lens[i] = c - 2
            i += 1
    t, m = make_table(lens)
    return (t, m, None)


def decompress(buf, pbit):
    comp_size, orig_size = struct.unpack_from('<II', buf, 0)
    br = BitReader(buf[8:8 + comp_size])
    out = bytearray()
    block = 0
    ct = pt = None
    while len(out) < orig_size:
        if block == 0:
            block = br.get(16)
            tt = read_pt_len(br, NT, TBIT, 3)
            ct = read_c_len(br, tt)
            pt = read_pt_len(br, MAXNP, pbit, -1)
        block -= 1
        c = decode(br, ct)
        if c < 256:
            out.append(c)
        else:
            n = c - 253
            v = decode(br, pt)
            p = v if v <= 1 else (1 << (v - 1)) + br.get(v - 1)
            idx = len(out) - p - 1
            if idx < 0:
                raise ValueError("bad distance")
            for _ in range(n):
                out.append(out[idx])
                idx += 1
    if br.pos > br.total + 32:
        raise ValueError("overrun")
    return bytes(out[:orig_size])


def auto(buf):
    last = None
    for pbit in (4, 5):
        try:
            return decompress(buf, pbit), pbit
        except Exception as e:
            last = e
    raise last
