#!/usr/bin/env python3
"""Synthetic Mach-O files exercising every dyld-info code path of the C++ walkers."""
import struct, sys
u16 = lambda v: struct.pack("<H", v & 0xFFFF)
u32 = lambda v: struct.pack("<I", v & 0xFFFFFFFF)
u64 = lambda v: struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)

def uleb(v):
    out = bytearray()
    while True:
        b = v & 0x7F; v >>= 7
        if v: out.append(b | 0x80)
        else: out.append(b); return bytes(out)

def rebase_stream():
    s = bytearray()
    s += bytes([0x11, 0x21]) + uleb(0x1234)          # type, segment+offset
    s += bytes([0x30]) + uleb(0x7FFFFFFFFF)           # ADD_ADDR_ULEB (big)
    s += bytes([0x43, 0x5F])                          # scaled, imm times
    s += bytes([0x60]) + uleb(0x1_0000_0005)          # uleb times (truncates to int)
    s += bytes([0x70]) + uleb(0xFFFFFFFFFFFFFFFF)     # add addr uleb (max)
    s += bytes([0x80]) + uleb(3) + uleb(0x80000001)   # times skipping
    s += bytes([0x12, 0x13, 0x1F, 0x2F]) + uleb(8)    # other types, bad segment index
    s += bytes([0x30]) + b"\x80" * 11 + b"\x00" + uleb(1)  # overlong uleb: size 0, bytes re-decoded as opcodes
    s += bytes([0x00, 0x11, 0x22])                    # DONE then ignored tail
    return bytes(s)

def bind_stream(tail=b""):
    s = bytearray()
    s += bytes([0x11, 0x20]) + uleb(300)              # ordinal imm, ordinal uleb
    s += bytes([0x30, 0x3F, 0x3E, 0x3D])              # special 0, -1, -2, -3
    s += bytes([0x48]) + b"_short\0"
    s += bytes([0x41]) + b"_a_much_longer_symbol_name\0"
    s += bytes([0x40]) + b"\0"                         # empty name
    s += bytes([0x40]) + b"_utf8_\xc3\xa9_bad_\xff\0"
    s += bytes([0x51, 0x52, 0x53, 0x5F])
    s += bytes([0x60, 0x7E, 0x60]) + b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x7f"  # sleb -2, i64::MIN
    s += bytes([0x72]) + uleb(0x4010) + bytes([0x7F]) + uleb(1)
    s += bytes([0x80]) + uleb(0x123456789AB)
    s += bytes([0x90])
    s += bytes([0xA0]) + uleb(0x18)
    s += bytes([0xB7])
    s += bytes([0xC0]) + uleb(0x1_0000_0002) + uleb(0xFFFFFFFF)
    s += bytes([0xD0, 0xE1, 0xF2])                    # unknown (threaded etc.)
    s += bytes([0x20]) + b"\x80" * 11                 # malformed uleb
    s += bytes([0x60]) + b"\xff" * 11                 # malformed sleb
    s += tail
    return bytes(s)

def classic_trie():
    # root with 4 children; nodes include re-export, resolver, cycle, out-of-range, long labels
    t = bytearray()
    def node_at(off):
        assert len(t) <= off, (len(t), off); t.extend(b"\xEE" * (off - len(t)))
    t += bytes([0x00, 0x06])
    t += b"_\0" + uleb(0x40)
    t += b"_a_rather_long_edge_label\0" + uleb(0x50)
    t += b"cyc\0" + uleb(0)
    t += b"far\0" + uleb(0x4000)
    t += b"big\0" + uleb(0x1FFFFFFFFF)
    t += b"\xc3\xa9\xff\0" + uleb(0x60)
    node_at(0x40); t += bytes([0x03, 0x00]) + uleb(0x1234) + bytes([0x02]) + b"x\0" + uleb(0x70) + b"y\0" + uleb(0x90)
    node_at(0x50); t += bytes([0x09, 0x08, 0x02]) + b"_orig\0" + bytes([0x00])   # re-export (misread by classic walker)
    node_at(0x60); t += bytes([0x05, 0x10]) + uleb(0x3000) + uleb(0x4000) + bytes([0x00])  # resolver
    node_at(0x70); t += bytes([0x04, 0x05]) + uleb(0xFFFFFFFFFF) + bytes([0x01]) + b"self\0" + uleb(0x70)  # TLS+weak, huge offset
    node_at(0x90); t += bytes([0x02, 0x80])            # truncated-ish flags (uleb continues into next bytes)
    node_at(0xA0); t += bytes([0x00, 0x03]) + b"unterminated"
    return bytes(t)

def modern_trie(variant):
    t = bytearray()
    def node_at(off):
        assert len(t) <= off, (len(t), off); t.extend(b"\xEE" * (off - len(t)))
    t += bytes([0x00, 0x09])
    t += b"_\0" + uleb(0xC0)
    t += b"re1\0" + uleb(0xE0)
    t += b"re2\0" + uleb(0x100)
    t += b"re3\0" + uleb(0x110)
    t += b"res\0" + uleb(0x120)
    t += b"cyc\0" + uleb(0)
    t += b"far\0" + uleb(0x100000)
    t += b"\xc3\xa9\xff\0" + uleb(0x140)
    t += b"wrap\0" + uleb(0x160)
    node_at(0xC0); t += uleb(3) + bytes([0x00]) + uleb(0x1234) + bytes([0x03]) + b"tls\0" + uleb(0x180) + b"weak\0" + uleb(0x190) + b"trunc\0" + uleb(0x1A0)
    node_at(0xE0); t += uleb(8) + bytes([0x08, 0x02]) + b"_orig\0" + bytes([0x00])
    node_at(0x100); t += uleb(3) + bytes([0x08, 0x01, 0x00]) + bytes([0x00])         # reexport, name eaten -> <none>
    node_at(0x110); t += uleb(4) + bytes([0x08, 0x01, 0x41, 0x00]) + bytes([0x00])   # reexport -> <same-name>
    node_at(0x120); t += uleb(6) + bytes([0x10]) + uleb(0x3000) + uleb(0x4000) + bytes([0x01]) + b"more\0" + uleb(0x1B0)
    node_at(0x140); t += uleb(0x81) + b"\x00" * 4       # terminal size bigger than remaining: depends on blob size
    node_at(0x160)
    if variant == 0: t += uleb((1 << 64) - 0x30)        # wraps to before the node (inside the blob/file)
    else: t += uleb((1 << 64) - 0x200)                 # wraps to before the blob, still inside the file
    node_at(0x180); t += uleb(2) + bytes([0x01, 0x10, 0x00])
    node_at(0x190); t += uleb(2) + bytes([0x04, 0x20, 0x00])
    node_at(0x1A0); t += uleb(2) + bytes([0x80])        # flags uleb runs past terminal
    node_at(0x1B0); t += uleb(2) + bytes([0x18, 0x05, 0x02]) + b"q\0" + uleb(0x1B0) + b"zz"  # reexport+resolver flags, self loop, unterminated edge
    return bytes(t)

NEXT64 = lambda n: (n & 0x7FF) << 51
RAW64 = [
    0x8000000005000003,  # bind / arm64e auth-rebase
    0x4000123400000007,  # arm64e bind
    0xC003BEEF00000009,  # arm64e auth-bind
    0x00002D0000012340,  # rebase / arm64e rebase
    0x0000000000004000,
    0x8001FFFF89ABCDEF,
    0x0000000FFFFFFFFF,
]
RAW32 = [0x00001000, 0x03FFFFFF, 0x00000000, 0x02345678]

def chained(imports_format, data_base):
    """Returns (blob, data) where data is placed at file offset data_base."""
    data = bytearray()
    blob = bytearray(b"\0" * 28)
    formats = list(range(0, 14)) + [2, 6]
    nseg = len(formats) + 4
    starts_off = 0x1C
    blob += u32(nseg)
    table_at = len(blob)
    blob += b"\0" * (4 * nseg)
    seg_offs = []
    for i, fmt in enumerate(formats):
        while len(blob) % 8: blob += b"\0"
        seg_offs.append(len(blob))
        seg_data = data_base + len(data)
        wide = fmt in (1, 2, 6, 7, 8, 9, 10, 11, 12)
        page_size = 0x100
        if i == len(formats) - 1:   # chain that walks off the end of the file
            seg_data_field = None
        blob += u32(24 + 6 + 4) + u16(page_size) + u16(fmt) + u64(seg_data) + u32(0) + u16(3) + u16(0xAAAA)
        # page starts at +24 (the C++ reader's idea), then the overflow table
        blob += u16(0x10) + u16(0xFFFF) + u16(0x8001)
        blob += u16(0x7777) + u16(0x0020) + u16(0x0040) + u16(0x8060)   # overflow[0] unused, [1],[2],[3 last]
        pages = bytearray(b"\0" * (3 * page_size))
        def put_chain(off, n):
            for k in range(n):
                last = k == n - 1
                if wide:
                    raw = RAW64[(k + i) % len(RAW64)] & ~NEXT64(0x7FF) | (0 if last else NEXT64(2 + (k % 2)))
                    pages[off:off + 8] = u64(raw); off += 4 * (2 + (k % 2))
                else:
                    raw = RAW32[(k + i) % len(RAW32)] & ~(0x1F << 26) | (0 if last else (1 + (k % 3)) << 26)
                    pages[off:off + 4] = u32(raw); off += 4 * (1 + (k % 3))
        put_chain(0x10, 7)
        put_chain(2 * page_size + 0x20, 2)
        put_chain(2 * page_size + 0x40, 1)
        put_chain(2 * page_size + 0x60, 3)
        data += pages
    # extra table entries: 0, out of range, and a multi page whose overflow list never ends
    while len(blob) % 8: blob += b"\0"
    endless = len(blob)
    blob += u32(0) + u16(0x10) + u16(3) + u64(data_base) + u32(0) + u16(1) + u16(0)
    blob += u16(0x8000)
    blob += b"".join(u16(0x10 + 4 * (k % 3)) for k in range(40))  # no "last" bit; runs into what follows
    while len(blob) % 8: blob += b"\0"
    huge = len(blob)   # segment_offset near u64 max: wraps to file offset 0
    blob += u32(0) + u16(0x1000) + u16(2) + u64(0xFFFFFFFFFFFFE000) + u32(0) + u16(2) + u16(0)
    blob += u16(0xFFFF) + u16(0x1000)
    entries = seg_offs + [0, 0xFFFFFFF0, endless, huge]
    assert len(entries) == nseg
    for k, e in enumerate(entries):
        blob[table_at + 4 * k: table_at + 4 * k + 4] = u32(e)
    while len(blob) % 8: blob += b"\0"
    imports_off = len(blob)
    names = [b"_puts", b"_printf", b"", b"_caf\xc3\xa9_\xff", b"_last"]
    sym = bytearray(b"\0")
    name_offs = []
    for n in names:
        name_offs.append(len(sym)); sym += n + b"\0"
    name_offs.append(0x7FFFFF if imports_format != 3 else 0xFFFFFFFF)   # invalid
    name_offs.append(len(sym))                                         # unterminated (blob ends)
    sym += b"_unterminated"
    count = len(name_offs)
    for k, no in enumerate(name_offs):
        lib = [1, 2, 0xFD, 0xFE, 0xFF, 0, 3][k]; weak = k % 2
        if imports_format in (1, 2):
            blob += u32(lib | (weak << 8) | (no << 9))
            if imports_format == 2: blob += struct.pack("<i", [0, -1, 5, -2**31, 2**31 - 1, 7, 8][k])
        elif imports_format == 3:
            blob += u64((lib | 0xFF00) | (weak << 16) | (0x7FFF << 17) | (no << 32)) + u64([0, 1, 2**64 - 1, 0x1234, 5, 6, 7][k])
        else:
            blob += u32(0xDEADBEEF)
    symbols_off = len(blob)
    blob += sym
    declared = count + 1 if imports_format in (1, 2, 3) else count   # one more than fits
    blob[0:28] = u32(0) + u32(starts_off) + u32(imports_off) + u32(symbols_off) + u32(declared) + u32(imports_format) + u32(1)
    return bytes(blob), bytes(data)

def build(path, is64=True, imports_format=1, variant=0, lazy_tail=b""):
    LC_SEGMENT, LC_SEGMENT_64 = 0x1, 0x19
    def segment(name, vmaddr, vmsize, fileoff, filesize):
        n = name.encode().ljust(16, b"\0")
        if is64: return u32(LC_SEGMENT_64) + u32(72) + n + u64(vmaddr) + u64(vmsize) + u64(fileoff) + u64(filesize) + u32(7) + u32(5) + u32(0) + u32(0)
        return u32(LC_SEGMENT) + u32(56) + n + u32(vmaddr) + u32(vmsize) + u32(fileoff) + u32(filesize) + u32(7) + u32(5) + u32(0) + u32(0)
    hdr_size = 32 if is64 else 28
    seg_size = 72 if is64 else 56
    ncmds = 3 + 3
    sizeofcmds = 3 * seg_size + 48 + 16 + 16
    blobs_at = (hdr_size + sizeofcmds + 0xFFF) & ~0xFFF
    # layout of the tail
    parts = {}
    cur = blobs_at
    def place(name, data):
        nonlocal cur
        parts[name] = (cur, data); cur += len(data); cur = (cur + 7) & ~7
    place("rebase", rebase_stream())
    place("bind", bind_stream())
    place("weak", bind_stream(b"\x00\x90"))              # DONE stops a weak walk
    place("lazy", bind_stream(b"\x00\x90\x00\x72\x10\x90\x00" + lazy_tail))
    place("export", classic_trie())
    place("trie", modern_trie(variant))
    cf_at = cur
    data_base = cf_at + 0x1000
    cf, data = chained(imports_format, data_base)
    assert len(cf) <= 0x1000, hex(len(cf))
    place("fixups", cf)
    cur = data_base
    place("data", data)
    total = cur
    lcs = b""
    lcs += segment("__TEXT", 0x100000000 if is64 else 0x1000, 0x4000, 0, blobs_at)
    lcs += segment("__DATA", 0x100004000 if is64 else 0x5000, 0x4000, blobs_at, 0x1000)
    lcs += segment("__LINKEDIT", 0x100008000 if is64 else 0x9000, 0x8000, blobs_at, total - blobs_at)
    p = parts
    lcs += u32(0x80000022) + u32(48) + b"".join(u32(p[k][0]) + u32(len(p[k][1])) for k in ("rebase", "bind", "weak", "lazy", "export"))
    lcs += u32(0x80000033) + u32(16) + u32(p["trie"][0]) + u32(len(p["trie"][1]))
    lcs += u32(0x80000034) + u32(16) + u32(p["fixups"][0]) + u32(len(p["fixups"][1]))
    assert len(lcs) == sizeofcmds
    if is64: hdr = u32(0xFEEDFACF) + u32(0x0100000C) + u32(0) + u32(6) + u32(ncmds) + u32(sizeofcmds) + u32(0) + u32(0)
    else: hdr = u32(0xFEEDFACE) + u32(12) + u32(9) + u32(6) + u32(ncmds) + u32(sizeofcmds) + u32(0)
    f = bytearray(hdr + lcs)
    for name, (at, data) in parts.items():
        f.extend(b"\0" * (at - len(f))); f.extend(data)
    f.extend(b"\0" * (total - len(f)))
    open(path, "wb").write(f)

build("synth_a", True, 1, 0)
build("synth_b", True, 2, 1)
build("synth_c", True, 3, 0, lazy_tail=b"\x40_unterminated_name")
build("synth_d", True, 9, 1)
build("synth_32", False, 1, 0)
