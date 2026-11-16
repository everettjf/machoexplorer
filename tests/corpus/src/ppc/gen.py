#!/usr/bin/env python3
"""Builds tests/corpus/bin/hello_ppc.o: a big-endian (PowerPC) object file.

No current toolchain targets Mach-O PowerPC, so the file is assembled by
hand: real PowerPC instructions, a C string section, an 8-byte literal, a
module initializer pointer, a symbol table and relocation entries, all in
big-endian byte order with the bit fields laid out as big-endian compilers
do. `otool -l`, `otool -rv`, `otool -s` and `nm` read the result.

    python3 tests/corpus/src/ppc/gen.py tests/corpus/bin/hello_ppc.o
"""
import struct
import sys

MH_MAGIC = 0xFEEDFACE
CPU_TYPE_POWERPC = 18
MH_OBJECT = 1
MH_SUBSECTIONS_VIA_SYMBOLS = 0x2000
LC_SEGMENT, LC_SYMTAB, LC_DYSYMTAB = 0x1, 0x2, 0xB
S_CSTRING_LITERALS, S_8BYTE_LITERALS, S_MOD_INIT_FUNC_POINTERS = 0x2, 0x4, 0x9
S_ATTR_PURE_INSTRUCTIONS, S_ATTR_SOME_INSTRUCTIONS = 0x80000000, 0x400
PPC_RELOC_VANILLA, PPC_RELOC_BR24 = 0, 3
N_EXT, N_SECT = 0x01, 0x0E


def be32(*values):
    return b"".join(struct.pack(">I", v & 0xFFFFFFFF) for v in values)


def name16(text):
    return text.encode().ljust(16, b"\0")


# _main at 0, _helper at 0x24.
CODE = be32(
    0x7C0802A6,  # 00 mflr  r0
    0x90010008,  # 04 stw   r0, 8(r1)
    0x9421FFC0,  # 08 stwu  r1, -64(r1)
    0x48000019,  # 0c bl    0x24            (_helper)
    0x48000001,  # 10 bl    _puts           (relocation)
    0x38210040,  # 14 addi  r1, r1, 64
    0x80010008,  # 18 lwz   r0, 8(r1)
    0x7C0803A6,  # 1c mtlr  r0
    0x4E800020,  # 20 blr
    0x3860002A,  # 24 li    r3, 42
    0x4E800020,  # 28 blr
)
CSTRING = b"hello\0ppc\0"
LITERAL8 = struct.pack(">d", 2.5)
MOD_INIT = be32(0)  # relocated to _helper

# (sectname, segname, contents, alignment as a power of two, flags)
SECTIONS = [
    ("__text", "__TEXT", CODE, 2, S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS),
    ("__cstring", "__TEXT", CSTRING, 0, S_CSTRING_LITERALS),
    ("__literal8", "__TEXT", LITERAL8, 3, S_8BYTE_LITERALS),
    ("__mod_init_func", "__DATA", MOD_INIT, 2, S_MOD_INIT_FUNC_POINTERS),
]

# (name, n_type, n_sect, n_value)
SYMBOLS = [
    ("_main", N_SECT | N_EXT, 1, 0x00),
    ("_helper", N_SECT | N_EXT, 1, 0x24),
    ("_puts", N_EXT, 0, 0),
]


def reloc(address, symbolnum, pcrel, length, extern, kind):
    # Big-endian bit field order: r_symbolnum:24, r_pcrel:1, r_length:2,
    # r_extern:1, r_type:4.
    word = symbolnum << 8 | pcrel << 7 | length << 5 | extern << 4 | kind
    return be32(address, word)


# Per section index: its relocation entries.
RELOCS = {
    0: reloc(0x10, 2, 1, 2, 1, PPC_RELOC_BR24),
    3: reloc(0x00, 1, 0, 2, 1, PPC_RELOC_VANILLA),
}


def build():
    sizeofcmds = (56 + 68 * len(SECTIONS)) + 24 + 80
    data_start = 28 + sizeofcmds

    # Lay the sections out at their alignment, addresses from 0.
    placed, address = [], 0
    for _, _, contents, align, _ in SECTIONS:
        address = (address + (1 << align) - 1) & ~((1 << align) - 1)
        placed.append(address)
        address += len(contents)
    vmsize = address
    body = bytearray(vmsize)
    for start, (_, _, contents, _, _) in zip(placed, SECTIONS):
        body[start : start + len(contents)] = contents

    reloc_start = data_start + len(body)
    reloc_offsets, at = {}, reloc_start
    for index in sorted(RELOCS):
        reloc_offsets[index] = at
        at += len(RELOCS[index])
    symoff = at
    strings = b"\0"
    nlists = b""
    for name, n_type, n_sect, n_value in SYMBOLS:
        nlists += be32(len(strings)) + bytes([n_type, n_sect]) + b"\0\0" + be32(n_value)
        strings += name.encode() + b"\0"
    strings = strings.ljust((len(strings) + 3) & ~3, b"\0")
    stroff = symoff + len(nlists)

    out = be32(
        MH_MAGIC, CPU_TYPE_POWERPC, 0, MH_OBJECT, 3, sizeofcmds, MH_SUBSECTIONS_VIA_SYMBOLS
    )
    out += be32(LC_SEGMENT, 56 + 68 * len(SECTIONS)) + name16("")
    out += be32(0, vmsize, data_start, len(body), 7, 7, len(SECTIONS), 0)
    for index, (start, (sect, seg, contents, align, flags)) in enumerate(zip(placed, SECTIONS)):
        entries = RELOCS.get(index, b"")
        out += name16(sect) + name16(seg)
        out += be32(
            start,
            len(contents),
            data_start + start,
            align,
            reloc_offsets.get(index, 0),
            len(entries) // 8,
            flags,
            0,
            0,
        )
    out += be32(LC_SYMTAB, 24, symoff, len(SYMBOLS), stroff, len(strings))
    # No local symbols; two defined external ones, then one undefined.
    out += be32(LC_DYSYMTAB, 80, 0, 0, 0, 2, 2, 1) + be32(*([0] * 12))
    assert len(out) == data_start
    out += bytes(body)
    for index in sorted(RELOCS):
        out += RELOCS[index]
    out += nlists + strings
    return out


if __name__ == "__main__":
    with open(sys.argv[1], "wb") as f:
        f.write(build())
