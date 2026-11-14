import struct, sys
sys.path.insert(0, '.')
from dag import load, build
ORDER = [[31,30,29,24,23,22,21],[15,14,13],[12,11,10],[20,19,18,17,16]]
out = []
out.append('''//! Which encodings of four AArch64 encoding classes Capstone 5 accepts.
//!
//! GENERATED, do not edit by hand. The tables were produced by decoding every
//! word of the classes with bits 28:25 = 0000 (reserved / SME), 0010 (SVE),
//! 0111 and 1111 (scalar floating point and Advanced SIMD) with the Capstone
//! build the previous implementation linked against, and folding the 2^28
//! answers per class into a small decision table:
//!
//! - `l1` is indexed by bits 31:29 and 24:21 and names a row of `l2`;
//! - `l2` is indexed by bits 15:13 and names a row of `l3`;
//! - `l3` is indexed by bits 12:10 and names a row of `l4`;
//! - `l4` is indexed by bits 20:16 and names a pattern;
//! - a pattern is indexed by bits 9:5 and holds one bit per value of bits 4:0.

pub(super) struct ClassTable {
    pub l1: &'static [u8; 128],
    pub l2: &'static [[u8; 8]],
    pub l3: &'static [[u8; 8]],
    pub l4: &'static [[u8; 32]],
    pub patterns: &'static [[u32; 32]],
}
''')
def fmt_rows(rows, per=32):
    lines = []
    for r in rows:
        lines.append('    [' + ', '.join(str(v) for v in r) + '],')
    return '\n'.join(lines)
for cls in ['0000','0010','0111','1111']:
    keys, pats = load(cls)
    st, memo = build(keys, ORDER)
    lv = [sorted(m.items(), key=lambda kv: kv[1]) for m in memo]
    assert len(lv[0]) == 1
    for l in lv: assert len(l) <= 256
    assert len(pats) <= 256
    l1 = lv[0][0][0]
    name = 'CLASS_' + cls
    out.append('#[rustfmt::skip]\npub(super) static %s: ClassTable = ClassTable {' % name)
    out.append('    l1: &[' + ', '.join(str(v) for v in l1) + '],')
    out.append('    l2: &[\n' + fmt_rows([n for n, _ in lv[1]]).replace('    [', '        [') + '\n    ],')
    out.append('    l3: &[\n' + fmt_rows([n for n, _ in lv[2]]).replace('    [', '        [') + '\n    ],')
    out.append('    l4: &[\n' + fmt_rows([n for n, _ in lv[3]]).replace('    [', '        [') + '\n    ],')
    prow = []
    for p in pats:
        rows = []
        for rn in range(32):
            m = 0
            for rd in range(32):
                lo = (rn << 5) | rd
                if p[lo >> 3] >> (lo & 7) & 1: m |= 1 << rd
            rows.append('0x%x' % m)
        prow.append('        [' + ', '.join(rows) + '],')
    out.append('    patterns: &[\n' + '\n'.join(prow) + '\n    ],')
    out.append('};\n')
src = '\n'.join(out)
# wrap long lines at ~110 cols
import textwrap
wrapped = []
for line in src.split('\n'):
    if len(line) > 112 and not line.startswith('//'):
        indent = len(line) - len(line.lstrip())
        parts = textwrap.wrap(line.strip(), 108 - indent - 4, break_long_words=False)
        wrapped.append(' ' * indent + parts[0])
        for p in parts[1:]: wrapped.append(' ' * (indent + 4) + p)
    else: wrapped.append(line)
open('/Users/xnu/products/brew/machoexplorer/crates/moex-core/src/macho/xref/a64_tables.rs','w').write('\n'.join(wrapped))
print(len(src), 'bytes')
