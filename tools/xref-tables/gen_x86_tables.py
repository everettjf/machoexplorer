import collections, textwrap
def load(f):
    kinds = collections.OrderedDict()
    for l in open(f):
        k, ctx, op, mem, reg, mixed = l.split()
        kinds.setdefault(k, {})[(int(ctx), int(op))] = (int(mem), int(reg))
    return kinds
k64, k32 = load('scan64.txt'), load('scan32.txt')
out = ['''//! Which x86 opcodes Capstone 5 accepts, per opcode map and prefix context.
//!
//! GENERATED, do not edit by hand. Produced by decoding, with the Capstone
//! build the previous implementation linked against, every opcode of the
//! two- and three-byte, VEX, XOP and EVEX maps with every ModRM byte under
//! each prefix context, and folding the answers:
//!
//! - `profile_of[opcode]` names a row of `profiles`;
//! - a profile holds one shape index per context;
//! - a shape is `(memory forms valid by ModRM.reg, register forms valid by
//!   ModRM.reg * 8 + ModRM.rm)`.
//!
//! Contexts: legacy maps use `66 | rep << 1 | REX.W << 3` (rep: 0 none,
//! 1 = F3, 2 = F2); VEX and XOP use `pp | L << 2 | W << 3 | (vvvv != 1111)
//! << 4`; EVEX uses `pp | L'L << 2 | W << 4 | (vvvv != 1111) << 5 | b << 6`
//! (scanned without masking or zeroing).

pub(super) struct MapTable {
    pub contexts: usize,
    pub profile_of: &'static [u8; 256],
    pub profiles: &'static [u8],
    pub shapes: &'static [(u8, u64)],
}
''']
def wrap(prefix, items, indent=8):
    line = ', '.join(items)
    parts = textwrap.wrap(line, 100 - indent, break_long_words=False)
    return prefix + '\n' + '\n'.join(' ' * indent + p for p in parts)
def emit(name, rows, nctx_expected):
    ctxs = sorted(set(c for c, _ in rows))
    # contexts may be sparse (rep == 3 is unused): fill gaps with "nothing valid"
    nctx = max(ctxs) + 1
    shapes = sorted(set(rows.values()) | {(0, 0)})
    sid = {s: i for i, s in enumerate(shapes)}
    profs = []; pid = {}; profile_of = []
    for op in range(256):
        p = tuple(sid[rows.get((c, op), (0, 0))] for c in range(nctx))
        if p not in pid: pid[p] = len(profs); profs.append(p)
        profile_of.append(pid[p])
    assert len(profs) <= 256 and len(shapes) <= 256
    out.append('#[rustfmt::skip]\npub(super) static %s: MapTable = MapTable {' % name)
    out.append('    contexts: %d,' % nctx)
    out.append(wrap('    profile_of: &[', [str(v) for v in profile_of]) + ',\n    ],')
    out.append('    profiles: &[')
    for p in profs: out.append(wrap('        // profile %d' % pid[p], [str(v) for v in p]) + ',')
    out.append('    ],')
    out.append('    shapes: &[')
    for m, r in shapes: out.append('        (0x%02x, 0x%016x),' % (m, r))
    out.append('    ],\n};\n')
for mode, kinds in (('64', k64), ('32', k32)):
    for k in ('two', '38', '3a'):
        emit('MAP_%s_%s' % ({'two': '0F', '38': '0F38', '3a': '0F3A'}[k], mode), kinds[k], 0)
for k in ('vex1', 'vex2', 'vex3', 'xop8', 'xop9', 'xop10', 'evex1', 'evex2', 'evex3'):
    emit(k.upper(), k64[k], 0)
# x87: same for all contexts and modes?
x87 = {}
for kinds in (k64, k32):
    for (c, op), v in kinds['x87'].items():
        assert x87.setdefault(op, v) == v
out.append('/// x87 escape opcodes D8..=DF: `(memory forms by reg, register forms by reg * 8 + rm)`.')
out.append('#[rustfmt::skip]\npub(super) static X87: [(u8, u64); 8] = [')
for op in range(0xd8, 0xe0): out.append('    (0x%02x, 0x%016x),' % x87[op])
out.append('];\n')
bits = [0] * 4
for (c, sfx), (v, _) in k64['3dnow'].items():
    assert k32['3dnow'][(c, sfx)] == (v, _)
    if v: bits[sfx >> 6] |= 1 << (sfx & 63)
out.append('/// Valid 3DNow! opcode suffixes (`0F 0F /r ib`), one bit per value.')
out.append('pub(super) static NOW3D: [u64; 4] = [' + ', '.join('0x%016x' % b for b in bits) + '];')
src = '\n'.join(out) + '\n'
open('/Users/xnu/products/brew/machoexplorer/crates/moex-core/src/macho/xref/x86_tables.rs', 'w').write(src)
print(len(src), 'bytes', src.count('\n'), 'lines')

# --- EVEX masking / zeroing classes -------------------------------------------------
d = {}
for l in open('evex.txt'):
    mp, ctx, op, var, mem, reg = map(int, l.split())
    d[(mp, ctx, op, var)] = (mem, reg)
def cls(base, v):
    if v == base: return 's'
    if v == (0, 0): return 'n'
    if v == (0, base[1]): return 'r'
    return 'o'
votes = collections.defaultdict(collections.Counter)
for (mp, ctx, op, var), v in d.items():
    if var == 0: continue
    base = d[(mp, ctx, op, 0)]
    if base == (0, 0): continue
    k = (mp, op, ctx & 3, (ctx >> 4) & 1)
    votes[k][(1 if var == 1 else 2, cls(base, v))] += 1
entries = []
for (mp, op, pp, W), c in sorted(votes.items()):
    k_cls = max(('s', 'n'), key=lambda x: c[(1, x)])
    z_cls = max(('s', 'n', 'r'), key=lambda x: c[(2, x)])
    code = {('s', 's'): 0, ('n', 'n'): 1, ('s', 'r'): 2, ('s', 'n'): 3}.get((k_cls, z_cls))
    assert code is not None, (mp, op, pp, W, c)
    if code: entries.append((mp << 11 | W << 10 | pp << 8 | op, code))
entries.sort()
src = open('/Users/xnu/products/brew/machoexplorer/crates/moex-core/src/macho/xref/x86_tables.rs').read()
src += '''
/// How EVEX instructions react to a write mask (`aaa != 0`) or zeroing
/// (`z`), keyed by `map << 11 | W << 10 | pp << 8 | opcode` and sorted by
/// key. Instructions not listed accept both. 1: neither is accepted;
/// 2: zeroing only with a register destination; 3: no zeroing.
#[rustfmt::skip]
pub(super) static EVEX_MASKING: &[(u16, u8)] = &[
'''
line = '   '
for k, c in entries:
    item = ' (0x%04x, %d),' % (k, c)
    if len(line) + len(item) > 100:
        src += line + '\n'; line = '   '
    line += item
src += line + '\n];\n'
open('/Users/xnu/products/brew/machoexplorer/crates/moex-core/src/macho/xref/x86_tables.rs', 'w').write(src)
print('masking entries', len(entries))
