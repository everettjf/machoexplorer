"""Rewrites a classic-opcode arm64 image (ld -no_fixup_chains) as an arm64e
image with threaded rebases/binds (BIND_OPCODE_THREADED), the form ld64 used
for arm64e before chained fixups. Fixup list comes from `dyld_info -fixups`."""
import struct,sys,subprocess,re
src,dst=sys.argv[1],sys.argv[2]
f=bytearray(open(src,'rb').read())
assert struct.unpack_from('<I',f,0)[0]==0xfeedfacf
ncmds=struct.unpack_from('<I',f,16)[0]; o=32
segs=[]; dylibs=[]; info=None
for _ in range(ncmds):
    cmd,size=struct.unpack_from('<II',f,o)
    if cmd==0x19:
        name=f[o+8:o+24].rstrip(b'\0').decode(); vm,vs,fo,fs=struct.unpack_from('<QQQQ',f,o+24)
        segs.append((name,vm,vs,fo))
    if cmd in (0xc,0x80000018,0x8000001f):
        so=struct.unpack_from('<I',f,o+8)[0]; p=f[o+so:o+size].split(b'\0')[0].decode()
        dylibs.append(p.split('/')[-1])
    if cmd==0x80000022: info=o
    o+=size
out=subprocess.run(['xcrun','dyld_info','-fixups',src],capture_output=True,text=True).stdout
fix={}
for l in out.split('\n'):
    m=re.match(r'\s+(\S+)\s+(\S+)\s+0x([0-9A-Fa-f]+)\s+(rebase|bind|lazy-bind)\s+(.*)$',l)
    if not m: continue
    seg,sect,addr,kind,target=m.groups(); addr=int(addr,16)
    if kind=='rebase' and addr not in fix: fix[addr]=('r',int(target,16))
    elif kind!='rebase':
        lib,sym=target.strip().split('/',1)
        sym=sym.split(' ')[0]
        fix[addr]=('b',lib,sym)
def segof(a):
    for i,(n,vm,vs,fo) in enumerate(segs):
        if vm<=a<vm+vs: return i,vm,fo
def ordinal(lib):
    for i,d in enumerate(dylibs):
        if d==lib or d.startswith(lib+'.') or d.split('.')[0]==lib: return i+1
    raise SystemExit('no dylib '+lib)
imports=[]
for a in sorted(fix):
    v=fix[a]
    if v[0]=='b' and (v[1],v[2]) not in imports: imports.append((v[1],v[2]))
def uleb(v):
    b=b''
    while True:
        c=v&0x7f; v>>=7
        if v: b+=bytes([c|0x80])
        else: return b+bytes([c])
s=bytes([0xD0])+uleb(len(imports))
for lib,sym in imports:
    s+=bytes([0x10|ordinal(lib),0x40])+sym.encode()+b'\0'+bytes([0x51,0x90])
addrs=sorted(fix); starts=[]
for i,a in enumerate(addrs):
    nxt=0
    if i+1<len(addrs):
        d=addrs[i+1]-a
        if segof(addrs[i+1])[0]==segof(a)[0] and d%8==0 and d//8<2048: nxt=d//8
    if i==0 or prev_next==0: starts.append(a)
    prev_next=nxt
    v=fix[a]
    if v[0]=='r': val=v[1]|nxt<<51
    else: val=imports.index((v[1],v[2]))|nxt<<51|1<<62
    si,vm,fo=segof(a)
    struct.pack_into('<Q',f,fo+(a-vm),val)
for a in starts:
    si,vm,fo=segof(a)
    s+=bytes([0x70|si])+uleb(a-vm)+bytes([0xD1])
s+=b'\0'
rebase_off,rebase_size,bind_off,bind_size,wo,ws,lazy_off,lazy_size=struct.unpack_from('<8I',f,info+8)
room=(lazy_off+lazy_size-bind_off) if lazy_off==bind_off+bind_size else bind_size
assert len(s)<=room,(len(s),room)
f[bind_off:bind_off+room]=s+bytes(room-len(s))
struct.pack_into('<8I',f,info+8,rebase_off,0,bind_off,room,wo,ws,0,0)
struct.pack_into('<I',f,8,0x80000002)
open(dst,'wb').write(f)
print('fixups',len(fix),'imports',len(imports),'chains',len(starts),'stream',len(s))
