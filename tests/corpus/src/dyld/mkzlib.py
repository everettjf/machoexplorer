"""Rewrites the symbol names of an image's chained fixups as a zlib stream
(dyld_chained_fixups_header.symbols_format = 1). No linker emits that form."""
import struct,sys,zlib
src,dst=sys.argv[1],sys.argv[2]
f=bytearray(open(src,'rb').read())
assert struct.unpack_from('<I',f,0)[0]==0xfeedfacf
ncmds=struct.unpack_from('<I',f,16)[0]; o=32
for _ in range(ncmds):
    cmd,size=struct.unpack_from('<II',f,o)
    if cmd==0x80000034:
        off,sz=struct.unpack_from('<II',f,o+8)
        ver,starts,imports,symbols,count,fmt,symfmt=struct.unpack_from('<7I',f,off)
        assert symfmt==0
        pool=bytes(f[off+symbols:off+sz])
        packed=zlib.compress(pool,9)
        assert len(packed)<=len(pool),(len(packed),len(pool))
        f[off+symbols:off+sz]=packed+bytes(len(pool)-len(packed))
        struct.pack_into('<I',f,off+24,1)
        print('names',len(pool),'->',len(packed))
    o+=size
open(dst,'wb').write(f)
