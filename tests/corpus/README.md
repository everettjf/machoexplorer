# Test corpus

`bin/` holds the binaries the golden and robustness tests run on; they are
checked in so results do not depend on the local toolchain. `src/` holds the
sources and notes on how each was built.

| Binary | Built from |
|---|---|
| `hello_*`, `lib_*.o`, `libmoex_*`, `libmulti.a` | `src/hello.c`, `src/lib.c` (clang, `ar`, `lipo`) |
| `hello_signed_arm64` | `hello_arm64` re-signed ad hoc with `src/ent.plist` (hardened runtime, entitlements) |
| `objc_*` | `src/objc.m` |
| `swift_arm64` | `src/app.swift` |
| `swiftrefs_arm64` | `src/refs.swift` (`swiftc -Onone -target arm64-apple-macos13 -module-name Refs`): field types whose mangled names hold symbolic references in every position |
| `cxx_arm64` | `src/cxx.cpp` |
| `dyld_classic_x86_64.dylib` | `src/dyld/` with `-Wl,-no_fixup_chains` (weak/lazy binds, re-exports, classic opcodes) |
| `dyld_chained_x86_64.dylib` | `src/dyld/` with chained fixups (re-export terminals) |
| `hello_ppc.o` | `src/ppc/gen.py`: a hand-built big-endian (PowerPC) object file; no current toolchain targets Mach-O PowerPC |
| `llvm_trivial_ppc.o`, `llvm_trivial_ppc64.o` | `trivial.obj.macho-ppc` and `trivial.obj.macho-ppc64` from `llvm/test/tools/llvm-readobj/MachO/Inputs` of the LLVM project (Apache-2.0 with LLVM exceptions): objects a PowerPC compiler made, with a symbol stub, lazy and non-lazy pointer sections and a common symbol; read for their structure only |
| `switch_arm64`, `switch_arm64e`, `switch_x86_64`, `switch_arm64.o`, `switch_x86_64.o` | `src/switch.c` (`clang -O2`, commands in the file): jump tables of bytes and halfwords in `__const` (arm64), of 32-bit offsets marked as data in `__text` (arm64e, x86-64), with and without a range check |
| `reloc_i386.o`, `reloc_i386_nopic.o`, `reloc_armv7.o`, `reloc_armv7_arm.o`, `reloc_armv7_nopic.o` | `src/reloc32.c` (`clang -O1 -c`, commands in the file): the relocation entries of 32-bit object code: i386 `VANILLA` / `SECTDIFF` / `LOCAL_SECTDIFF`, ARM `BR24` / `THUMB_BR22` / `HALF` / `HALF_SECTDIFF` |
| `objc_threaded_arm64e` | `src/objc.m` linked with `-arch arm64 -mmacosx-version-min=11.0 -Wl,-no_fixup_chains -framework Foundation`, then rewritten by `src/dyld/mkthreaded.py` as an arm64e image with threaded rebases and binds (`BIND_OPCODE_THREADED`). No current linker emits that form, and neither `dyld_info` nor `llvm-objdump` reads it any more; the fixups the script threads are the ones `dyld_info -fixups` lists for the linker's output |
| `objc_zlib_arm64` | `objc_arm64` with the symbol names of its chained fixups deflated by `src/dyld/mkzlib.py` (`symbols_format` 1). No linker emits that form and dyld rejects it |
| `dyld_synth_b`, `dyld_synth_c` | `src/dyld/gen.py`: hand-built Mach-Os covering opcodes, trie terminals and chained pointer formats no linker emits |

After adding a binary, add it to `CASES` in
`crates/moex-core/tests/golden.rs` and create its baseline with
`MOEX_UPDATE_BASELINES=1 cargo test -p moex-core --test golden`.
