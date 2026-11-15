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
| `cxx_arm64` | `src/cxx.cpp` |
| `dyld_classic_x86_64.dylib` | `src/dyld/` with `-Wl,-no_fixup_chains` (weak/lazy binds, re-exports, classic opcodes) |
| `dyld_chained_x86_64.dylib` | `src/dyld/` with chained fixups (re-export terminals) |
| `dyld_synth_b`, `dyld_synth_c` | `src/dyld/gen.py`: hand-built Mach-Os covering opcodes, trie terminals and chained pointer formats no linker emits |

After adding a binary, add it to `CASES` in
`crates/moex-core/tests/golden.rs` and create its baseline with
`MOEX_UPDATE_BASELINES=1 cargo test -p moex-core --test golden`.
