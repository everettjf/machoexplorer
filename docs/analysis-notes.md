# Analysis notes

What the analysis shows, how it differs from the C++ releases (up to
`v2.0.17`), and where it is knowingly incomplete.

The first Rust version reproduced the C++ output cell for cell, bugs
included, so that the two could be compared mechanically. That comparison is
finished and the C++ tool is retired. The analysis now follows the formats
themselves (`<mach-o/loader.h>`, `<mach-o/fixup-chains.h>`, `<mach-o/nlist.h>`,
the objc4 runtime headers, the Swift ABI) and is checked against Apple's
tools (`otool`, `dyld_info`, `nm`, `lipo`, `dwarfdump`, `ar`). Output that
changes is caught by the snapshot test in `tests/golden/`.

## Changes from the C++ releases

### Files, headers and load commands

| Where | Now |
|---|---|
| Fat files | A slice can be a Mach-O, a static library (`Archive (<arch>)`, as in fat `.a` files) or unknown data (`Slice (<arch>)`). Slice alignment is not checked. |
| `Mach Header (<arch>)` | Architecture names follow `lipo`: `arm64e`, `armv7`, `armv7s`, `arm64_32`, `i386`, `x86_64h`, … |
| CPU subtype | arm64e and the other current subtypes are named; for arm64e the top byte is shown as the pointer-authentication ABI version, not `LIB64`. An unknown subtype is listed as "unknown". |
| Big-endian Mach-O | The header is decoded; load commands are not parsed and the node has a single child "Unsupported Byte Order". |
| `LC_UUID` | Shows the UUID. |
| `LC_SOURCE_VERSION` | Full `A.B.C.D.E`. |
| `LC_*_DYLIB` | "Name" is the whole path when it has no `/`. |
| Byte ranges | Every node's range is a file offset, also inside fat files and archives. |
| `Integrity Report` | Offsets are checked against the slice, not the whole file. |

### Link-edit data

| Where | Now |
|---|---|
| `Symbol Table` | `n_desc` is unsigned; sizes are 64-bit. |
| `Dynamic Symbol Table` | The byte range covers all tables present; `Indirect Symbols` has its own range and per-row ranges. |
| `Function Starts` | Ends at the zero terminator. |
| `Segment Split Info` | Named as such (it was called "Two Level Hints Table"). Its contents are not decoded. |
| `Rebase Info`, `Binding Info`, `Weak Binding Info`, `Lazy Binding Info` | Headers `Offset, Data, Description, Value`. Operands sit at their own offsets with 64-bit values, `DO_*` rows show the location they apply to, special dylib ordinals are signed and named, threaded binds are decoded, and an unknown opcode or malformed operand ends the walk with a row saying so. |
| `Export Info`, `Exports Trie` | One real trie decoder for both: ULEB terminal sizes, flags, re-exports (`ordinal=N import=<name>`), stub-and-resolver entries. |
| `Chained Fixups` | Decoded per `fixup-chains.h`: segment starts, `page_start[]`, multi-start pages, all pointer formats including the arm64e authenticated ones, imports with names. Fixup rows read `addr=… rebase target=…` or `[auth-]bind ordinal=N symbol=…`. Agrees with `dyld_info -fixups`. |

### Sections

| Where | Now |
|---|---|
| `Section(...)` | Section and segment name rows are present; each content view's byte range is the section contents. |
| ObjC views | Chosen by section name in any segment (`__DATA`, `__DATA_CONST`, `__AUTH`, …). Pointers are decoded through chained fixups and classic binds, so targets resolve on arm64 and arm64e. Relative method lists, metaclasses (class methods), properties and ivars are decoded. Agrees with `dyld_info -objc` and `otool -ov`. |
| Pointer tables | `Literal Pointers`, init/term function pointers and symbol pointers show `<file offset>-><decoded target>`. |
| `Floating Point Literals` | Values are decoded as float / double; 16-byte literals show the 128-bit value and both doubles. |
| `Disassembly (Capstone)` | Undecodable bytes and `LC_DATA_IN_CODE` ranges become data rows (`.byte`, `.short`, `.long`) and decoding continues, restarting at symbols and function starts. 32-bit ARM picks ARM or Thumb per function; arm64_32 is supported. Agrees with `otool -tV` on addresses and mnemonics. |
| `Swift Metadata` | The symbol list is no longer repeated under every view; relative pointers of zero read as `none`. |
| `Swift Semantic Graph` | Strings are shown as stored; opaque types are named; the Swift symbols are listed once at the end. |

### Xref Report

The sweep uses Capstone's operand and register-access detail rather than
private decoders.

- It covers the whole of `__TEXT,__text`: decoding restarts at every symbol
  and function start and steps over data.
- Kinds: `call`, `jump`, `addr` (`adr`, `adrp`+`add`, `lea`), `load` and
  `store` (memory operands at a known address), and pointers found in data
  sections. The call graph uses calls and jumps only.
- Register tracking treats `w8`/`x8` and `eax`/`rax` as one register, honours
  `movk` shifts, and forgets values at function starts, after unconditional
  jumps and returns, and for caller-saved registers across calls.
- Pointers in data are decoded through chained fixups; only values that land
  in a mapped segment are reported.
- 32-bit ARM reports direct branch and call targets only.

### Archives and the dyld shared cache

| Where | Now |
|---|---|
| `.a` archives | GNU (`/`, `//`, `/NN`, `/SYM64/`) and BSD (`#1/NN`, `__.SYMDEF`) conventions are handled; long-named members are recognised as Mach-O; a member that is not a well-formed Mach-O is listed as data. |
| `Dyld Shared Cache` | Magic, UUID, cache type, sub-cache array, real offsets; images come from the modern image table when present. |
| `moex cache-extract` | Reads segments from the sub-cache files (`.01`, `.02`, …) next to the main file, so extraction from a current system cache works. `--compact` leaves zero offsets alone. |

### Demangling

| Kind | How |
|---|---|
| C++ | The C++ runtime's `__cxa_demangle` on macOS (`libc++abi`) and Linux (`libstdc++`); the `cpp_demangle` crate on Windows, whose text differs for special names (`{vtable(Foo)}` for `vtable for Foo`) and some templated ones. |
| Swift | Swift's own demangler, compiled in through the `symbolic-demangle` crate. No external process is started and it works on every platform. Compared with `xcrun swift-demangle`: types are printed without sugar (`Swift.Optional<Swift.String>`, not `Swift.String?`), and names using manglings newer than the bundled demangler (about 1 in 75 on a current macOS) are left as they are. |

### Command-line tools

| Where | Now |
|---|---|
| `moex cache-list --limit=X`, `moex cache-extract --max=X` | A non-numeric value is a usage error (exit 2); the C++ tools crashed. |
| `moex cache-list` | The magic is printed without its NUL padding. |
| `moex cache-extract` | Write failures, an output the filesystem rejects and segments whose offsets wrap are reported (exit 1) and the partial file is removed; the C++ tool reported success. |
| Usage text | Names the program as `moex <subcommand>`. |
| Empty file | Reports `File is empty`. |
| Non-UTF-8 bytes in a cell | Written as `?` in both the text and the JSON dump. |

## Known limits

- Only `__TEXT,__text` is disassembled and swept for references; `__stubs`
  and other code sections (`__TEXT_EXEC,__text` in kernels) are not.
- Capstone 5.0.6 (bundled by the `capstone` crate) does not know some recent
  arm64e instructions (`pacibsppc` and similar) and rejects the x86-64
  `63 /r` encoding without REX.W; such bytes show as data rows.
- On Windows, Capstone prints some negative 32-bit arm64 immediates
  sign-extended to 64 bits (`#-0xffffffff80000000` for `#-0x80000000`).
- Xref register tracking is a linear sweep, not data-flow analysis: a label
  reached both by fall-through and by a jump is treated as fall-through.
  Instructions patched by relocations in object files are not resolved.
- In object files (`.o`), ObjC pointers that need relocations are not
  resolved.
- Old arm64e threaded binds in `LC_DYLD_INFO`, zlib-compressed chained import
  names and weak-bind streams are not applied when decoding pointers.
- The Swift Semantic Graph still reads `typeref`, `assocty`, `capture` and
  `builtin` sections as arrays of relative pointers, which is not what they
  are; many of those rows are noise.
- `moex cache-extract` copies the shared `__LINKEDIT` whole, so an extracted
  image can be very large; in raw (non-compact) mode segments from different
  sub-caches can overlap.
- Big-endian Mach-O files are identified but not analysed.

## Bounds against hostile input

Every read is bounds-checked. Work is also bounded where a crafted file
could otherwise ask for unbounded output: 2,000,000 rows per ObjC table,
1,000,000 chained-fixup rows and 65,536 fixups per chain start, 500,000 trie
edges, 8,000,000 opcodes per opcode stream, and an Xref sweep of at most four
times the file size per Mach-O header. No well-formed binary reaches these.
