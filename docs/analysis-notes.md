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
| Big-endian Mach-O | Analysed like any other: a file whose magic is byte-swapped (PowerPC and older architectures) is read in its own byte order throughout, including the bit fields of relocation entries, which big-endian compilers lay out from the other end. PowerPC (32- and 64-bit) code is disassembled. |
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
| ObjC views | Chosen by section name in any segment (`__DATA`, `__DATA_CONST`, `__AUTH`, …). Pointers are decoded through chained fixups and classic binds, so targets resolve on arm64 and arm64e. Relative method lists, metaclasses (class methods), properties and ivars are decoded. Agrees with `dyld_info -objc` and `otool -ov`. In an object file (`.o`) the pointers are followed through the relocation entries, so the same views are filled there. |
| Pointer decoding | A stored pointer is turned into what it will be once loaded: chained fixups (rebase or bind, with import names, also when the name table is zlib-compressed), the bind streams of `LC_DYLD_INFO`, the threaded rebases and binds of the first arm64e images (`BIND_OPCODE_THREADED`), and in an object file the relocation entry of the slot (symbol address plus the addend stored in the slot, or the name of an undefined symbol; the second half of a `SUBTRACTOR` pair is a difference and is left as a number). |
| Pointer tables | `Literal Pointers`, init/term function pointers and symbol pointers show `<file offset>-><decoded target>`. A slot named in the weak bind stream is followed by `(weak <symbol>)`: dyld points it at whichever definition of that symbol wins across all images, which is the address shown unless another image overrides it. A weak-bound slot that holds nothing shows the symbol name alone. |
| `Floating Point Literals` | Values are decoded as float / double; 16-byte literals show the 128-bit value and both doubles. |
| `Disassembly (Capstone)` | Every code section has one: sections whose attributes mark them as instructions (`__text`, `__stub_helper`, `__objc_stubs`, the `__TEXT_EXEC,__text` of kernels, …), symbol stub sections (`__stubs`, `__auth_stubs`) and `__TEXT,__text`. Undecodable bytes and `LC_DATA_IN_CODE` ranges become data rows (`.byte`, `.short`, `.long`) and decoding continues, restarting at symbols and function starts. 32-bit ARM picks ARM or Thumb per function; arm64_32 and PowerPC are supported. Agrees with `otool -tV` on addresses and mnemonics. |
| Instructions Capstone lacks | The bundled Capstone (5.0.6) does not decode some instructions that current toolchains emit. These are decoded by the tool itself, with operands as `otool -tV` prints them: AArch64 `pacibsppc` / `paciasppc` / `pacnbi[ab]sppc`, `retaasppc` / `retabsppc`, `autiasppc` / `autibsppc` and their `…r` register forms (FEAT_PAuth_LR; the label is shown as an address), `addpt` / `subpt` / `maddpt` / `msubpt` (FEAT_CPA), `abs` / `cnt` / `ctz` / `smax` / `smin` / `umax` / `umin` (FEAT_CSSC); and x86-64 `movsxd` without `REX.W`. |
| `Swift Metadata` | The symbol list is no longer repeated under every view; relative pointers of zero read as `none`. The reflection sections are decoded by their layout (`swift/RemoteInspection/Records.h`), each row covering the bytes of its record: `__swift5_fieldmd` (field descriptors and their records), `__swift5_assocty` (associated type descriptors and their records), `__swift5_capture` (capture descriptors with their capture types and metadata sources), `__swift5_builtin` (size, alignment, stride, extra inhabitants, bitwise-takable), `__swift5_mpenum` (type, size in words, flags), `__swift5_reflstr` (C strings, UTF-8) and `__swift5_typeref` (the mangled names, found by walking the section; a metadata source string is marked as such). A section that ends inside a record ends with a row saying so. |
| Swift mangled names | A name's end is found by walking it, since the operand of a symbolic reference can hold zero bytes. Each name is shown as stored, with every symbolic reference replaced by `{what it refers to}`: the qualified name read from the context descriptor (through the parent chain, and through a bound pointer for an imported one), or the kind and target address when that is not a named context. Where the demangler can take it, the demangled form is shown as well. The `{…}` forms agree with the `_symbolic …` symbols the linker leaves in unstripped binaries. |
| `Swift Semantic Graph` | Strings are shown as stored; opaque types are named; the Swift symbols are listed once at the end. The reflection sections are decoded as in `Swift Metadata`; edges run from a descriptor to the names and strings it refers to, and from a mangled name to the targets of its symbolic references. |

### Xref Report

The sweep uses Capstone's operand and register-access detail rather than
private decoders.

- It covers every code section (see `Disassembly (Capstone)`): decoding
  restarts at every symbol and function start and steps over data. The
  referrer names the section (`__TEXT/__stubs [load] …`).
- Kinds: `call`, `jump`, `addr` (`adr`, `adrp`+`add`, `lea`), `load` and
  `store` (memory operands at a known address), and pointers found in data
  sections. The call graph uses calls and jumps only.
- Register tracking treats `w8`/`x8` and `eax`/`rax` as one register and
  honours `movk` shifts. Values are followed through one run of code at a
  time (the instructions between two symbols or function starts: a
  function) along every path. At a label a register holds a value only if
  it holds that value on every way of reaching the label: falling in from
  above and each direct jump to it, loops included (a register the loop
  body changes is not known at the loop head). Nothing is known at the
  start of a run, at a label that is also the target of a call, of a jump
  from another run or of a jump whose target a relocation supplies, and
  for caller-saved registers after a call.
- In an object file the operands of an instruction that a relocation
  patches are placeholders. On x86-64 and arm64 the relocation entry is
  used instead: a branch, a pc-relative operand, an `adrp` pair or a GOT
  load refers to the symbol's address when the symbol is defined in the
  file, and to nothing when it is not. A symbol at address 0 (the first
  function) can be a target.
- Pointers in data are decoded as described under "Pointer decoding"; only
  values that land in a mapped segment are reported. In an object file,
  where addresses start at 0 and every small number would qualify, the
  relocation entries say which slots of the ObjC sections are pointers.
- A target is named by the external symbol at its address when there is
  one, otherwise by the first symbol there.
- 32-bit ARM and PowerPC report direct branch and call targets only.

### Archives and the dyld shared cache

| Where | Now |
|---|---|
| `.a` archives | GNU (`/`, `//`, `/NN`, `/SYM64/`) and BSD (`#1/NN`, `__.SYMDEF`) conventions are handled; long-named members are recognised as Mach-O; a member that is not a well-formed Mach-O is listed as data. |
| `Dyld Shared Cache` | Magic, UUID, cache type, sub-cache array, real offsets; images come from the modern image table when present. |
| `moex cache-extract` | Reads segments from the sub-cache files (`.01`, `.02`, …) next to the main file, so extraction from a current system cache works. The shared `__LINKEDIT` is not copied: the output gets its own, holding the image's `LC_DYLD_INFO` tables, the data of its `linkedit_data_command`s (export trie, chained fixups, function starts, data in code, split info, …), its symbols (the three `LC_DYSYMTAB` ranges, renumbered from 0), its indirect symbol table and a string table with only those symbols' names. Segment, section and linkedit file offsets are rewritten to match the output, absent tables (offset 0) stay absent, and `MH_DYLIB_IN_CACHE` is cleared. The code signature, two-level hints, the `LC_DYSYMTAB` table of contents / module / reference / relocation tables and section relocations are dropped (offsets and counts 0). libobjc from a macOS 27 cache: 127 MB (its 124 MB `__OBJC_RO` included), 1.6 GB before. |
| `moex cache-extract` layout | `--compact`: header segment at 0, the others in load command order at 4 KiB boundaries, `__LINKEDIT` last. Without it segments keep their recorded file offsets only when the image is in one cache file and those ranges overlap neither each other nor the header; otherwise (always, in a split cache) the compact layout is used and reported as `mode: compact`. No two segments share file bytes in either mode. |

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
| `moex cache-extract` | Write failures, an output the filesystem rejects, a segment that is in no cache file and inconsistent linkedit data are reported (exit 1) and the partial file is removed; the C++ tool reported success. |
| Usage text | Names the program as `moex <subcommand>`. |
| Empty file | Reports `File is empty`. |
| Non-UTF-8 bytes in a cell | Written as `?` in both the text and the JSON dump. |

## Known limits

- Instructions newer than Capstone 5.0.6 other than those listed under
  "Instructions Capstone lacks" show as data rows. Across the binaries of a
  current macOS (`/bin`, `/usr/bin`, `/usr/sbin`, `/usr/libexec` and the
  kernel) nothing else was found: of the 1,856 distinct words left as data
  in code sections there, a current LLVM decodes six, each occurring once
  among other data.
- The Xref sweep does not follow indirect jumps (jump tables), so code
  reached only through one starts with nothing known. A register that
  holds different values on different paths to an instruction yields no
  reference there, rather than one per path.
- In object files, instructions patched by an external relocation are
  resolved on x86-64 and arm64 only; on 32-bit x86, 32-bit ARM and PowerPC
  they refer to nothing (section-relative entries, which leave the address
  in the instruction, are followed on every architecture).
- Threaded binds, zlib-compressed chained import names and big-endian
  files are covered by hand-built inputs only (`tests/corpus/src/ppc`, the
  unit tests of `macho/ptr.rs`): no current toolchain produces them.
  PowerPC disassembly was compared with `llvm-objdump -d` on that input.
- Big-endian architectures other than PowerPC (m68k, SPARC, …) are
  analysed but not disassembled.
- Swift mangled names with symbolic references are demangled by giving the
  demangler a stand-in type for each reference, which does not always work.
  A name is left as stored (referents in `{…}`, not demangled) when it
  refers to an opaque result type (`some View`), an accessor function, an
  ObjC protocol or an existential shape; when a reference that is a protocol
  or the head of a generic type (`{Foo}y…G`) is followed by a back-reference
  (any `A` later in the name); or when the demangled text would exceed 4095
  bytes. Names built from SwiftUI view types are mostly of these kinds.
- In `__swift5_mpenum` the spare-bit mask words are not decoded. The
  `__swift5_*` sections not listed under "Sections" (`__swift5_entry`,
  `__swift5_proto`, `__swift5_acfuncs`, …) are read as arrays of 32-bit
  relative pointers, as `__swift5_types` and `__swift5_protos` are, without
  a check that this is their layout.
- `moex cache-extract` does not read the `.symbols` file of a cache, so an
  image whose local symbols the cache builder moved there is extracted
  without them. Segments keep their cache addresses and what the cache
  builder did to the image is not undone (segments scattered over the
  cache's regions, emptied stub sections, `__DATA_CONST` without
  `SG_READ_ONLY`), so the result is for analysis, not for loading. Apple's
  `dyld_info` refuses most extracted images for those reasons
  (`__DATA_CONST segment missing SG_READ_ONLY flag`, `segment '__DATA' vm
  address out of order`, `section '__TEXT/__objc_stubs' align field ... does
  not match address`); `otool`, `nm` and `moex` read them. Linkedit data
  must lie inside the image's own `__LINKEDIT` segment, or the image is not
  extracted; `linkedit_data_command`s newer than `LC_LAZY_LOAD_DYLIB_INFO`
  (0x3A) are not known and keep stale offsets.

## Bounds against hostile input

Every read is bounds-checked. Work is also bounded where a crafted file
could otherwise ask for unbounded output: 2,000,000 rows per ObjC table,
1,000,000 chained-fixup rows and 65,536 fixups per chain start, 500,000 trie
edges, 8,000,000 opcodes per opcode stream, an Xref sweep of at most four
times the file size per Mach-O header, 1,000,000 records per Swift reflection
section, and, per table, a budget for reading Swift mangled names of four
times the file size plus 1 MiB (one unit per byte of a name, 16 per context
descriptor visited; at most 16 contexts are followed from one reference).
No well-formed binary reaches these.
