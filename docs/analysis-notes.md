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
| Big-endian Mach-O | Its structure is read like that of any other file: a file whose magic is byte-swapped (PowerPC and older architectures) is read in its own byte order throughout, including the bit fields of relocation entries, which big-endian compilers lay out from the other end. The code of such a file is not disassembled and not swept for references (the architectures are PowerPC and older ones); its pointer sections, literals, symbols and relocation tables are shown. |
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
| `Chained Fixups` | Decoded per `fixup-chains.h`: segment starts, `page_start[]`, multi-start pages, all pointer formats including the arm64e authenticated ones, imports with names (inflated first when `symbols_format` says they are a zlib stream). Fixup rows read `addr=… rebase target=…` or `[auth-]bind ordinal=N symbol=…`. Agrees with `dyld_info -fixups`. |

### Sections

| Where | Now |
|---|---|
| `Section(...)` | Section and segment name rows are present; each content view's byte range is the section contents. |
| ObjC views | Chosen by section name in any segment (`__DATA`, `__DATA_CONST`, `__AUTH`, …). Pointers are decoded through chained fixups and classic binds, so targets resolve on arm64 and arm64e. Relative method lists, metaclasses (class methods), properties and ivars are decoded. Agrees with `dyld_info -objc` and `otool -ov`. In an object file (`.o`) the pointers are followed through the relocation entries, so the same views are filled there. |
| Pointer decoding | A stored pointer is turned into what it will be once loaded: chained fixups (rebase or bind, with import names, also when the name table is zlib-compressed), the bind streams of `LC_DYLD_INFO`, the threaded rebases and binds of the first arm64e images (`BIND_OPCODE_THREADED`), and in an object file the relocation entry of the slot (symbol address plus the addend stored in the slot, or the name of an undefined symbol; the second half of a `SUBTRACTOR` pair is a difference and is left as a number). |
| Pointer tables | `Literal Pointers`, init/term function pointers and symbol pointers show `<file offset>-><decoded target>`. A slot named in the weak bind stream is followed by `(weak <symbol>)`: dyld points it at whichever definition of that symbol wins across all images, which is the address shown unless another image overrides it. A weak-bound slot that holds nothing shows the symbol name alone. |
| `Floating Point Literals` | Values are decoded as float / double; 16-byte literals show the 128-bit value and both doubles. |
| `Disassembly (Capstone)` | Every code section has one: sections whose attributes mark them as instructions (`__text`, `__stub_helper`, `__objc_stubs`, the `__TEXT_EXEC,__text` of kernels, …), symbol stub sections (`__stubs`, `__auth_stubs`) and `__TEXT,__text`. Undecodable bytes and `LC_DATA_IN_CODE` ranges become data rows (`.byte`, `.short`, `.long`) and decoding continues, restarting at symbols and function starts. 32-bit ARM picks ARM or Thumb per function; arm64_32 is supported. Agrees with `otool -tV` on addresses and mnemonics. |
| Instructions Capstone lacks | The bundled Capstone (5.0.6) does not decode some instructions that current toolchains emit. These are decoded by the tool itself, with operands as `otool -tV` prints them: AArch64 `pacibsppc` / `paciasppc` / `pacnbi[ab]sppc`, `retaasppc` / `retabsppc`, `autiasppc` / `autibsppc` and their `…r` register forms (FEAT_PAuth_LR; the label is shown as an address), `addpt` / `subpt` / `maddpt` / `msubpt` (FEAT_CPA), `abs` / `cnt` / `ctz` / `smax` / `smin` / `umax` / `umin` (FEAT_CSSC); and x86-64 `movsxd` without `REX.W`. |
| `Swift Metadata` | The symbol list is no longer repeated under every view; relative pointers of zero read as `none`. The reflection sections are decoded by their layout (`swift/RemoteInspection/Records.h`), each row covering the bytes of its record: `__swift5_fieldmd` (field descriptors and their records), `__swift5_assocty` (associated type descriptors and their records), `__swift5_capture` (capture descriptors with their capture types and metadata sources), `__swift5_builtin` (size, alignment, stride, extra inhabitants, bitwise-takable), `__swift5_mpenum` (type, size in words, flags, and the payload's spare bit mask with the byte offset it applies at), `__swift5_reflstr` (C strings, UTF-8), `__swift5_typeref` (the mangled names, found by walking the section; a metadata source string is marked as such), `__swift5_proto` (each protocol conformance descriptor as `Type: Protocol`, which agrees with the `…Mc` symbols of an unstripped binary), `__swift5_types2` (as `__swift5_types`), `__swift5_acfuncs` (accessible function records: demangled name, function type, address, flags) and `__swift5_entry` (the entry point). A section that ends inside a record ends with a row saying so. |
| Swift mangled names | A name's end is found by walking it, since the operand of a symbolic reference can hold zero bytes. Each name is shown as stored, with every symbolic reference replaced by `{what it refers to}`: the qualified name read from the context descriptor (through the parent chain, and through a bound pointer for an imported one), or the kind and target address when that is not a named context. The demangled form is shown as well: the demangler is given the name as stored and, for each reference, what it stands for, as the Swift runtime does: the mangling of the type or protocol declaration (built from the descriptor's parent chain, or taken from the symbol of an imported descriptor), of an Objective-C protocol, or of the declaration whose opaque result type (`some View`) it is (from the `…MQ` symbol); an existential shape is printed with its address. Types declared in an extension made in another module print as Swift prints them, `(extension in Module):Type.Name`. The `{…}` forms agree with the `_symbolic …` symbols the linker leaves in unstripped binaries. Over the 44 Swift applications of a current macOS, 326 of about 163,000 type names are left undemangled; most of those are padding bytes in the section, not names. |
| `Swift Semantic Graph` | Strings are shown as stored; opaque types are named; the Swift symbols are listed once at the end. The reflection sections are decoded as in `Swift Metadata`; edges run from a descriptor to the names and strings it refers to, and from a mangled name to the targets of its symbolic references. |

### Xref Report

The sweep uses Capstone's operand and register-access detail rather than
private decoders.

- It covers every code section (see `Disassembly (Capstone)`): decoding
  restarts at every symbol and function start and steps over data. The
  referrer names the section (`__TEXT/__stubs [load] …`).
- Kinds: `call`, `jump`, `jump-table` (one per case a jump through a jump
  table goes to), `addr` (`adr`, `adrp`+`add`, `lea`), `load` and `store`
  (memory operands at a known address), and pointers found in data
  sections. The call graph uses calls and jumps only.
- Register tracking treats `w8`/`x8` and `eax`/`rax` as one register and
  honours `movk` shifts. Values are followed through one run of code at a
  time (the instructions between two symbols or function starts: a
  function) along every path. At a label a register holds a value only if
  it holds that value on every way of reaching the label: falling in from
  above, each direct jump to it and each jump table that leads to it, loops
  included (a register the loop body changes is not known at the loop
  head). Nothing is known at the start of a run, at a label that is also
  the target of a call, of a jump from another run or of a jump whose
  target a relocation supplies, and for caller-saved registers after a
  call. Code that follows a return or an unconditional jump and that no
  jump and no jump table leads to starts with nothing known.
- Jump tables. The sequences clang emits for a dense `switch` are
  followed on arm64 and x86-64: the table's address (`adrp`+`add`, `lea
  table(%rip)`), an entry loaded at an index scaled by the entry size
  (`ldrsw`, `ldrh`, `ldrb`; `movslq (%table,%index,4)`), added to the
  table's address or to another address of the function (`adr`), and a
  jump to the sum (`br`, `jmp *%reg`). That covers tables of 32-bit
  offsets from the table (x86-64, arm64e, uncompressed arm64) and of bytes
  or halfwords that count instructions from a block of the function
  (arm64). The number of entries is what the range check of the index
  allows: `cmp reg, #n` followed by `b.hi` / `ja` (or the `ls`, `hs`, `lo`
  forms) with the flags and the register untouched in between, also when
  the index is the register the compared one was last copied to or from,
  or the `csel` / `csneg … , xzr, ls` that arm64e code clamps the index
  with.
  Without a visible check the table ends where something else is known to
  start: the end of its section or data-in-code range, the next symbol,
  the next jump table found, the next address the code of the section
  computes with an `adrp` pair, the next address anything refers to; up to
  15 zero bytes of padding before that are not entries. A table counts
  only when every entry leads to an instruction of the same run and no
  relocation patches an entry; then the indirect jump refers to each
  distinct case (`jump-table`) and the cases are reached with what is
  known at the jump. Tables hold at most 65,536 entries, and a section's
  tables together at most one entry per byte of its code; a run is gone
  over at most 41 times, as before.
- In an object file the operands of an instruction that a relocation
  patches are placeholders, and the relocation entry is used instead; the
  reference is to the symbol's address when the symbol is defined in the
  file, and to nothing when it is not. A symbol at address 0 (the first
  function) can be a target. Section-relative entries leave the address in
  the instruction on every architecture.
  - x86-64 and arm64: a branch, a pc-relative operand, an `adrp` pair or a
    GOT load.
  - 32-bit x86: a call or jump to a symbol (`GENERIC_RELOC_VANILLA`,
    pc-relative, external), an absolute operand or immediate
    (`mov eax, [_v]`, `mov eax, offset _v`; an immediate that a
    section-relative entry patches is an address too), and the
    differences position-independent code adds to the address it read
    with `call` / `pop` (`SECTDIFF`, `LOCAL_SECTDIFF`).
  - 32-bit ARM: `bl` / `b` (`ARM_RELOC_BR24`, `ARM_THUMB_RELOC_BR22`) and
    `movw` / `movt` pairs (`ARM_RELOC_HALF` with its `PAIR`). A pair that
    holds a difference (`ARM_RELOC_HALF_SECTDIFF`) is resolved when the
    instruction it counts from is `add rN, pc` or, in ARM code,
    `add rN, pc, rM` / `ldr rN, [pc, rM]`. The reference (`addr`) is at
    the `movw`; the low bit of a pointer to a Thumb function is dropped.

  The direct branch targets that decide what is known at a label come
  from the relocation entries as well, so the placeholder operand of a
  call to another file (`bl 0`, `call next`) does not count as a branch
  to the address it happens to spell.
- In an object file `LC_DATA_IN_CODE` offsets are addresses (the assembler
  writes the address of the label that starts the range), so jump tables
  in `__text` are stepped over there as they are in linked images.
- Pointers in data are decoded as described under "Pointer decoding"; only
  values that land in a mapped segment are reported. In an object file,
  where addresses start at 0 and every small number would qualify, the
  relocation entries say which slots of the ObjC sections are pointers.
- A target is named by the external symbol at its address when there is
  one, otherwise by the first symbol there.
- 32-bit ARM reports direct branch and call targets, plus, in object
  files, what the relocation entries say (above). Registers are not
  followed for it.

### Archives and the dyld shared cache

| Where | Now |
|---|---|
| `.a` archives | GNU (`/`, `//`, `/NN`, `/SYM64/`) and BSD (`#1/NN`, `__.SYMDEF`) conventions are handled; long-named members are recognised as Mach-O; a member that is not a well-formed Mach-O is listed as data. |
| `Dyld Shared Cache` | Magic, UUID, cache type, sub-cache array, real offsets; images come from the modern image table when present. |
| `moex cache-extract` | Reads segments from the sub-cache files (`.01`, `.02`, …) next to the main file, so extraction from a current system cache works. The shared `__LINKEDIT` is not copied: the output gets its own, holding the image's `LC_DYLD_INFO` tables, the data of its `linkedit_data_command`s (export trie, chained fixups, function starts, data in code, split info, …), its symbols (the three `LC_DYSYMTAB` ranges, renumbered from 0), its indirect symbol table and a string table with only those symbols' names. Segment, section and linkedit file offsets are rewritten to match the output, absent tables (offset 0) stay absent, and `MH_DYLIB_IN_CACHE` is cleared. The code signature, two-level hints, the `LC_DYSYMTAB` table of contents / module / reference / relocation tables and section relocations are dropped (offsets and counts 0). libobjc from a macOS 27 cache: 127 MB (its 124 MB `__OBJC_RO` included), 1.6 GB before. |
| `moex cache-extract` local symbols | Local symbols the cache builder moved out of the images are merged back: from the `dyld_cache_local_symbols_info` in the cache file (old caches, 32-bit entries keyed by the header's file offset) or in the `<cache>.symbols` file whose UUID is the header's `symbolFileUUID` (current iOS-family caches, 64-bit entries keyed by the offset from the cache's base address). They go first in the symbol table, the image's `<redacted>` placeholder symbols are left out (an indirect symbol table entry naming one becomes `INDIRECT_SYMBOL_LOCAL`), and `LC_SYMTAB` / `LC_DYSYMTAB` count the result. A symbols file that is missing, foreign or malformed is a warning, not a failure. macOS caches have no such data and nothing changes for them. |
| `moex cache-extract` and `dyld_info` | Segment load commands are put in ascending address order (the cache builder places segments in another order than the commands list them; symbols' `n_sect` are renumbered to match), `__DATA_CONST` gets back the `SG_READ_ONLY` flag the builder cleared, and a section alignment that its address does not have is lowered to the one it has. Addresses are kept. With that Apple's `dyld_info` accepts the output: `dyld_info -segments -exports -fixups` succeeds on all 4108 images of a macOS 27.2 arm64e cache (118 before), and its export list for an extracted image equals the one it prints for the same image inside the cache (52 images compared). `nm` prints the same symbols as before the change. |
| `moex cache-extract` layout | `--compact`: header segment at 0, the others in load command order (address order) at 4 KiB boundaries, `__LINKEDIT` last. Without it segments keep their recorded file offsets only when the image is in one cache file and those ranges overlap neither each other nor the header; otherwise (always, in a split cache) the compact layout is used and reported as `mode: compact`. No two segments share file bytes in either mode. |

### Demangling

| Kind | How |
|---|---|
| C++ | The C++ runtime's `__cxa_demangle` on macOS (`libc++abi`) and Linux (`libstdc++`); the `cpp_demangle` crate on Windows, whose text differs for special names (`{vtable(Foo)}` for `vtable for Foo`) and some templated ones. |
| Swift | Swift's own demangler (Swift 6.3.1), bundled as source in `crates/moex-core/vendor/swift` exactly as the `symbolic-demangle` crate ships it and built with a small C interface (`src/swift_demangle.cpp`), because that crate offers symbol demangling only and type names need the demangler's resolver for symbolic references. No external process is started and it works on every platform. Demangled text longer than 64 KiB is dropped. Compared with `xcrun swift-demangle`: types are printed without sugar (`Swift.Optional<Swift.String>`, not `Swift.String?`), and names using manglings newer than the bundled demangler (about 1 in 75 on a current macOS) are left as they are. |

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
- Jump tables in the Xref sweep (see "Xref Report" for what is
  recognised). Not recognised: tables of absolute addresses
  (`jmp *table(,%rax,8)`, non-PIC x86), 32-bit x86, 32-bit ARM (`tbb` /
  `tbh`) tables, a table address or entry that passes through
  memory or through an instruction the sweep does not model, and a table
  without a visible range check (none in the code, or the checked index
  passes through memory) that is not followed directly by something the
  sweep knows to start there (then nothing is assumed rather than a length
  guessed). A range check is taken as the table's length; when the
  compiler checked a smaller range than the table has, the remaining
  entries are not listed. Where a function's basic blocks have symbols of
  their own (an object file assembled with local labels kept), each block
  is a run of its own and its jump table leads out of the run: not
  followed. Code reached only through an indirect jump that is not
  followed starts with nothing known. A register that holds different
  values on different paths to an instruction yields no reference there,
  rather than one per path; following a jump table adds paths, so a
  reference the earlier sweep reported from one path alone can go.
- In object files of 32-bit x86 and 32-bit ARM, relocation entries are
  resolved for the instruction forms listed under "Xref Report". Not
  resolved: `GENERIC_RELOC_TLV`, plain `ARM_RELOC_SECTDIFF`, an operand
  with a base or
  index register that an external entry patches (`_array(,%eax,4)`), an
  immediate that is not the source of a register move (`push offset _s`),
  and an ARM `HALF_SECTDIFF` pair whose program-counter instruction is
  neither of the forms above. `*_PB_LA_PTR` entries belong to lazy
  pointer sections, not to code.
- Threaded binds and zlib-compressed chained import names are tested on
  files derived from the linker's output, not on files a toolchain made
  that way: `objc_threaded_arm64e` and `objc_zlib_arm64` in the corpus are
  rewritten from real binaries (`tests/corpus/src/dyld/mkthreaded.py`,
  `mkzlib.py`), and their Objective-C, pointer and import views equal
  those of the originals. No current linker emits threaded binds, and
  neither `dyld_info` ("old arm64e bind opcodes not supported") nor
  `llvm-objdump` reads them any more, so there is nothing left to compare
  with but a binary built for iOS 12, which was not at hand; authenticated
  entries of a threaded chain are covered by unit tests only. Compressed
  import names were never emitted by a linker and dyld rejects them
  (`symbols_format unknown`), so no real file of that kind exists.
- Big-endian files (PowerPC and older architectures) have their structure
  read, but their code is not disassembled and not swept for references:
  the `Disassembly` view says the architecture is not supported. They are
  covered by three small PowerPC objects, one hand-built
  (`tests/corpus/src/ppc`) and two a compiler made (LLVM's test inputs),
  whose symbols read as `nm` prints them; no linked big-endian image was
  tested, and Apple's `otool` refuses all three ("symbol table extends
  beyond the end of the file").
- A Swift type name is left as stored (referents in `{…}`, not demangled)
  when a reference in it cannot be resolved: a descriptor that is not
  readable, a type declared in an extension with generic constraints or of
  a type that is not named by one reference or a short mangling, a type
  whose name cannot be written as an identifier. A private or local type
  is shown as a member of what encloses it, without its discriminator
  (`Module.Type`, not `Module.(Type in _HASH)`). A stripped binary has no
  `…MQ` symbols, so the opaque result types of its own declarations print
  as `opaque type symbolic reference 0x…`; imported ones are named. Names
  that begin with 0xFF (references to accessor functions) are not types
  and are not demangled.
- `__swift5_replace`, `__swift5_replac2` and any `__swift5_*` section not
  named under "Swift Metadata" are shown as arrays of 32-bit relative
  pointers, which is not known to be their layout. `__swift5_acfuncs` was
  checked on one system binary (`appleaccountd`), the spare bit masks of
  `__swift5_mpenum` against the arm64 pointer spare bits
  (`0xF000000000000007`) in system applications.
- `moex cache-extract` output is for analysis, not for loading. Segments
  keep their cache addresses (they are scattered over the cache's regions
  and need not start or end on a page boundary). What the cache builder
  removed is not put back: stub sections it emptied stay empty, the rebase
  and bind information it applied is gone (`dyld_info -fixups` prints an
  empty table; pointers in data are stored the way the cache stores them),
  and there is no code signature. The segment load commands are not sorted
  by address for an image that has rebase or bind opcodes, chained fixups or
  split-segment info (they name segments by index and are not rewritten);
  its output is then in an order that `dyld_info` refuses (`vm address out
  of order`). No image of the macOS 27.2 cache is such a case.
  `SG_READ_ONLY` is restored on `__DATA_CONST` only.
- Merging local symbols from a cache's local symbols data (in the cache
  file or in `<cache>.symbols`) is written from the format in dyld's
  `dyld_cache_format.h` and tested with synthetic caches and with a copy of
  the macOS 27.2 cache rearranged to have a `.symbols` file (libsystem_c,
  libswiftCore and Foundation: `nm` output equal to the plain extraction,
  accepted by `dyld_info`). It has not been run on a cache built by Apple
  that has such data: macOS caches keep their local symbols, and no iOS
  cache was at hand. `otool -Iv` lists no indirect symbols for those images,
  so the renumbering of indirect symbol table entries is covered by unit
  tests only. An image without `LC_SYMTAB` gets no symbols.
- In `moex cache-extract`, linkedit data must lie inside the image's own
  `__LINKEDIT` segment, or the image is not extracted;
  `linkedit_data_command`s newer than `LC_LAZY_LOAD_DYLIB_INFO` (0x3A) are
  not known and keep stale offsets.

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
