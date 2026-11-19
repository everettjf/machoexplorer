# Bundled sources

`swift/` is the demangler of the Swift compiler (Swift 6.3.1), reduced to
what demangling needs, exactly as the `symbolic-demangle` crate 13.9.0
ships it (including its two patches, kept as `swift/*.patch`; see
`swift/README.md` for how that subset is made). It is built by `build.rs`
together with `src/swift_demangle.cpp`.

It is bundled here, instead of used through that crate, because the crate
exposes symbol demangling only: the type names in a binary's reflection
metadata contain symbolic references, which the demangler resolves through
a callback that only its C++ interface offers.

The demangled text is part of the dump output and of the golden baselines,
so updating these sources means regenerating and reviewing them.
