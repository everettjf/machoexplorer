//! Builds the bundled Swift demangler (`vendor/swift`) and its C interface
//! (`src/swift_demangle.cpp`).

fn main() {
    const SOURCES: [&str; 9] = [
        "src/swift_demangle.cpp",
        "vendor/swift/lib/Demangling/Context.cpp",
        "vendor/swift/lib/Demangling/Demangler.cpp",
        "vendor/swift/lib/Demangling/Errors.cpp",
        "vendor/swift/lib/Demangling/ManglingUtils.cpp",
        "vendor/swift/lib/Demangling/NodeDumper.cpp",
        "vendor/swift/lib/Demangling/NodePrinter.cpp",
        "vendor/swift/lib/Demangling/Punycode.cpp",
        "vendor/swift/lib/Demangling/Remangler.cpp",
    ];
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/swift_demangle.cpp");
    println!("cargo:rerun-if-changed=vendor/swift");
    cc::Build::new()
        .cpp(true)
        .std("c++17")
        .files(SOURCES)
        .flag_if_supported("-fpermissive")
        .flag_if_supported("-Wno-changes-meaning")
        .define("LLVM_DISABLE_ABI_BREAKING_CHECKS_ENFORCING", "1")
        .define("SWIFT_STDLIB_HAS_TYPE_PRINTING", "1")
        // The demangler's assertions abort; a mangled name read from a
        // file must never do that.
        .define("NDEBUG", None)
        .warnings(false)
        .include("vendor/swift/include")
        .compile("moexswiftdemangle");
}
