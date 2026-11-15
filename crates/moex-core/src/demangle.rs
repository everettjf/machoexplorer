//! C++ (Itanium ABI) symbol demangling.
//!
//! On macOS and Linux the C++ runtime's own `__cxa_demangle` does the work
//! (`libc++abi` and `libstdc++`; the latter is linked anyway for the Swift
//! demangler). Windows has no such runtime, so the pure-Rust `cpp_demangle`
//! crate is used there; its text differs for special names (it prints
//! `{vtable(Foo)}` for `vtable for Foo`) and some heavily templated ones.

/// Demangle an Itanium-mangled name (starting with `_Z`). `None` when the
/// name is not valid.
pub fn demangle_itanium(mangled: &[u8]) -> Option<String> {
    if !mangled.starts_with(b"_Z") {
        return None;
    }
    imp::demangle(mangled).filter(|s| !s.is_empty())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod imp {
    use std::ffi::{c_char, c_int, c_void, CStr, CString};

    #[cfg_attr(target_os = "macos", link(name = "c++abi"))]
    #[cfg_attr(target_os = "linux", link(name = "stdc++"))]
    extern "C" {
        fn __cxa_demangle(
            mangled_name: *const c_char,
            output_buffer: *mut c_char,
            length: *mut usize,
            status: *mut c_int,
        ) -> *mut c_char;
    }

    extern "C" {
        fn free(ptr: *mut c_void);
    }

    pub fn demangle(mangled: &[u8]) -> Option<String> {
        // Interior NULs cannot be part of a symbol name.
        let input = CString::new(mangled).ok()?;
        let mut status: c_int = 0;
        // SAFETY: `input` is a valid NUL-terminated string that outlives the
        // call. With a null output buffer and length, `__cxa_demangle`
        // returns either null or a malloc'ed NUL-terminated string that we
        // own and must release with `free`.
        unsafe {
            let out = __cxa_demangle(
                input.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut status,
            );
            if out.is_null() {
                return None;
            }
            // libstdc++ still separates nested template closers (`> >`).
            let text = (status == 0).then(|| {
                crate::hex::utf8_safe(CStr::from_ptr(out).to_bytes())
                    .replace("> >", ">>")
                    .replace("> >", ">>")
            });
            free(out.cast());
            text
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod imp {
    pub fn demangle(mangled: &[u8]) -> Option<String> {
        let sym = cpp_demangle::Symbol::new(mangled).ok()?;
        let out = sym.demangle().ok()?;
        // Match the modern `>>` spelling of nested template closers.
        Some(out.replace("> >", ">>").replace("> >", ">>"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demangles_simple_names() {
        assert_eq!(demangle_itanium(b"_Z3fooi").as_deref(), Some("foo(int)"));
        assert_eq!(
            demangle_itanium(b"_ZN3Foo3barEv").as_deref(),
            Some("Foo::bar()")
        );
        assert_eq!(
            demangle_itanium(b"_ZNSt3__16vectorIiNS_9allocatorIiEEE9push_backEOi").as_deref(),
            Some("std::__1::vector<int, std::__1::allocator<int>>::push_back(int&&)")
        );
    }

    #[test]
    fn rejects_non_mangled_or_broken_names() {
        assert_eq!(demangle_itanium(b"main"), None);
        assert_eq!(demangle_itanium(b"_Z"), None);
        assert_eq!(demangle_itanium(b"_Z3fo"), None);
        assert_eq!(demangle_itanium(b"_Z3foo\0i"), None);
        assert_eq!(demangle_itanium(b""), None);
    }
}
