//! Helpers for the subcommands that keep the argument syntax of the
//! stand-alone `moex-*` tools (`--flag` and `--key=value` options first,
//! then positionals).

use std::io::Write;
use std::process::ExitCode;

/// `std::stoi`-style parse: optional leading whitespace and sign, then at
/// least one digit; anything after the digits is ignored. `None` when there
/// are no digits or the value does not fit in an `i32`.
pub fn stoi(s: &str) -> Option<i32> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let negative = match b.get(i) {
        Some(b'-') => {
            i += 1;
            true
        }
        Some(b'+') => {
            i += 1;
            false
        }
        _ => false,
    };
    let start = i;
    let mut value: i64 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        value = value.checked_mul(10)?.checked_add((b[i] - b'0') as i64)?;
        if value > i32::MAX as i64 + 1 {
            return None;
        }
        i += 1;
    }
    if i == start {
        return None;
    }
    i32::try_from(if negative { -value } else { value }).ok()
}

/// Value of a `--name=N` count option: negative values clamp to 0.
pub fn count_option(value: &str) -> Option<u32> {
    stoi(value).map(|v| v.max(0) as u32)
}

/// Write to stdout, ignoring errors such as a closed pipe.
pub fn out(bytes: &[u8]) {
    let _ = std::io::stdout().lock().write_all(bytes);
}

/// Write `bytes` plus a newline to stderr, ignoring errors.
pub fn err_line(bytes: &[u8]) {
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(bytes);
    let _ = stderr.write_all(b"\n");
}

pub const EXIT_FAILURE: u8 = 1;
pub const EXIT_USAGE: u8 = 2;

pub fn exit(code: u8) -> ExitCode {
    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stoi_like_cpp() {
        assert_eq!(stoi("12"), Some(12));
        assert_eq!(stoi("  +7abc"), Some(7));
        assert_eq!(stoi("-3"), Some(-3));
        assert_eq!(stoi("2147483647"), Some(i32::MAX));
        assert_eq!(stoi("-2147483648"), Some(i32::MIN));
        assert_eq!(stoi("2147483648"), None);
        assert_eq!(stoi("99999999999999999999999999"), None);
        assert_eq!(stoi(""), None);
        assert_eq!(stoi("abc"), None);
        assert_eq!(stoi("-"), None);
    }

    #[test]
    fn counts_clamp_negative() {
        assert_eq!(count_option("5"), Some(5));
        assert_eq!(count_option("-5"), Some(0));
        assert_eq!(count_option("x"), None);
    }
}
