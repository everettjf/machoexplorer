//! String formatting helpers. Names and output mirror `moex::util` so table
//! cells are byte-identical to the previous implementation.

/// Decimal.
pub fn as_string<T: std::fmt::Display>(v: T) -> String {
    v.to_string()
}

/// Upper-case hex, zero-padded to at least 8 digits.
pub fn as_hex_string(v: u64) -> String {
    format!("{:08X}", v)
}

/// Upper-case hex, no padding.
pub fn as_short_hex_string(v: u64) -> String {
    format!("{:X}", v)
}

/// File offset column: upper-case hex, zero-padded to at least 8 digits.
pub fn as_address(v: u64) -> String {
    format!("{:08X}", v)
}

/// Bytes as contiguous upper-case hex.
pub fn as_hex_data(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02X}", b));
    }
    s
}

/// `major.minor.patch` from a packed `xxxx.yy.zz` version.
pub fn format_version(ver: u32) -> String {
    format!("{}.{}.{}", ver >> 16, (ver >> 8) & 0xff, ver & 0xff)
}

/// `ctime(3)`-style local time, including the trailing newline, e.g.
/// `"Thu Jan  1 00:00:02 1970\n"`. Set `MOEX_TZ=UTC` to format in UTC
/// (used by tests for reproducible output).
pub fn format_timestamp(timestamp: u32) -> String {
    use chrono::{Local, TimeZone, Utc};
    const FMT: &str = "%a %b %e %H:%M:%S %Y\n";
    let secs = timestamp as i64;
    if std::env::var("MOEX_TZ")
        .map(|v| v.eq_ignore_ascii_case("UTC"))
        .unwrap_or(false)
    {
        Utc.timestamp_opt(secs, 0)
            .single()
            .map(|t| t.format(FMT).to_string())
    } else {
        Local
            .timestamp_opt(secs, 0)
            .single()
            .map(|t| t.format(FMT).to_string())
    }
    .unwrap_or_default()
}

/// Lower-case canonical UUID text.
pub fn format_uuid(d: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]
    )
}

/// Convert raw bytes to a `String`, replacing each malformed UTF-8 byte with
/// `?` (not U+FFFD). Cell values can hold raw bytes from malformed binaries.
pub fn utf8_safe(input: &[u8]) -> String {
    let n = input.len();
    let mut out = String::with_capacity(n);
    let mut i = 0;
    while i < n {
        let c = input[i];
        if c < 0x80 {
            out.push(c as char);
            i += 1;
            continue;
        }
        let (len, min_cp) = if c & 0xE0 == 0xC0 {
            (2usize, 0x80u32)
        } else if c & 0xF0 == 0xE0 {
            (3, 0x800)
        } else if c & 0xF8 == 0xF0 {
            (4, 0x10000)
        } else {
            out.push('?');
            i += 1;
            continue;
        };
        if i + len > n {
            out.push('?');
            i += 1;
            continue;
        }
        let mut cp = (c as u32) & (0x7F >> len);
        let mut ok = true;
        for k in 1..len {
            let cc = input[i + k];
            if cc & 0xC0 != 0x80 {
                ok = false;
                break;
            }
            cp = (cp << 6) | (cc as u32 & 0x3F);
        }
        match (ok && cp >= min_cp).then(|| char::from_u32(cp)).flatten() {
            Some(ch) => {
                out.push(ch);
                i += len;
            }
            None => {
                out.push('?');
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(as_hex_string(0x1f), "0000001F");
        assert_eq!(as_hex_string(0x1_2345_6789), "123456789");
        assert_eq!(as_short_hex_string(0x4000), "4000");
        assert_eq!(format_version(0x000A_0F02), "10.15.2");
        assert_eq!(as_hex_data(&[0, 0xAB, 0x7]), "00AB07");
    }

    #[test]
    fn utf8_safe_replaces_bad_bytes() {
        assert_eq!(utf8_safe(b"abc"), "abc");
        assert_eq!(utf8_safe("中文".as_bytes()), "中文");
        assert_eq!(utf8_safe(&[b'a', 0xFF, b'b']), "a?b");
        // truncated 3-byte sequence
        assert_eq!(utf8_safe(&[0xE4, 0xB8]), "??");
        // overlong encoding of '/'
        assert_eq!(utf8_safe(&[0xC0, 0xAF]), "??");
        // UTF-16 surrogate
        assert_eq!(utf8_safe(&[0xED, 0xA0, 0x80]), "???");
    }
}
