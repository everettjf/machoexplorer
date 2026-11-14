//! LEB128 readers mirroring `util::readUnsignedLeb128` /
//! `util::readSignedLeb128`, including where they give up.

/// Decode one ULEB128 value from the start of `data`. Returns the value and
/// the number of bytes it occupies, or `None` when the input is truncated or
/// the value does not fit in 64 bits.
pub fn read_uleb128(data: &[u8]) -> Option<(u64, u32)> {
    let mut result: u64 = 0;
    let mut bit: u32 = 0;
    let mut used: u32 = 0;
    loop {
        let byte = *data.get(used as usize)?;
        let slice = (byte & 0x7f) as u64;
        if bit >= 64 || (slice << bit) >> bit != slice {
            return None;
        }
        result |= slice << bit;
        bit += 7;
        used = used.checked_add(1)?;
        if byte & 0x80 == 0 {
            return Some((result, used));
        }
    }
}

/// Decode one SLEB128 value from the start of `data`. Returns the value and
/// the number of bytes it occupies, or `None` when the input is truncated or
/// longer than ten bytes. Bits shifted past bit 63 are dropped silently.
pub fn read_sleb128(data: &[u8]) -> Option<(i64, u32)> {
    let mut result: u64 = 0;
    let mut bit: u32 = 0;
    let mut used: u32 = 0;
    loop {
        if bit >= 64 {
            return None;
        }
        let byte = *data.get(used as usize)?;
        used = used.checked_add(1)?;
        result |= ((byte & 0x7f) as u64) << bit;
        bit += 7;
        if byte & 0x80 == 0 {
            if byte & 0x40 != 0 && bit < 64 {
                result |= u64::MAX << bit;
            }
            return Some((result as i64, used));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uleb() {
        assert_eq!(read_uleb128(&[0]), Some((0, 1)));
        assert_eq!(read_uleb128(&[0x7f, 0xff]), Some((0x7f, 1)));
        assert_eq!(read_uleb128(&[0xe5, 0x8e, 0x26]), Some((624485, 3)));
        // Non-canonical padding is accepted.
        assert_eq!(read_uleb128(&[0x80, 0x00]), Some((0, 2)));
        // u64::MAX: nine 0xff bytes then 0x01.
        let mut max = vec![0xff; 9];
        max.push(0x01);
        assert_eq!(read_uleb128(&max), Some((u64::MAX, 10)));
    }

    #[test]
    fn uleb_rejects_bad_input() {
        assert_eq!(read_uleb128(&[]), None);
        // Continuation bit set on the last available byte.
        assert_eq!(read_uleb128(&[0x80]), None);
        assert_eq!(read_uleb128(&[0xff, 0xff]), None);
        // Tenth byte carries bits that do not fit in 64 bits.
        let mut over = vec![0xff; 9];
        over.push(0x02);
        assert_eq!(read_uleb128(&over), None);
        // Eleven bytes: shift reaches 70.
        let mut long = vec![0x80; 10];
        long.push(0x00);
        assert_eq!(read_uleb128(&long), None);
    }

    #[test]
    fn sleb() {
        assert_eq!(read_sleb128(&[0]), Some((0, 1)));
        assert_eq!(read_sleb128(&[0x02]), Some((2, 1)));
        assert_eq!(read_sleb128(&[0x7e]), Some((-2, 1)));
        assert_eq!(read_sleb128(&[0xff, 0x00]), Some((127, 2)));
        assert_eq!(read_sleb128(&[0x80, 0x7f]), Some((-128, 2)));
        assert_eq!(read_sleb128(&[0xc0, 0xbb, 0x78]), Some((-123456, 3)));
        // i64::MIN: nine 0x80 bytes then 0x7f.
        let mut min = vec![0x80; 9];
        min.push(0x7f);
        assert_eq!(read_sleb128(&min), Some((i64::MIN, 10)));
    }

    #[test]
    fn sleb_rejects_bad_input() {
        assert_eq!(read_sleb128(&[]), None);
        assert_eq!(read_sleb128(&[0x80]), None);
        // Eleven bytes.
        let mut long = vec![0x80; 10];
        long.push(0x00);
        assert_eq!(read_sleb128(&long), None);
    }
}
