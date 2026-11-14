//! Small helpers shared by several modules.

use std::time::{SystemTime, UNIX_EPOCH};

/// `yyyyMMdd-hhmmss-zzz` in UTC (used in temp file names, as Qt did).
pub fn utc_stamp(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    format!(
        "{year:04}{month:02}{day:02}-{:02}{:02}{:02}-{:03}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        d.subsec_millis()
    )
}

pub fn utc_stamp_now() -> String {
    utc_stamp(SystemTime::now())
}

pub fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn stamps() {
        assert_eq!(utc_stamp(UNIX_EPOCH), "19700101-000000-000");
        assert_eq!(
            utc_stamp(UNIX_EPOCH + Duration::from_millis(1_709_210_096_789)),
            "20240229-123456-789"
        );
        assert_eq!(
            utc_stamp(UNIX_EPOCH + Duration::from_secs(1_767_225_599)),
            "20251231-235959-000"
        );
    }

    #[test]
    fn names() {
        assert_eq!(
            file_name("/a/b/dyld_shared_cache_arm64e"),
            "dyld_shared_cache_arm64e"
        );
        assert_eq!(file_name("C:\\x\\y.bin"), "y.bin");
        assert_eq!(file_name("plain"), "plain");
    }
}
