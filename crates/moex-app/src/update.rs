//! Update check against GitHub Releases. Decoding and version comparison are
//! pure (`ReleaseInfo`, `evaluate`); only `fetch_latest_release` touches the
//! network and it is never called from tests.

use std::time::Duration;

pub const RELEASE_API_URL: &str =
    "https://api.github.com/repos/everettjf/MachOExplorer/releases/latest";
pub const RELEASE_PAGE_URL: &str = "https://github.com/everettjf/MachOExplorer/releases";
pub const USER_AGENT: &str = "MachOExplorer-UpdateChecker";
const MAX_BODY: u64 = 1024 * 1024;
/// A cached valid response is reused for this long (seconds).
pub const CACHE_SECONDS: i64 = 3600;

/// A strict `major.minor.patch` version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u64, pub u64, pub u64);

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// Accepts `1.2.3` with optional surrounding whitespace and a leading `v`;
/// anything else (pre-release suffixes, two components, junk) is rejected.
pub fn parse_version(value: &str) -> Option<Version> {
    let v = value.trim();
    let v = v.strip_prefix('v').unwrap_or(v);
    let mut parts = v.split('.');
    let mut out = [0u64; 3];
    for slot in &mut out {
        let p = parts.next()?;
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *slot = p.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(Version(out[0], out[1], out[2]))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseInfo {
    pub version: Version,
    pub url: String,
}

impl ReleaseInfo {
    /// Decode a GitHub "latest release" response. Returns `None` unless it is
    /// a published, non-prerelease release with a strict version tag and an
    /// `https://github.com/everettjf/machoexplorer/releases/tag/...` URL.
    pub fn parse(body: &[u8]) -> Option<ReleaseInfo> {
        let doc: serde_json::Value = serde_json::from_slice(body).ok()?;
        let obj = doc.as_object()?;
        if obj.get("draft")?.as_bool()? || obj.get("prerelease")?.as_bool()? {
            return None;
        }
        let version = parse_version(obj.get("tag_name")?.as_str()?)?;
        let url = obj.get("html_url")?.as_str()?;
        if !is_trusted_release_url(url) {
            return None;
        }
        Some(ReleaseInfo {
            version,
            url: url.to_string(),
        })
    }
}

fn is_trusted_release_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    // No port, no user info, exact host.
    if !authority.eq_ignore_ascii_case("github.com") {
        return false;
    }
    if path.contains('?') || path.contains('#') {
        return false;
    }
    const PREFIX: &str = "/everettjf/machoexplorer/releases/tag/";
    path.len() >= PREFIX.len() && path[..PREFIX.len()].eq_ignore_ascii_case(PREFIX)
}

/// What to tell the user after a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// Response could not be decoded / is not a trusted stable release.
    Invalid,
    /// The running build has a version that cannot be compared (e.g. `-dev`).
    DevelopmentBuild {
        latest: Version,
        url: String,
    },
    UpToDate {
        current: Version,
        latest: Version,
    },
    Available {
        current: Version,
        latest: Version,
        url: String,
    },
}

pub fn evaluate(current_version: &str, body: &[u8]) -> UpdateOutcome {
    let Some(release) = ReleaseInfo::parse(body) else {
        return UpdateOutcome::Invalid;
    };
    match parse_version(current_version) {
        None => UpdateOutcome::DevelopmentBuild {
            latest: release.version,
            url: release.url,
        },
        Some(current) if release.version <= current => UpdateOutcome::UpToDate {
            current,
            latest: release.version,
        },
        Some(current) => UpdateOutcome::Available {
            current,
            latest: release.version,
            url: release.url,
        },
    }
}

/// The startup check is skipped while a "remind me later" snooze is active.
pub fn should_check_on_startup(remind_until_utc: i64, now_utc: i64) -> bool {
    remind_until_utc <= now_utc
}

pub fn cache_is_fresh(checked_at_utc: i64, now_utc: i64) -> bool {
    let age = now_utc - checked_at_utc;
    (0..CACHE_SECONDS).contains(&age)
}

pub fn now_utc() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub const DAY_SECONDS: i64 = 24 * 60 * 60;

/// Blocking GET of the latest-release document. Call on a background thread.
pub fn fetch_latest_release() -> Result<Vec<u8>, String> {
    use std::io::Read;
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(15))
        .redirects(0)
        .user_agent(USER_AGENT)
        .build();
    let resp = agent
        .get(RELEASE_API_URL)
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| e.to_string())?;
    if resp.status() != 200 {
        return Err(format!("unexpected HTTP status {}", resp.status()));
    }
    let mut body = Vec::new();
    resp.into_reader()
        .take(MAX_BODY + 1)
        .read_to_end(&mut body)
        .map_err(|e| e.to_string())?;
    if body.len() as u64 > MAX_BODY {
        return Err("response too large".into());
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    //! Ported from tests/regression/release_info_test.cpp.
    use super::*;

    const GOOD_URL: &str = "https://github.com/everettjf/MachOExplorer/releases/tag/v2.0.16";

    fn release(tag: &str, url: &str) -> Vec<u8> {
        serde_json::json!({"tag_name": tag, "html_url": url, "draft": false, "prerelease": false})
            .to_string()
            .into_bytes()
    }

    #[test]
    fn stable_github_response() {
        let info = ReleaseInfo::parse(&release("v2.0.16", GOOD_URL)).unwrap();
        assert_eq!(info.version, Version(2, 0, 16));
        assert_eq!(info.url, GOOD_URL);
    }

    #[test]
    fn canonical_lowercase_repository_url() {
        let url = "https://github.com/everettjf/machoexplorer/releases/tag/v2.0.16";
        assert!(ReleaseInfo::parse(&release("v2.0.16", url)).is_some());
    }

    #[test]
    fn numeric_ordering() {
        let v = parse_version("v2.0.16").unwrap();
        assert!(v > parse_version("2.0.9").unwrap());
        assert!(v < parse_version("2.0.17").unwrap());
    }

    #[test]
    fn trim_and_prefix() {
        assert_eq!(parse_version(" v2.0.16\n"), Some(Version(2, 0, 16)));
    }

    #[test]
    fn malformed_or_prerelease_tag() {
        for tag in [
            "",
            "v2.0.16-beta",
            "2.0.16evil",
            "version2.0.16",
            "2.0",
            "2.0.16.1",
            "2..16",
            "+2.0.1",
        ] {
            assert!(
                ReleaseInfo::parse(&release(tag, GOOD_URL)).is_none(),
                "{tag}"
            );
        }
    }

    #[test]
    fn untrusted_release_url() {
        for url in [
            "http://github.com/everettjf/MachOExplorer/releases/tag/v2.0.16",
            "https://evil.test/download",
            "https://github.com/other/project/releases/tag/v2.0.16",
            "https://github.com:4444/everettjf/MachOExplorer/releases/tag/v2.0.16",
            "https://user@github.com/everettjf/MachOExplorer/releases/tag/v2.0.16",
            "https://github.com/everettjf/MachOExplorer/releases/tag/v2.0.16?x=1",
            "https://github.com/everettjf/MachOExplorer/releases/tag/v2.0.16#frag",
            "https://github.com.evil.test/everettjf/MachOExplorer/releases/tag/v2.0.16",
        ] {
            assert!(
                ReleaseInfo::parse(&release("v2.0.16", url)).is_none(),
                "{url}"
            );
        }
    }

    #[test]
    fn invalid_json_and_unexpected_shapes() {
        assert!(ReleaseInfo::parse(b"not json").is_none());
        assert!(ReleaseInfo::parse(b"[]").is_none());
        assert!(ReleaseInfo::parse(br#"{"message":"rate limited"}"#).is_none());
    }

    #[test]
    fn unpublished_release() {
        for field in ["draft", "prerelease"] {
            let mut doc: serde_json::Value =
                serde_json::from_slice(&release("v2.0.16", GOOD_URL)).unwrap();
            doc[field] = serde_json::Value::Bool(true);
            assert!(ReleaseInfo::parse(doc.to_string().as_bytes()).is_none());
            // The flags must be real booleans.
            doc[field] = serde_json::Value::String("false".into());
            assert!(ReleaseInfo::parse(doc.to_string().as_bytes()).is_none());
        }
    }

    #[test]
    fn evaluate_outcomes() {
        let body = release("v2.0.16", GOOD_URL);
        assert_eq!(
            evaluate("2.0.15", &body),
            UpdateOutcome::Available {
                current: Version(2, 0, 15),
                latest: Version(2, 0, 16),
                url: GOOD_URL.into()
            }
        );
        assert_eq!(
            evaluate("v2.0.16", &body),
            UpdateOutcome::UpToDate {
                current: Version(2, 0, 16),
                latest: Version(2, 0, 16)
            }
        );
        assert!(matches!(
            evaluate("2.1.0", &body),
            UpdateOutcome::UpToDate { .. }
        ));
        assert!(matches!(
            evaluate("3.0.0-dev", &body),
            UpdateOutcome::DevelopmentBuild { .. }
        ));
        assert_eq!(evaluate("2.0.15", b"{}"), UpdateOutcome::Invalid);
    }

    #[test]
    fn startup_snooze_and_cache() {
        assert!(should_check_on_startup(0, 100));
        assert!(should_check_on_startup(100, 100));
        assert!(!should_check_on_startup(101, 100));
        assert!(cache_is_fresh(100, 100 + CACHE_SECONDS - 1));
        assert!(!cache_is_fresh(100, 100 + CACHE_SECONDS));
        assert!(!cache_is_fresh(200, 100));
    }
}
