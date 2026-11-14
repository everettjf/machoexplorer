//! "Extract Image From Dyld Cache": the seam to the core's cache functions
//! ([`CacheTools`]) plus the UI-independent parts of the flow.
//!
//! Wiring the real implementation: implement [`CacheTools`] on a type that
//! calls the core's list/extract functions and return it from
//! [`default_tools`]. Nothing else needs to change.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Sink for progress/diagnostic lines (shown in the Log pane).
pub type LogSink<'a> = &'a (dyn Fn(String) + Send + Sync);

pub trait CacheTools: Send + Sync {
    /// Paths of up to `limit` images contained in the cache at `cache`.
    fn list(&self, cache: &Path, limit: usize) -> Result<Vec<String>, String>;

    /// Extract the image selected by `selector` (exact path or substring)
    /// from `cache` into the file `output`. Must poll `cancel` and return an
    /// error promptly once it is set.
    fn extract(
        &self,
        cache: &Path,
        selector: &str,
        output: &Path,
        cancel: &AtomicBool,
        log: LogSink,
    ) -> Result<(), String>;
}

pub const MSG_NOT_AVAILABLE: &str = "Dyld shared cache tools are not available yet in this build.";

/// Temporary implementation until the core functions land.
pub struct UnavailableCacheTools;

impl CacheTools for UnavailableCacheTools {
    fn list(&self, _cache: &Path, _limit: usize) -> Result<Vec<String>, String> {
        Err(MSG_NOT_AVAILABLE.into())
    }

    fn extract(
        &self,
        _cache: &Path,
        _selector: &str,
        _output: &Path,
        _cancel: &AtomicBool,
        _log: LogSink,
    ) -> Result<(), String> {
        Err(MSG_NOT_AVAILABLE.into())
    }
}

/// In-process implementation backed by `moex_core::cache_tools`.
pub struct CoreCacheTools;

impl CacheTools for CoreCacheTools {
    fn list(&self, cache: &Path, limit: usize) -> Result<Vec<String>, String> {
        let cache = moex_core::cache_tools::open_cache(cache).map_err(|e| e.to_string())?;
        let mut images = moex_core::cache_tools::image_paths(&cache);
        images.truncate(limit);
        Ok(images)
    }

    fn extract(
        &self,
        cache: &Path,
        selector: &str,
        output: &Path,
        cancel: &AtomicBool,
        log: LogSink,
    ) -> Result<(), String> {
        let options = moex_core::cache_tools::ExtractOptions::default();
        let mut sink = |line: &str| log(line.to_string());
        moex_core::cache_tools::extract_from_cache_file(
            cache, selector, false, output, &options, cancel, &mut sink,
        )
        .map(|_| ())
        .map_err(|e| String::from_utf8_lossy(&e.message).into_owned())
    }
}

/// The implementation the app uses.
pub fn default_tools() -> Arc<dyn CacheTools> {
    Arc::new(CoreCacheTools)
}

pub const LIST_LIMIT: usize = 5000;
pub const DEFAULT_CACHE_DIR: &str = "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld";
pub const DEFAULT_SELECTOR: &str = "libswiftCore.dylib";

/// Qt skipped the file picker when the open document already was a cache.
pub fn is_cache_file(path: &str) -> bool {
    crate::util::file_name(path).starts_with("dyld_shared_cache")
}

/// Trim, drop empties, deduplicate and sort case-insensitively.
pub fn prepare_image_list(images: Vec<String>) -> Vec<String> {
    let mut v: Vec<String> = images
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    v.sort_by(|a, b| {
        a.to_lowercase()
            .cmp(&b.to_lowercase())
            .then_with(|| a.cmp(b))
    });
    v.dedup();
    v
}

/// Indices of images whose path contains `query` (case-insensitive).
pub fn filter_images(images: &[String], query: &str) -> Vec<usize> {
    let q = query.trim().to_lowercase();
    (0..images.len())
        .filter(|i| crate::table_model::contains_ci(&images[*i], &q))
        .collect()
}

pub fn validate_selector(text: &str) -> Result<String, String> {
    let s = text.trim();
    if s.is_empty() {
        return Err("Image selector is empty.".into());
    }
    if s.contains('\n') || s.contains('\r') {
        return Err("Invalid image selector: newline is not allowed.".into());
    }
    Ok(s.to_string())
}

pub fn output_path(cache: &str, stamp: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "MachOExplorer-cache-extract-{}-{stamp}",
        crate::util::file_name(cache)
    ))
}

/// Output path when extracting from a row of the cache's image table.
pub fn row_output_path(image: &str, stamp: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "MachOExplorer-cache-row-{}-{stamp}",
        crate::util::file_name(image)
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractOutcome {
    /// Output written; `size` bytes.
    Done {
        size: u64,
    },
    Canceled,
    Failed(String),
}

/// Run one extraction to completion (blocking; call on a background thread).
/// Removes the output file unless the extraction succeeded.
pub fn run_extract(
    tools: &dyn CacheTools,
    cache: &Path,
    selector: &str,
    output: &Path,
    cancel: &AtomicBool,
    log: LogSink,
) -> ExtractOutcome {
    let result = tools.extract(cache, selector, output, cancel, log);
    if cancel.load(Ordering::Relaxed) {
        let _ = std::fs::remove_file(output);
        return ExtractOutcome::Canceled;
    }
    if let Err(e) = result {
        let _ = std::fs::remove_file(output);
        let details = e.trim();
        let details = if details.is_empty() {
            "(no process output)"
        } else {
            details
        };
        return ExtractOutcome::Failed(format!("Extraction failed:\n{details}"));
    }
    match std::fs::metadata(output) {
        Ok(m) if m.len() > 0 => ExtractOutcome::Done { size: m.len() },
        _ => {
            let _ = std::fs::remove_file(output);
            ExtractOutcome::Failed(format!(
                "Extraction completed but output is missing or empty:\n{}",
                output.display()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        fail: Option<&'static str>,
        write: &'static [u8],
        cancel_during: bool,
    }

    impl CacheTools for Fake {
        fn list(&self, _: &Path, limit: usize) -> Result<Vec<String>, String> {
            Ok(vec![
                "/usr/lib/b.dylib".into(),
                " /usr/lib/A.dylib ".into(),
                "".into(),
                "/usr/lib/b.dylib".into(),
            ]
            .into_iter()
            .take(limit)
            .collect())
        }

        fn extract(
            &self,
            _: &Path,
            selector: &str,
            output: &Path,
            cancel: &AtomicBool,
            log: LogSink,
        ) -> Result<(), String> {
            log(format!("extracting {selector}"));
            if !self.write.is_empty() {
                std::fs::write(output, self.write).unwrap();
            }
            if self.cancel_during {
                cancel.store(true, Ordering::Relaxed);
                return Err("canceled".into());
            }
            match self.fail {
                Some(e) => Err(e.into()),
                None => Ok(()),
            }
        }
    }

    fn run(fake: Fake) -> (ExtractOutcome, bool, Vec<String>) {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out.bin");
        let cancel = AtomicBool::new(false);
        let lines = std::sync::Mutex::new(Vec::new());
        let outcome = run_extract(&fake, Path::new("/cache"), "libfoo", &out, &cancel, &|l| {
            lines.lock().unwrap().push(l)
        });
        (outcome, out.exists(), lines.into_inner().unwrap())
    }

    #[test]
    fn extract_outcomes() {
        let (o, exists, log) = run(Fake {
            fail: None,
            write: b"macho",
            cancel_during: false,
        });
        assert_eq!(o, ExtractOutcome::Done { size: 5 });
        assert!(exists);
        assert_eq!(log, vec!["extracting libfoo"]);

        let (o, exists, _) = run(Fake {
            fail: Some(" boom \n"),
            write: b"partial",
            cancel_during: false,
        });
        assert_eq!(o, ExtractOutcome::Failed("Extraction failed:\nboom".into()));
        assert!(!exists);

        let (o, _, _) = run(Fake {
            fail: Some(""),
            write: b"",
            cancel_during: false,
        });
        assert_eq!(
            o,
            ExtractOutcome::Failed("Extraction failed:\n(no process output)".into())
        );

        let (o, exists, _) = run(Fake {
            fail: None,
            write: b"",
            cancel_during: false,
        });
        assert!(
            matches!(o, ExtractOutcome::Failed(m) if m.starts_with("Extraction completed but output is missing or empty:\n"))
        );
        assert!(!exists);

        let (o, exists, _) = run(Fake {
            fail: None,
            write: b"partial",
            cancel_during: true,
        });
        assert_eq!(o, ExtractOutcome::Canceled);
        assert!(!exists);
    }

    #[test]
    fn core_tools_report_core_errors() {
        let tools = default_tools();
        // Missing file and a Mach-O that is not a cache both fail cleanly.
        assert!(tools
            .list(Path::new("/nonexistent/dyld_shared_cache"), 10)
            .is_err());
        let sample = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sample/simple");
        assert!(tools.list(&sample, 10).is_err());
        let cancel = AtomicBool::new(false);
        let out = std::env::temp_dir().join("moex-core-tools-test.out");
        assert!(tools
            .extract(&sample, "libobjc", &out, &cancel, &|_| {})
            .is_err());
        assert!(!out.exists());
    }

    #[test]
    fn placeholder_reports_unavailable() {
        let tools: Arc<dyn CacheTools> = Arc::new(UnavailableCacheTools);
        assert_eq!(
            tools.list(Path::new("/x"), 10).unwrap_err(),
            MSG_NOT_AVAILABLE
        );
        let cancel = AtomicBool::new(false);
        let o = run_extract(
            &*tools,
            Path::new("/x"),
            "y",
            Path::new("/nonexistent/out"),
            &cancel,
            &|_| {},
        );
        assert_eq!(
            o,
            ExtractOutcome::Failed(format!("Extraction failed:\n{MSG_NOT_AVAILABLE}"))
        );
    }

    #[test]
    fn list_preparation_and_search() {
        let fake = Fake {
            fail: None,
            write: b"",
            cancel_during: false,
        };
        let list = prepare_image_list(fake.list(Path::new("/c"), LIST_LIMIT).unwrap());
        assert_eq!(list, vec!["/usr/lib/A.dylib", "/usr/lib/b.dylib"]);
        assert_eq!(filter_images(&list, "B.DY"), vec![1]);
        assert_eq!(filter_images(&list, "  "), vec![0, 1]);
        assert!(filter_images(&list, "zzz").is_empty());
    }

    #[test]
    fn selectors_and_paths() {
        assert_eq!(
            validate_selector("  libswiftCore.dylib ").unwrap(),
            "libswiftCore.dylib"
        );
        assert!(validate_selector("   ").is_err());
        assert_eq!(
            validate_selector("a\nb").unwrap_err(),
            "Invalid image selector: newline is not allowed."
        );
        assert!(is_cache_file("/System/x/dyld_shared_cache_arm64e"));
        assert!(!is_cache_file("/bin/ls"));
        assert!(!is_cache_file(""));
        let p = output_path("/x/dyld_shared_cache_arm64e", "20240101-000000-000");
        assert_eq!(
            p.file_name().unwrap(),
            "MachOExplorer-cache-extract-dyld_shared_cache_arm64e-20240101-000000-000"
        );
        let p = row_output_path("/usr/lib/libobjc.A.dylib", "S");
        assert_eq!(
            p.file_name().unwrap(),
            "MachOExplorer-cache-row-libobjc.A.dylib-S"
        );
    }
}
