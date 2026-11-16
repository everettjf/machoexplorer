//! `moex cache-extract`: extract images from a dyld shared cache.

use crate::legacy_args::*;
use moex_core::cache_tools::*;
use moex_core::macho::{Binary, Kind};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;

fn print_usage() {
    eprint!(
        "usage: moex cache-extract [--compact] [--all] [--exact] [--dry-run] [--json] [--max=N] <dyld_shared_cache_file> <image-path-or-substr> <output-macho-or-dir>\n\
         \x20 --compact   pack segments back to back instead of keeping their recorded file offsets\n\
         \x20 --all       extract all matched images into output directory\n\
         \x20 --exact     exact path match (default: substring)\n\
         \x20 --dry-run   print extraction plan without writing output files\n\
         \x20 --json      print machine-readable JSON lines\n\
         \x20 --max=N     max image count processed in --all mode (0 means unlimited)\n"
    );
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Options {
    compact: bool,
    all: bool,
    exact: bool,
    dry_run: bool,
    json: bool,
    max: u32,
    cache: String,
    selector: String,
    output: String,
}

enum Parsed {
    Run(Options),
    Help,
    Usage,
}

fn parse(args: &[String]) -> Parsed {
    let mut o = Options::default();
    let mut i = 0;
    while i < args.len() {
        let opt = args[i].as_str();
        match opt {
            "--help" | "-h" => return Parsed::Help,
            "--compact" => o.compact = true,
            "--all" => o.all = true,
            "--exact" => o.exact = true,
            "--dry-run" => o.dry_run = true,
            "--json" => o.json = true,
            _ => match opt.strip_prefix("--max=") {
                // The C++ tool aborted on a non-numeric value; treat it as
                // a usage error instead.
                Some(v) => match count_option(v) {
                    Some(n) => o.max = n,
                    None => return Parsed::Usage,
                },
                None => break,
            },
        }
        i += 1;
    }
    let rest = &args[i..];
    if rest.len() != 3 {
        return Parsed::Usage;
    }
    o.cache = rest[0].clone();
    o.selector = rest[1].clone();
    o.output = rest[2].clone();
    Parsed::Run(o)
}

pub fn run(args: &[String]) -> ExitCode {
    let o = match parse(args) {
        Parsed::Run(o) => o,
        Parsed::Help => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        Parsed::Usage => {
            print_usage();
            return exit(EXIT_USAGE);
        }
    };

    let cache = match Binary::open(Path::new(&o.cache)) {
        Ok(Binary {
            kind: Kind::DyldSharedCache(cache),
            ..
        }) => cache,
        Ok(_) => {
            eprintln!("{NOT_A_CACHE}");
            return exit(EXIT_FAILURE);
        }
        Err(e) => {
            eprintln!("moex-cache-extract failed: {e}");
            return exit(EXIT_FAILURE);
        }
    };

    let matched = select_images(&cache, o.selector.as_bytes(), o.exact);
    if matched.is_empty() {
        eprintln!("image not found: {}", o.selector);
        return exit(EXIT_FAILURE);
    }

    let options = ExtractOptions {
        compact: o.compact,
        dry_run: o.dry_run,
    };
    let cancel = AtomicBool::new(false);
    let extract_one = |image: &CacheImage, output: &Path| -> bool {
        match extract_image(&cache, image, output, &options, &cancel, &mut |_| {}) {
            Ok(outcome) => {
                out(&if o.json {
                    outcome.json()
                } else {
                    outcome.text()
                });
                true
            }
            Err(e) => {
                err_line(&e.message);
                false
            }
        }
    };

    if !o.all {
        if matched.len() > 1 {
            let mut line = Vec::new();
            if o.json {
                line.extend_from_slice(
                    format!(
                        "{{\"event\":\"warning\",\"message\":\"multiple matches; using first\",\"matched\":{},\"image\":\"",
                        matched.len()
                    )
                    .as_bytes(),
                );
                line.extend_from_slice(&json_escape(&matched[0].path));
                line.extend_from_slice(b"\"}");
            } else {
                line.extend_from_slice(
                    format!(
                        "warning: selector matched {} images, using first: ",
                        matched.len()
                    )
                    .as_bytes(),
                );
                line.extend_from_slice(&matched[0].path);
            }
            err_line(&line);
        }
        return if extract_one(&matched[0], Path::new(&o.output)) {
            ExitCode::SUCCESS
        } else {
            exit(EXIT_FAILURE)
        };
    }

    if !o.dry_run {
        if let Err(message) = ensure_directory(&o.output) {
            eprintln!("{message}");
            return exit(EXIT_FAILURE);
        }
    }

    let mut namer = BatchNamer::new();
    let mut ok_count: u32 = 0;
    let mut processed: u32 = 0;
    for image in &matched {
        if o.max > 0 && processed >= o.max {
            break;
        }
        let mut full_output = o.output.clone().into_bytes();
        if !full_output.is_empty() && full_output.last() != Some(&b'/') {
            full_output.push(b'/');
        }
        full_output.extend_from_slice(&namer.next_name(&image.path));
        if extract_one(image, &bytes_to_path(&full_output)) {
            ok_count += 1;
        }
        processed += 1;
    }
    let summary = if o.json {
        format!("{{\"event\":\"batch\",\"matched\":{},\"processed\":{processed},\"extracted\":{ok_count}}}\n", matched.len())
    } else {
        format!(
            "batch: matched={} processed={processed} extracted={ok_count}\n",
            matched.len()
        )
    };
    out(summary.as_bytes());
    if ok_count == processed {
        ExitCode::SUCCESS
    } else {
        exit(EXIT_FAILURE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn options_then_positionals() {
        let Parsed::Run(o) = parse(&args(&[
            "--compact",
            "--all",
            "--exact",
            "--dry-run",
            "--json",
            "--max=2",
            "c",
            "sel",
            "out",
        ])) else {
            panic!("expected run");
        };
        assert_eq!(
            o,
            Options {
                compact: true,
                all: true,
                exact: true,
                dry_run: true,
                json: true,
                max: 2,
                cache: "c".into(),
                selector: "sel".into(),
                output: "out".into()
            }
        );
    }

    #[test]
    fn usage_errors() {
        assert!(matches!(parse(&args(&[])), Parsed::Usage));
        assert!(matches!(parse(&args(&["c", "sel"])), Parsed::Usage));
        assert!(matches!(
            parse(&args(&["c", "sel", "out", "extra"])),
            Parsed::Usage
        ));
        assert!(matches!(
            parse(&args(&["--max=x", "c", "sel", "out"])),
            Parsed::Usage
        ));
        assert!(matches!(
            parse(&args(&["c", "sel", "--json"])),
            Parsed::Run(_)
        ));
        assert!(matches!(parse(&args(&["--help"])), Parsed::Help));
    }
}
