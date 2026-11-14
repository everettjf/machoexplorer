//! `moex cache-list`: list the images of a dyld shared cache.

use crate::legacy_args::*;
use moex_core::cache_tools::{json_escape, list_images, NOT_A_CACHE};
use moex_core::hex::as_short_hex_string;
use moex_core::macho::{Binary, Kind};
use std::path::Path;
use std::process::ExitCode;

fn print_usage() {
    eprint!(
        "usage: moex cache-list [--json] [--exact] [--limit=N] [--output=file] <dyld_shared_cache_file> [path-filter]\n\
         \x20 --json         output JSON payload\n\
         \x20 --exact        exact path match (default: substring)\n\
         \x20 --limit=N      stop after N matches (0 means unlimited)\n\
         \x20 --output=file  write output to file instead of stdout\n"
    );
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Options {
    json: bool,
    exact: bool,
    limit: u32,
    output: String,
    cache: String,
    filter: String,
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
        if opt == "--help" || opt == "-h" {
            return Parsed::Help;
        } else if opt == "--json" {
            o.json = true;
        } else if opt == "--exact" {
            o.exact = true;
        } else if let Some(v) = opt.strip_prefix("--limit=") {
            // The C++ tool aborted on a non-numeric value; treat it as a
            // usage error instead.
            let Some(n) = count_option(v) else {
                return Parsed::Usage;
            };
            o.limit = n;
        } else if let Some(v) = opt.strip_prefix("--output=") {
            o.output = v.to_string();
        } else {
            break;
        }
        i += 1;
    }
    let rest = &args[i..];
    if rest.is_empty() || rest.len() > 2 {
        return Parsed::Usage;
    }
    o.cache = rest[0].clone();
    o.filter = rest.get(1).cloned().unwrap_or_default();
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
            eprintln!("moex-cache-list failed: {e}");
            return exit(EXIT_FAILURE);
        }
    };

    let mut file = None;
    if !o.output.is_empty() {
        match std::fs::File::create(&o.output) {
            Ok(f) => file = Some(f),
            Err(_) => {
                eprintln!("cannot open output file: {}", o.output);
                return exit(EXIT_FAILURE);
            }
        }
    }

    let header = &cache.header;
    let mut buf: Vec<u8> = Vec::new();
    // QUIRK(parity): all 16 magic bytes are written, including the
    // trailing NUL padding (unescaped even in JSON mode).
    if o.json {
        buf.extend_from_slice(b"{\"magic\":\"");
        buf.extend_from_slice(&json_escape(&header.magic));
        buf.extend_from_slice(
            format!(
                "\",\"mappingCount\":{},\"imageCount\":{},\"images\":[",
                header.mapping_count, header.images_count
            )
            .as_bytes(),
        );
    } else {
        buf.extend_from_slice(b"magic: ");
        buf.extend_from_slice(&header.magic);
        buf.extend_from_slice(
            format!(
                "\nmappingCount: {} imageCount: {}\n",
                header.mapping_count, header.images_count
            )
            .as_bytes(),
        );
    }

    let mut shown: u32 = 0;
    for item in list_images(&cache, o.filter.as_bytes(), o.exact) {
        let address = as_short_hex_string(item.address);
        if o.json {
            if shown > 0 {
                buf.push(b',');
            }
            buf.extend_from_slice(format!("{{\"address\":\"0x{address}\",\"path\":\"").as_bytes());
            buf.extend_from_slice(&json_escape(&item.path));
            buf.extend_from_slice(b"\"}");
        } else {
            buf.extend_from_slice(format!("0x{address} ").as_bytes());
            buf.extend_from_slice(&item.path);
            buf.push(b'\n');
        }
        shown += 1;
        if o.limit > 0 && shown >= o.limit {
            break;
        }
    }

    if o.json {
        buf.extend_from_slice(format!("],\"shown\":{shown}}}\n").as_bytes());
    } else {
        buf.extend_from_slice(format!("shown: {shown}\n").as_bytes());
    }

    match file {
        Some(mut f) => {
            use std::io::Write;
            let _ = f.write_all(&buf);
        }
        None => out(&buf),
    }
    ExitCode::SUCCESS
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
            "--json",
            "--exact",
            "--limit=3",
            "--output=o.txt",
            "cache",
            "libobjc",
        ])) else {
            panic!("expected run");
        };
        assert_eq!(
            o,
            Options {
                json: true,
                exact: true,
                limit: 3,
                output: "o.txt".into(),
                cache: "cache".into(),
                filter: "libobjc".into()
            }
        );
        // options after the first positional are positionals
        let Parsed::Run(o) = parse(&args(&["cache", "--json"])) else {
            panic!("expected run")
        };
        assert!(!o.json);
        assert_eq!(o.filter, "--json");
        assert!(matches!(
            parse(&args(&["--limit=-4", "cache"])),
            Parsed::Run(Options { limit: 0, .. })
        ));
    }

    #[test]
    fn usage_errors() {
        assert!(matches!(parse(&args(&[])), Parsed::Usage));
        assert!(matches!(parse(&args(&["--json"])), Parsed::Usage));
        assert!(matches!(parse(&args(&["a", "b", "c"])), Parsed::Usage));
        assert!(matches!(parse(&args(&["--limit=x", "a"])), Parsed::Usage));
        assert!(matches!(parse(&args(&["--json", "-h", "a"])), Parsed::Help));
        // an unknown option is taken as the cache path
        assert!(matches!(parse(&args(&["--bogus"])), Parsed::Run(_)));
    }
}
