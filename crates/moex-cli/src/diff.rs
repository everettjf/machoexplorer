//! `moex diff`: compare two Mach-O files.

use crate::legacy_args::*;
use moex_core::diff::{diff_files, DiffError};
use std::path::Path;
use std::process::ExitCode;

pub fn run(args: &[String]) -> ExitCode {
    if args.len() != 2 {
        eprintln!("usage: moex diff <fileA> <fileB>");
        return exit(EXIT_USAGE);
    }
    match diff_files(Path::new(&args[0]), Path::new(&args[1])) {
        Ok(report) => {
            out(report.to_string().as_bytes());
            ExitCode::SUCCESS
        }
        Err(DiffError::Parse(e)) => {
            eprintln!("moex-diff failed: {e}");
            exit(EXIT_FAILURE)
        }
        Err(e @ DiffError::NoHeader) => {
            eprintln!("{e}");
            exit(EXIT_FAILURE)
        }
    }
}
