//! `moex`: MachOExplorer command-line tools.

mod cache_extract;
mod cache_list;
mod diff;
mod legacy_args;

use clap::{Parser, Subcommand, ValueEnum};
use moex_core::dump::{dump_file, DumpOptions};
use std::io::Write;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "moex",
    version,
    about = "Mach-O / Fat / archive / dyld shared cache analysis"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check that files parse; prints one [ok]/[fail] line per file
    Parse {
        #[arg(required = true)]
        files: Vec<String>,
    },
    /// Export the full analysis tree as text or JSON
    Dump(DumpArgs),
    /// List the images of a dyld shared cache
    ///
    /// [--json] [--exact] [--limit=N] [--output=file] <dyld_shared_cache_file> [path-filter]
    #[command(disable_help_flag = true)]
    CacheList(RawArgs),
    /// Extract images from a dyld shared cache
    ///
    /// [--compact] [--all] [--exact] [--dry-run] [--json] [--max=N]
    /// <dyld_shared_cache_file> <image-path-or-substr> <output-macho-or-dir>
    #[command(disable_help_flag = true)]
    CacheExtract(RawArgs),
    /// Compare the first Mach-O header, sections and symbols of two files
    #[command(disable_help_flag = true)]
    Diff(RawArgs),
}

/// Arguments handed through untouched: these subcommands keep the option
/// syntax, usage text and exit codes of the stand-alone `moex-*` tools they
/// replace, so they parse their own arguments.
#[derive(clap::Args)]
struct RawArgs {
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "ARGS"
    )]
    args: Vec<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Clone, Copy, ValueEnum)]
enum TableMode {
    Full,
    Headers,
    Summary,
}

#[derive(clap::Args)]
struct DumpArgs {
    /// Output format
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
    /// Write result to file (default: stdout)
    #[arg(long)]
    output: Option<String>,
    /// Limit rows printed per table (0 means all)
    #[arg(long, default_value_t = 0)]
    max_rows: usize,
    /// Limit analysis tree depth (0 means all)
    #[arg(long, default_value_t = 0)]
    max_depth: usize,
    /// Dump only the matching node subtree
    #[arg(long, default_value = "")]
    root_path: String,
    /// Keep only nodes whose names match text
    #[arg(long, default_value = "")]
    name_filter: String,
    /// Table export mode
    #[arg(long, value_enum, default_value = "full")]
    table_mode: TableMode,
    /// Include empty nodes in output
    #[arg(long)]
    include_empty: bool,
    file: String,
}

fn run_parse(files: &[String]) -> ExitCode {
    let mut failed = false;
    for f in files {
        match moex_core::macho::Binary::open(std::path::Path::new(f)) {
            Ok(bin) => println!("[ok] {f} headers={}", bin.headers().len()),
            Err(e) => {
                eprintln!("[fail] {f} error={e}");
                failed = true;
            }
        }
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn run_dump(a: &DumpArgs) -> ExitCode {
    let options = DumpOptions {
        json_output: matches!(a.format, Format::Json),
        include_empty_nodes: a.include_empty,
        max_rows_per_table: a.max_rows,
        max_depth: a.max_depth,
        root_path: a.root_path.clone(),
        name_filter: a.name_filter.clone(),
        table_mode: match a.table_mode {
            TableMode::Full => "full",
            TableMode::Headers => "headers",
            TableMode::Summary => "summary",
        }
        .into(),
        ..Default::default()
    };
    // Buffer so a failed analysis leaves no partial output behind.
    let mut buf = Vec::new();
    if let Err(e) = dump_file(&a.file, &options, &mut buf) {
        eprintln!("analysis failed: {e}");
        return ExitCode::from(1);
    }
    let result = match &a.output {
        Some(path) => {
            std::fs::write(path, &buf).map_err(|_| format!("cannot open output file: {path}"))
        }
        None => std::io::stdout().write_all(&buf).map_err(|e| e.to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Parse { files } => run_parse(&files),
        Command::Dump(args) => run_dump(&args),
        Command::CacheList(raw) => cache_list::run(&raw.args),
        Command::CacheExtract(raw) => cache_extract::run(&raw.args),
        Command::Diff(raw) => diff::run(&raw.args),
    }
}
