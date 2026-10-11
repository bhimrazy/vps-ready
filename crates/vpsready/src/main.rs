//! The `vpsready` command-line entry point. All logic lives in the library;
//! this file only parses arguments, sets up logging and maps errors to exit
//! codes.

use std::io;
use std::process::ExitCode;

use clap::Parser;
use tracing_subscriber::EnvFilter;
use vpsready::cli::{self, Cli};

fn main() -> ExitCode {
    // Usage errors are reported by clap itself with exit code 2.
    let cli = Cli::parse();
    init_tracing(cli.verbose, cli.color_enabled());

    match cli::run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) if is_broken_pipe(&err) => ExitCode::SUCCESS,
        Err(err) => {
            // `{:#}` prints the context chain on one line, without a backtrace.
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Logs go to stderr. `RUST_LOG` wins when set; otherwise `-v` raises the
/// level from `warn` to `info`, `debug` and `trace`.
fn init_tracing(verbose: u8, ansi: bool) {
    let default = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .with_ansi(ansi)
        .with_target(false)
        .without_time()
        .init();
}

/// `vpsready detect | head -1` should not print an error.
fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.downcast_ref::<io::Error>()
        .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
}
