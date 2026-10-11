//! Command-line interface: argument definitions and command dispatch.
//!
//! M0 ships `version` and `detect`. Further commands (`audit`, `plan`,
//! `apply`, `confirm`, `rollback`, ...) are added as their milestones land;
//! see the GitHub milestones.

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::Context;
use clap::{ArgAction, Parser, Subcommand};
use owo_colors::OwoColorize;

use crate::VERSION_INFO;
use crate::facts::{self, Facts};
use crate::sys::{RealFs, RealRunner};

/// Detect, audit and safely harden a fresh Linux VPS.
#[derive(Debug, Parser)]
#[command(name = "vpsready", version, about, long_about = None)]
pub struct Cli {
    /// Print machine-readable JSON instead of text.
    #[arg(long, global = true)]
    pub json: bool,

    /// Increase log verbosity (-v info, -vv debug, -vvv trace). `RUST_LOG` overrides.
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub verbose: u8,

    /// Disable colored output (also honoured: the `NO_COLOR` environment variable).
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print version and build information.
    Version,
    /// Detect facts about this system (OS, init system) and print them.
    Detect {
        /// Inspect a filesystem tree mounted at PATH instead of `/`.
        #[arg(long, value_name = "PATH", default_value = "/")]
        root: PathBuf,
    },
}

impl Cli {
    /// Whether to emit ANSI colors: not with `--no-color`, not when `NO_COLOR`
    /// is set to a non-empty value (<https://no-color.org>), and only when
    /// stdout is a terminal.
    #[must_use]
    pub fn color_enabled(&self) -> bool {
        let no_color_env = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        !self.no_color && !no_color_env && io::stdout().is_terminal()
    }
}

/// Runs the parsed command line.
///
/// # Errors
///
/// Returns an error if the command fails or stdout cannot be written.
pub fn run(cli: &Cli) -> anyhow::Result<()> {
    let mut out = io::stdout().lock();
    match &cli.command {
        Command::Version => {
            if cli.json {
                serde_json::to_writer_pretty(&mut out, &VERSION_INFO)?;
                writeln!(out)?;
            } else {
                writeln!(out, "{VERSION_INFO}")?;
            }
        }
        Command::Detect { root } => {
            let fs = RealFs::new(root);
            let facts = facts::collect(&fs, &RealRunner)
                .with_context(|| format!("detecting facts under {}", root.display()))?;
            for notice in &facts.notices {
                tracing::warn!("{notice}");
            }
            if cli.json {
                serde_json::to_writer_pretty(&mut out, &facts)?;
                writeln!(out)?;
            } else {
                print_facts(&mut out, &facts, cli.color_enabled())?;
            }
        }
    }
    out.flush()?;
    Ok(())
}

fn print_facts(out: &mut impl Write, facts: &Facts, color: bool) -> io::Result<()> {
    let os = &facts.os;
    let id = if os.id_like.is_empty() {
        os.id.clone()
    } else {
        format!("{} (like {})", os.id, os.id_like.join(", "))
    };
    let rows = [
        ("OS", os.pretty_name.clone()),
        ("ID", id),
        (
            "Version",
            os.version_id.clone().unwrap_or_else(|| "-".into()),
        ),
        ("Family", os.family.to_string()),
        ("Init", facts.init.to_string()),
    ];
    for (key, value) in rows {
        if color {
            writeln!(out, "{:<8} {value}", key.bold())?;
        } else {
            writeln!(out, "{key:<8} {value}")?;
        }
    }
    Ok(())
}
