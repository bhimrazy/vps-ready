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
use crate::facts::{self, Env, Facts, Listener};
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
    /// Detect facts about this system (OS, virtualization, SSH, open ports) and print them.
    Detect {
        /// Read files from a tree mounted at PATH instead of `/`. Commands such
        /// as `sshd -T` still run on this machine.
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
            let facts = facts::collect(&fs, &RealRunner, &Env::from_process())
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
    let mut os_line = os.pretty_name.clone();
    if os.family != facts::OsFamily::Unknown {
        os_line.push_str(&format!(" ({} family)", os.family));
    }
    let virt = &facts.virtualization;
    let rows = [
        ("OS", os_line),
        ("Init", facts.init.to_string()),
        (
            "Virt",
            format!("container {}, vm {}", virt.container, virt.vm),
        ),
        ("SSH", ssh_line(&facts.ssh)),
        ("Ports", ports_line(&facts.listeners)),
        (
            "You",
            facts.session.map_or_else(
                || "not connected over SSH".to_owned(),
                |s| {
                    format!(
                        "connected from {} to port {}",
                        s.client.ip(),
                        s.server.port()
                    )
                },
            ),
        ),
        (
            "Docker",
            if facts.docker {
                "installed"
            } else {
                "not installed"
            }
            .to_owned(),
        ),
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

/// e.g. `OpenSSH 9.6p1, socket activation, port 22, passwords yes, root login without-password`.
fn ssh_line(ssh: &facts::Ssh) -> String {
    let mut parts = vec![
        ssh.version.as_ref().map_or_else(
            || "OpenSSH version unknown".to_owned(),
            |v| format!("OpenSSH {v}"),
        ),
        ssh.activation.to_string(),
    ];
    match &ssh.effective {
        Some(config) => {
            let ports = config.get_all("port").join(",");
            parts.push(format!("port {ports}"));
            for (label, key) in [
                ("passwords", "passwordauthentication"),
                ("root login", "permitrootlogin"),
            ] {
                parts.push(format!("{label} {}", config.get(key).unwrap_or("?")));
            }
        }
        None => parts.push("effective config unknown".to_owned()),
    }
    parts.join(", ")
}

/// Unique `proto/port (processes)` entries, e.g. `tcp/22 (sshd, systemd)`.
fn ports_line(listeners: &[Listener]) -> String {
    let mut seen: Vec<String> = Vec::new();
    for l in listeners {
        let entry = if l.processes.is_empty() {
            format!("{}/{}", l.proto, l.port)
        } else {
            format!("{}/{} ({})", l.proto, l.port, l.processes.join(", "))
        };
        if !seen.contains(&entry) {
            seen.push(entry);
        }
    }
    if seen.is_empty() {
        "none found".to_owned()
    } else {
        seen.join(", ")
    }
}
