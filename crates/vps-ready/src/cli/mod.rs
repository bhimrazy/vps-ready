//! Command-line interface: argument definitions and command dispatch.
//!
//! Today: `version`, `detect` and `audit`. Further commands (`plan`,
//! `apply`, `confirm`, `rollback`, ...) are added as their milestones land;
//! see the GitHub milestones.

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::{ArgAction, Parser, Subcommand};
use owo_colors::OwoColorize;
use tracing_subscriber::EnvFilter;

use crate::VERSION_INFO;
use crate::audit::{self, Check, Outcome, Report};
use crate::facts::{self, Env, Facts, Listener};
use crate::sys::{RealFs, RealRunner};

/// Exit code of `audit` when a control failed or could not be checked.
pub const EXIT_AUDIT_FAILED: u8 = 1;

/// Exit code for errors, the same code clap uses for usage errors.
pub const EXIT_ERROR: u8 = 2;

/// Command-line arguments of `vps-ready`.
#[derive(Debug, Parser)]
#[command(name = "vps-ready", version, about, long_about = None)]
pub struct Cli {
    /// Print machine-readable JSON instead of text.
    #[arg(long, global = true)]
    pub json: bool,

    /// Increase log verbosity (-v info, -vv debug, -vvv trace). `RUST_LOG` overrides.
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub verbose: u8,

    /// Disable colored output (also honored: the `NO_COLOR` environment variable).
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
    /// Check this system against the security controls and report what fails.
    ///
    /// Exits 0 when no control fails or is unknown, 1 otherwise, and 2 on
    /// error. Some checks need root, so run it with sudo.
    Audit,
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

/// Runs the command line of this process: parses arguments, sets up logging
/// and maps the result to an exit code. Both the `vps-ready` and `vpsready`
/// binaries are this one call.
#[must_use]
pub fn main() -> ExitCode {
    // Usage errors are reported by clap itself, also with exit code 2.
    let cli = Cli::parse();
    init_tracing(cli.verbose, cli.color_enabled());

    match run(&cli) {
        Ok(code) => code,
        Err(err) if is_broken_pipe(&err) => ExitCode::SUCCESS,
        Err(err) => {
            // `{:#}` prints the context chain on one line, without a backtrace.
            eprintln!("error: {err:#}");
            ExitCode::from(EXIT_ERROR)
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

/// `vps-ready detect | head -1` should not print an error.
fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.downcast_ref::<io::Error>()
        .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
}

/// Runs the parsed command line and returns the exit code to use on success.
///
/// # Errors
///
/// Returns an error if the command fails or stdout cannot be written.
pub fn run(cli: &Cli) -> anyhow::Result<ExitCode> {
    let mut out = io::stdout().lock();
    let mut code = ExitCode::SUCCESS;
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
            let facts = collect_facts(root, &[])?;
            if cli.json {
                serde_json::to_writer_pretty(&mut out, &facts)?;
                writeln!(out)?;
            } else {
                print_facts(&mut out, &facts, cli.color_enabled())?;
            }
        }
        Command::Audit => {
            let controls = audit::catalog()?;
            // The audit does not use the SSH session, so its notice is noise.
            let facts = collect_facts(Path::new("/"), &[facts::session::UNSET_NOTICE])?;
            let report = audit::run(controls, &facts);
            if !report.all_passed() {
                code = ExitCode::from(EXIT_AUDIT_FAILED);
            }
            let printed = if cli.json {
                serde_json::to_writer_pretty(&mut out, &report)
                    .map_err(io::Error::from)
                    .and_then(|()| writeln!(out))
            } else {
                let host = if facts.os.family == facts::OsFamily::Unknown {
                    "this host"
                } else {
                    &facts.os.pretty_name
                };
                let root_hint = !running_as_root() && root_would_help(&report, &facts);
                print_report(&mut out, &report, host, root_hint, cli.color_enabled())
            };
            match printed.and_then(|()| out.flush()) {
                // `audit | head` must still report the result, not success.
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return Ok(code),
                other => other?,
            }
        }
    }
    out.flush()?;
    Ok(code)
}

/// Collects facts, logging each notice except those in `quiet` as a warning
/// on stderr. All notices stay in the facts, and so in `--json` output.
fn collect_facts(root: &Path, quiet: &[&str]) -> anyhow::Result<Facts> {
    let facts = facts::collect(&RealFs::new(root), &RealRunner, &Env::from_process())
        .with_context(|| format!("detecting facts under {}", root.display()))?;
    for notice in facts
        .notices
        .iter()
        .filter(|n| !quiet.contains(&n.as_str()))
    {
        tracing::warn!("{notice}");
    }
    Ok(facts)
}

/// Whether running as root would let an unknown control be checked: when
/// `sshd -T` or `nft list ruleset` could not run (both need root), or a
/// `/proc/sys` file is root-only on this kernel.
fn root_would_help(report: &Report, facts: &Facts) -> bool {
    report.findings.iter().any(|f| {
        matches!(f.outcome, Outcome::Unknown { .. })
            && match &f.control.check {
                Check::SshdEffective { .. } => facts.ssh.effective.is_none(),
                Check::Sysctl { key, .. } => {
                    facts.sysctl.as_ref().is_some_and(|s| s.is_unreadable(key))
                }
                // `apt-config` and `systemctl show` work without root.
                Check::AutoUpdates => false,
                // `nft list ruleset` needs root.
                Check::InboundDefaultDeny | Check::PublishedPorts => facts.firewall.is_none(),
            }
    })
}

/// A title, a header row, one block per control, then a summary line:
///
/// ```text
/// Audit of Ubuntu 24.04.5 LTS: 5 controls
///
/// STATUS   ID       SEVERITY  CONTROL
/// FAIL     SSH-002  high      Password authentication disabled
///                             passwordauthentication is yes, expected no
///                             Passwords can be guessed or reused from leaks; ...
/// PASS     SSH-003  high      Keyboard-interactive authentication disabled
///
/// 3 passed, 2 failed, 0 unknown
/// ```
///
/// Skipped controls get a row without details, and each distinct reason is
/// printed once after the summary.
fn print_report(
    out: &mut impl Write,
    report: &Report,
    host: &str,
    root_hint: bool,
    color: bool,
) -> io::Result<()> {
    const INDENT: &str = "                            ";
    const WIDTH: usize = 100;
    let title = format!("Audit of {host}: {} controls", report.findings.len());
    let header = format!("{:<7}  {:<7}  {:<8}  CONTROL", "STATUS", "ID", "SEVERITY");
    if color {
        writeln!(out, "{}\n\n{}", title.bold(), header.dimmed())?;
    } else {
        writeln!(out, "{title}\n\n{header}")?;
    }
    for finding in &report.findings {
        let control = &finding.control;
        // Pad before coloring: escape codes would count towards the width.
        let label = match finding.outcome {
            Outcome::Pass => "PASS   ",
            Outcome::Fail { .. } => "FAIL   ",
            Outcome::Unknown { .. } => "UNKNOWN",
            Outcome::Skip { .. } => "SKIP   ",
        };
        let label = match (color, &finding.outcome) {
            (false, _) => label.to_owned(),
            (true, Outcome::Pass) => label.green().to_string(),
            (true, Outcome::Fail { .. }) => label.red().to_string(),
            (true, Outcome::Unknown { .. }) => label.yellow().to_string(),
            (true, Outcome::Skip { .. }) => label.dimmed().to_string(),
        };
        let severity = control.severity.to_string();
        writeln!(
            out,
            "{label}  {:<7}  {severity:<8}  {}",
            control.id, control.title
        )?;
        // Skip reasons repeat across controls, so they are listed once below.
        if let Some(detail) = finding.detail()
            && !matches!(finding.outcome, Outcome::Skip { .. })
        {
            for line in wrap(&detail, WIDTH - INDENT.len()) {
                writeln!(out, "{INDENT}{line}")?;
            }
        }
        if matches!(finding.outcome, Outcome::Fail { .. }) {
            for line in wrap(&control.why, WIDTH - INDENT.len()) {
                if color {
                    writeln!(out, "{INDENT}{}", line.dimmed())?;
                } else {
                    writeln!(out, "{INDENT}{line}")?;
                }
            }
        }
    }
    let s = report.summary;
    write!(
        out,
        "\n{} passed, {} failed, {} unknown",
        s.passed, s.failed, s.unknown
    )?;
    if s.skipped > 0 {
        write!(out, ", {} skipped", s.skipped)?;
    }
    writeln!(out)?;
    if s.unknown > 0 {
        write!(
            out,
            "Unknown controls could not be checked; the warnings on stderr say why."
        )?;
        if root_hint {
            write!(out, " Run it with sudo: some checks need root.")?;
        }
        writeln!(out)?;
    }
    let mut reasons: Vec<&str> = Vec::new();
    for finding in &report.findings {
        if let Outcome::Skip { reason } = &finding.outcome
            && !reasons.contains(&reason.as_str())
        {
            reasons.push(reason);
        }
    }
    for reason in reasons {
        writeln!(out, "Skipped: {reason}.")?;
    }
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

/// Whether this process runs as root: the effective UID, the second field of
/// the `Uid:` line in `/proc/self/status`. False where there is no `/proc`.
fn running_as_root() -> bool {
    std::fs::read_to_string("/proc/self/status").is_ok_and(|status| {
        status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|ids| ids.split_whitespace().nth(1))
            == Some("0")
    })
}

/// Splits `text` into lines of at most `width` characters at spaces. A word
/// longer than `width` gets a line of its own.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::fixtures::{HOSTS, host};

    #[test]
    fn audit_text_explains_unknown() {
        let facts = host("ubuntu-24.04", &["sshd-T-before-login"]);
        let report = audit::run(audit::catalog().unwrap(), &facts);
        assert!(root_would_help(&report, &facts));
        let mut text = Vec::new();
        print_report(&mut text, &report, "this host", true, false).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("0 passed, 2 failed, 5 unknown"), "{text}");
        assert!(text.contains("Run it with sudo"), "{text}");

        let mut text = Vec::new();
        print_report(&mut text, &report, "this host", false, false).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(!text.contains("sudo"), "{text}");
    }

    /// A kernel setting that only root can read is worth a sudo hint; one
    /// the kernel does not have is not.
    #[test]
    fn root_hint_covers_root_only_kernel_settings() {
        let mut facts = host("debian-13", &[]);
        facts.virtualization.container = crate::facts::Virt::None;
        let mut sysctl = crate::facts::Sysctl::default();
        for key in crate::facts::sysctl::KEYS {
            sysctl.values.insert(key.to_owned(), "1".to_owned());
        }
        sysctl.values.remove("kernel.yama.ptrace_scope");
        facts.sysctl = Some(sysctl.clone());
        let report = audit::run(audit::catalog().unwrap(), &facts);
        assert!(report.summary.unknown > 0);
        assert!(!root_would_help(&report, &facts));

        sysctl.values.remove("fs.protected_symlinks");
        sysctl.unreadable.push("fs.protected_symlinks".to_owned());
        facts.sysctl = Some(sysctl);
        let report = audit::run(audit::catalog().unwrap(), &facts);
        assert!(root_would_help(&report, &facts));
    }

    #[test]
    fn wraps_at_spaces() {
        assert_eq!(wrap("aa bb cc", 5), ["aa bb", "cc"]);
        assert_eq!(wrap("  aa   bb ", 80), ["aa bb"]);
        assert_eq!(wrap("toolongword x", 4), ["toolongword", "x"]);
        assert!(wrap("", 10).is_empty());
    }

    #[test]
    fn audit_text_snapshot() {
        for name in HOSTS {
            let report = audit::run(audit::catalog().unwrap(), &host(name, &[]));
            let mut text = Vec::new();
            print_report(
                &mut text,
                &report,
                &host(name, &[]).os.pretty_name,
                false,
                false,
            )
            .unwrap();
            insta::assert_snapshot!(format!("audit-{name}"), String::from_utf8(text).unwrap());
        }
    }
}
