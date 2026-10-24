//! Command-line interface: argument definitions and command dispatch.
//!
//! Today: `version`, `detect`, `audit`, `plan`, `apply`, `rollback` and
//! `history`. Further commands (`confirm`, ...) are added as their milestones
//! land; see the GitHub milestones.

use std::cmp::Reverse;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;
use clap::builder::PossibleValuesParser;
use clap::{ArgAction, ArgGroup, Parser, Subcommand};
use owo_colors::OwoColorize;
use tracing_subscriber::EnvFilter;

use crate::VERSION_INFO;
use crate::audit::{self, Check, Finding, Outcome, Report, Severity};
use crate::engine::{StateDir, Target};
use crate::facts::{self, Env, Facts, Listener};
use crate::modules;
use crate::sys::{RealFs, RealRunner, Sys};

mod change;

/// Exit code of `audit` when a control failed or could not be checked.
pub const EXIT_AUDIT_FAILED: u8 = 1;

/// Exit code for errors, the same code clap uses for usage errors.
pub const EXIT_ERROR: u8 = 2;

/// Exit code of `apply` when it failed and every change was rolled back.
pub const EXIT_ROLLED_BACK: u8 = 1;

/// Exit code of `apply` and `rollback` when a rollback did not complete.
pub const EXIT_INCOMPLETE: u8 = 3;

/// Shown at the end of the help, which a bare `vps-ready` prints.
const FIRST_RUN: &str = "\
Typical first run, as root:
  vps-ready detect          what this server is
  vps-ready audit           what fails and why
  vps-ready plan            what apply would change (read-only)
  vps-ready apply           make the changes; undo with `rollback --last`";

/// Command-line arguments of `vps-ready`.
#[derive(Debug, Parser)]
#[command(
    name = "vps-ready",
    version,
    about,
    long_about = None,
    arg_required_else_help = true,
    after_help = FIRST_RUN,
)]
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
    Audit {
        /// Also list passing and skipped controls.
        #[arg(long)]
        all: bool,
    },
    /// Show what `apply` would change. Does not need root, but then skips
    /// what only root can read.
    Plan {
        /// Plan only this module (repeatable). Default: every module.
        #[arg(long = "module", value_name = "ID", value_parser = module_ids())]
        modules: Vec<String>,
    },
    /// Make the changes of the plan, after asking. Needs root.
    ///
    /// Exits 0 when applied or nothing to do, 1 when it failed and every
    /// change was rolled back, 2 on error, and 3 when the rollback after a
    /// failure did not complete.
    Apply {
        /// Apply only this module (repeatable). Default: every applicable module.
        #[arg(long = "module", value_name = "ID", value_parser = module_ids())]
        modules: Vec<String>,
        /// Do not ask; required when stdin is not a terminal.
        #[arg(long, short)]
        yes: bool,
        /// Show the plan and change nothing, like `plan`.
        #[arg(long, short = 'n', conflicts_with = "yes")]
        dry_run: bool,
    },
    /// Undo the changes of a transaction. Needs root.
    ///
    /// If the host rebooted since apply, kernel settings keep their running
    /// values until the next boot, which reads the restored configuration.
    ///
    /// Exits 0 when rolled back, 2 on error (including a refusal because
    /// something changed since apply), and 3 when it did not complete.
    #[command(group(ArgGroup::new("target").required(true)))]
    Rollback {
        /// The unfinished transaction if there is one, otherwise the newest applied one.
        #[arg(long, group = "target")]
        last: bool,
        /// The transaction with this ID (see `history`).
        #[arg(long, value_name = "ID", group = "target")]
        txn: Option<String>,
    },
    /// List the transactions, newest first. Needs root.
    History,
}

/// `--module` accepts the IDs of the registry.
fn module_ids() -> PossibleValuesParser {
    PossibleValuesParser::new(modules::all().iter().map(|m| m.id()))
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
            ExitCode::from(change::exit_code(&err))
        }
    }
}

/// Whether notices print as `vps-ready: <notice>` instead of log lines.
static PLAIN_NOTICES: AtomicBool = AtomicBool::new(false);

/// Logs go to stderr. `RUST_LOG` wins when set; otherwise `-v` raises the
/// level from `warn` to `info`, `debug` and `trace`. Without either, notices
/// are plain lines and only errors from the logs remain.
fn init_tracing(verbose: u8, ansi: bool) {
    PLAIN_NOTICES.store(
        verbose == 0 && std::env::var_os("RUST_LOG").is_none(),
        Ordering::Relaxed,
    );
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
        Command::Audit { all } => {
            let controls = audit::catalog()?;
            // The audit does not use the SSH session, so its notices are noise.
            let facts = collect_facts(Path::new("/"), &[facts::session::NOTICE])?;
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
                print_report(
                    &mut out,
                    &report,
                    host,
                    *all,
                    root_hint,
                    cli.color_enabled(),
                )
            };
            match printed.and_then(|()| out.flush()) {
                // `audit | head` must still report the result, not success.
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return Ok(code),
                other => other?,
            }
        }
        Command::Plan { modules } => {
            let n = change::plan(&real_host(cli), modules, cli.json, &mut out)?;
            code = ExitCode::from(n);
        }
        Command::Apply {
            modules,
            dry_run: true,
            ..
        } => {
            let n = change::plan(&real_host(cli), modules, cli.json, &mut out)?;
            code = ExitCode::from(n);
        }
        Command::Apply { modules, yes, .. } => {
            no_json(cli, "apply")?;
            let stdin = io::stdin();
            let mut stdin = stdin.is_terminal().then(|| stdin.lock());
            let input = stdin.as_mut().map(|s| s as &mut dyn BufRead);
            let n = change::apply(
                &real_host(cli),
                modules,
                *yes,
                input,
                &mut out,
                &mut io::stderr(),
            )?;
            code = ExitCode::from(n);
        }
        Command::Rollback { last, txn } => {
            no_json(cli, "rollback")?;
            let target = match txn {
                Some(id) => Target::Txn(id),
                // clap requires exactly one of the two.
                None => {
                    debug_assert!(*last);
                    Target::Last
                }
            };
            let n = change::rollback(&real_host(cli), target, &mut out, &mut io::stderr())?;
            code = ExitCode::from(n);
        }
        Command::History => {
            let n = change::history(&real_host(cli), cli.json, &mut out)?;
            code = ExitCode::from(n);
        }
    }
    out.flush()?;
    Ok(code)
}

fn no_json(cli: &Cli, command: &str) -> anyhow::Result<()> {
    if cli.json {
        anyhow::bail!("{command} has no JSON output");
    }
    Ok(())
}

/// This machine, with the state in [`StateDir::DEFAULT`] owned by root.
fn real_host(cli: &Cli) -> change::Host<'static> {
    static FS: std::sync::LazyLock<RealFs> = std::sync::LazyLock::new(|| RealFs::new("/"));
    change::Host {
        sys: Sys {
            fs: &*FS,
            runner: &RealRunner,
        },
        modules: modules::all(),
        state_dir: Path::new(StateDir::DEFAULT),
        state_uid: 0,
        root: running_as_root(),
        facts: host_facts,
        color: cli.color_enabled(),
    }
}

/// Facts of this machine for the change commands, which log the notices.
fn host_facts(sys: Sys) -> anyhow::Result<Facts> {
    facts::collect(sys.fs, sys.runner, &Env::from_process()).context("detecting facts")
}

/// Collects facts, printing each notice except those starting with one in `quiet` on stderr. All notices stay in the facts, and so in `--json` output.
fn collect_facts(root: &Path, quiet: &[&str]) -> anyhow::Result<Facts> {
    // A mounted tree has no live process table to find a session in.
    let env = if root == Path::new("/") {
        Env::from_process()
    } else {
        Env::default()
    };
    let facts = facts::collect(&RealFs::new(root), &RealRunner, &env)
        .with_context(|| format!("detecting facts under {}", root.display()))?;
    log_notices(&facts, quiet);
    Ok(facts)
}

/// Prints each notice except those starting with one in `quiet` on stderr:
/// as `vps-ready: <notice>`, or as a warning log line with `-v` or
/// `RUST_LOG`.
fn log_notices(facts: &Facts, quiet: &[&str]) {
    for notice in facts
        .notices
        .iter()
        .filter(|n| !quiet.iter().any(|q| n.starts_with(q)))
    {
        if PLAIN_NOTICES.load(Ordering::Relaxed) {
            eprintln!("vps-ready: {notice}");
        } else {
            tracing::warn!("{notice}");
        }
    }
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
                // Sudo helps only when nft was refused for lack of privileges.
                Check::InboundDefaultDeny | Check::PublishedPorts => {
                    facts.firewall.is_none()
                        && facts
                            .notices
                            .iter()
                            .any(|n| n.ends_with(crate::facts::firewall::NEEDS_ROOT))
                }
                Check::Apparmor => false,
                // `/proc/sys/net/ipv4/conf` is readable by anyone.
                Check::ReversePathFilter
                | Check::IcmpRedirectsIgnored
                | Check::IcmpRedirectsNotSent => false,
            }
    })
}

/// A title, then, unless nothing failed or is unknown, a header row and one
/// block per control, then a summary:
///
/// ```text
/// Audit of Ubuntu 24.04.5 LTS: 5 controls
///
/// STATUS   ID       SEVERITY  CONTROL
/// FAIL     SSH-002  high      Password authentication disabled
///          passwordauthentication is yes, expected no
///          Passwords can be guessed or reused from leaks; ...
///          fix: not automated yet
///
/// 3 passed, 1 failed (1 high), 1 unknown
/// ```
///
/// Without `all`, only failed and unknown controls get a block: failures by
/// severity (highest first) and ID, then unknowns in catalog order. With
/// `all`, every control does, in catalog order; a passed or skipped one is a
/// row without details.
///
/// A failed control ends with the command to fix it, e.g. `fix: sudo
/// vps-ready apply --module kernel.sysctl`, or `fix: not automated yet`. An
/// unknown one says why it could not be checked, with the cause from the
/// notices when they name it.
///
/// After the summary come each distinct skip reason, once; the failed
/// controls that have a fix, with the command that shows the changes; and,
/// when rows were left out, how to list them.
fn print_report(
    out: &mut (impl Write + ?Sized),
    report: &Report,
    host: &str,
    all: bool,
    root_hint: bool,
    color: bool,
) -> io::Result<()> {
    const INDENT: &str = "         ";
    const WIDTH: usize = 80;
    let s = report.summary;
    let problems = s.failed + s.unknown > 0;
    let mut shown: Vec<&Finding> = report.findings.iter().collect();
    if !problems && !all {
        shown.clear();
    } else if !all {
        shown.retain(|f| matches!(f.outcome, Outcome::Fail { .. } | Outcome::Unknown { .. }));
        // Stable, so unknowns keep catalog order.
        shown.sort_by_key(|f| match f.outcome {
            Outcome::Fail { .. } => (0, Reverse(f.control.severity), f.control.id.as_str()),
            _ => (1, Reverse(Severity::Low), ""),
        });
    }
    let title = format!("Audit of {host}: {} controls", report.findings.len());
    if color {
        writeln!(out, "{}", title.bold())?;
    } else {
        writeln!(out, "{title}")?;
    }
    if !shown.is_empty() {
        let header = format!("{:<7}  {:<7}  {:<8}  CONTROL", "STATUS", "ID", "SEVERITY");
        if color {
            writeln!(out, "\n{}", header.dimmed())?;
        } else {
            writeln!(out, "\n{header}")?;
        }
    }
    for finding in &shown {
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
        if let Some(mut detail) = finding.detail()
            && !matches!(finding.outcome, Outcome::Skip { .. })
        {
            if matches!(finding.outcome, Outcome::Unknown { .. })
                && let Some(cause) = unknown_cause(&finding.control.check, &report.notices)
            {
                detail = format!("{detail}: {cause}");
            }
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
            match &control.fix {
                Some(module) => {
                    writeln!(out, "{INDENT}fix: sudo vps-ready apply --module {module}")?;
                }
                None => writeln!(out, "{INDENT}fix: not automated yet")?,
            }
        }
    }
    write!(out, "\n{} passed, {} failed", s.passed, s.failed)?;
    let by_severity: Vec<String> = [Severity::High, Severity::Medium, Severity::Low]
        .into_iter()
        .filter_map(|sev| {
            let n = report
                .findings
                .iter()
                .filter(|f| matches!(f.outcome, Outcome::Fail { .. }) && f.control.severity == sev)
                .count();
            (n > 0).then(|| format!("{n} {sev}"))
        })
        .collect();
    if !by_severity.is_empty() {
        write!(out, " ({})", by_severity.join(", "))?;
    }
    write!(out, ", {} unknown", s.unknown)?;
    if s.skipped > 0 {
        write!(out, ", {} skipped", s.skipped)?;
    }
    writeln!(out)?;
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
    if s.unknown > 0 && root_hint {
        writeln!(out, "Run it with sudo: some checks need root.")?;
    }
    let fixable: Vec<&str> = shown
        .iter()
        .filter(|f| matches!(f.outcome, Outcome::Fail { .. }) && f.control.fix.is_some())
        .map(|f| f.control.id.as_str())
        .collect();
    if !fixable.is_empty() {
        let ids = fixable.join(", ");
        let count = if fixable.len() == s.failed {
            format!("all {}", s.failed)
        } else {
            format!("{} of the {}", fixable.len(), s.failed)
        };
        let line = format!("vps-ready can fix {count} ({ids}): run `sudo vps-ready plan`.");
        for line in wrap(&line, WIDTH) {
            writeln!(out, "{line}")?;
        }
        match s.failed - fixable.len() {
            0 => {}
            1 => writeln!(
                out,
                "The other one needs a manual fix for now; it says so above."
            )?,
            n => writeln!(
                out,
                "The other {n} need a manual fix for now; each says so above."
            )?,
        }
    }
    // The clean case is one summary line, so it gets no pointer.
    if problems && !all {
        let (n, what) = if s.passed > 0 {
            (s.passed, "passing")
        } else {
            (s.skipped, "skipped")
        };
        if n > 0 {
            let noun = if n == 1 { "control" } else { "controls" };
            writeln!(
                out,
                "Run `vps-ready audit --all` to list the {n} {what} {noun} too."
            )?;
        }
    }
    Ok(())
}

/// Why an unknown control could not be checked, from the notice about the
/// tool it needs: the part before the first `;`, e.g. `nft not found`.
fn unknown_cause<'a>(check: &Check, notices: &'a [String]) -> Option<&'a str> {
    let prefixes: [&str; 2] = match check {
        Check::InboundDefaultDeny | Check::PublishedPorts => ["nft ", "`nft "],
        Check::SshdEffective { .. } => ["sshd ", "`sshd -T` "],
        _ => return None,
    };
    notices
        .iter()
        .find(|n| prefixes.iter().any(|p| n.starts_with(p)) && n.contains(';'))
        .and_then(|n| n.split(';').next())
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
            facts
                .session
                .as_ref()
                .map_or_else(|| "not connected over SSH".to_owned(), session_line),
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

/// e.g. `admin, connected from 198.51.100.7 to port 22 (sshd PID 812)`.
fn session_line(s: &facts::Session) -> String {
    let user = s.user.clone().unwrap_or_else(|| format!("uid {}", s.uid));
    format!(
        "{user}, connected from {} to port {} (sshd PID {})",
        s.client.ip(),
        s.server.port(),
        s.id.pid
    )
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
        print_report(&mut text, &report, "this host", false, true, false).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("0 passed, 2 failed ("), "{text}");
        assert!(text.contains(", 7 unknown"), "{text}");
        assert!(
            text.contains("effective SSH config is unknown: `sshd -T` failed (Missing"),
            "{text}"
        );
        assert!(text.contains("Run it with sudo"), "{text}");

        let mut text = Vec::new();
        print_report(&mut text, &report, "this host", false, false, false).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(!text.contains("Run it with sudo"), "{text}");
    }

    /// With a fixable failure the output ends with the next step; a failure
    /// no module fixes says so.
    #[test]
    fn audit_text_points_to_plan() {
        let mut facts = host("debian-13", &[]);
        facts.virtualization.container = crate::facts::Virt::None;
        let mut sysctl = crate::facts::Sysctl::default();
        for key in crate::facts::sysctl::KEYS {
            sysctl.values.insert(key.to_owned(), "1".to_owned());
        }
        sysctl
            .values
            .insert("kernel.kptr_restrict".to_owned(), "0".to_owned());
        sysctl.values.insert(
            "kernel.unprivileged_bpf_disabled".to_owned(),
            "0".to_owned(),
        );
        facts.sysctl = Some(sysctl);
        let controls = |ids: &[&str]| -> Vec<_> {
            audit::catalog()
                .unwrap()
                .into_iter()
                .filter(|c| ids.contains(&c.id.as_str()))
                .collect()
        };
        let text = |ids: &[&str]| {
            let report = audit::run(controls(ids), &facts);
            let mut text = Vec::new();
            print_report(&mut text, &report, "this host", false, false, false).unwrap();
            String::from_utf8(text).unwrap()
        };

        let both = text(&["KRN-001", "MAC-001"]);
        assert!(both.contains("fix: not automated yet"), "{both}");
        assert!(
            both.ends_with(
                "vps-ready can fix 1 of the 2 (KRN-001): run `sudo vps-ready plan`.\n\
                 The other one needs a manual fix for now; it says so above.\n"
            ),
            "{both}"
        );

        let two = text(&["KRN-001", "KRN-003", "MAC-001"]);
        assert!(
            two.contains("\nvps-ready can fix 2 of the 3 (KRN-003, KRN-001): "),
            "{two}"
        );
        let all = text(&["KRN-001", "KRN-003"]);
        assert!(all.contains("\nvps-ready can fix all 2 ("), "{all}");
        assert!(!all.contains("manual fix"), "{all}");

        let unfixable = text(&["MAC-001"]);
        assert!(unfixable.contains("fix: not automated yet"), "{unfixable}");
        assert!(!unfixable.contains("can fix"), "{unfixable}");
        assert!(!text(&["KRN-002"]).contains("can fix"));
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

    /// Without nft, or when it fails for another reason, sudo would not help
    /// FW-001; when nft is refused for lack of privileges, it would.
    #[test]
    fn root_hint_for_firewall_depends_on_why_nft_failed() {
        let mut facts = host("debian-13", &[]);
        facts.virtualization.container = crate::facts::Virt::None;
        let mut sysctl = crate::facts::Sysctl::default();
        for key in crate::facts::sysctl::KEYS {
            sysctl.values.insert(key.to_owned(), "1".to_owned());
        }
        facts.sysctl = Some(sysctl);
        facts.firewall = None;
        for (notice, hint) in [
            ("nft not found; the firewall is unknown", false),
            (
                "`nft list ruleset` failed (Error: no nf_tables); the firewall is unknown",
                false,
            ),
            (
                "`nft list ruleset` failed (Operation not permitted); the firewall is unknown. \
                 Reading the ruleset needs root (CAP_NET_ADMIN)",
                true,
            ),
        ] {
            facts.notices = vec![notice.to_owned()];
            let report = audit::run(audit::catalog().unwrap(), &facts);
            assert_eq!(root_would_help(&report, &facts), hint, "{notice}");
        }
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
                false,
            )
            .unwrap();
            insta::assert_snapshot!(format!("audit-{name}"), String::from_utf8(text).unwrap());
        }
    }

    /// `--all` keeps the full table, including passed and skipped rows.
    #[test]
    fn audit_text_all_snapshot() {
        let name = "debian-12";
        let report = audit::run(audit::catalog().unwrap(), &host(name, &[]));
        let mut text = Vec::new();
        let os = &host(name, &[]).os.pretty_name;
        print_report(&mut text, &report, os, true, false, false).unwrap();
        insta::assert_snapshot!("audit-all-debian-12", String::from_utf8(text).unwrap());
    }

    /// A host with nothing to report gets the title and the summary.
    #[test]
    fn audit_text_clean_is_one_summary() {
        let facts = host("debian-13", &[]);
        let controls = audit::catalog()
            .unwrap()
            .into_iter()
            .filter(|c| c.id == "SSH-003")
            .collect();
        let report = audit::run(controls, &facts);
        let mut text = Vec::new();
        print_report(&mut text, &report, "this host", false, false, false).unwrap();
        assert_eq!(
            String::from_utf8(text).unwrap(),
            "Audit of this host: 1 controls\n\n1 passed, 0 failed, 0 unknown\n"
        );
    }

    /// The kernel and network controls of a Debian 13 VM with the kernel's
    /// defaults: a failed control that a module fixes names the command, in
    /// text and in JSON.
    #[test]
    fn audit_shows_fix() {
        let mut facts = host("debian-13", &[]);
        facts.virtualization.container = crate::facts::Virt::None;
        let mut sysctl = crate::facts::Sysctl::default();
        for (key, value) in [
            ("fs.protected_fifos", "1"),
            ("fs.protected_hardlinks", "1"),
            ("fs.protected_regular", "2"),
            ("fs.protected_symlinks", "1"),
            ("fs.suid_dumpable", "0"),
            ("kernel.dmesg_restrict", "1"),
            ("kernel.kptr_restrict", "0"),
            ("kernel.perf_event_paranoid", "3"),
            ("kernel.randomize_va_space", "2"),
            ("kernel.unprivileged_bpf_disabled", "2"),
            ("kernel.yama.ptrace_scope", "0"),
            ("net.ipv4.conf.all.accept_source_route", "0"),
            ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
            ("net.ipv4.tcp_syncookies", "1"),
        ] {
            sysctl.values.insert(key.to_owned(), value.to_owned());
        }
        for dir in ["all", "default", "eth0"] {
            let conf = [
                ("accept_redirects", "1"),
                ("forwarding", "0"),
                ("rp_filter", "0"),
                ("send_redirects", "1"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
            sysctl.ipv4_conf.insert(dir.to_owned(), conf);
        }
        facts.sysctl = Some(sysctl);
        let controls = audit::catalog()
            .unwrap()
            .into_iter()
            .filter(|c| c.id.starts_with("KRN-") || c.id.starts_with("NET-"))
            .collect();
        let report = audit::run(controls, &facts);

        let mut text = Vec::new();
        print_report(&mut text, &report, "a Debian 13 VM", false, false, false).unwrap();
        insta::assert_snapshot!(String::from_utf8(text).unwrap());

        let json = serde_json::to_value(&report).unwrap();
        let fix = |id: &str| {
            json["findings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["id"] == id)
                .unwrap()
                .get("fix")
                .cloned()
        };
        assert_eq!(fix("KRN-001"), Some("kernel.sysctl".into()));
        assert_eq!(fix("KRN-002"), Some("kernel.sysctl".into()));
        assert_eq!(fix("NET-004"), None);
    }
}
