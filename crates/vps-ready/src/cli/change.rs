//! `plan`, `apply`, `rollback`, `confirm` and `history`, run against a
//! [`Host`]: the real system, or a fake one in tests.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::bail;
use owo_colors::OwoColorize;

use super::{EXIT_ERROR, EXIT_INCOMPLETE, EXIT_ROLLED_BACK, print_report};
use crate::audit::{self, Outcome};
use crate::config::Profile;
use crate::engine::{
    self, ApplyOutcome, Deadman, DeadmanOutcome, Engine, EngineError, ModuleStatus, Plan, Progress,
    Rollback, Selected, StateDir, Target, TxnInfo, TxnState,
};
use crate::facts::{Facts, NoSession, Session};
use crate::modules::Module;
use crate::resource::{Backup, Resource, Reversibility};
use crate::sys::Sys;

/// What the commands act on.
pub(super) struct Host<'a> {
    pub sys: Sys<'a>,
    /// The registry, in order.
    pub modules: &'a [&'a dyn Module],
    pub state_dir: &'a Path,
    /// The uid that must own the state directory.
    pub state_uid: u32,
    /// Whether this process runs as root.
    pub root: bool,
    /// Collects the facts; called again after apply for the audit.
    pub facts: fn(Sys) -> anyhow::Result<Facts>,
    pub color: bool,
    /// This binary, which the dead-man timer and boot hook run.
    pub binary: PathBuf,
    /// Finds the SSH login this process runs in, for `confirm`.
    pub session: fn(Sys) -> Result<Session, NoSession>,
    /// `SUDO_USER`, the user the printed `ssh` line logs in as.
    pub sudo_user: Option<String>,
    /// Set to stop waiting for a confirm: by Ctrl-C, or by a test.
    pub stop: Arc<AtomicBool>,
    /// Whether Ctrl-C sets `stop` while `apply` waits, instead of ending
    /// the process.
    pub catch_sigint: bool,
    /// Set by the wizard, whose handler ends the process on Ctrl-C while
    /// this is true; the wait for a confirm clears it.
    pub sigint_ends: Option<Arc<AtomicBool>>,
    /// Whether stderr is a terminal, for a countdown on one line.
    pub tty: bool,
    /// How often the wait for a confirm reads the journal.
    pub poll: Duration,
}

/// The modules `plan` and `apply` run without `--profile` and `--module`:
/// the safe set. Modules that can lock someone out or install packages need
/// a profile or `--module`.
pub(super) const DEFAULT_MODULES: [&str; 2] = ["kernel.sysctl", "updates.auto"];

/// Which modules `plan` and `apply` act on.
#[derive(Debug, Default, Clone)]
pub(super) struct Selection {
    /// `--profile`: a built-in name or a path.
    pub profile: Option<String>,
    /// `--module`: only these; with a profile, the profile must enable them.
    pub modules: Vec<String>,
}

impl Selection {
    /// The modules to run, with their params from `profile`.
    pub(super) fn select<'a>(
        &self,
        all: &[&'a dyn Module],
        profile: Option<&'a Profile>,
    ) -> anyhow::Result<Vec<Selected<'a>>> {
        let ids = &self.modules;
        if let Some(id) = ids.iter().find(|id| !all.iter().any(|m| m.id() == *id)) {
            bail!("no module {id}");
        }
        let mut selected = Vec::new();
        for &module in all {
            let id = module.id();
            let named = ids.iter().any(|n| n == id);
            match profile {
                Some(profile) => match profile.params(id) {
                    Some(params) if named || ids.is_empty() => {
                        selected.push(Selected { module, params });
                    }
                    Some(_) => {}
                    None if named => {
                        bail!("{id} is not enabled by profile {}", self.profile());
                    }
                    None => {}
                },
                None if named || (ids.is_empty() && DEFAULT_MODULES.contains(&id)) => {
                    selected.push(Selected::new(module));
                }
                None => {}
            }
        }
        Ok(selected)
    }

    fn profile(&self) -> &str {
        self.profile.as_deref().unwrap_or_default()
    }

    /// The command line that repeats this selection, e.g.
    /// ` --profile web --module ssh.server`.
    fn args(&self) -> String {
        let profile = self.profile.iter().map(|p| format!(" --profile {p}"));
        let modules = self.modules.iter().map(|id| format!(" --module {id}"));
        profile.chain(modules).collect()
    }

    /// The profile, read from a built-in name or a file.
    fn load(&self, host: &Host) -> anyhow::Result<Option<Profile>> {
        let Some(spec) = &self.profile else {
            return Ok(None);
        };
        if let Some(profile) = Profile::built_in(spec, host.modules)? {
            return Ok(Some(profile));
        }
        let path = std::path::absolute(spec)?;
        let text = host
            .sys
            .fs
            .read(&path)
            .map_err(|e| anyhow::anyhow!("{spec} is not a built-in profile ({e})"))?;
        let text = String::from_utf8(text)
            .map_err(|_| anyhow::anyhow!("profile {spec} is not valid UTF-8"))?;
        Profile::parse(&text, host.modules)
            .map(Some)
            .map_err(|e| anyhow::anyhow!("profile {spec}: {e}"))
    }
}

/// The exit code for an error: [`EXIT_INCOMPLETE`] for a rollback that did
/// not complete, [`EXIT_ERROR`] otherwise.
pub(super) fn exit_code(err: &anyhow::Error) -> u8 {
    match err.downcast_ref::<EngineError>() {
        Some(EngineError::RollbackIncomplete { .. }) => EXIT_INCOMPLETE,
        _ => EXIT_ERROR,
    }
}

/// `plan`: prints what `apply` would change. Takes no lock and needs no root.
pub(super) fn plan(
    host: &Host,
    sel: &Selection,
    json: bool,
    out: &mut dyn Write,
) -> anyhow::Result<u8> {
    let profile = sel.load(host)?;
    plan_profile(host, profile, sel, json, out)
}

/// [`plan`] with `profile` loaded; `sel` picks its modules.
pub(super) fn plan_profile(
    host: &Host,
    profile: Option<Profile>,
    sel: &Selection,
    json: bool,
    out: &mut dyn Write,
) -> anyhow::Result<u8> {
    let modules = sel.select(host.modules, profile.as_ref())?;
    let facts = (host.facts)(host.sys)?;
    log_notices(&facts);
    let plan = engine::plan(&modules, &facts, host.sys)?;
    if json {
        serde_json::to_writer_pretty(&mut *out, &plan)?;
        writeln!(out)?;
        return Ok(0);
    }
    print_plan(out, &plan, &fixes(&plan, &facts)?, host.color)?;
    let n = plan.steps().count();
    if n == 0 {
        let whole = profile.is_some() && sel.modules.is_empty();
        writeln!(out, "\n{}", nothing_to_do(whole))?;
    } else {
        let args = sel.args();
        let them = if n == 1 { "it" } else { "them" };
        writeln!(out, "Run `sudo vps-ready apply{args}` to make {them}.")?;
    }
    Ok(0)
}

/// `apply`: plans under the lock, asks, applies, then audits what it fixed.
/// `window` is the dead-man window. `input` is stdin when it is a terminal.
#[allow(clippy::too_many_arguments)]
pub(super) fn apply(
    host: &Host,
    sel: &Selection,
    yes: bool,
    window: Duration,
    input: Option<&mut dyn BufRead>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<u8> {
    // Before the load, so a run without root says so first.
    require_root(host, "apply")?;
    let profile = sel.load(host)?;
    let whole = profile.is_some() && sel.modules.is_empty();
    Ok(
        match apply_profile(host, profile, sel, yes, window, input, out, err)? {
            Applied::Nothing => {
                writeln!(out, "\n{}", nothing_to_do(whole))?;
                0
            }
            Applied::Declined => 0,
            Applied::Ran(code) => code,
        },
    )
}

/// The end of an empty plan: a whole profile, not narrowed by `--module`,
/// says the server matches it.
fn nothing_to_do(whole: bool) -> &'static str {
    if whole {
        "Nothing to do: this server already matches."
    } else {
        "Nothing to do."
    }
}

/// How [`apply_profile`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Applied {
    /// The plan has no change. Not printed: the caller knows what was asked
    /// for.
    Nothing,
    /// The answer was no.
    Declined,
    /// It ran and exits with this code.
    Ran(u8),
}

/// [`apply`] with `profile` loaded; `sel` picks its modules. Checks root
/// itself too, for callers that did not load a profile first.
#[allow(clippy::too_many_arguments)]
pub(super) fn apply_profile(
    host: &Host,
    profile: Option<Profile>,
    sel: &Selection,
    yes: bool,
    window: Duration,
    input: Option<&mut dyn BufRead>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<Applied> {
    require_root(host, "apply")?;
    let modules = sel.select(host.modules, profile.as_ref())?;
    let state = StateDir::create(host.sys.fs, host.state_dir, host.state_uid)?;
    let engine = Engine::lock(&state, host.sys)?;
    engine.ensure_finished()?;
    let facts = (host.facts)(host.sys)?;
    log_notices(&facts);
    let plan = engine::plan(&modules, &facts, host.sys)?;
    if !sel.modules.is_empty() {
        for m in &plan.modules {
            if let ModuleStatus::NotApplicable { reason } = &m.status {
                bail!("{} does not apply to this host: {reason}", m.id);
            }
        }
    }
    print_plan(out, &plan, &fixes(&plan, &facts)?, host.color)?;
    let n = plan.steps().count();
    if n == 0 {
        return Ok(Applied::Nothing);
    }
    if !yes {
        let Some(input) = input else {
            bail!("stdin is not a terminal; pass --yes to apply without asking");
        };
        write!(out, "Apply {n} {}? [y/N] ", plural(n, "change"))?;
        out.flush()?;
        let mut answer = String::new();
        input.read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            writeln!(out, "Nothing was changed.")?;
            return Ok(Applied::Declined);
        }
    }
    // An interrupted apply leaves its transaction unfinished; `rollback
    // --last` resumes and finishes it.
    writeln!(
        err,
        "If this is interrupted, run `sudo vps-ready rollback --last` to undo it."
    )?;
    let deadman = Deadman {
        window,
        binary: host.binary.clone(),
    };
    match engine.apply(&plan, &deadman, &mut |p| print_progress(err, &p))? {
        ApplyOutcome::NothingToDo => writeln!(out, "Nothing to do.")?,
        ApplyOutcome::Pending { txn, deadline } => {
            // A confirm and the timer's rollback need the lock.
            drop(engine);
            writeln!(
                out,
                "Applied {n} {} (transaction {txn}). Undo them now with `sudo vps-ready \
                 rollback --last`.",
                plural(n, "change"),
            )?;
            let left = match engine::watch(&state, host.sys.fs, &txn)? {
                engine::Watch::Pending { left, .. } => left,
                _ => Duration::ZERO,
            };
            confirm::print_pending(host, &facts, &plan.admins(), deadline, left, out)?;
            out.flush()?;
            return confirm::wait(host, &state, &txn, deadline, &plan, out, err).map(Applied::Ran);
        }
        ApplyOutcome::Applied { txn } => {
            let journal = host.state_dir.join("txn").join(&txn);
            writeln!(
                out,
                "Applied {n} {} (transaction {txn}, journal {}). \
                 Undo with `sudo vps-ready rollback --last`.",
                plural(n, "change"),
                journal.display()
            )?;
            if let Err(e) = audit_fixed(host, &plan, out) {
                writeln!(err, "vps-ready: could not audit after apply: {e:#}")?;
            }
        }
        ApplyOutcome::RolledBack { txn, reason, cause } => {
            let state = TxnState::RolledBack { reason };
            writeln!(
                err,
                "error: apply failed: {cause}. Every change was restored; \
                 transaction {txn} is {state}."
            )?;
            return Ok(Applied::Ran(EXIT_ROLLED_BACK));
        }
    }
    Ok(Applied::Ran(0))
}

/// `rollback`: undoes one transaction.
pub(super) fn rollback(
    host: &Host,
    target: Target,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<u8> {
    require_root(host, "rollback")?;
    let state = StateDir::create(host.sys.fs, host.state_dir, host.state_uid)?;
    // Who runs it: a rollback must not remove their account.
    let mut own: Vec<String> = host.sudo_user.iter().cloned().collect();
    own.extend((host.session)(host.sys).ok().and_then(|s| s.user));
    let done = Engine::lock(&state, host.sys)?.rollback_by(target, &own, &mut |p| {
        print_progress(err, &p);
    })?;
    print_rollback(out, &done)?;
    Ok(0)
}

/// `rollback --txn ID --deadman`, run by the dead-man timer: waits for the
/// lock, then rolls back the transaction unless it was confirmed, finished
/// or extended meanwhile. Its output goes to the unit's log.
pub(super) fn rollback_deadman(
    host: &Host,
    txn: &str,
    attempt: u32,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<u8> {
    require_root(host, "rollback")?;
    let state = StateDir::create(host.sys.fs, host.state_dir, host.state_uid)?;
    let engine = Engine::lock_wait(&state, host.sys)?;
    match engine.deadman(txn, &host.binary, attempt, &mut |p| print_progress(err, &p))? {
        DeadmanOutcome::Finished(state) => {
            writeln!(out, "Transaction {txn} is {state}; nothing to roll back.")?;
        }
        DeadmanOutcome::Rearmed(deadline) => writeln!(
            out,
            "Transaction {txn} now reverts at {}; re-armed for then.",
            clock(deadline.wall)
        )?,
        DeadmanOutcome::RolledBack(done) => print_rollback(out, &done)?,
    }
    Ok(0)
}

/// `rollback --deadman-boot`, run by the boot hook before sshd starts.
pub(super) fn rollback_deadman_boot(
    host: &Host,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<u8> {
    require_root(host, "rollback")?;
    let state = StateDir::create(host.sys.fs, host.state_dir, host.state_uid)?;
    let engine = Engine::lock_wait(&state, host.sys)?;
    let done = engine.deadman_boot(&host.binary, &mut |p| print_progress(err, &p))?;
    if done.is_empty() {
        writeln!(out, "Nothing was left unconfirmed by the reboot.")?;
    }
    for done in &done {
        print_rollback(out, done)?;
    }
    Ok(0)
}

pub(super) use confirm::confirm;

/// What a rollback did, including what it left and the edits it kept.
fn print_rollback(out: &mut dyn Write, done: &Rollback) -> io::Result<()> {
    writeln!(
        out,
        "Rolled back transaction {}: restored {} {}.",
        done.txn,
        done.restored,
        plural(done.restored, "change")
    )?;
    let n = done.at_next_boot.len();
    if n > 0 {
        writeln!(
            out,
            "{n} kernel {} {} running value until the next boot: {}",
            plural(n, "setting"),
            if n == 1 { "keeps its" } else { "keep their" },
            done.at_next_boot.join(", ")
        )?;
    }
    for copy in &done.during {
        writeln!(
            out,
            "A file changed since apply was restored anyway; its edit is in {}.",
            copy.display()
        )?;
    }
    if !done.skipped.is_empty() {
        writeln!(
            out,
            "Left as they are because they changed since apply; restore them by hand:"
        )?;
        for step in &done.skipped {
            writeln!(out, "  {step}")?;
        }
    }
    Ok(())
}

/// Unix seconds as the time of day, e.g. `14:07:30 UTC`.
fn clock(at: u64) -> String {
    let secs = at % 86_400;
    format!(
        "{:02}:{:02}:{:02} UTC",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// `history`: every transaction, newest first. Needs root, since the state
/// dir is private; takes no lock.
pub(super) fn history(host: &Host, json: bool, out: &mut dyn Write) -> anyhow::Result<u8> {
    require_root(host, "history")?;
    // A fresh host has no state dir; listing must not create it.
    let txns = if host.sys.fs.exists(host.state_dir) {
        let state = StateDir::open(host.sys.fs, host.state_dir, host.state_uid)?;
        engine::history(&state, host.sys.fs)?
    } else {
        Vec::new()
    };
    if json {
        serde_json::to_writer_pretty(&mut *out, &txns)?;
        writeln!(out)?;
    } else {
        print_history(out, &txns)?;
    }
    Ok(0)
}

/// Logs the notices of `facts`, except the SSH session ones: these commands
/// do not use the session.
fn log_notices(facts: &Facts) {
    super::log_notices(facts, &[crate::facts::session::NOTICE]);
}

fn require_root(host: &Host, command: &str) -> anyhow::Result<()> {
    if !host.root {
        bail!("{command} needs root; run it with sudo");
    }
    Ok(())
}

/// For each module with changes, the IDs of the failed controls it fixes.
fn fixes(plan: &Plan, facts: &Facts) -> anyhow::Result<BTreeMap<String, Vec<String>>> {
    let changed = plan.changed_modules();
    let report = audit::run(fixed_by(&changed)?, facts);
    let mut fixes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for finding in report.findings {
        if let (Outcome::Fail { .. }, Some(fix)) = (&finding.outcome, finding.control.fix) {
            fixes.entry(fix).or_default().push(finding.control.id);
        }
    }
    Ok(fixes)
}

/// The controls whose `fix` is one of `modules`.
fn fixed_by(modules: &[String]) -> anyhow::Result<Vec<audit::Control>> {
    Ok(audit::catalog()?
        .into_iter()
        .filter(|c| c.fix.as_ref().is_some_and(|f| modules.contains(f)))
        .collect())
}

/// Audits the controls the applied modules fix, with fresh facts. Their
/// notices were logged before apply, so they are not logged again.
fn audit_fixed(host: &Host, plan: &Plan, out: &mut dyn Write) -> anyhow::Result<()> {
    let facts = (host.facts)(host.sys)?;
    let report = audit::run(fixed_by(&plan.changed_modules())?, &facts);
    writeln!(out)?;
    print_report(
        out,
        &report,
        "this host after apply",
        false,
        false,
        host.color,
    )?;
    Ok(())
}

/// The plan as text, e.g.:
///
/// ```text
/// kernel.sysctl: Harden kernel settings (fixes KRN-001, NET-002)
///   + /etc/sysctl.d/90-vps-ready.conf (mode 0644, root:root)              reversible
///       @@ -0,0 +1,3 @@
///       +kernel.kptr_restrict = 1
///   ~ kernel.kptr_restrict 0 -> 1                                         reversible
///
/// 2 changes in 1 module: 1 file, 1 kernel setting.
/// ```
///
/// A `partial` step adds a footnote line before the final one. An empty
/// plan ends with its modules: the caller says why there is nothing to do.
fn print_plan(
    out: &mut dyn Write,
    plan: &Plan,
    fixes: &BTreeMap<String, Vec<String>>,
    color: bool,
) -> io::Result<()> {
    const WIDTH: usize = 72;
    for m in &plan.modules {
        let header = match &m.status {
            ModuleStatus::NotApplicable { reason } => {
                format!("{}: not applicable ({reason})", m.id)
            }
            ModuleStatus::Applicable { changes, .. } if changes.is_empty() => {
                format!("{}: {}: no changes", m.id, m.title)
            }
            ModuleStatus::Applicable { .. } => match fixes.get(m.id) {
                Some(ids) => format!("{}: {} (fixes {})", m.id, m.title, ids.join(", ")),
                None => format!("{}: {}", m.id, m.title),
            },
        };
        if color {
            writeln!(out, "{}", header.bold())?;
        } else {
            writeln!(out, "{header}")?;
        }
        for note in &m.notes {
            if color {
                writeln!(out, "  {}", format!("note: {note}").yellow())?;
            } else {
                writeln!(out, "  note: {note}")?;
            }
        }
        let ModuleStatus::Applicable { changes, .. } = &m.status else {
            continue;
        };
        for step in changes {
            let summary = step.change.summary.as_str();
            let (sign, text) = match &step.resource {
                Resource::File(_) | Resource::Directory(_) | Resource::AuthorizedKeys(_) => {
                    match summary.strip_prefix("create ") {
                        Some(rest) => ('+', show_owner(rest)),
                        None => (
                            '~',
                            show_owner(summary.strip_prefix("update ").unwrap_or(summary)),
                        ),
                    }
                }
                Resource::Sysctl(_) | Resource::Service(_) => ('~', summary.to_owned()),
                Resource::Package(_) => ('+', summary.to_owned()),
                Resource::User(_) if summary.starts_with("create ") => ('+', summary.to_owned()),
                Resource::User(_) => ('~', summary.to_owned()),
            };
            let rev = match step.change.reversibility {
                Reversibility::Reversible => "reversible",
                Reversibility::Partial => "partial",
            };
            // Pad before coloring: escape codes would count towards the width.
            let line = format!("{sign} {text}");
            let pad = " ".repeat(WIDTH.saturating_sub(line.chars().count()).max(2));
            if color {
                let line = if sign == '+' {
                    line.green().to_string()
                } else {
                    line.yellow().to_string()
                };
                writeln!(out, "  {line}{pad}{}", rev.dimmed())?;
            } else {
                writeln!(out, "  {line}{pad}{rev}")?;
            }
            for line in step.change.diff.iter().flat_map(|d| d.lines()) {
                match (color, line.chars().next()) {
                    (true, Some('+')) => writeln!(out, "      {}", line.green())?,
                    (true, Some('-')) => writeln!(out, "      {}", line.red())?,
                    (true, Some('@')) => writeln!(out, "      {}", line.cyan())?,
                    _ => writeln!(out, "      {line}")?,
                }
            }
        }
    }
    let n = plan.steps().count();
    if n == 0 {
        Ok(())
    } else {
        let modules = plan.changed_modules().len();
        writeln!(
            out,
            "\n{n} {} in {modules} {}: {}.",
            plural(n, "change"),
            plural(modules, "module"),
            kinds(plan)
        )?;
        let partial = |kind: fn(&Resource) -> bool| {
            plan.steps()
                .any(|s| s.change.reversibility == Reversibility::Partial && kind(&s.resource))
        };
        if partial(|r| matches!(r, Resource::Package(_))) {
            writeln!(
                out,
                "partial: rollback restores the files but leaves installed packages in place."
            )?;
        }
        if partial(|r| matches!(r, Resource::User(_))) {
            writeln!(
                out,
                "partial: rollback removes a user it created but keeps its home directory."
            )?;
        }
        Ok(())
    }
}

/// The steps by kind, e.g. `2 files, 6 kernel settings, 1 package`. A
/// package step counts each package it installs.
fn kinds(plan: &Plan) -> String {
    let count = |f: fn(&Resource) -> bool| plan.steps().filter(|s| f(&s.resource)).count();
    let packages = plan
        .steps()
        .filter(|s| matches!(s.resource, Resource::Package(_)))
        .map(|s| {
            s.change
                .summary
                .strip_prefix("install ")
                .map_or(1, |names| names.split(", ").count())
        })
        .sum();
    [
        (
            count(|r| matches!(r, Resource::File(_) | Resource::AuthorizedKeys(_))),
            "file",
        ),
        (count(|r| matches!(r, Resource::Directory(_))), "directory"),
        (
            count(|r| matches!(r, Resource::Sysctl(_))),
            "kernel setting",
        ),
        (packages, "package"),
        (count(|r| matches!(r, Resource::Service(_))), "service"),
        (count(|r| matches!(r, Resource::User(_))), "user"),
    ]
    .into_iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, word)| format!("{n} {}", plural(n, word)))
    .collect::<Vec<_>>()
    .join(", ")
}

/// Spells out the owner of a file summary: `(0644 0:0)` becomes
/// `(mode 0644, root:root)`; other owners keep their numbers. Text after
/// the owner, such as a file's `describe` line, is kept.
fn show_owner(summary: &str) -> String {
    let Some((head, tail)) = summary.split_once(" (") else {
        return summary.to_owned();
    };
    let Some((owners, rest)) = tail.split_once(')') else {
        return summary.to_owned();
    };
    let spelled: Vec<String> = owners
        .split(" -> ")
        .map(|o| match o.split_once(' ') {
            Some((mode, "0:0")) => format!("mode {mode}, root:root"),
            Some((mode, owner)) => format!("mode {mode}, {owner}"),
            None => o.to_owned(),
        })
        .collect();
    format!("{head} ({}){rest}", spelled.join(" -> "))
}

/// One line of progress, e.g. `[2/8] set kernel.kptr_restrict 0 -> 1`.
/// Plain text, so it reads the same when stderr is a file. A failed write
/// is ignored: it must not stop a transaction part way.
fn print_progress(err: &mut dyn Write, progress: &Progress) {
    let line = match progress {
        Progress::Apply { n, total, step } => {
            let summary = &step.change.summary;
            let text = match &step.resource {
                Resource::File(_) | Resource::Directory(_) | Resource::AuthorizedKeys(_) => {
                    show_owner(summary)
                }
                Resource::Sysctl(_) => format!("set {summary}"),
                Resource::Package(_) => {
                    format!("{summary} (apt-get update, then install; can take a few minutes)")
                }
                Resource::Service(_) | Resource::User(_) => summary.clone(),
            };
            format!("[{n}/{total}] {text}")
        }
        Progress::Verified => "verify: ok".to_owned(),
        Progress::Restore(backup) => match backup {
            Backup::File {
                path,
                original: Some(_),
                ..
            } => format!("restore {}", path.display()),
            Backup::File { path, .. } => format!("remove {}", path.display()),
            Backup::Directory {
                path,
                created: true,
            } => format!("remove directory {} if it is empty", path.display()),
            Backup::Directory { path, .. } => format!("leave {} as it is", path.display()),
            Backup::Sysctl { key, value, .. } => format!("restore {key} = {value}"),
            Backup::Package { name, .. } => {
                let names = name.split(' ').collect::<Vec<_>>().join(", ");
                format!("leave {names} as it is (rollback does not remove packages)")
            }
            Backup::Service {
                unit,
                was_enabled,
                was_active,
                ..
            } => format!(
                "restore {unit} ({}, {})",
                if *was_enabled { "enabled" } else { "disabled" },
                if *was_active { "active" } else { "inactive" }
            ),
            Backup::User {
                name,
                created: true,
                ..
            } => format!("remove user {name} (its home directory stays)"),
            Backup::User {
                name, added_groups, ..
            } if added_groups.is_empty() => format!("leave user {name} as it is"),
            Backup::User {
                name, added_groups, ..
            } => format!("remove {name} from groups {}", added_groups.join(",")),
            Backup::AuthorizedKeys {
                path,
                original: Some(_),
                ..
            } => format!("restore {}", path.display()),
            Backup::AuthorizedKeys { path, .. } => format!("remove {}", path.display()),
        },
        Progress::Leave(Backup::Sysctl { key, .. }) => {
            format!("leave {key} as it is (the host rebooted since apply; the next boot sets it)")
        }
        // The engine leaves only sysctls.
        Progress::Leave(_) => return,
        Progress::Armed { deadline } => format!(
            "Armed the dead-man switch: changes revert by {} if apply does not finish",
            clock(deadline.wall)
        ),
        Progress::Reload(reload) => format!("reload: {reload}"),
        Progress::Waiting { left } => {
            format!("waiting for a confirm: {} left", confirm::countdown(*left))
        }
        Progress::During { path, copy } => format!(
            "{} changed since apply; keeping it as {}, then restoring it",
            path.display(),
            copy.display()
        ),
        Progress::Skip(step) => format!("leave {step} (it changed since apply)"),
        Progress::ReloadSkipped { reload, reason } => {
            format!("skip {reload}, so the daemon keeps its config: {reason}")
        }
    };
    let _ = writeln!(err, "{line}");
}

/// One line per transaction, e.g.
/// `20261023T114246Z  applied  kernel.sysctl  15 changes`.
fn print_history(out: &mut dyn Write, txns: &[TxnInfo]) -> io::Result<()> {
    if txns.is_empty() {
        return writeln!(out, "No transactions.");
    }
    let modules: Vec<String> = txns
        .iter()
        .map(|t| {
            if t.modules.is_empty() {
                "-".to_owned()
            } else {
                t.modules.join(",")
            }
        })
        .collect();
    let width = modules.iter().map(String::len).max().unwrap_or(0);
    let states: Vec<String> = txns
        .iter()
        .map(|t| match (t.unfinished, t.reverts_in) {
            (true, _) => format!("unfinished ({})", t.state),
            (false, Some(0)) => format!("{} (deadline passed)", t.state),
            (false, Some(secs)) => format!("{} (reverts in {})", t.state, short(secs)),
            (false, None) => t.state.to_string(),
        })
        .collect();
    let state_width = states.iter().map(String::len).max().unwrap_or(0).max(29);
    for ((t, modules), state) in txns.iter().zip(&modules).zip(&states) {
        writeln!(
            out,
            "{:<20}  {state:<state_width$}  {modules:<width$}  {} {}",
            t.id,
            t.changes,
            plural(t.changes, "change")
        )?;
        for step in &t.skipped {
            writeln!(out, "  left by the dead-man rollback: {step}")?;
        }
    }
    Ok(())
}

/// Seconds as `3m12s`, or `45s` under a minute.
fn short(secs: u64) -> String {
    match secs / 60 {
        0 => format!("{secs}s"),
        m => format!("{m}m{:02}s", secs % 60),
    }
}

pub(super) fn plural(n: usize, word: &str) -> String {
    match (n, word) {
        (1, _) => word.to_owned(),
        (_, "directory") => "directories".to_owned(),
        _ => format!("{word}s"),
    }
}

mod confirm;
#[cfg(test)]
pub(super) mod tests;
