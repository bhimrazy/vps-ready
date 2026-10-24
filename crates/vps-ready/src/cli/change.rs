//! `plan`, `apply`, `rollback` and `history`, run against a [`Host`]: the
//! real system, or a fake one in tests.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::bail;
use owo_colors::OwoColorize;

use super::{EXIT_ERROR, EXIT_INCOMPLETE, EXIT_PENDING, EXIT_ROLLED_BACK, print_report};
use crate::audit::{self, Outcome};
use crate::config::Profile;
use crate::engine::{
    self, ApplyOutcome, Deadman, DeadmanOutcome, Engine, EngineError, ModuleStatus, Plan, Progress,
    Rollback, Selected, StateDir, Target, TxnInfo, TxnState,
};
use crate::facts::Facts;
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
}

/// The modules `plan` and `apply` run without `--profile` and `--module`:
/// the safe set. Modules that can lock someone out or install packages need
/// a profile or `--module`.
const DEFAULT_MODULES: [&str; 2] = ["kernel.sysctl", "updates.auto"];

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
    fn select<'a>(
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
    if n > 0 {
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
    require_root(host, "apply")?;
    let profile = sel.load(host)?;
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
        return Ok(0);
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
            return Ok(0);
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
            writeln!(
                out,
                "Applied {n} {} (transaction {txn}). The changes are live and are rolled \
                 back at {} unless confirmed. Undo them now with `sudo vps-ready rollback --last`.",
                plural(n, "change"),
                clock(deadline.wall)
            )?;
            return Ok(EXIT_PENDING);
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
            return Ok(EXIT_ROLLED_BACK);
        }
    }
    Ok(0)
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
    let done =
        Engine::lock(&state, host.sys)?.rollback(target, &mut |p| print_progress(err, &p))?;
    print_rollback(out, &done)?;
    Ok(0)
}

/// `rollback --txn ID --deadman`, run by the dead-man timer: waits for the
/// lock, then rolls back the transaction unless it was confirmed, finished
/// or extended meanwhile. Its output goes to the unit's log.
pub(super) fn rollback_deadman(
    host: &Host,
    txn: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<u8> {
    require_root(host, "rollback")?;
    let state = StateDir::create(host.sys.fs, host.state_dir, host.state_uid)?;
    let engine = Engine::lock_wait(&state, host.sys)?;
    match engine.deadman(txn, &host.binary, &mut |p| print_progress(err, &p))? {
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
    let done = engine.deadman_boot(&mut |p| print_progress(err, &p))?;
    if done.is_empty() {
        writeln!(out, "Nothing was left unconfirmed by the reboot.")?;
    }
    for done in &done {
        print_rollback(out, done)?;
    }
    Ok(0)
}

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
/// A `partial` step adds a footnote line before the final one.
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
                Resource::File(_) | Resource::AuthorizedKeys(_) => {
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
        writeln!(out, "\nNothing to do.")
    } else {
        let modules = plan.changed_modules().len();
        writeln!(
            out,
            "\n{n} {} in {modules} {}: {}.",
            plural(n, "change"),
            plural(modules, "module"),
            kinds(plan)
        )?;
        if plan
            .steps()
            .any(|s| s.change.reversibility == Reversibility::Partial)
        {
            writeln!(
                out,
                "partial: rollback restores the files but leaves installed packages in place."
            )?;
        }
        Ok(())
    }
}

/// The steps by kind, e.g. `2 files, 6 kernel settings, 1 package`.
fn kinds(plan: &Plan) -> String {
    let count = |f: fn(&Resource) -> bool| plan.steps().filter(|s| f(&s.resource)).count();
    [
        (
            count(|r| matches!(r, Resource::File(_) | Resource::AuthorizedKeys(_))),
            "file",
        ),
        (
            count(|r| matches!(r, Resource::Sysctl(_))),
            "kernel setting",
        ),
        (count(|r| matches!(r, Resource::Package(_))), "package"),
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
/// `(mode 0644, root:root)`; other owners keep their numbers.
fn show_owner(summary: &str) -> String {
    let Some((head, tail)) = summary.split_once(" (") else {
        return summary.to_owned();
    };
    let Some(owners) = tail.strip_suffix(')') else {
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
    format!("{head} ({})", spelled.join(" -> "))
}

/// One line of progress, e.g. `[2/8] set kernel.kptr_restrict 0 -> 1`.
/// Plain text, so it reads the same when stderr is a file. A failed write
/// is ignored: it must not stop a transaction part way.
fn print_progress(err: &mut dyn Write, progress: &Progress) {
    let line = match progress {
        Progress::Apply { n, total, step } => {
            let summary = &step.change.summary;
            let text = match &step.resource {
                Resource::File(_) | Resource::AuthorizedKeys(_) => show_owner(summary),
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
            Backup::Sysctl { key, value, .. } => format!("restore {key} = {value}"),
            Backup::Package { name, .. } => {
                format!("leave {name} as it is (rollback does not remove packages)")
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
        Progress::Waiting { left } => format!("waiting for a confirm: {}s left", left.as_secs()),
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
    for (t, modules) in txns.iter().zip(&modules) {
        let state = if t.unfinished {
            format!("unfinished ({})", t.state)
        } else {
            t.state.to_string()
        };
        writeln!(
            out,
            "{:<20}  {state:<29}  {modules:<width$}  {} {}",
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

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        word.to_owned()
    } else {
        format!("{word}s")
    }
}

#[cfg(test)]
mod tests;
