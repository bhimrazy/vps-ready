//! `plan`, `apply`, `rollback` and `history`, run against a [`Host`]: the
//! real system, or a fake one in tests.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::path::Path;

use anyhow::bail;
use owo_colors::OwoColorize;

use super::{EXIT_ERROR, EXIT_INCOMPLETE, EXIT_ROLLED_BACK, print_report};
use crate::audit::{self, Outcome};
use crate::engine::{
    self, ApplyOutcome, Engine, EngineError, ModuleStatus, Plan, StateDir, Target, TxnInfo,
    TxnState,
};
use crate::facts::Facts;
use crate::modules::Module;
use crate::resource::{Resource, Reversibility};
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
    ids: &[String],
    json: bool,
    out: &mut dyn Write,
) -> anyhow::Result<u8> {
    let modules = select(host.modules, ids)?;
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
        let args: String = ids.iter().map(|id| format!(" --module {id}")).collect();
        writeln!(out, "Run `sudo vps-ready apply{args}` to make them.")?;
    }
    Ok(0)
}

/// `apply`: plans under the lock, asks, applies, then audits what it fixed.
/// `input` is stdin when it is a terminal.
pub(super) fn apply(
    host: &Host,
    ids: &[String],
    yes: bool,
    input: Option<&mut dyn BufRead>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<u8> {
    require_root(host, "apply")?;
    let modules = select(host.modules, ids)?;
    let state = StateDir::create(host.sys.fs, host.state_dir, host.state_uid)?;
    let engine = Engine::lock(&state, host.sys)?;
    engine.ensure_finished()?;
    let facts = (host.facts)(host.sys)?;
    log_notices(&facts);
    let plan = engine::plan(&modules, &facts, host.sys)?;
    if !ids.is_empty() {
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
    match engine.apply(&plan)? {
        ApplyOutcome::NothingToDo => writeln!(out, "Nothing to do.")?,
        ApplyOutcome::Applied { txn } => {
            writeln!(
                out,
                "Applied {n} {} (transaction {txn}). Undo with `sudo vps-ready rollback --last`.",
                plural(n, "change")
            )?;
            if let Err(e) = audit_fixed(host, &plan, out) {
                tracing::warn!("could not audit after apply: {e:#}");
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
pub(super) fn rollback(host: &Host, target: Target, out: &mut dyn Write) -> anyhow::Result<u8> {
    require_root(host, "rollback")?;
    let state = StateDir::create(host.sys.fs, host.state_dir, host.state_uid)?;
    let done = Engine::lock(&state, host.sys)?.rollback(target)?;
    writeln!(
        out,
        "Rolled back transaction {}: restored {} {}.",
        done.txn,
        done.restored,
        plural(done.restored, "change")
    )?;
    Ok(0)
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

/// Logs the notices of `facts`, except the SSH session one: these commands
/// do not use the session.
fn log_notices(facts: &Facts) {
    super::log_notices(facts, &[crate::facts::session::UNSET_NOTICE]);
}

fn require_root(host: &Host, command: &str) -> anyhow::Result<()> {
    if !host.root {
        bail!("{command} needs root; run it with sudo");
    }
    Ok(())
}

/// The modules named by `ids` in registry order, or all of them.
fn select<'a>(all: &[&'a dyn Module], ids: &[String]) -> anyhow::Result<Vec<&'a dyn Module>> {
    if let Some(id) = ids.iter().find(|id| !all.iter().any(|m| m.id() == *id)) {
        bail!("no module {id}");
    }
    Ok(all
        .iter()
        .filter(|m| ids.is_empty() || ids.iter().any(|id| id == m.id()))
        .copied()
        .collect())
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
    print_report(out, &report, "this host after apply", false, host.color)?;
    Ok(())
}

/// The plan as text, e.g.:
///
/// ```text
/// kernel.sysctl: Harden kernel settings (fixes KRN-001, NET-002)
///   + /etc/sysctl.d/90-vps-ready.conf (0644 0:0)                          reversible
///       @@ -0,0 +1,3 @@
///       +kernel.kptr_restrict = 1
///   ~ kernel.kptr_restrict 0 -> 1                                         reversible
///
/// 2 changes in 1 module.
/// ```
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
            ModuleStatus::Applicable { changes } if changes.is_empty() => {
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
        let ModuleStatus::Applicable { changes } = &m.status else {
            continue;
        };
        for step in changes {
            let summary = step.change.summary.as_str();
            let (sign, text) = match &step.resource {
                Resource::File(_) => match summary.strip_prefix("create ") {
                    Some(rest) => ('+', rest),
                    None => ('~', summary.strip_prefix("update ").unwrap_or(summary)),
                },
                Resource::Sysctl(_) => ('~', summary),
                Resource::Package(_) => ('+', summary),
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
            "\n{n} {} in {modules} {}.",
            plural(n, "change"),
            plural(modules, "module")
        )
    }
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
            "{:<20}  {state:<26}  {modules:<width$}  {} {}",
            t.id,
            t.changes,
            plural(t.changes, "change")
        )?;
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
