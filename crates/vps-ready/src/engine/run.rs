//! Apply, rollback and history.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use serde::Serialize;

use super::journal::{self, Event, Record, RollbackReason, TxnState};
use super::plan::{Plan, Step};
use super::reload::{self, Reload};
use super::{EngineError, StateDir, Txn, id};
use crate::resource::sysctl::boot_id;
use crate::resource::{Backup, Resource, Sysctl, after_path, before_path, restore};
use crate::sys::{FileKind, Fs, FsLock, Sys, SysError};

/// The engine with the lock held: apply and rollback run through it.
pub struct Engine<'a> {
    state: &'a StateDir,
    sys: Sys<'a>,
    _lock: FsLock,
}

/// How [`Engine::apply`] ended, other than with an error.
#[derive(Debug)]
pub enum ApplyOutcome {
    /// The plan had no changes; no transaction was created.
    NothingToDo,
    /// Every change was applied and verified.
    Applied {
        /// Transaction ID.
        txn: String,
    },
    /// A step failed or a change did not verify, and every change was
    /// restored.
    RolledBack {
        /// Transaction ID.
        txn: String,
        /// Why.
        reason: RollbackReason,
        /// The failure.
        cause: EngineError,
    },
}

/// Which transaction [`Engine::rollback`] undoes.
#[derive(Debug, Clone, Copy)]
pub enum Target<'a> {
    /// The unfinished one if there is one, otherwise the newest applied one.
    Last,
    /// The one with this ID.
    Txn(&'a str),
}

/// What [`Engine::apply`] or [`Engine::rollback`] is about to do or has
/// done, for the caller to show.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Progress<'a> {
    /// A step is about to be applied.
    Apply {
        /// Position, from 1.
        n: usize,
        /// How many steps the plan has.
        total: usize,
        /// The step.
        step: &'a Step,
    },
    /// Every change was applied and verified.
    Verified,
    /// A backup is about to be restored.
    Restore(&'a Backup),
    /// A sysctl backed up in an earlier boot is left as it is.
    Leave(&'a Backup),
}

/// A finished [`Engine::rollback`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rollback {
    /// Transaction ID.
    pub txn: String,
    /// How many changes this run restored; earlier runs may have restored others.
    pub restored: usize,
    /// Keys of the sysctls this run left as they are, because they were
    /// backed up in an earlier boot.
    pub at_next_boot: Vec<String>,
}

/// A resource to put back by hand, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByHand {
    /// Resource ID.
    pub resource: String,
    /// The step, e.g. `sysctl -w fs.suid_dumpable=0`.
    pub step: String,
}

impl fmt::Display for ByHand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.resource, self.step)
    }
}

/// One line of `history`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TxnInfo {
    /// Transaction ID.
    pub id: String,
    /// Its state.
    #[serde(flatten)]
    pub state: TxnState,
    /// Whether it stopped during an apply or a rollback.
    pub unfinished: bool,
    /// Unix seconds of the `begin` record.
    pub started: u64,
    /// IDs of the modules in its plan.
    pub modules: Vec<String>,
    /// How many resources it backed up.
    pub changes: usize,
}

impl<'a> Engine<'a> {
    /// Takes the lock of `state`, without waiting.
    ///
    /// # Errors
    ///
    /// [`EngineError::Busy`] or [`EngineError::Sys`].
    pub fn lock(state: &'a StateDir, sys: Sys<'a>) -> Result<Self, EngineError> {
        let lock = state.lock(sys.fs)?;
        Ok(Self {
            state,
            sys,
            _lock: lock,
        })
    }

    /// Fails if any transaction is unfinished. [`Engine::apply`] checks this
    /// too; call it before planning to fail early.
    ///
    /// # Errors
    ///
    /// [`EngineError::Unfinished`], or an error reading the journals.
    pub fn ensure_finished(&self) -> Result<(), EngineError> {
        match self.state.unfinished(self.sys.fs)?.pop() {
            Some(txn) => Err(EngineError::Unfinished(txn.id().to_owned())),
            None => Ok(()),
        }
    }

    /// Applies `plan`, the plan shown to the user. Each change is re-diffed
    /// first, and nothing happens if one differs. Resources that had no
    /// change are not re-diffed: if they drifted since, the next plan shows
    /// it. Then, for each resource: snapshot, `backup` line, apply, `applied`
    /// line; after a module's resources, each of its reloads: check,
    /// `reloaded` line, reload. Then every resource is verified, and each
    /// module with a change runs its own verify. On a failure the changes are
    /// rolled back without the safety check of [`Engine::rollback`], since
    /// they were made under this lock a moment ago. Each step and restore is
    /// reported to `progress` before it runs, and a passed verify after it.
    ///
    /// # Errors
    ///
    /// [`EngineError::RollbackIncomplete`] if a failure was not fully rolled
    /// back. Any other error means nothing was changed: an unfinished
    /// transaction, [`EngineError::DuplicateResource`],
    /// [`EngineError::PlanChanged`], or a failure before the first `backup`
    /// line.
    pub fn apply(
        &self,
        plan: &Plan,
        progress: &mut dyn FnMut(Progress),
    ) -> Result<ApplyOutcome, EngineError> {
        self.ensure_finished()?;
        let steps: Vec<&Step> = plan.steps().collect();
        if steps.is_empty() {
            return Ok(ApplyOutcome::NothingToDo);
        }
        // Rollback tracks `restored` lines by resource ID.
        let mut seen = BTreeSet::new();
        if let Some(step) = steps.iter().find(|s| !seen.insert(&s.change.id)) {
            return Err(EngineError::DuplicateResource(step.change.id.clone()));
        }
        for step in &steps {
            let now = diff(self.sys, &step.resource)?;
            if now.as_ref() != Some(&step.change) {
                return Err(EngineError::PlanChanged(step.change.id.clone()));
            }
        }

        let txn = self.state.create_txn(self.sys.fs, id::now())?;
        let id = txn.id().to_owned();
        let mut open = Open::new(self.sys.fs, txn, Vec::new())?;
        open.append(Event::Begin {
            version: crate::VERSION_INFO.version.to_owned(),
            modules: plan.changed_modules(),
        })?;

        let failure = match self.run(&mut open, plan, steps.len(), progress) {
            Err(e) => (RollbackReason::ApplyFailed, e),
            Ok(()) => match self.verify(plan) {
                Err(failure) => failure,
                Ok(()) => {
                    progress(Progress::Verified);
                    match open.append(Event::State {
                        state: TxnState::Applied,
                    }) {
                        Ok(()) => return Ok(ApplyOutcome::Applied { txn: id }),
                        Err(e) => (RollbackReason::ApplyFailed, e),
                    }
                }
            },
        };
        let (reason, cause) = failure;
        tracing::error!(txn = %id, "{cause}; rolling back");
        self.roll_back(&mut open, reason, false, progress)?;
        Ok(ApplyOutcome::RolledBack {
            txn: id,
            reason,
            cause,
        })
    }

    /// Applies each module's steps, then runs its reloads.
    fn run(
        &self,
        open: &mut Open,
        plan: &Plan,
        total: usize,
        progress: &mut dyn FnMut(Progress),
    ) -> Result<(), EngineError> {
        let mut n = 0;
        for module in &plan.modules {
            for step in module.changes() {
                n += 1;
                progress(Progress::Apply {
                    n: n as usize,
                    total,
                    step,
                });
                self.apply_step(open, n, step)?;
            }
            for &reload in module.reloads() {
                if let Some(check) = reload.check() {
                    reload::run(self.sys, &check)
                        .map_err(|reason| EngineError::ReloadCheck { reload, reason })?;
                }
                open.append(Event::Reloaded { reload })?;
                reload::run(self.sys, &reload.command())
                    .map_err(|reason| EngineError::Reload { reload, reason })?;
            }
        }
        Ok(())
    }

    /// Snapshot, `backup` line, apply, `applied` line.
    fn apply_step(&self, open: &mut Open, n: u32, step: &Step) -> Result<(), EngineError> {
        let id = &step.change.id;
        let backup = step
            .resource
            .snapshot(self.sys, open.txn.dir(), n)
            .map_err(|source| EngineError::Resource {
                id: id.clone(),
                source,
            })?;
        open.append(Event::Backup {
            resource: id.clone(),
            backup,
        })?;
        step.resource
            .apply(self.sys)
            .map_err(|source| EngineError::Resource {
                id: id.clone(),
                source,
            })?;
        open.append(Event::Applied {
            resource: id.clone(),
        })
    }

    /// Every resource must now be in its desired state, and every module
    /// with a change must pass its own verify.
    fn verify(&self, plan: &Plan) -> Result<(), (RollbackReason, EngineError)> {
        let mut differ = Vec::new();
        for step in plan.steps() {
            match diff(self.sys, &step.resource) {
                Ok(None) => {}
                Ok(Some(_)) => differ.push(step.change.id.clone()),
                Err(e) => return Err((RollbackReason::ApplyFailed, e)),
            }
        }
        for module in &plan.modules {
            if module.changes().is_empty() {
                continue;
            }
            if let Err(e) = module.verify(plan.facts, self.sys) {
                differ.push(format!("{}: {e}", module.id));
            }
        }
        if differ.is_empty() {
            Ok(())
        } else {
            Err((
                RollbackReason::VerifyFailed,
                EngineError::VerifyFailed(differ),
            ))
        }
    }

    /// Rolls back `target`, resuming it if it is unfinished. First checks
    /// that no backed-up resource changed since apply; if one did, nothing is
    /// restored. A sysctl backed up in an earlier boot is neither checked nor
    /// restored: the boot configuration set its running value. The reloads
    /// apply journaled run again, check first, after the restores of their
    /// module. Each restore is reported to `progress` before it runs.
    ///
    /// # Errors
    ///
    /// [`EngineError::Changed`] from the safety check;
    /// [`EngineError::RollbackIncomplete`] if a restore or journal line
    /// failed (running it again continues); [`EngineError::NothingToRollBack`],
    /// [`EngineError::UnknownTxn`] or [`EngineError::AlreadyRolledBack`].
    pub fn rollback(
        &self,
        target: Target,
        progress: &mut dyn FnMut(Progress),
    ) -> Result<Rollback, EngineError> {
        let fs = self.sys.fs;
        let txn = match target {
            Target::Last => match self.state.unfinished(fs)?.pop() {
                Some(txn) => txn,
                None => self
                    .newest_applied()?
                    .ok_or(EngineError::NothingToRollBack)?,
            },
            Target::Txn(id) => self
                .state
                .txns(fs)?
                .into_iter()
                .find(|t| t.id() == id)
                .ok_or_else(|| EngineError::UnknownTxn(id.to_owned()))?,
        };
        let mut records = txn.read(fs)?;
        if journal::is_unfinished(&records) {
            records = txn.resume(fs)?;
        }
        if records.is_empty() {
            return Err(EngineError::NothingToRollBack);
        }
        if let TxnState::RolledBack { .. } = journal::replay(&records)? {
            return Err(EngineError::AlreadyRolledBack(txn.id().to_owned()));
        }
        let id = txn.id().to_owned();
        let mut open = Open::new(fs, txn, records)?;
        let (restored, at_next_boot) =
            self.roll_back(&mut open, RollbackReason::Manual, true, progress)?;
        Ok(Rollback {
            txn: id,
            restored,
            at_next_boot,
        })
    }

    fn newest_applied(&self) -> Result<Option<Txn>, EngineError> {
        for txn in self.state.txns(self.sys.fs)?.into_iter().rev() {
            if journal::replay(&txn.read(self.sys.fs)?)? == TxnState::Applied {
                return Ok(Some(txn));
            }
        }
        Ok(None)
    }

    /// Restores every backup without a `restored` line, newest first, with
    /// the reloads apply journaled in between, then writes the final state.
    /// A `rollback` record goes first, unless an earlier run wrote one; its
    /// reason then wins over `reason`. A sysctl
    /// backed up in an earlier boot gets a `restored` line without a restore.
    /// Returns how many it restored and the keys of those sysctls.
    fn roll_back(
        &self,
        open: &mut Open,
        reason: RollbackReason,
        check: bool,
        progress: &mut dyn FnMut(Progress),
    ) -> Result<(usize, Vec<String>), EngineError> {
        let boot = boot_id(self.sys.fs);
        let boot = boot.as_deref();
        let (id, dir) = (open.txn.id().to_owned(), open.txn.dir().to_path_buf());
        let records = open.records().map_err(|e| incomplete(&id, &dir, None, e))?;
        let started = records.iter().rev().find_map(|r| match r.event {
            Event::Rollback { reason } => Some(reason),
            _ => None,
        });
        let restored: BTreeSet<&str> = records
            .iter()
            .filter_map(|r| match &r.event {
                Event::Restored { resource } => Some(resource.as_str()),
                _ => None,
            })
            .collect();
        // Reloads journaled by apply, not by an earlier run of this rollback.
        let applying = records
            .iter()
            .position(|r| matches!(r.event, Event::Rollback { .. }))
            .map_or(records, |i| &records[..i]);
        let undo: Vec<Undo> = applying
            .iter()
            .filter_map(|r| match &r.event {
                Event::Backup { resource, backup } if !restored.contains(resource.as_str()) => {
                    Some(Undo::Restore(resource.clone(), backup.clone()))
                }
                Event::Reloaded { reload } => Some(Undo::Reload(*reload)),
                _ => None,
            })
            .collect();
        let pending = || {
            undo.iter().filter_map(|u| match u {
                Undo::Restore(resource, backup) => Some((resource, backup)),
                Undo::Reload(_) => None,
            })
        };
        let left = |upto: usize| {
            Some(
                undo[..upto]
                    .iter()
                    .filter_map(|u| match u {
                        Undo::Restore(r, b) if !earlier_boot(b, boot) => by_hand(&dir, r, b),
                        _ => None,
                    })
                    .collect(),
            )
        };

        if check {
            let mut changed = Vec::new();
            for (resource, backup) in pending() {
                if earlier_boot(backup, boot) || unchanged(self.sys, &dir, backup)? {
                    continue;
                }
                changed.extend(by_hand(&dir, resource, backup).map(|mut step| {
                    if let Backup::File {
                        n, original: None, ..
                    } = backup
                    {
                        let after = after_path(&dir, *n);
                        step.step += &format!("; it no longer matches {}", after.display());
                    }
                    step
                }));
            }
            if !changed.is_empty() {
                return Err(EngineError::Changed { txn: id, changed });
            }
        }

        let reason = match started {
            Some(reason) => reason,
            None => {
                // A failed `state applied` append may have landed; from
                // `applied` only a manual rollback is legal.
                let reason = if open.state == Some(TxnState::Applied) {
                    RollbackReason::Manual
                } else {
                    reason
                };
                open.append(Event::Rollback { reason })
                    .map_err(|e| incomplete(&id, &dir, left(undo.len()), e))?;
                reason
            }
        };
        let mut at_next_boot = Vec::new();
        // A reload runs once the restores journaled before it, back to the
        // previous reload, are done: those of its module, perhaps with
        // those of a module without reloads.
        let mut due = None;
        for (i, item) in undo.iter().enumerate().rev() {
            let (resource, backup) = match item {
                Undo::Reload(reload) => {
                    if let Some(due) = due.replace(*reload) {
                        self.replay(open, due)
                            .map_err(|e| incomplete(&id, &dir, left(i), e))?;
                    }
                    continue;
                }
                Undo::Restore(resource, backup) => (resource, backup),
            };
            let result = match backup {
                Backup::Sysctl { key, .. } if earlier_boot(backup, boot) => {
                    progress(Progress::Leave(backup));
                    at_next_boot.push(key.clone());
                    Ok(())
                }
                _ => {
                    progress(Progress::Restore(backup));
                    restore(self.sys, &dir, backup).map_err(|source| EngineError::Resource {
                        id: resource.clone(),
                        source,
                    })
                }
            };
            let result = result.and_then(|()| {
                open.append(Event::Restored {
                    resource: resource.clone(),
                })
            });
            if let Err(e) = result {
                return Err(incomplete(&id, &dir, left(i + 1), e));
            }
        }
        if let Some(due) = due {
            self.replay(open, due)
                .map_err(|e| incomplete(&id, &dir, left(0), e))?;
        }
        open.append(Event::State {
            state: TxnState::RolledBack { reason },
        })
        .map_err(|e| incomplete(&id, &dir, left(0), e))?;
        Ok((pending().count() - at_next_boot.len(), at_next_boot))
    }

    /// Runs a reload that apply journaled, check first. A failed check skips
    /// it, so a running daemon keeps its config instead of loading a broken
    /// one (e.g. an `sshd_config` edited since apply). A resumed rollback
    /// runs every such reload again; that is harmless.
    fn replay(&self, open: &mut Open, reload: Reload) -> Result<(), EngineError> {
        if let Some(check) = reload.check()
            && let Err(reason) = reload::run(self.sys, &check)
        {
            tracing::warn!("not running {reload}, so the daemon keeps its config: {reason}");
            return Ok(());
        }
        reload::run(self.sys, &reload.command())
            .map_err(|reason| EngineError::Reload { reload, reason })?;
        open.append(Event::Reloaded { reload })
    }
}

/// What a rollback undoes, in journal order.
enum Undo {
    /// A backup without a `restored` line: resource ID and backup.
    Restore(String, Backup),
    /// A reload that apply journaled.
    Reload(Reload),
}

/// Every transaction with a `begin` record, newest first. Reads only; takes
/// no lock. A transaction whose journal is empty changed nothing and is left
/// out.
///
/// # Errors
///
/// [`EngineError`] if `txn/` or a journal cannot be read or parsed.
pub fn history(state: &StateDir, fs: &dyn Fs) -> Result<Vec<TxnInfo>, EngineError> {
    let mut infos = Vec::new();
    for txn in state.txns(fs)?.into_iter().rev() {
        let records = txn.read(fs)?;
        let Some(first) = records.first() else {
            continue;
        };
        let modules = match &first.event {
            Event::Begin { modules, .. } => modules.clone(),
            _ => Vec::new(),
        };
        infos.push(TxnInfo {
            id: txn.id().to_owned(),
            state: journal::replay(&records)?,
            unfinished: journal::is_unfinished(&records),
            started: first.at,
            modules,
            changes: records
                .iter()
                .filter(|r| matches!(r.event, Event::Backup { .. }))
                .count(),
        });
    }
    Ok(infos)
}

fn diff(sys: Sys, resource: &Resource) -> Result<Option<crate::resource::Change>, EngineError> {
    resource.diff(sys).map_err(|source| EngineError::Resource {
        id: resource.id(),
        source,
    })
}

fn incomplete(id: &str, dir: &Path, left: Option<Vec<ByHand>>, source: EngineError) -> EngineError {
    EngineError::RollbackIncomplete {
        txn: id.to_owned(),
        dir: dir.display().to_string(),
        left,
        source: Box::new(source),
    }
}

/// Whether `backup` is a sysctl read in a boot other than `boot`; false
/// when either boot ID is unknown.
fn earlier_boot(backup: &Backup, boot: Option<&str>) -> bool {
    matches!(
        (backup, boot),
        (Backup::Sysctl { boot_id: Some(then), .. }, Some(now)) if then != now
    )
}

/// The safety check: whether the resource is as apply left it or as it was
/// before. Both are allowed because a crash may have come just before or
/// after apply. Mode and owner are not compared; restore sets them.
fn unchanged(sys: Sys, dir: &Path, backup: &Backup) -> Result<bool, EngineError> {
    match backup {
        Backup::File { path, n, original } => {
            let current = match sys.fs.metadata(path) {
                Ok(meta) if meta.kind == FileKind::File => Some(sys.fs.read(path)?),
                Ok(_) => return Ok(false),
                Err(SysError::NotFound(_)) => None,
                Err(e) => return Err(e.into()),
            };
            let Some(current) = current else {
                return Ok(original.is_none());
            };
            if current == sys.fs.read(&after_path(dir, *n))? {
                return Ok(true);
            }
            Ok(original.is_some() && current == sys.fs.read(&before_path(dir, *n))?)
        }
        Backup::Sysctl {
            key,
            value,
            applied,
            ..
        } => {
            // `diff` is `None` when the running value matches.
            for candidate in [applied, value] {
                let resource = Resource::Sysctl(Sysctl {
                    key: key.clone(),
                    value: candidate.clone(),
                });
                if diff(sys, &resource)?.is_none() {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        // Restoring a package does nothing.
        Backup::Package { .. } => Ok(true),
    }
}

/// How to restore `backup` by hand; `None` for a package, which rollback
/// leaves as it is.
fn by_hand(dir: &Path, resource: &str, backup: &Backup) -> Option<ByHand> {
    let step = match backup {
        Backup::File {
            path,
            n,
            original: Some(copy),
        } => format!(
            "copy {} to {} (mode {:04o}, owner {}:{})",
            before_path(dir, *n).display(),
            path.display(),
            copy.mode,
            copy.uid,
            copy.gid
        ),
        Backup::File {
            path,
            original: None,
            ..
        } => format!("remove {}", path.display()),
        Backup::Sysctl { key, value, .. } => format!("sysctl -w '{key}={value}'"),
        Backup::Package { .. } => return None,
    };
    Some(ByHand {
        resource: resource.to_owned(),
        step,
    })
}

/// A transaction being written. Every append is checked with
/// [`journal::transition`] first.
struct Open<'a> {
    fs: &'a dyn Fs,
    txn: Txn,
    records: Vec<Record>,
    state: Option<TxnState>,
    /// An append failed, so the file may hold a torn or a whole line that
    /// `records` lacks.
    dirty: bool,
}

impl<'a> Open<'a> {
    fn new(fs: &'a dyn Fs, txn: Txn, records: Vec<Record>) -> Result<Self, EngineError> {
        let state = if records.is_empty() {
            None
        } else {
            Some(journal::replay(&records)?)
        };
        Ok(Self {
            fs,
            txn,
            records,
            state,
            dirty: false,
        })
    }

    /// The records on disk, re-read after a failed append.
    fn records(&mut self) -> Result<&[Record], EngineError> {
        if self.dirty {
            let records = self.txn.resume(self.fs)?;
            *self = Self::new(self.fs, self.txn.clone(), records)?;
        }
        Ok(&self.records)
    }

    fn append(&mut self, event: Event) -> Result<(), EngineError> {
        self.records()?;
        let next = journal::transition(self.state, &event)?;
        let record = Record {
            at: id::now(),
            event,
        };
        if let Err(e) = self.txn.append(self.fs, &record) {
            self.dirty = true;
            return Err(e);
        }
        self.records.push(record);
        self.state = Some(next);
        Ok(())
    }
}
