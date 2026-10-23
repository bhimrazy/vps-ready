//! Apply, rollback and history.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use serde::Serialize;

use super::journal::{self, Event, Record, RollbackReason, TxnState};
use super::plan::{Plan, Step};
use super::{EngineError, StateDir, Txn, id};
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

/// A finished [`Engine::rollback`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rollback {
    /// Transaction ID.
    pub txn: String,
    /// How many changes this run restored; earlier runs may have restored others.
    pub restored: usize,
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
    /// first, and nothing happens if one differs. Then, for each resource:
    /// snapshot, `backup` line, apply, `applied` line; then every resource is
    /// verified. On a failure the changes are rolled back without the safety
    /// check of [`Engine::rollback`], since they were made under this lock a
    /// moment ago and a change that did not verify would fail it.
    ///
    /// # Errors
    ///
    /// [`EngineError::RollbackIncomplete`] if a failure was not fully rolled
    /// back. Any other error means nothing was changed: an unfinished
    /// transaction, [`EngineError::PlanChanged`], or a failure before the
    /// first `backup` line.
    pub fn apply(&self, plan: &Plan) -> Result<ApplyOutcome, EngineError> {
        self.ensure_finished()?;
        let steps: Vec<&Step> = plan.steps().collect();
        if steps.is_empty() {
            return Ok(ApplyOutcome::NothingToDo);
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

        let failure = match self.run(&mut open, &steps) {
            Err(e) => (RollbackReason::ApplyFailed, e),
            Ok(()) => match self.verify(&steps) {
                Err(failure) => failure,
                Ok(()) => match open.append(Event::State {
                    state: TxnState::Applied,
                }) {
                    Ok(()) => return Ok(ApplyOutcome::Applied { txn: id }),
                    Err(e) => (RollbackReason::ApplyFailed, e),
                },
            },
        };
        let (reason, cause) = failure;
        tracing::error!(txn = %id, "{cause}; rolling back");
        self.roll_back(&mut open, reason, false)?;
        Ok(ApplyOutcome::RolledBack {
            txn: id,
            reason,
            cause,
        })
    }

    fn run(&self, open: &mut Open, steps: &[&Step]) -> Result<(), EngineError> {
        let mut n = 0;
        for step in steps {
            n += 1;
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
            })?;
        }
        Ok(())
    }

    /// Every resource must now be in its desired state.
    fn verify(&self, steps: &[&Step]) -> Result<(), (RollbackReason, EngineError)> {
        let mut differ = Vec::new();
        for step in steps {
            match diff(self.sys, &step.resource) {
                Ok(None) => {}
                Ok(Some(_)) => differ.push(step.change.id.clone()),
                Err(e) => return Err((RollbackReason::ApplyFailed, e)),
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
    /// restored.
    ///
    /// # Errors
    ///
    /// [`EngineError::Changed`] from the safety check;
    /// [`EngineError::RollbackIncomplete`] if a restore or journal line
    /// failed (running it again continues); [`EngineError::NothingToRollBack`],
    /// [`EngineError::UnknownTxn`] or [`EngineError::AlreadyRolledBack`].
    pub fn rollback(&self, target: Target) -> Result<Rollback, EngineError> {
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
        let restored = self.roll_back(&mut open, RollbackReason::Manual, true)?;
        Ok(Rollback { txn: id, restored })
    }

    fn newest_applied(&self) -> Result<Option<Txn>, EngineError> {
        for txn in self.state.txns(self.sys.fs)?.into_iter().rev() {
            if journal::replay(&txn.read(self.sys.fs)?)? == TxnState::Applied {
                return Ok(Some(txn));
            }
        }
        Ok(None)
    }

    /// Restores every backup without a `restored` line, newest first, then
    /// writes the final state. Returns how many it restored.
    fn roll_back(
        &self,
        open: &mut Open,
        reason: RollbackReason,
        check: bool,
    ) -> Result<usize, EngineError> {
        let (id, dir) = (open.txn.id().to_owned(), open.txn.dir().to_path_buf());
        let records = open
            .records()
            .map_err(|e| incomplete(&id, &dir, Vec::new(), e))?;
        let restored: BTreeSet<&str> = records
            .iter()
            .filter_map(|r| match &r.event {
                Event::Restored { resource } => Some(resource.as_str()),
                _ => None,
            })
            .collect();
        let pending: Vec<(String, Backup)> = records
            .iter()
            .filter_map(|r| match &r.event {
                Event::Backup { resource, backup } if !restored.contains(resource.as_str()) => {
                    Some((resource.clone(), backup.clone()))
                }
                _ => None,
            })
            .collect();

        if check {
            let mut changed = Vec::new();
            for (resource, backup) in &pending {
                if !unchanged(self.sys, &dir, backup)? {
                    changed.push(by_hand(&dir, resource, backup));
                }
            }
            if !changed.is_empty() {
                return Err(EngineError::Changed { txn: id, changed });
            }
        }

        for (i, (resource, backup)) in pending.iter().enumerate().rev() {
            let result = restore(self.sys, &dir, backup)
                .map_err(|source| EngineError::Resource {
                    id: resource.clone(),
                    source,
                })
                .and_then(|()| {
                    open.append(Event::Restored {
                        resource: resource.clone(),
                    })
                });
            if let Err(e) = result {
                let left = pending[..=i]
                    .iter()
                    .map(|(r, b)| by_hand(&dir, r, b))
                    .collect();
                return Err(incomplete(&id, &dir, left, e));
            }
        }
        open.append(Event::State {
            state: TxnState::RolledBack { reason },
        })
        .map_err(|e| incomplete(&id, &dir, Vec::new(), e))?;
        Ok(pending.len())
    }
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

fn incomplete(id: &str, dir: &Path, left: Vec<ByHand>, source: EngineError) -> EngineError {
    EngineError::RollbackIncomplete {
        txn: id.to_owned(),
        dir: dir.display().to_string(),
        left,
        source: Box::new(source),
    }
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
        } => {
            // `diff` is `None` when the running value matches.
            for value in [applied, value] {
                let resource = Resource::Sysctl(Sysctl {
                    key: key.clone(),
                    value: value.clone(),
                });
                if diff(sys, &resource)?.is_none() {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

fn by_hand(dir: &Path, resource: &str, backup: &Backup) -> ByHand {
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
    };
    ByHand {
        resource: resource.to_owned(),
        step,
    }
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
