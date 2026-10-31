//! Apply, rollback, the dead-man rollbacks and history.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use super::deadman::{self, Deadman, unit_name};
use super::journal::{self, Deadline, Event, Record, RollbackReason, TxnState};
use super::plan::{Plan, Step};
use super::reload::{self, Reload, SYSTEMCTL_TIMEOUT};
use super::{EngineError, StateDir, Txn, id};
use crate::resource::sysctl::boot_id;
use crate::resource::{
    Backup, Resource, ResourceError, Sysctl, after_path, authorized_keys, before_path, directory,
    during_path, restore, service, user,
};
use crate::sys::{Cmd, FileKind, FileOwner, Fs, FsLock, Sys, SysError};

/// The engine with the lock held: apply and rollback run through it.
pub struct Engine<'a> {
    pub(super) state: &'a StateDir,
    pub(super) sys: Sys<'a>,
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
    /// Every change was applied and verified, and the dead-man timer rolls
    /// them back at `deadline` unless they are confirmed.
    Pending {
        /// Transaction ID.
        txn: String,
        /// When the timer fires.
        deadline: Deadline,
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
    /// The unfinished one if there is one, then the pending one, otherwise
    /// the newest applied or confirmed one.
    Last,
    /// The one with this ID.
    Txn(&'a str),
}

/// What [`Engine::apply`] or a rollback is about to do or has done, for the
/// caller to show.
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
    /// The dead-man timer is armed: it rolls back at `deadline` if apply
    /// does not finish.
    Armed {
        /// When it fires.
        deadline: Deadline,
    },
    /// A reload is about to run, check first.
    Reload(Reload),
    /// Every change was applied and verified.
    Verified,
    /// Waiting for a confirm; `left` until the timer fires.
    Waiting {
        /// Time left.
        left: Duration,
    },
    /// A backup is about to be restored.
    Restore(&'a Backup),
    /// A sysctl backed up in an earlier boot is left as it is.
    Leave(&'a Backup),
    /// A dead-man rollback kept the bytes a changed file had before it
    /// restores it anyway.
    During {
        /// The file.
        path: &'a Path,
        /// Where its bytes are kept.
        copy: &'a Path,
    },
    /// A dead-man rollback left a resource that changed since apply.
    Skip(&'a ByHand),
    /// A rollback did not run a reload because its check failed.
    ReloadSkipped {
        /// The reload.
        reload: Reload,
        /// The check's failure.
        reason: &'a str,
    },
}

/// A finished rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rollback {
    /// Transaction ID.
    pub txn: String,
    /// How many changes this run restored; earlier runs may have restored others.
    pub restored: usize,
    /// Keys of the sysctls this run left as they are, because they were
    /// backed up in an earlier boot.
    pub at_next_boot: Vec<String>,
    /// What a dead-man rollback left because it changed since apply.
    pub skipped: Vec<ByHand>,
    /// Where a dead-man rollback kept the bytes of changed files it
    /// restored anyway.
    pub during: Vec<PathBuf>,
}

/// How [`Engine::deadman`] ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeadmanOutcome {
    /// The transaction was not pending or unfinished; nothing was done.
    Finished(TxnState),
    /// The deadline was moved since this timer was armed; a new timer fires
    /// at it.
    Rearmed(Deadline),
    /// The transaction was rolled back.
    RolledBack(Rollback),
}

/// A resource to put back by hand, and how.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    /// What a dead-man rollback left, with the steps to restore it by hand.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<ByHand>,
    /// For one pending a confirm: seconds until its timer rolls it back, 0
    /// once its deadline or boot passed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverts_in: Option<u64>,
}

/// How a rollback treats resources that changed since apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// After a failed apply, under the same lock: no check.
    Apply,
    /// `rollback`: if one changed, nothing is restored.
    Manual,
    /// The dead-man paths: forced resources are restored anyway, others
    /// skipped; restores go first and the journal is best effort.
    Deadman,
    /// The boot hook: as `Deadman`, but before sshd starts, so without
    /// `sshd-reload`.
    Boot,
}

impl Mode {
    /// Whether a failed journal line or restore lets the others go on.
    fn best_effort(self) -> bool {
        matches!(self, Self::Deadman | Self::Boot)
    }
}

/// The longest a command of the boot hook may run, which has 120 s in all
/// before systemd gives up on it and starts sshd anyway.
const BOOT_TIMEOUT: Duration = Duration::from_secs(20);

/// How many times a timer rollback that did not complete is tried again.
const RETRIES: u32 = 5;

/// How long after a timer rollback that did not complete it is tried again.
const RETRY_AFTER: Duration = Duration::from_secs(60);

/// How often [`Engine::lock_wait`] tries the lock.
const LOCK_POLL: Duration = Duration::from_millis(250);

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

    /// Takes the lock of `state`, waiting as long as it takes: for the
    /// dead-man rollbacks, where giving up would leave a lockout in place.
    /// Whoever holds it releases it within its own command timeouts or by
    /// dying.
    ///
    /// # Errors
    ///
    /// [`EngineError::Sys`].
    pub fn lock_wait(state: &'a StateDir, sys: Sys<'a>) -> Result<Self, EngineError> {
        let mut logged = false;
        loop {
            match Self::lock(state, sys) {
                Err(EngineError::Busy) => {
                    if !logged {
                        tracing::warn!("waiting for another vps-ready to finish");
                        logged = true;
                    }
                    std::thread::sleep(LOCK_POLL);
                }
                other => return other,
            }
        }
    }

    /// Takes the lock of `state`, waiting at most `max`: for `confirm`,
    /// whose lock a dead-man rollback may hold for a moment.
    ///
    /// # Errors
    ///
    /// [`EngineError::Busy`] once `max` passed, or [`EngineError::Sys`].
    pub fn lock_timeout(
        state: &'a StateDir,
        sys: Sys<'a>,
        max: Duration,
    ) -> Result<Self, EngineError> {
        let start = std::time::Instant::now();
        loop {
            match Self::lock(state, sys) {
                Err(EngineError::Busy) if start.elapsed() < max => std::thread::sleep(LOCK_POLL),
                other => return other,
            }
        }
    }

    /// Fails if any transaction is unfinished or pending a confirm.
    /// [`Engine::apply`] checks this too; call it before planning to fail
    /// early.
    ///
    /// # Errors
    ///
    /// [`EngineError::Unfinished`], [`EngineError::Pending`], or an error
    /// reading the journals.
    pub fn ensure_finished(&self) -> Result<(), EngineError> {
        if let Some(txn) = self.state.unfinished(self.sys.fs)?.pop() {
            return Err(EngineError::Unfinished(txn.id().to_owned()));
        }
        match self.pending()? {
            Some(txn) => Err(EngineError::Pending(txn.id().to_owned())),
            None => Ok(()),
        }
    }

    /// Applies `plan`, the plan shown to the user. Each change is re-diffed
    /// first, and nothing happens if one differs. Resources that had no
    /// change are not re-diffed: if they drifted since, the next plan shows
    /// it. If a module needs the dead-man switch, the binary is checked
    /// before anything else, and the boot hook and a timer that rolls the
    /// transaction back are set up before the first `backup` line. Then, for
    /// each resource: snapshot, `backup` line, apply, `applied` line; after
    /// a module's resources, each of its reloads: check, `reloaded` line,
    /// reload. Then every resource is verified, and each module with a
    /// change runs its own verify. With the dead-man switch, the timer is
    /// then re-armed to `deadman.window` from now and the transaction is
    /// pending a confirm. On a failure the changes are rolled back without
    /// the safety check of [`Engine::rollback`], since they were made under
    /// this lock a moment ago, and the timer is stopped once that rollback
    /// finished. Each step and restore is reported to `progress` before it
    /// runs, and a passed verify after it.
    ///
    /// # Errors
    ///
    /// [`EngineError::RollbackIncomplete`] if a failure was not fully rolled
    /// back; the timer is then left to finish it. Any other error means
    /// nothing was changed: an unfinished or pending transaction,
    /// [`EngineError::DuplicateResource`], [`EngineError::PlanChanged`],
    /// [`EngineError::UnsafeBinary`], or a failure before the first `backup`
    /// line.
    pub fn apply(
        &self,
        plan: &Plan,
        deadman: &Deadman,
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
        let armed = plan.needs_deadman();
        if armed {
            deadman::check_binary(self.sys.fs, &deadman.binary).map_err(|reason| {
                EngineError::UnsafeBinary {
                    path: deadman.binary.display().to_string(),
                    reason,
                }
            })?;
            // The deadlines need both.
            deadman::boottime(self.sys.fs)?;
            current_boot(self.sys.fs)?;
        }

        let txn = self.state.create_txn(self.sys.fs, id::now())?;
        let id = txn.id().to_owned();
        let mut open = Open::new(self.sys.fs, txn, Vec::new())?;
        open.append(Event::Begin {
            version: crate::VERSION_INFO.version.to_owned(),
            modules: plan.changed_modules(),
        })?;

        let mut timer = None;
        let (reason, cause) = match self.apply_txn(
            &mut open,
            plan,
            steps.len(),
            armed,
            deadman,
            &mut timer,
            progress,
        ) {
            Ok(outcome) => return Ok(outcome),
            Err(failure) => failure,
        };
        tracing::error!(txn = %id, "{cause}; rolling back");
        self.roll_back(&mut open, reason, Mode::Apply, progress)?;
        if armed {
            self.disarm(timer.as_deref(), true);
        }
        Ok(ApplyOutcome::RolledBack {
            txn: id,
            reason,
            cause,
        })
    }

    /// Arms, applies, verifies and finishes the transaction; `timer` is the
    /// unit armed last.
    #[allow(clippy::too_many_arguments)]
    fn apply_txn(
        &self,
        open: &mut Open,
        plan: &Plan,
        total: usize,
        armed: bool,
        deadman: &Deadman,
        timer: &mut Option<String>,
        progress: &mut dyn FnMut(Progress),
    ) -> Result<ApplyOutcome, (RollbackReason, EngineError)> {
        let failed = |e| (RollbackReason::ApplyFailed, e);
        let txn = open.txn.id().to_owned();
        if armed {
            let deadline = self.arm_first(open, plan, deadman, timer).map_err(failed)?;
            progress(Progress::Armed { deadline });
        }
        self.run(open, plan, total, progress).map_err(failed)?;
        self.verify(plan)?;
        progress(Progress::Verified);
        if !armed {
            open.append(Event::state(TxnState::Applied))
                .map_err(failed)?;
            return Ok(ApplyOutcome::Applied { txn });
        }
        let deadline = self.go_live(open, plan, deadman, timer).map_err(failed)?;
        Ok(ApplyOutcome::Pending { txn, deadline })
    }

    /// Installs and enables the boot hook, then starts the first timer, with
    /// a deadline that leaves apply all of its command timeouts.
    fn arm_first(
        &self,
        open: &mut Open,
        plan: &Plan,
        deadman: &Deadman,
        timer: &mut Option<String>,
    ) -> Result<Deadline, EngineError> {
        let boot_id = current_boot(self.sys.fs)?;
        deadman::install_hook(self.sys, &deadman.binary).map_err(EngineError::Deadman)?;
        let after = first_window(plan, deadman.window);
        let (now, wall) = (deadman::boottime(self.sys.fs)?, id::now());
        let txn = open.txn.id().to_owned();
        let unit = unit_name(&txn, 1);
        deadman::arm(self.sys, &unit, after, &deadman.binary, &txn)
            .map_err(EngineError::Deadman)?;
        *timer = Some(unit.clone());
        let deadline = Deadline {
            boottime: now + after.as_secs(),
            wall: wall + after.as_secs(),
        };
        open.append(Event::Armed {
            unit,
            boot_id,
            deadline,
        })?;
        Ok(deadline)
    }

    /// Re-arms the timer to the window from now and journals the pending
    /// state, with the moment the changes went live and the session.
    fn go_live(
        &self,
        open: &mut Open,
        plan: &Plan,
        deadman: &Deadman,
        timer: &mut Option<String>,
    ) -> Result<Deadline, EngineError> {
        let (live_since, wall) = (deadman::boottime(self.sys.fs)?, id::now());
        let txn = open.txn.id().to_owned();
        let n = deadman::last_unit(open.records()?).map_or(0, |(_, n)| n) + 1;
        let unit = unit_name(&txn, n);
        // Arm first: if that fails, the old timer still covers the rollback.
        deadman::arm(self.sys, &unit, deadman.window, &deadman.binary, &txn)
            .map_err(EngineError::Deadman)?;
        // With its service: its rollback may be waiting for this lock.
        if let Some(old) = timer.replace(unit.clone())
            && let Err(e) = deadman::stop(self.sys, &old, true)
        {
            tracing::info!("stopping the dead-man timer {old}: {e}");
        }
        let deadline = Deadline {
            boottime: live_since + deadman.window.as_secs(),
            wall: wall + deadman.window.as_secs(),
        };
        open.append(Event::State {
            state: TxnState::PendingConfirm {
                deadline,
                live_since,
                session: plan.facts.session.as_ref().map(|s| s.id),
            },
            unit: Some(unit),
            admins: plan.admins(),
            ssh_port: plan.facts.session.as_ref().map(|s| s.server.port()),
        })?;
        Ok(deadline)
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
                self.apply_step(open, n, step, module.force_restore())?;
            }
            for &reload in module.reloads() {
                progress(Progress::Reload(reload));
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
    fn apply_step(
        &self,
        open: &mut Open,
        n: u32,
        step: &Step,
        force_restore: bool,
    ) -> Result<(), EngineError> {
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
            force_restore,
        })?;
        let applied = step
            .resource
            .apply(self.sys)
            .map_err(|source| EngineError::Resource {
                id: id.clone(),
                source,
            })?;
        open.append(Event::Applied {
            resource: id.clone(),
            uid: applied.uid,
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
    /// module. Each restore is reported to `progress` before it runs. For an
    /// armed transaction, the timer is stopped and the boot hook disabled
    /// once the rollback finished; one whose deadline or boot passed keeps
    /// that as its reason.
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
        self.rollback_by(target, &[], progress)
    }

    /// [`Engine::rollback`], run by the users in `own` (the login and the
    /// one who ran sudo): it refuses to remove an account that is one of
    /// them, since `userdel` fails while that user has processes, and its
    /// by-hand step ends their session.
    ///
    /// # Errors
    ///
    /// [`EngineError::OwnAccount`], or those of [`Engine::rollback`].
    pub fn rollback_by(
        &self,
        target: Target,
        own: &[String],
        progress: &mut dyn FnMut(Progress),
    ) -> Result<Rollback, EngineError> {
        let fs = self.sys.fs;
        let txn = match target {
            Target::Last => match self.state.unfinished(fs)?.pop() {
                Some(txn) => txn,
                None => self.newest_done()?.ok_or(EngineError::NothingToRollBack)?,
            },
            Target::Txn(id) => self.find(id)?,
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
        if let Some(user) = created_users(&records).find(|u| own.iter().any(|o| o == u)) {
            return Err(EngineError::OwnAccount {
                txn: txn.id().to_owned(),
                user: user.to_owned(),
            });
        }
        // The dead-man paths need no such check: they roll back only a
        // pending or unfinished transaction, and apply refuses to start
        // while one exists, so it is always the newest.
        if let Some(user) = created_users(&records).next()
            && let Some(later) = self.later_in_place(txn.id())?
        {
            return Err(EngineError::LaterTxn {
                txn: txn.id().to_owned(),
                user: user.to_owned(),
                later,
            });
        }
        let switch = deadman::switch(&records);
        let unit = deadman::last_unit(&records).map(|(u, _)| u.to_owned());
        let reason = switch
            .as_ref()
            .and_then(|s| s.expired(fs))
            .unwrap_or(RollbackReason::Manual);
        let mut open = Open::new(fs, txn, records)?;
        let done = self.roll_back(&mut open, reason, Mode::Manual, progress)?;
        if switch.is_some() {
            self.disarm(unit.as_deref(), true);
        }
        Ok(done)
    }

    /// The dead-man rollback the timer of transaction `id` runs. Under the
    /// lock, the journal is read again: a transaction that is no longer
    /// pending or unfinished is left alone; one whose deadline moved gets a
    /// timer for it, armed with `binary`. Otherwise it is rolled back
    /// resource by resource: those that changed since apply are restored
    /// anyway if their module forces it (their bytes kept in
    /// `files/<n>.during` first, best effort), and skipped otherwise. The
    /// journal is best effort: a failed line does not stop a restore. Then
    /// the boot hook is disabled. A rollback that did not complete is tried
    /// again by a new timer a minute later, up to 5 times; `attempt` is this
    /// try's number, 0 for the first.
    ///
    /// # Errors
    ///
    /// [`EngineError::RollbackIncomplete`] if a restore, a reload or the
    /// final journal line failed; [`EngineError::UnknownTxn`]; an error
    /// reading the journal or re-arming.
    pub fn deadman(
        &self,
        id: &str,
        binary: &Path,
        attempt: u32,
        progress: &mut dyn FnMut(Progress),
    ) -> Result<DeadmanOutcome, EngineError> {
        let fs = self.sys.fs;
        let mut open = Open::resume_best_effort(fs, self.find(id)?)?;
        let records = &open.records;
        if records.is_empty() {
            return Ok(DeadmanOutcome::Finished(TxnState::Planned));
        }
        let unfinished = journal::is_unfinished(records);
        let state = journal::replay(records)?;
        let expired = deadman::switch(records).and_then(|s| s.expired(fs));
        match state {
            TxnState::Applied | TxnState::Confirmed | TxnState::RolledBack { .. } => {
                return Ok(DeadmanOutcome::Finished(state));
            }
            TxnState::PendingConfirm { deadline, .. } if !unfinished && expired.is_none() => {
                return self.rearm(open, deadline, binary);
            }
            TxnState::PendingConfirm { .. } | TxnState::Planned => {}
        }
        let unit = deadman::last_unit(records).map(|(u, _)| u.to_owned());
        let reason = expired.unwrap_or(RollbackReason::DeadmanTimeout);
        let done = match self.roll_back(&mut open, reason, Mode::Deadman, progress) {
            Ok(done) => done,
            Err(e @ EngineError::RollbackIncomplete { .. }) => {
                self.retry(&mut open, attempt, binary);
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        self.disarm(unit.as_deref(), false);
        Ok(DeadmanOutcome::RolledBack(done))
    }

    /// After a timer rollback that did not complete, arms the next of at
    /// most [`RETRIES`] tries, [`RETRY_AFTER`] from now, and journals it
    /// best effort. The boot hook stays enabled either way.
    fn retry(&self, open: &mut Open, attempt: u32, binary: &Path) {
        if attempt >= RETRIES {
            tracing::error!(
                "giving up after {RETRIES} retries; the boot hook tries again at the next boot"
            );
            return;
        }
        let txn = open.txn.id().to_owned();
        match deadman::arm_retry(self.sys, attempt + 1, RETRY_AFTER, binary, &txn) {
            Ok(unit) => {
                tracing::warn!(
                    "trying the rollback again in {}s ({unit})",
                    RETRY_AFTER.as_secs()
                );
                let line = Event::Retry {
                    unit,
                    attempt: attempt + 1,
                };
                // Best effort: the error is logged inside.
                let _ = note(open, line, true);
            }
            Err(e) => tracing::error!("arming a retry of the rollback: {e}"),
        }
    }

    /// Arms a new timer for the pending `deadline`, then stops the timer
    /// the journal named.
    fn rearm(
        &self,
        mut open: Open,
        deadline: Deadline,
        binary: &Path,
    ) -> Result<DeadmanOutcome, EngineError> {
        let fs = self.sys.fs;
        deadman::check_binary(fs, binary).map_err(|reason| EngineError::UnsafeBinary {
            path: binary.display().to_string(),
            reason,
        })?;
        let left = deadline.boottime.saturating_sub(deadman::boottime(fs)?);
        let (old, n) =
            deadman::last_unit(&open.records).map_or((None, 0), |(u, n)| (Some(u.to_owned()), n));
        let txn = open.txn.id().to_owned();
        let unit = unit_name(&txn, n + 1);
        deadman::arm(self.sys, &unit, Duration::from_secs(left), binary, &txn)
            .map_err(EngineError::Deadman)?;
        open.append(Event::Extended { unit, deadline })?;
        if let Some(old) = old
            && let Err(e) = deadman::stop(self.sys, &old, false)
        {
            tracing::info!("stopping the dead-man timer {old}: {e}");
        }
        Ok(DeadmanOutcome::Rearmed(deadline))
    }

    /// The dead-man rollback the boot hook runs: every transaction that is
    /// pending, or unfinished with an `armed` record, from a boot other than
    /// this one, as [`Engine::deadman`] does with reason `deadman-reboot`.
    /// A boot ID that cannot be read counts as another boot. A journal that
    /// cannot be read does not stop the others. A rollback that did not
    /// complete is tried again by timers that run `binary`, as after the
    /// timer's rollback. Disables the hook once none is left. Every command
    /// it runs has 20 s at most.
    ///
    /// # Errors
    ///
    /// The first error, after every transaction was tried.
    pub fn deadman_boot(
        &self,
        binary: &Path,
        progress: &mut dyn FnMut(Progress),
    ) -> Result<Vec<Rollback>, EngineError> {
        let capped = deadman::Capped {
            inner: self.sys.runner,
            max: BOOT_TIMEOUT,
        };
        // Under the lock `self` holds for as long as this runs.
        let engine = Engine {
            state: self.state,
            sys: Sys {
                fs: self.sys.fs,
                runner: &capped,
            },
            _lock: FsLock::new(()),
        };
        engine.boot_rollbacks(binary, progress)
    }

    /// [`Engine::deadman_boot`], with the commands already capped.
    fn boot_rollbacks(
        &self,
        binary: &Path,
        progress: &mut dyn FnMut(Progress),
    ) -> Result<Vec<Rollback>, EngineError> {
        let fs = self.sys.fs;
        let boot = boot_id(fs);
        let mut done = Vec::new();
        let mut first_err = None;
        let mut left = false;
        for txn in self.state.txns(fs)? {
            let result = (|| {
                let records = txn.read(fs)?;
                let unfinished = journal::is_unfinished(&records);
                let state = journal::replay(&records)?;
                let Some(switch) = deadman::switch(&records) else {
                    return Ok(None);
                };
                let due = matches!(state, TxnState::PendingConfirm { .. })
                    || (state == TxnState::Planned && unfinished);
                if !due {
                    return Ok(None);
                }
                if boot.as_deref() == Some(switch.boot_id.as_str()) {
                    // This boot's timer covers it.
                    left = true;
                    return Ok(None);
                }
                let mut open = Open::resume_best_effort(fs, txn.clone())?;
                let reason = RollbackReason::DeadmanReboot;
                let done = self.roll_back(&mut open, reason, Mode::Boot, progress);
                if let Err(EngineError::RollbackIncomplete { .. }) = done {
                    self.retry(&mut open, 0, binary);
                }
                done.map(Some)
            })();
            match result {
                Ok(Some(rollback)) => done.push(rollback),
                Ok(None) => {}
                Err(e) => {
                    tracing::error!(txn = %txn.id(), "{e}");
                    left = true;
                    first_err.get_or_insert(e);
                }
            }
        }
        if !left {
            self.disarm(None, false);
        }
        first_err.map_or(Ok(done), Err)
    }

    /// The transaction with ID `id`.
    pub(super) fn find(&self, id: &str) -> Result<Txn, EngineError> {
        self.state
            .txns(self.sys.fs)?
            .into_iter()
            .find(|t| t.id() == id)
            .ok_or_else(|| EngineError::UnknownTxn(id.to_owned()))
    }

    /// The transaction pending a confirm, if any.
    fn pending(&self) -> Result<Option<Txn>, EngineError> {
        for txn in self.state.txns(self.sys.fs)?.into_iter().rev() {
            if let TxnState::PendingConfirm { .. } = journal::replay(&txn.read(self.sys.fs)?)? {
                return Ok(Some(txn));
            }
        }
        Ok(None)
    }

    /// The newest transaction after `id` that is applied, confirmed or
    /// pending a confirm, if any.
    fn later_in_place(&self, id: &str) -> Result<Option<String>, EngineError> {
        for txn in self.state.txns(self.sys.fs)?.into_iter().rev() {
            // `txns` is in ID order, oldest first.
            if txn.id() == id {
                break;
            }
            if let TxnState::Applied | TxnState::Confirmed | TxnState::PendingConfirm { .. } =
                journal::replay(&txn.read(self.sys.fs)?)?
            {
                return Ok(Some(txn.id().to_owned()));
            }
        }
        Ok(None)
    }

    /// The pending transaction, else the newest applied or confirmed one.
    fn newest_done(&self) -> Result<Option<Txn>, EngineError> {
        if let Some(txn) = self.pending()? {
            return Ok(Some(txn));
        }
        for txn in self.state.txns(self.sys.fs)?.into_iter().rev() {
            if let TxnState::Applied | TxnState::Confirmed =
                journal::replay(&txn.read(self.sys.fs)?)?
            {
                return Ok(Some(txn));
            }
        }
        Ok(None)
    }

    /// Stops the timer `unit`, with its service if `service`, and disables
    /// the boot hook, best effort: a timer that fires anyway finds the
    /// transaction finished, and so does the hook.
    pub(super) fn disarm(&self, unit: Option<&str>, service: bool) {
        if let Some(unit) = unit
            && let Err(e) = deadman::stop(self.sys, unit, service)
        {
            tracing::info!("stopping the dead-man timer {unit}: {e}");
        }
        if let Err(e) = deadman::disable_hook(self.sys) {
            tracing::warn!("disabling the dead-man boot hook: {e}");
        }
    }

    /// Restores every backup without a `restored` line, newest first, with
    /// the reloads apply journaled in between, then writes the final state.
    /// A `rollback` record goes first, unless an earlier run wrote one; its
    /// reason then wins over `reason`, and so does `manual` where `reason`
    /// cannot follow the state. A sysctl backed up in an earlier boot gets a
    /// `restored` line without a restore. `mode` decides what happens to
    /// resources that changed since apply.
    fn roll_back(
        &self,
        open: &mut Open,
        reason: RollbackReason,
        mode: Mode,
        progress: &mut dyn FnMut(Progress),
    ) -> Result<Rollback, EngineError> {
        let boot = boot_id(self.sys.fs);
        let boot = boot.as_deref();
        let best_effort = mode.best_effort();
        let (id, dir) = (open.txn.id().to_owned(), open.txn.dir().to_path_buf());
        let records = if best_effort {
            open.records_best_effort()
        } else {
            open.records().map_err(|e| incomplete(&id, &dir, None, e))?
        };
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
        // A rollback's lines start with `rollback`, or, where that line is
        // best effort (the dead-man paths), with `restored` or `skipped`.
        let applying = records
            .iter()
            .position(|r| {
                matches!(
                    r.event,
                    Event::Rollback { .. }
                        | Event::Restored { .. }
                        | Event::Skipped { .. }
                        | Event::ReloadSkipped { .. }
                )
            })
            .map_or(records, |i| &records[..i]);
        // A module's reloads follow its backups: a backup between two
        // reloads starts another module's group.
        let mut group = 0;
        let undo: Vec<Undo> = applying
            .iter()
            .filter_map(|r| match &r.event {
                Event::Backup {
                    resource,
                    backup,
                    force_restore,
                } => {
                    group += 1;
                    (!restored.contains(resource.as_str())).then(|| Undo::Restore {
                        uid: applying.iter().find_map(|r| match &r.event {
                            Event::Applied { resource: id, uid } if id == resource => *uid,
                            _ => None,
                        }),
                        resource: resource.clone(),
                        backup: backup.clone(),
                        force: *force_restore,
                    })
                }
                Event::Reloaded { reload } => Some(Undo::Reload(*reload, group)),
                _ => None,
            })
            .collect();
        let pending = || {
            undo.iter().filter_map(|u| match u {
                Undo::Restore {
                    resource,
                    backup,
                    uid,
                    ..
                } => Some((resource, backup, *uid)),
                Undo::Reload(..) => None,
            })
        };
        let left = |upto: usize| {
            Some(
                undo[..upto]
                    .iter()
                    .filter_map(|u| match u {
                        Undo::Restore {
                            resource, backup, ..
                        } if !earlier_boot(backup, boot) => by_hand(&dir, resource, backup),
                        _ => None,
                    })
                    .collect(),
            )
        };

        if mode == Mode::Manual {
            let mut changed = Vec::new();
            for (resource, backup, uid) in pending() {
                if earlier_boot(backup, boot) || unchanged(self.sys, &dir, resource, backup, uid)? {
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
                let armed = deadman::switch(&open.records).is_some()
                    && matches!(
                        open.state,
                        Some(TxnState::Planned | TxnState::PendingConfirm { .. })
                    );
                return Err(EngineError::Changed {
                    txn: id,
                    changed,
                    armed,
                });
            }
        }

        let reason = match started {
            Some(reason) => reason,
            None => {
                // E.g. a failed `state applied` append may have landed.
                let reason = if journal::can_roll_back(open.state, reason) {
                    reason
                } else {
                    RollbackReason::Manual
                };
                note(open, Event::Rollback { reason }, best_effort)
                    .map_err(|e| incomplete(&id, &dir, left(undo.len()), e))?;
                reason
            }
        };
        let mut done = Rollback {
            txn: id.clone(),
            restored: 0,
            at_next_boot: Vec::new(),
            skipped: Vec::new(),
            during: Vec::new(),
        };
        // The reloads a module journaled run once the restores journaled
        // before them, back to the previous module's reloads, are done:
        // those of their module, perhaps with those of a module without
        // reloads. Consecutive reloads (e.g. `daemon-reload` then the
        // firewall's) are one group and run in journal order. A failed
        // reload does not stop the restores of earlier modules, which may be
        // the ones that matter (e.g. an sshd drop-in before a firewall); the
        // rollback then ends incomplete, without a final state. In the
        // dead-man paths a failed restore does not stop the others either,
        // but after a failed forced one the unforced ones wait; elsewhere it
        // ends the rollback, but only after the reloads due by then ran, so
        // a daemon does not keep a config whose files are already restored.
        let mut due: Vec<Reload> = Vec::new();
        let mut failed = Vec::new();
        let mut unrestored: Vec<(ByHand, EngineError)> = Vec::new();
        // Unforced restores held back after a forced one failed.
        let mut held: Vec<ByHand> = Vec::new();
        let mut forced_failed = false;
        let mut run = || -> Result<(), EngineError> {
            // The group of the reloads in `due`.
            let mut due_group = None;
            for (i, item) in undo.iter().enumerate().rev() {
                let (resource, backup, force, uid) = match item {
                    Undo::Reload(reload, group) => {
                        if due_group.replace(*group).is_some_and(|g| g != *group) {
                            self.flush(open, &mut due, mode, &mut failed, progress)
                                .map_err(|e| incomplete(&id, &dir, left(i), e))?;
                        }
                        due.insert(0, *reload);
                        continue;
                    }
                    Undo::Restore {
                        resource,
                        backup,
                        force,
                        uid,
                    } => (resource, backup, *force, *uid),
                };
                if let Backup::Sysctl { key, .. } = backup
                    && earlier_boot(backup, boot)
                {
                    progress(Progress::Leave(backup));
                    done.at_next_boot.push(key.clone());
                    let line = Event::Restored {
                        resource: resource.clone(),
                    };
                    note(open, line, best_effort)
                        .map_err(|e| incomplete(&id, &dir, left(i + 1), e))?;
                    continue;
                }
                // A lock-down still in place needs the way in that apply set
                // up before it, such as the admin `ssh.server` relies on, so
                // the unforced restores wait for a rerun.
                if forced_failed && !force {
                    held.extend(by_hand(&dir, resource, backup).map(|mut step| {
                        step.step = format!("only after the steps above succeed, {}", step.step);
                        step
                    }));
                    continue;
                }
                if best_effort {
                    let same =
                        unchanged(self.sys, &dir, resource, backup, uid).unwrap_or_else(|e| {
                            tracing::warn!("{resource}: {e}; treating it as changed");
                            false
                        });
                    if !same && !force {
                        if let Some(step) = by_hand(&dir, resource, backup) {
                            progress(Progress::Skip(&step));
                            let line = Event::Skipped {
                                resource: resource.clone(),
                                by_hand: step.step.clone(),
                            };
                            note(open, line, true)?;
                            done.skipped.push(step);
                        }
                        continue;
                    }
                    if !same
                        && let Backup::File { path, n, .. } = backup
                        && let Some(copy) = keep_during(self.sys, &dir, path, *n)
                    {
                        progress(Progress::During { path, copy: &copy });
                        done.during.push(copy);
                    }
                }
                progress(Progress::Restore(backup));
                let result =
                    restore(self.sys, &dir, backup).map_err(|source| EngineError::Resource {
                        id: resource.clone(),
                        source,
                    });
                match result {
                    Ok(()) => done.restored += 1,
                    Err(e) if best_effort => {
                        tracing::error!("{e}; restoring the others");
                        forced_failed |= force;
                        let step = by_hand(&dir, resource, backup).unwrap_or_else(|| ByHand {
                            resource: resource.clone(),
                            step: "see the journal".into(),
                        });
                        unrestored.push((step, e));
                        continue;
                    }
                    Err(e) => return Err(incomplete(&id, &dir, left(i + 1), e)),
                }
                let line = Event::Restored {
                    resource: resource.clone(),
                };
                note(open, line, best_effort).map_err(|e| incomplete(&id, &dir, left(i + 1), e))?;
            }
            Ok(())
        };
        let ran = run();
        let flushed = self.flush(open, &mut due, mode, &mut failed, progress);
        ran?;
        flushed.map_err(|e| incomplete(&id, &dir, left(0), e))?;
        if !unrestored.is_empty() || !failed.is_empty() {
            let mut left: Vec<ByHand> = unrestored.iter().map(|(step, _)| step.clone()).collect();
            left.append(&mut held);
            left.extend(failed.iter().map(|(reload, _)| ByHand {
                resource: reload.name().to_owned(),
                step: reload::line(&reload.command()),
            }));
            let source = match unrestored.into_iter().next() {
                Some((_, e)) => e,
                None => {
                    let (reload, reason) = failed.swap_remove(0);
                    EngineError::Reload { reload, reason }
                }
            };
            return Err(incomplete(&id, &dir, Some(left), source));
        }
        open.append(Event::state(TxnState::RolledBack { reason }))
            .map_err(|e| incomplete(&id, &dir, left(0), e))?;
        Ok(done)
    }

    /// Replays the reloads in `due`, in order, and empties it. A failed
    /// journal line does not stop the others; the first is returned.
    fn flush(
        &self,
        open: &mut Open,
        due: &mut Vec<Reload>,
        mode: Mode,
        failed: &mut Vec<(Reload, String)>,
        progress: &mut dyn FnMut(Progress),
    ) -> Result<(), EngineError> {
        let mut first = Ok(());
        for reload in due.drain(..) {
            if let Err(e) = self.replay(open, reload, mode, failed, progress) {
                tracing::error!("{e}");
                if first.is_ok() {
                    first = Err(e);
                }
            }
        }
        first
    }

    /// Runs a reload that apply journaled, check first. A failed check skips
    /// it, so a running daemon keeps its config instead of loading a broken
    /// one (e.g. an `sshd_config` edited since apply); that gets a
    /// `reload-skipped` line. A resumed rollback runs every such reload
    /// again; that is harmless. A failed reload is added to `failed`; only a
    /// failed journal line outside the dead-man paths is an error.
    fn replay(
        &self,
        open: &mut Open,
        reload: Reload,
        mode: Mode,
        failed: &mut Vec<(Reload, String)>,
        progress: &mut dyn FnMut(Progress),
    ) -> Result<(), EngineError> {
        let best_effort = mode.best_effort();
        // The hook runs before sshd starts, which then reads the restored
        // config; `sshd -t` fails there on Ubuntu (no /run/sshd yet).
        if mode == Mode::Boot && reload == Reload::SshdReload {
            return Ok(());
        }
        progress(Progress::Reload(reload));
        if let Some(check) = reload.check()
            && let Err(reason) = reload::run(self.sys, &check)
        {
            tracing::warn!("not running {reload}, so the daemon keeps its config: {reason}");
            progress(Progress::ReloadSkipped {
                reload,
                reason: &reason,
            });
            return note(open, Event::ReloadSkipped { reload, reason }, best_effort);
        }
        if let Err(reason) = reload::run(self.sys, &reload.command()) {
            failed.push((reload, reason));
            return Ok(());
        }
        note(open, Event::Reloaded { reload }, best_effort)
    }
}

/// The accounts `records` created and no rollback removed yet.
fn created_users(records: &[Record]) -> impl Iterator<Item = &str> {
    records.iter().filter_map(move |r| match &r.event {
        Event::Backup {
            resource,
            backup:
                Backup::User {
                    name,
                    created: true,
                    ..
                },
            ..
        } if !records.iter().any(
            |r| matches!(&r.event, Event::Restored { resource: done } if done == resource),
        ) =>
        {
            Some(name.as_str())
        }
        _ => None,
    })
}

/// Appends `event`; with `best_effort`, a failure is only logged (to
/// stderr, the unit's log), so the restores go on.
fn note(open: &mut Open, event: Event, best_effort: bool) -> Result<(), EngineError> {
    match open.append(event) {
        Err(e) if best_effort => {
            tracing::error!("journal: {e}; going on");
            Ok(())
        }
        other => other,
    }
}

/// Copies the current bytes of file `n` at `path` to `files/<n>.during`,
/// best effort: a failure (a full disk) is logged and the restore goes on.
fn keep_during(sys: Sys, dir: &Path, path: &Path, n: u32) -> Option<PathBuf> {
    let meta = match sys.fs.metadata(path) {
        Ok(meta) if meta.kind == FileKind::File => meta,
        // Nothing to keep: gone, or not a file.
        _ => return None,
    };
    let copy = during_path(dir, n);
    let owner = FileOwner {
        mode: 0o600,
        ..meta.owner()
    };
    match sys
        .fs
        .read(path)
        .and_then(|bytes| sys.fs.write_atomic(&copy, &bytes, owner))
    {
        Ok(()) => Some(copy),
        Err(e) => {
            tracing::error!(
                "keeping {} as {}: {e}; restoring it anyway",
                path.display(),
                copy.display()
            );
            None
        }
    }
}

/// The current boot ID, which arming needs.
fn current_boot(fs: &dyn Fs) -> Result<String, EngineError> {
    boot_id(fs).ok_or_else(|| EngineError::Deadman("the boot ID cannot be read".into()))
}

/// The first deadline after arming: `window` plus every command timeout of
/// the plan after arming, so the timer cannot fire while apply is within its
/// own limits: each step's snapshot and apply, and its diff again in verify;
/// each changed module's reloads and its own verify.
fn first_window(plan: &Plan, window: Duration) -> Duration {
    let steps: Duration = plan
        .steps()
        .map(|s| s.resource.timeout() + s.resource.diff_timeout())
        .sum();
    let modules: Duration = plan
        .modules
        .iter()
        .filter(|m| !m.changes().is_empty())
        .map(|m| m.reloads().iter().map(|r| r.timeout()).sum::<Duration>() + m.verify_timeout())
        .sum();
    // Stopping the first timer and starting the next.
    window + steps + modules + SYSTEMCTL_TIMEOUT + Cmd::DEFAULT_TIMEOUT
}

/// What a rollback undoes, in journal order.
enum Undo {
    /// A backup without a `restored` line.
    Restore {
        resource: String,
        backup: Backup,
        /// The `force_restore` of its record.
        force: bool,
        /// The uid of its `applied` record.
        uid: Option<u32>,
    },
    /// A reload that apply journaled, and its module's group: reloads with
    /// no backup between them share one.
    Reload(Reload, usize),
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
        let state = journal::replay(&records)?;
        let unfinished = journal::is_unfinished(&records);
        let reverts_in = match state {
            TxnState::PendingConfirm { deadline, .. } if !unfinished => {
                Some(super::confirm::left(fs, &records, deadline).as_secs())
            }
            _ => None,
        };
        infos.push(TxnInfo {
            id: txn.id().to_owned(),
            state,
            unfinished,
            started: first.at,
            modules,
            changes: records
                .iter()
                .filter(|r| matches!(r.event, Event::Backup { .. }))
                .count(),
            skipped: records
                .iter()
                .filter_map(|r| match &r.event {
                    Event::Skipped { resource, by_hand } => Some(ByHand {
                        resource: resource.clone(),
                        step: by_hand.clone(),
                    }),
                    _ => None,
                })
                .collect(),
            reverts_in,
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
/// after apply. Mode and owner are not compared; restore sets them. `uid`
/// is that of the resource's `applied` record.
fn unchanged(
    sys: Sys,
    dir: &Path,
    resource: &str,
    backup: &Backup,
    uid: Option<u32>,
) -> Result<bool, EngineError> {
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
        Backup::Directory { .. } => directory::unchanged(sys, backup).map_err(at(resource)),
        // Restoring a package does nothing.
        Backup::Package { .. } => Ok(true),
        Backup::Service { .. } => service::unchanged(sys, backup).map_err(at(resource)),
        Backup::User { .. } => user::unchanged(sys, backup, uid).map_err(at(resource)),
        Backup::AuthorizedKeys { .. } => {
            authorized_keys::unchanged(sys, dir, backup).map_err(at(resource))
        }
    }
}

fn at(resource: &str) -> impl FnOnce(ResourceError) -> EngineError {
    let id = resource.to_owned();
    |source| EngineError::Resource { id, source }
}

/// How to restore `backup` by hand; `None` for a package, which rollback
/// leaves as it is, and for a service or user that apply left as it was.
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
        Backup::Directory { .. } => directory::by_hand(backup)?,
        Backup::Sysctl { key, value, .. } => format!("sysctl -w '{key}={value}'"),
        Backup::Package { .. } => return None,
        Backup::Service { .. } => service::by_hand(backup)?,
        Backup::User { .. } => user::by_hand(backup)?,
        Backup::AuthorizedKeys { .. } => authorized_keys::by_hand(dir, backup)?,
    };
    Some(ByHand {
        resource: resource.to_owned(),
        step,
    })
}

/// A transaction being written. Every append is checked with
/// [`journal::transition`] first.
pub(super) struct Open<'a> {
    fs: &'a dyn Fs,
    txn: Txn,
    records: Vec<Record>,
    state: Option<TxnState>,
    /// An append failed, so the file may hold a torn or a whole line that
    /// `records` lacks.
    dirty: bool,
}

impl<'a> Open<'a> {
    pub(super) fn new(fs: &'a dyn Fs, txn: Txn, records: Vec<Record>) -> Result<Self, EngineError> {
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

    /// For a dead-man rollback of `txn`: its records, with a torn final line
    /// removed, or, if that rewrite fails (a full disk), as read, with the
    /// next append trying it again.
    fn resume_best_effort(fs: &'a dyn Fs, txn: Txn) -> Result<Self, EngineError> {
        let records = txn.read(fs)?;
        if !journal::is_unfinished(&records) {
            return Self::new(fs, txn, records);
        }
        match txn.resume(fs) {
            Ok(records) => Self::new(fs, txn, records),
            Err(e) => {
                tracing::error!("journal: {e}; going on");
                let mut open = Self::new(fs, txn, records)?;
                open.dirty = true;
                Ok(open)
            }
        }
    }

    /// [`Open::records`], or the records in memory if the re-read fails.
    fn records_best_effort(&mut self) -> &[Record] {
        if self.dirty
            && let Err(e) = self.records()
        {
            tracing::error!("journal: {e}; going on");
        }
        &self.records
    }

    /// The records on disk, re-read after a failed append.
    fn records(&mut self) -> Result<&[Record], EngineError> {
        if self.dirty {
            let records = self.txn.resume(self.fs)?;
            *self = Self::new(self.fs, self.txn.clone(), records)?;
        }
        Ok(&self.records)
    }

    pub(super) fn append(&mut self, event: Event) -> Result<(), EngineError> {
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
