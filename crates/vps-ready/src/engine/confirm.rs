//! `confirm` and `confirm --extend`: ending or moving the wait of a
//! transaction pending a confirm, and watching that wait.

use std::path::Path;
use std::time::Duration;

use super::deadman::{self, MAX_EXTEND, MAX_PENDING, unit_name};
use super::journal::{self, Deadline, Event, Record, RollbackReason, TxnState};
use super::run::{Engine, Open};
use super::{EngineError, StateDir, Txn, id};
use crate::facts::{Session, SessionId};
use crate::sys::Fs;

/// Why `confirm` or `confirm --extend` refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// No transaction waits for a confirm.
    #[error("nothing is waiting for a confirm")]
    NothingPending,
    /// More than one does, so `--txn` must say which.
    #[error("{} transactions are waiting for a confirm ({}); pass --txn", .0.len(), .0.join(", "))]
    SeveralPending(Vec<String>),
    /// The transaction named by `--txn` does not wait for one.
    #[error("transaction {txn} is not waiting for a confirm; it is {state}")]
    NotPending {
        /// Transaction ID.
        txn: String,
        /// Its state.
        state: TxnState,
    },
    /// A rollback of it has started.
    #[error("transaction {0} is being rolled back")]
    RollingBack(String),
    /// A confirm wrote its `confirmed` line but not the state, so the
    /// transaction counts as unfinished.
    #[error(
        "a confirm of transaction {0} was interrupted before it finished, so it is not \
         confirmed; its timer reverts the changes"
    )]
    Interrupted(String),
    /// No port sshd listens on is known, so a login through another sshd
    /// could not be told apart.
    #[error(
        "cannot tell which ports sshd listens on: fix `sshd -T`, or roll back with \
         `sudo vps-ready rollback --last`"
    )]
    PortsUnknown,
    /// Its deadline or its boot passed; its dead-man rollback is due.
    #[error("{}; its changes are being rolled back", expired(.txn, *.reason))]
    Expired {
        /// Transaction ID.
        txn: String,
        /// The reason the rollback records.
        reason: RollbackReason,
    },
    /// The confirm runs in the SSH session that applied the changes.
    #[error("this is the SSH session that applied the changes")]
    SameSession,
    /// The confirm runs in an SSH session that started before the changes
    /// went live, so it proves nothing about them.
    #[error("this SSH session started before the changes went live")]
    OldSession,
    /// The SSH login came in through a port the host's sshd does not
    /// listen on: another sshd, which proves nothing about this one's config.
    #[error(
        "this SSH login came in on port {port}, which the host's sshd does not listen on ({})",
        list_ports(.ports)
    )]
    OtherSshd {
        /// The server port of the login.
        port: u16,
        /// The ports sshd listens on.
        ports: Vec<u16>,
    },
    /// The login is not one of the users the plan gave SSH keys, so it
    /// proves nothing about their login.
    #[error(
        "this SSH login is {}, but the changes give SSH keys to {}: log in as {} to confirm",
        .user.as_deref().unwrap_or("a user without a name"),
        .admins.join(", "),
        .admins.join(" or ")
    )]
    NotAdmin {
        /// The login user.
        user: Option<String>,
        /// Who may confirm.
        admins: Vec<String>,
    },
}

fn expired(txn: &str, reason: RollbackReason) -> String {
    match reason {
        RollbackReason::DeadmanReboot => format!("the host rebooted since transaction {txn}"),
        _ => format!("the deadline of transaction {txn} passed"),
    }
}

fn list_ports(ports: &[u16]) -> String {
    let ports: Vec<String> = ports.iter().map(u16::to_string).collect();
    format!("it listens on {}", ports.join(", "))
}

/// A transaction that `confirm` may act on.
struct Waiting {
    txn: Txn,
    records: Vec<Record>,
    live_since: u64,
    session: Option<SessionId>,
    /// From its `state pending-confirm` record.
    admins: Vec<String>,
    ssh_port: Option<u16>,
}

/// How [`Engine::extend`] moved a deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extended {
    /// Transaction ID.
    pub txn: String,
    /// The new deadline.
    pub deadline: Deadline,
    /// Time from now to it.
    pub left: Duration,
    /// Whether the 2-hour limit made it earlier than asked.
    pub capped: bool,
}

impl Engine<'_> {
    /// The ID of the transaction a confirm would act on (`id`, or the only
    /// one pending), and the users who may confirm it, none meaning any. It
    /// must be pending, with no rollback started and its deadline and boot
    /// not passed.
    ///
    /// # Errors
    ///
    /// [`EngineError::Refused`] says why not; others if a journal cannot be
    /// read.
    pub fn waiting(&self, id: Option<&str>) -> Result<(String, Vec<String>), EngineError> {
        self.waiting_txn(id)
            .map(|w| (w.txn.id().to_owned(), w.admins))
    }

    fn waiting_txn(&self, id: Option<&str>) -> Result<Waiting, EngineError> {
        let fs = self.sys.fs;
        let (txn, records) = match id {
            Some(id) => {
                let txn = self.find(id)?;
                let records = txn.read(fs)?;
                (txn, records)
            }
            None => {
                let mut pending = Vec::new();
                for txn in self.state.txns(fs)? {
                    let records = txn.read(fs)?;
                    if let TxnState::PendingConfirm { .. } = journal::replay(&records)? {
                        pending.push((txn, records));
                    }
                }
                if pending.len() > 1 {
                    let ids = pending.iter().map(|(t, _)| t.id().to_owned()).collect();
                    return Err(Refusal::SeveralPending(ids).into());
                }
                pending.pop().ok_or(Refusal::NothingPending)?
            }
        };
        let id = txn.id().to_owned();
        let (live_since, session) = match journal::replay(&records)? {
            TxnState::PendingConfirm {
                live_since,
                session,
                ..
            } => (live_since, session),
            state => return Err(Refusal::NotPending { txn: id, state }.into()),
        };
        if journal::is_unfinished(&records) {
            let interrupted = records
                .iter()
                .rev()
                .find(|r| !matches!(r.event, Event::Extended { .. }))
                .is_some_and(|r| matches!(r.event, Event::Confirmed { .. }));
            return Err(if interrupted {
                Refusal::Interrupted(id)
            } else {
                Refusal::RollingBack(id)
            }
            .into());
        }
        if let Some(reason) = deadman::switch(&records).and_then(|s| s.expired(fs)) {
            return Err(Refusal::Expired { txn: id, reason }.into());
        }
        let (admins, ssh_port) = records
            .iter()
            .rev()
            .find_map(|r| match &r.event {
                Event::State {
                    state: TxnState::PendingConfirm { .. },
                    admins,
                    ssh_port,
                    ..
                } => Some((admins.clone(), *ssh_port)),
                _ => None,
            })
            .unwrap_or_default();
        Ok(Waiting {
            txn,
            records,
            live_since,
            session,
            admins,
            ssh_port,
        })
    }

    /// Confirms the pending transaction `id` (or the only one) from
    /// `session`, which must be a new SSH login: not the session that
    /// applied it, started after its changes went live, through one of
    /// `ports` (those the host's sshd listens on) or the port apply's
    /// session came in on, and as one of the users the plan named as
    /// admins, if any. With no port known at all, it refuses.
    /// Journals `confirmed` and
    /// the state, and only then stops its timers and disables the boot hook,
    /// best effort: a timer or a hook that runs anyway finds it confirmed.
    /// Returns its ID.
    ///
    /// # Errors
    ///
    /// [`EngineError::Refused`], or an error reading or writing the
    /// journal; a failed write leaves the timer to roll it back.
    pub fn confirm(
        &self,
        id: Option<&str>,
        session: &Session,
        ports: &[u16],
    ) -> Result<String, EngineError> {
        let w = self.waiting_txn(id)?;
        if w.session == Some(session.id) {
            return Err(Refusal::SameSession.into());
        }
        if !session.is_new(w.session, w.live_since) {
            return Err(Refusal::OldSession.into());
        }
        // The firewall always accepts the port apply's session came in on.
        let mut ports = ports.to_vec();
        ports.extend(w.ssh_port.filter(|p| !ports.contains(p)));
        if ports.is_empty() {
            return Err(Refusal::PortsUnknown.into());
        }
        let port = session.server.port();
        if !ports.contains(&port) {
            return Err(Refusal::OtherSshd { port, ports }.into());
        }
        if !w.admins.is_empty() && !session.user.as_ref().is_some_and(|u| w.admins.contains(u)) {
            return Err(Refusal::NotAdmin {
                user: session.user.clone(),
                admins: w.admins,
            }
            .into());
        }
        let txn = w.txn.id().to_owned();
        let units: Vec<String> = deadman::live_units(&w.records)
            .into_iter()
            .map(str::to_owned)
            .collect();
        let mut open = Open::new(self.sys.fs, w.txn, w.records)?;
        open.append(Event::Confirmed {
            session: session.id,
            user: session
                .user
                .clone()
                .unwrap_or_else(|| session.uid.to_string()),
            client: session.client.ip(),
        })?;
        open.append(Event::state(TxnState::Confirmed))?;
        // With their services: a rollback may be waiting for this lock.
        for unit in &units {
            if let Err(e) = deadman::stop(self.sys, unit, true) {
                tracing::info!("stopping the dead-man timer {unit}: {e}");
            }
        }
        self.disarm(None, false);
        Ok(txn)
    }

    /// Moves the deadline of the pending transaction `id` (or the only one)
    /// to `by` from now, at most 30 minutes and at most 2 hours after its
    /// changes went live, from any session. Arms a timer for it with
    /// `binary`, journals `extended`, then stops the previous timer.
    ///
    /// # Errors
    ///
    /// [`EngineError::Refused`], [`EngineError::UnsafeBinary`],
    /// [`EngineError::Deadman`] if the timer cannot be armed, or an error
    /// reading or writing the journal.
    pub fn extend(
        &self,
        id: Option<&str>,
        by: Duration,
        binary: &Path,
    ) -> Result<Extended, EngineError> {
        let fs = self.sys.fs;
        let w = self.waiting_txn(id)?;
        deadman::check_binary(fs, binary).map_err(|reason| EngineError::UnsafeBinary {
            path: binary.display().to_string(),
            reason,
        })?;
        let txn = w.txn.id().to_owned();
        let now = deadman::boottime(fs)?;
        let limit = w.live_since + MAX_PENDING.as_secs();
        let wanted = now + by.min(MAX_EXTEND).as_secs();
        // Before the limit: no deadline is later, and this one has not passed.
        let target = wanted.min(limit);
        let left = Duration::from_secs(target.saturating_sub(now));
        let (old, n) =
            deadman::last_unit(&w.records).map_or((None, 0), |(u, n)| (Some(u.to_owned()), n));
        let unit = unit_name(&txn, n + 1);
        // Arm first: if that fails, the old timer still covers the rollback.
        deadman::arm(self.sys, &unit, left, binary, &txn).map_err(EngineError::Deadman)?;
        let deadline = Deadline {
            boottime: target,
            wall: id::now() + left.as_secs(),
        };
        let mut open = Open::new(fs, w.txn, w.records)?;
        open.append(Event::Extended { unit, deadline })?;
        // With its service: its rollback may be waiting for this lock, and
        // would re-arm anyway.
        if let Some(old) = old
            && let Err(e) = deadman::stop(self.sys, &old, true)
        {
            tracing::info!("stopping the dead-man timer {old}: {e}");
        }
        Ok(Extended {
            txn,
            deadline,
            left,
            capped: wanted > limit,
        })
    }
}

/// Where the wait for a confirm of a transaction stands, for `apply` to
/// show while it waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Watch {
    /// Still pending.
    Pending {
        /// When the timer fires; `confirm --extend` moves it.
        deadline: Deadline,
        /// Time until then.
        left: Duration,
    },
    /// A rollback of it has started and not finished.
    RollingBack,
    /// It is no longer pending: confirmed or rolled back.
    Done(TxnState),
}

/// Reads where transaction `id` stands. Takes no lock.
///
/// # Errors
///
/// [`EngineError::UnknownTxn`], or an error reading the journal.
pub fn watch(state: &StateDir, fs: &dyn Fs, id: &str) -> Result<Watch, EngineError> {
    let txn = state
        .txns(fs)?
        .into_iter()
        .find(|t| t.id() == id)
        .ok_or_else(|| EngineError::UnknownTxn(id.to_owned()))?;
    let records = txn.read(fs)?;
    let state = journal::replay(&records)?;
    if journal::is_unfinished(&records) {
        return Ok(Watch::RollingBack);
    }
    let TxnState::PendingConfirm { deadline, .. } = state else {
        return Ok(Watch::Done(state));
    };
    Ok(Watch::Pending {
        deadline,
        left: left(fs, &records, deadline),
    })
}

/// Time until `deadline` of a pending transaction with `records`: none once
/// it or its boot passed, or when the clock cannot be read.
pub(super) fn left(fs: &dyn Fs, records: &[Record], deadline: Deadline) -> Duration {
    if deadman::switch(records).is_some_and(|s| s.expired(fs).is_some()) {
        return Duration::ZERO;
    }
    deadman::boottime(fs).map_or(Duration::ZERO, |now| {
        Duration::from_secs(deadline.boottime.saturating_sub(now))
    })
}
