//! Journal records, their parser and the transaction state machine.

use std::fmt;
use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{EngineError, Reload};
use crate::facts::SessionId;
use crate::resource::Backup;

/// One journal line: when it was written and what happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Unix seconds.
    pub at: u64,
    /// The event, with its `event` tag.
    #[serde(flatten)]
    pub event: Event,
}

/// What a journal line records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum Event {
    /// The transaction started.
    Begin {
        /// Version of the vps-ready that started it.
        version: String,
        /// IDs of the modules in the plan.
        modules: Vec<String>,
    },
    /// The dead-man timer was started, before the first `backup`.
    Armed {
        /// The transient systemd unit, e.g. `vps-ready-deadman-<txn>-1`.
        unit: String,
        /// The boot the deadline belongs to.
        boot_id: String,
        /// When the timer rolls the transaction back.
        deadline: Deadline,
    },
    /// A resource's original state was saved; it may change from here on.
    Backup {
        /// Resource ID, e.g. `sysctl:kernel.kptr_restrict`.
        resource: String,
        /// What restoring the resource needs.
        backup: Backup,
        /// Whether a dead-man rollback restores it even if it changed since
        /// apply. Absent (`false`) in journals from before 0.3.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        force_restore: bool,
    },
    /// A resource was changed.
    Applied {
        /// Resource ID.
        resource: String,
        /// The uid of the account a `user` resource created.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        uid: Option<u32>,
    },
    /// A reload is about to run: in apply after its check passed, so a
    /// rollback replays any reload that may have run; in a rollback after
    /// it ran.
    Reloaded {
        /// Which one.
        reload: Reload,
    },
    /// The dead-man deadline moved; the timer was re-armed under `unit`.
    Extended {
        /// The new transient unit.
        unit: String,
        /// The new deadline, in the boot of the `armed` record.
        deadline: Deadline,
    },
    /// A new SSH session confirmed the pending changes.
    Confirmed {
        /// The confirming sshd session.
        session: SessionId,
        /// Its login user.
        user: String,
        /// Its client address.
        client: IpAddr,
    },
    /// A rollback started; written before its first restore.
    Rollback {
        /// Why. A resumed rollback ends with this reason.
        reason: RollbackReason,
    },
    /// A resource was restored from its backup.
    Restored {
        /// Resource ID.
        resource: String,
    },
    /// A dead-man rollback left a resource that changed since apply.
    Skipped {
        /// Resource ID.
        resource: String,
        /// How to restore it by hand.
        by_hand: String,
    },
    /// A rollback did not run a reload because its check failed, so the
    /// daemon kept its running config.
    ReloadSkipped {
        /// Which one.
        reload: Reload,
        /// The check's exit status and stderr, or why it could not run.
        reason: String,
    },
    /// A timer rollback did not complete, and `unit` tries it again.
    Retry {
        /// The transient unit.
        unit: String,
        /// Which retry it is, from 1.
        attempt: u32,
    },
    /// The transaction reached a new state.
    State {
        /// The new state.
        #[serde(flatten)]
        state: TxnState,
        /// The dead-man unit armed for it; only with `pending-confirm`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unit: Option<String>,
    },
}

impl Event {
    /// The `event` tag, for messages.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Begin { .. } => "begin",
            Self::Armed { .. } => "armed",
            Self::Backup { .. } => "backup",
            Self::Applied { .. } => "applied",
            Self::Reloaded { .. } => "reloaded",
            Self::Extended { .. } => "extended",
            Self::Confirmed { .. } => "confirmed",
            Self::Rollback { .. } => "rollback",
            Self::Restored { .. } => "restored",
            Self::Skipped { .. } => "skipped",
            Self::ReloadSkipped { .. } => "reload-skipped",
            Self::Retry { .. } => "retry",
            Self::State { .. } => "state",
        }
    }

    /// A `state` record without a unit.
    #[must_use]
    pub fn state(state: TxnState) -> Self {
        Self::State { state, unit: None }
    }
}

/// When a dead-man timer fires: `CLOCK_BOOTTIME` seconds, which an NTP
/// step cannot move, and the Unix time for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deadline {
    /// Seconds since boot, in the boot of the transaction's `armed` record.
    pub boottime: u64,
    /// Unix seconds.
    pub wall: u64,
}

/// The state of a transaction: the last `state` record in its journal, or
/// [`TxnState::Planned`] if there is none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum TxnState {
    /// Started, not yet applied and verified.
    Planned,
    /// Every change was applied and verified.
    Applied,
    /// Applied and verified with the dead-man switch armed: rolled back at
    /// `deadline` unless a new session confirms.
    PendingConfirm {
        /// When the timer rolls it back; moved by `extended`.
        deadline: Deadline,
        /// Seconds since boot when the changes went live.
        live_since: u64,
        /// The session apply ran in, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session: Option<SessionId>,
    },
    /// A new session confirmed the changes of a pending transaction.
    Confirmed,
    /// Every change was restored.
    RolledBack {
        /// Why it was rolled back.
        reason: RollbackReason,
    },
}

/// Why a transaction was rolled back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RollbackReason {
    /// A step of apply failed.
    ApplyFailed,
    /// A resource still had a change after apply.
    VerifyFailed,
    /// The user ran `rollback`. Also the reason for resuming a rollback whose
    /// journal has no `rollback` record (one written before that record
    /// existed), unless the transaction was armed and its deadline or boot
    /// has passed.
    Manual,
    /// The dead-man deadline passed without a confirm.
    DeadmanTimeout,
    /// The host rebooted before a confirm.
    DeadmanReboot,
}

impl RollbackReason {
    /// The name the journal records, e.g. `deadman-timeout`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::ApplyFailed => "apply-failed",
            Self::VerifyFailed => "verify-failed",
            Self::Manual => "manual",
            Self::DeadmanTimeout => "deadman-timeout",
            Self::DeadmanReboot => "deadman-reboot",
        }
    }
}

impl fmt::Display for TxnState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Planned => f.write_str("planned"),
            Self::Applied => f.write_str("applied"),
            Self::PendingConfirm { .. } => f.write_str("pending-confirm"),
            Self::Confirmed => f.write_str("confirmed"),
            Self::RolledBack { reason } => write!(f, "rolled-back ({})", reason.name()),
        }
    }
}

/// The state after `event`, from `state` (`None` before the `begin` record).
///
/// # Errors
///
/// [`EngineError::Transition`] if `event` cannot follow `state`.
pub fn transition(state: Option<TxnState>, event: &Event) -> Result<TxnState, EngineError> {
    use RollbackReason::{DeadmanReboot, DeadmanTimeout, Manual};
    use TxnState::{Applied, Confirmed, PendingConfirm, Planned, RolledBack};

    match (state, event) {
        (None, Event::Begin { .. }) => Ok(Planned),
        // Apply, and the rollback of a failed or stopped one. `skipped`
        // comes only from a dead-man rollback.
        (
            Some(Planned),
            Event::Armed { .. }
            | Event::Backup { .. }
            | Event::Applied { .. }
            | Event::Reloaded { .. }
            | Event::Rollback { .. }
            | Event::Restored { .. }
            | Event::Skipped { .. }
            | Event::ReloadSkipped { .. }
            | Event::Retry { .. },
        ) => Ok(Planned),
        (
            Some(Planned),
            Event::State {
                state: next @ (Applied | PendingConfirm { .. } | RolledBack { .. }),
                ..
            },
        ) => Ok(*next),
        (
            Some(PendingConfirm {
                live_since,
                session,
                ..
            }),
            Event::Extended { deadline, .. },
        ) => Ok(PendingConfirm {
            deadline: *deadline,
            live_since,
            session,
        }),
        // A dead-man rollback journals best effort, so `restored` and
        // `skipped` may come without a `rollback` record.
        (
            Some(pending @ PendingConfirm { .. }),
            Event::Confirmed { .. }
            | Event::Rollback {
                reason: DeadmanTimeout | DeadmanReboot | Manual,
            }
            | Event::Restored { .. }
            | Event::Skipped { .. }
            | Event::Reloaded { .. }
            | Event::ReloadSkipped { .. }
            | Event::Retry { .. },
        ) => Ok(pending),
        (
            Some(PendingConfirm { .. }),
            Event::State {
                state:
                    next @ (Confirmed
                    | RolledBack {
                        reason: DeadmanTimeout | DeadmanReboot | Manual,
                    }),
                ..
            },
        ) => Ok(*next),
        (
            Some(done @ (Applied | Confirmed)),
            Event::Restored { .. }
            | Event::Reloaded { .. }
            | Event::ReloadSkipped { .. }
            | Event::Rollback { reason: Manual },
        ) => Ok(done),
        (
            Some(Applied | Confirmed),
            Event::State {
                state: next @ RolledBack { reason: Manual },
                ..
            },
        ) => Ok(*next),
        (from, event) => Err(EngineError::Transition {
            from,
            event: event.name(),
        }),
    }
}

/// Whether a rollback with `reason` may start from `state`.
#[must_use]
pub fn can_roll_back(state: Option<TxnState>, reason: RollbackReason) -> bool {
    transition(state, &Event::Rollback { reason }).is_ok()
}

/// The state after all of `records`. An empty journal is [`TxnState::Planned`].
///
/// # Errors
///
/// [`EngineError::Transition`] at the first record that cannot follow the ones before it.
pub fn replay(records: &[Record]) -> Result<TxnState, EngineError> {
    let mut state = None;
    for record in records {
        state = Some(transition(state, &record.event)?);
    }
    Ok(state.unwrap_or(TxnState::Planned))
}

/// Whether there are records and the last is not a `state` record: the
/// transaction stopped during an apply or a rollback. A transaction with no
/// records changed nothing.
#[must_use]
pub fn is_unfinished(records: &[Record]) -> bool {
    records
        .last()
        .is_some_and(|r| !matches!(r.event, Event::State { .. }))
}

/// The length of `bytes` up to and including the last newline: what is left
/// after dropping a torn final line.
#[must_use]
pub fn clean_len(bytes: &[u8]) -> usize {
    bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1)
}

/// Parses journal bytes, one JSON record per line. Unknown fields are
/// ignored. A final line without a newline is a write torn by a crash, and
/// is dropped whether or not it parses.
///
/// # Errors
///
/// [`EngineError::Journal`] for any other line that does not parse,
/// including an unknown event; `path` is only for the message.
pub fn parse(path: &Path, bytes: &[u8]) -> Result<Vec<Record>, EngineError> {
    let clean = clean_len(bytes);
    if clean < bytes.len() {
        tracing::warn!(path = %path.display(), "ignoring a torn final journal line");
    }
    let Some(body) = bytes[..clean].strip_suffix(b"\n") else {
        return Ok(Vec::new());
    };
    body.split(|b| *b == b'\n')
        .enumerate()
        .map(|(i, line)| {
            serde_json::from_slice(line).map_err(|source| EngineError::Journal {
                path: path.display().to_string(),
                line: i + 1,
                source,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(event: Event) -> Record {
        Record { at: 7, event }
    }

    fn begin() -> Event {
        Event::Begin {
            version: "0.2.0".into(),
            modules: vec!["kernel.sysctl".into()],
        }
    }

    fn applied() -> Event {
        Event::Applied {
            resource: "sysctl:kernel.kptr_restrict".into(),
            uid: None,
        }
    }

    fn restored() -> Event {
        Event::Restored {
            resource: "sysctl:kernel.kptr_restrict".into(),
        }
    }

    fn reloaded() -> Event {
        Event::Reloaded {
            reload: Reload::SshdReload,
        }
    }

    fn state(state: TxnState) -> Event {
        Event::state(state)
    }

    const DEADLINE: Deadline = Deadline {
        boottime: 1575,
        wall: 1_792_932_341,
    };

    const SESSION: SessionId = SessionId {
        pid: 812,
        start: 10433,
    };

    fn pending() -> TxnState {
        TxnState::PendingConfirm {
            deadline: DEADLINE,
            live_since: 1275,
            session: Some(SESSION),
        }
    }

    fn armed() -> Event {
        Event::Armed {
            unit: "vps-ready-deadman-20261025T120000Z-1".into(),
            boot_id: "0d5c".into(),
            deadline: Deadline {
                boottime: 1234,
                wall: 1_792_932_900,
            },
        }
    }

    fn skipped() -> Event {
        Event::Skipped {
            resource: "authorized-keys:admin".into(),
            by_hand: "copy files/2.before to /home/admin/.ssh/authorized_keys".into(),
        }
    }

    fn reload_skipped() -> Event {
        Event::ReloadSkipped {
            reload: Reload::SshdReload,
            reason: "`sshd -t` exited with status 255: line 9: Bad configuration option".into(),
        }
    }

    fn confirmed() -> Event {
        Event::Confirmed {
            session: SessionId {
                pid: 951,
                start: 12655,
            },
            user: "admin".into(),
            client: "198.51.100.7".parse().unwrap(),
        }
    }

    fn extended(boottime: u64) -> Event {
        Event::Extended {
            unit: "vps-ready-deadman-20261025T120000Z-3".into(),
            deadline: Deadline {
                boottime,
                wall: 1_792_932_700,
            },
        }
    }

    fn rolled_back(reason: RollbackReason) -> TxnState {
        TxnState::RolledBack { reason }
    }

    #[test]
    fn records_serialize_as_in_the_plan() {
        let line = |event| serde_json::to_string(&rec(event)).unwrap();
        assert_eq!(
            line(begin()),
            r#"{"at":7,"event":"begin","version":"0.2.0","modules":["kernel.sysctl"]}"#
        );
        assert_eq!(
            line(Event::Backup {
                resource: "sysctl:kernel.kptr_restrict".into(),
                backup: Backup::Sysctl {
                    key: "kernel.kptr_restrict".into(),
                    value: "0".into(),
                    applied: "1".into(),
                    boot_id: None,
                },
                force_restore: false,
            }),
            r#"{"at":7,"event":"backup","resource":"sysctl:kernel.kptr_restrict","backup":{"kind":"sysctl","key":"kernel.kptr_restrict","value":"0","applied":"1"}}"#
        );
        assert_eq!(
            line(Event::Backup {
                resource: "file:/etc/sysctl.d/90-vps-ready.conf".into(),
                backup: Backup::File {
                    path: "/etc/sysctl.d/90-vps-ready.conf".into(),
                    n: 1,
                    original: None,
                },
                force_restore: true,
            }),
            r#"{"at":7,"event":"backup","resource":"file:/etc/sysctl.d/90-vps-ready.conf","backup":{"kind":"file","path":"/etc/sysctl.d/90-vps-ready.conf","n":1,"original":null},"force_restore":true}"#
        );
        assert_eq!(
            line(armed()),
            r#"{"at":7,"event":"armed","unit":"vps-ready-deadman-20261025T120000Z-1","boot_id":"0d5c","deadline":{"boottime":1234,"wall":1792932900}}"#
        );
        assert_eq!(
            line(Event::State {
                state: pending(),
                unit: Some("vps-ready-deadman-20261025T120000Z-2".into()),
            }),
            r#"{"at":7,"event":"state","state":"pending-confirm","deadline":{"boottime":1575,"wall":1792932341},"live_since":1275,"session":{"pid":812,"start":10433},"unit":"vps-ready-deadman-20261025T120000Z-2"}"#
        );
        assert_eq!(
            line(extended(1934)),
            r#"{"at":7,"event":"extended","unit":"vps-ready-deadman-20261025T120000Z-3","deadline":{"boottime":1934,"wall":1792932700}}"#
        );
        assert_eq!(
            line(confirmed()),
            r#"{"at":7,"event":"confirmed","session":{"pid":951,"start":12655},"user":"admin","client":"198.51.100.7"}"#
        );
        assert_eq!(
            line(state(TxnState::Confirmed)),
            r#"{"at":7,"event":"state","state":"confirmed"}"#
        );
        assert_eq!(
            line(skipped()),
            r#"{"at":7,"event":"skipped","resource":"authorized-keys:admin","by_hand":"copy files/2.before to /home/admin/.ssh/authorized_keys"}"#
        );
        assert_eq!(
            line(state(rolled_back(RollbackReason::DeadmanTimeout))),
            r#"{"at":7,"event":"state","state":"rolled-back","reason":"deadman-timeout"}"#
        );
        assert_eq!(
            line(reloaded()),
            r#"{"at":7,"event":"reloaded","reload":"sshd-reload"}"#
        );
        assert_eq!(
            line(state(TxnState::Applied)),
            r#"{"at":7,"event":"state","state":"applied"}"#
        );
        assert_eq!(
            line(Event::Rollback {
                reason: RollbackReason::ApplyFailed
            }),
            r#"{"at":7,"event":"rollback","reason":"apply-failed"}"#
        );
        assert_eq!(
            line(state(rolled_back(RollbackReason::VerifyFailed))),
            r#"{"at":7,"event":"state","state":"rolled-back","reason":"verify-failed"}"#
        );
    }

    #[test]
    fn parse_round_trips() {
        let records = [
            rec(begin()),
            rec(Event::Backup {
                resource: "file:/etc/x".into(),
                backup: Backup::File {
                    path: "/etc/x".into(),
                    n: 1,
                    original: Some(crate::resource::FileCopy {
                        mode: 0o644,
                        uid: 0,
                        gid: 0,
                    }),
                },
                force_restore: true,
            }),
            rec(applied()),
            rec(restored()),
            rec(state(rolled_back(RollbackReason::ApplyFailed))),
        ];
        let records = [
            &records[..],
            &[
                rec(armed()),
                rec(Event::State {
                    state: pending(),
                    unit: Some("u".into()),
                }),
                rec(state(TxnState::PendingConfirm {
                    deadline: DEADLINE,
                    live_since: 3,
                    session: None,
                })),
                rec(extended(9)),
                rec(confirmed()),
                rec(skipped()),
                rec(reload_skipped()),
            ],
        ]
        .concat();
        let mut bytes = Vec::new();
        for r in &records {
            bytes.extend(serde_json::to_vec(r).unwrap());
            bytes.push(b'\n');
        }
        assert_eq!(parse(Path::new("j"), &bytes).unwrap(), records);
        assert_eq!(parse(Path::new("j"), b"").unwrap(), vec![]);
    }

    #[test]
    fn parse_ignores_unknown_fields() {
        let bytes = b"{\"at\":1,\"event\":\"applied\",\"resource\":\"r\",\"new\":true}\n\
            {\"at\":2,\"event\":\"state\",\"state\":\"applied\",\"extra\":[1]}\n";
        let records = parse(Path::new("j"), bytes).unwrap();
        assert_eq!(
            records,
            vec![
                Record {
                    at: 1,
                    event: Event::Applied {
                        resource: "r".into(),
                        uid: None,
                    }
                },
                Record {
                    at: 2,
                    event: state(TxnState::Applied)
                },
            ]
        );
    }

    #[test]
    fn parse_drops_only_a_torn_final_line() {
        let good = b"{\"at\":1,\"event\":\"applied\",\"resource\":\"r\"}\n";
        let torn = [&good[..], b"{\"at\":2,\"event\":\"appl"].concat();
        assert_eq!(parse(Path::new("j"), &torn).unwrap().len(), 1);
        assert_eq!(clean_len(&torn), good.len());
        assert_eq!(clean_len(b"no newline"), 0);

        // A final line without a newline is dropped even if it parses.
        let whole_but_unterminated = [&good[..], &good[..good.len() - 1]].concat();
        assert_eq!(
            parse(Path::new("j"), &whole_but_unterminated)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            parse(Path::new("j"), &good[..good.len() - 1]).unwrap(),
            vec![]
        );

        // The same bytes with a newline are not torn.
        let bad_last = [&torn[..], b"\n"].concat();
        let err = parse(Path::new("j"), &bad_last).unwrap_err();
        assert!(
            matches!(err, EngineError::Journal { line: 2, .. }),
            "{err:?}"
        );

        let bad_middle = [&b"{\"at\":2,\"event\":\"appl\n"[..], good].concat();
        let err = parse(Path::new("j"), &bad_middle).unwrap_err();
        assert!(
            matches!(err, EngineError::Journal { line: 1, .. }),
            "{err:?}"
        );

        let blank_middle = [&b"\n"[..], good].concat();
        assert!(parse(Path::new("j"), &blank_middle).is_err());
    }

    #[test]
    fn parse_rejects_an_unknown_event() {
        let bytes = b"{\"at\":1,\"event\":\"teleported\",\"resource\":\"r\"}\n";
        let err = parse(Path::new("/x/journal.jsonl"), bytes).unwrap_err();
        assert!(
            err.to_string().starts_with("/x/journal.jsonl line 1:"),
            "{err}"
        );
        let bytes = b"{\"at\":1,\"event\":\"state\",\"state\":\"forgotten\"}\n";
        assert!(parse(Path::new("j"), bytes).is_err());
    }

    #[test]
    fn replays_dead_man_sequences() {
        use RollbackReason::{DeadmanReboot, DeadmanTimeout, Manual};

        let pending_txn = [
            rec(begin()),
            rec(armed()),
            rec(applied()),
            rec(reloaded()),
            rec(Event::State {
                state: pending(),
                unit: Some("u-2".into()),
            }),
        ];
        assert_eq!(replay(&pending_txn).unwrap(), pending());
        assert!(!is_unfinished(&pending_txn));

        let moved = [&pending_txn[..], &[rec(extended(1934))]].concat();
        let TxnState::PendingConfirm {
            deadline,
            live_since,
            session,
        } = replay(&moved).unwrap()
        else {
            panic!("not pending");
        };
        assert_eq!(
            (deadline.boottime, live_since, session),
            (1934, 1275, Some(SESSION))
        );

        let confirmed_txn = [
            &moved[..],
            &[rec(confirmed()), rec(state(TxnState::Confirmed))],
        ]
        .concat();
        assert_eq!(replay(&confirmed_txn).unwrap(), TxnState::Confirmed);
        // A confirmed transaction rolls back by hand, as an applied one does.
        let undone = [
            &confirmed_txn[..],
            &[
                rec(Event::Rollback { reason: Manual }),
                rec(restored()),
                rec(reloaded()),
                rec(reload_skipped()),
                rec(state(rolled_back(Manual))),
            ],
        ]
        .concat();
        assert_eq!(replay(&undone).unwrap(), rolled_back(Manual));

        for reason in [DeadmanTimeout, DeadmanReboot, Manual] {
            let full = [
                &pending_txn[..],
                &[
                    rec(Event::Rollback { reason }),
                    rec(restored()),
                    rec(skipped()),
                    rec(reloaded()),
                    rec(state(rolled_back(reason))),
                ],
            ]
            .concat();
            assert_eq!(replay(&full).unwrap(), rolled_back(reason));
            // Journaled best effort: no `rollback` record.
            let best_effort = [
                &pending_txn[..],
                &[
                    rec(skipped()),
                    rec(restored()),
                    rec(state(rolled_back(reason))),
                ],
            ]
            .concat();
            assert_eq!(replay(&best_effort).unwrap(), rolled_back(reason));
            // The dead-man rollback of an apply that stopped part way.
            let stopped = [
                rec(begin()),
                rec(armed()),
                rec(applied()),
                rec(Event::Rollback { reason }),
                rec(skipped()),
                rec(restored()),
                rec(reload_skipped()),
                rec(state(rolled_back(reason))),
            ];
            assert_eq!(replay(&stopped).unwrap(), rolled_back(reason));
        }
    }

    #[test]
    fn transitions_of_the_dead_man_states() {
        use RollbackReason::{ApplyFailed, DeadmanReboot, DeadmanTimeout, Manual, VerifyFailed};
        use TxnState::{Applied, Confirmed, Planned};

        let legal = [
            (Some(Planned), armed(), Planned),
            (Some(Planned), reloaded(), Planned),
            (Some(Planned), skipped(), Planned),
            (Some(Planned), reload_skipped(), Planned),
            (Some(Planned), state(pending()), pending()),
            (Some(pending()), confirmed(), pending()),
            (Some(pending()), state(Confirmed), Confirmed),
            (Some(pending()), restored(), pending()),
            (Some(pending()), skipped(), pending()),
            (Some(pending()), reloaded(), pending()),
            (Some(pending()), reload_skipped(), pending()),
            (Some(Confirmed), restored(), Confirmed),
            (Some(Confirmed), reloaded(), Confirmed),
            (
                Some(Confirmed),
                Event::Rollback { reason: Manual },
                Confirmed,
            ),
            (
                Some(Confirmed),
                state(rolled_back(Manual)),
                rolled_back(Manual),
            ),
            (Some(Applied), reload_skipped(), Applied),
        ];
        for (from, event, to) in legal {
            assert_eq!(transition(from, &event).unwrap(), to, "{from:?} {event:?}");
        }
        for reason in [DeadmanTimeout, DeadmanReboot, Manual] {
            assert!(can_roll_back(Some(pending()), reason));
            assert_eq!(
                transition(Some(pending()), &state(rolled_back(reason))).unwrap(),
                rolled_back(reason)
            );
        }

        let illegal = [
            (Some(Planned), state(Confirmed)),
            (Some(Planned), extended(1)),
            (Some(Planned), confirmed()),
            (Some(Applied), armed()),
            (Some(Applied), skipped()),
            (Some(Applied), confirmed()),
            (Some(Applied), state(pending())),
            (Some(pending()), armed()),
            (Some(pending()), begin()),
            (Some(pending()), applied()),
            (Some(pending()), state(Applied)),
            (Some(pending()), state(pending())),
            (Some(pending()), state(rolled_back(ApplyFailed))),
            (Some(pending()), state(rolled_back(VerifyFailed))),
            (Some(Confirmed), extended(1)),
            (Some(Confirmed), confirmed()),
            (Some(Confirmed), skipped()),
            (Some(Confirmed), state(Confirmed)),
            (Some(Confirmed), state(rolled_back(DeadmanTimeout))),
            (Some(rolled_back(DeadmanTimeout)), extended(1)),
            (Some(rolled_back(DeadmanTimeout)), confirmed()),
            (Some(rolled_back(DeadmanTimeout)), skipped()),
        ];
        for (from, event) in illegal {
            assert!(
                transition(from, &event).is_err(),
                "{from:?} {event:?} is legal"
            );
        }
        for reason in [ApplyFailed, VerifyFailed] {
            assert!(!can_roll_back(Some(pending()), reason));
        }
        for reason in [ApplyFailed, VerifyFailed, DeadmanTimeout, DeadmanReboot] {
            assert!(!can_roll_back(Some(Confirmed), reason));
            assert!(!can_roll_back(Some(Applied), reason));
        }
    }

    #[test]
    fn replays_legal_sequences() {
        let applied_txn = [
            rec(begin()),
            rec(applied()),
            rec(reloaded()),
            rec(state(TxnState::Applied)),
        ];
        assert_eq!(replay(&applied_txn).unwrap(), TxnState::Applied);

        let manual = [
            &applied_txn[..],
            &[
                rec(Event::Rollback {
                    reason: RollbackReason::Manual,
                }),
                rec(restored()),
                rec(reloaded()),
                rec(state(rolled_back(RollbackReason::Manual))),
            ],
        ]
        .concat();
        assert_eq!(
            replay(&manual).unwrap(),
            rolled_back(RollbackReason::Manual)
        );

        for reason in [
            RollbackReason::ApplyFailed,
            RollbackReason::VerifyFailed,
            RollbackReason::Manual,
        ] {
            let failed = [
                rec(begin()),
                rec(applied()),
                rec(Event::Rollback { reason }),
                rec(restored()),
                rec(state(rolled_back(reason))),
            ];
            assert_eq!(replay(&failed).unwrap(), rolled_back(reason));
        }

        assert_eq!(replay(&[]).unwrap(), TxnState::Planned);
        assert_eq!(replay(&[rec(begin())]).unwrap(), TxnState::Planned);
    }

    #[test]
    fn rejects_illegal_transitions() {
        use RollbackReason::{ApplyFailed, Manual, VerifyFailed};
        use TxnState::{Applied, Planned};

        let illegal = [
            (None, applied()),
            (None, state(Applied)),
            (Some(Planned), begin()),
            (Some(Planned), state(Planned)),
            (Some(Applied), begin()),
            (Some(Applied), applied()),
            (Some(Applied), state(Applied)),
            (Some(Applied), state(rolled_back(ApplyFailed))),
            (Some(Applied), state(rolled_back(VerifyFailed))),
            (
                Some(Applied),
                Event::Rollback {
                    reason: ApplyFailed,
                },
            ),
            (
                Some(rolled_back(Manual)),
                Event::Rollback { reason: Manual },
            ),
            (None, Event::Rollback { reason: Manual }),
            (None, reloaded()),
            (Some(rolled_back(Manual)), reloaded()),
            (Some(rolled_back(Manual)), restored()),
            (Some(rolled_back(Manual)), state(rolled_back(Manual))),
            (Some(rolled_back(ApplyFailed)), state(Applied)),
        ];
        for (from, event) in illegal {
            let err = transition(from, &event).unwrap_err();
            assert!(
                matches!(err, EngineError::Transition { .. }),
                "{from:?} {event:?}: {err:?}"
            );
        }
        let err = transition(Some(Applied), &applied()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "illegal journal event `applied` in state applied"
        );
    }

    #[test]
    fn unfinished_means_no_final_state_record() {
        assert!(!is_unfinished(&[]));
        assert!(is_unfinished(&[rec(begin())]));
        assert!(is_unfinished(&[rec(begin()), rec(applied())]));
        let done = [rec(begin()), rec(applied()), rec(state(TxnState::Applied))];
        assert!(!is_unfinished(&done));
        // A rollback that stopped after a restore.
        assert!(is_unfinished(&[&done[..], &[rec(restored())]].concat()));
        // A rollback that stopped before its first restore.
        let started = rec(Event::Rollback {
            reason: RollbackReason::Manual,
        });
        assert!(is_unfinished(&[&done[..], &[started]].concat()));
    }
}
