//! Journal records, their parser and the transaction state machine.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::EngineError;

/// One journal line: when it was written and what happened.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    /// Unix seconds.
    pub at: u64,
    /// The event, with its `event` tag.
    #[serde(flatten)]
    pub event: Event,
}

/// What a journal line records.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum Event {
    /// The transaction started.
    Begin {
        /// Version of the vps-ready that started it.
        version: String,
        /// IDs of the modules in the plan.
        modules: Vec<String>,
    },
    /// A resource's original state was saved; it may change from here on.
    Backup {
        /// Resource ID, e.g. `sysctl:kernel.kptr_restrict`.
        resource: String,
        /// The resource's backup. Kept as raw JSON until the `resource`
        /// module's `Backup` type is wired in.
        backup: serde_json::Value,
    },
    /// A resource was changed.
    Applied {
        /// Resource ID.
        resource: String,
    },
    /// A resource was restored from its backup.
    Restored {
        /// Resource ID.
        resource: String,
    },
    /// The transaction reached a new state.
    State {
        /// The new state.
        #[serde(flatten)]
        state: TxnState,
    },
}

impl Event {
    /// The `event` tag, for messages.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Begin { .. } => "begin",
            Self::Backup { .. } => "backup",
            Self::Applied { .. } => "applied",
            Self::Restored { .. } => "restored",
            Self::State { .. } => "state",
        }
    }
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
    /// The user ran `rollback`.
    Manual,
}

impl fmt::Display for TxnState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Planned => f.write_str("planned"),
            Self::Applied => f.write_str("applied"),
            Self::RolledBack { reason } => {
                let reason = match reason {
                    RollbackReason::ApplyFailed => "apply-failed",
                    RollbackReason::VerifyFailed => "verify-failed",
                    RollbackReason::Manual => "manual",
                };
                write!(f, "rolled-back ({reason})")
            }
        }
    }
}

/// The state after `event`, from `state` (`None` before the `begin` record).
///
/// # Errors
///
/// [`EngineError::Transition`] if `event` cannot follow `state`.
pub fn transition(state: Option<TxnState>, event: &Event) -> Result<TxnState, EngineError> {
    use RollbackReason::Manual;
    use TxnState::{Applied, Planned, RolledBack};

    match (state, event) {
        (None, Event::Begin { .. }) => Ok(Planned),
        (Some(Planned), Event::Backup { .. } | Event::Applied { .. } | Event::Restored { .. }) => {
            Ok(Planned)
        }
        (Some(Applied), Event::Restored { .. }) => Ok(Applied),
        (Some(Planned), Event::State { state: Applied }) => Ok(Applied),
        (
            Some(Planned),
            Event::State {
                state: next @ RolledBack { .. },
            },
        ) => Ok(*next),
        (
            Some(Applied),
            Event::State {
                state: next @ RolledBack { reason: Manual },
            },
        ) => Ok(*next),
        (from, event) => Err(EngineError::Transition {
            from,
            event: event.name(),
        }),
    }
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

/// Whether the last record is not a `state` record: the transaction stopped
/// during an apply or a rollback.
#[must_use]
pub fn is_unfinished(records: &[Record]) -> bool {
    !matches!(
        records.last(),
        Some(Record {
            event: Event::State { .. },
            ..
        })
    )
}

/// Parses journal bytes, one JSON record per line. Unknown fields are
/// ignored. A final line without a newline that does not parse is a write
/// torn by a crash, and is dropped.
///
/// # Errors
///
/// [`EngineError::Journal`] for any other line that does not parse,
/// including an unknown event; `path` is only for the message.
pub fn parse(path: &Path, bytes: &[u8]) -> Result<Vec<Record>, EngineError> {
    let mut records = Vec::new();
    let mut lines = bytes.split(|b| *b == b'\n').enumerate().peekable();
    while let Some((i, line)) = lines.next() {
        let last = lines.peek().is_none();
        if last && line.is_empty() {
            break;
        }
        match serde_json::from_slice(line) {
            Ok(record) => records.push(record),
            Err(_) if last => {
                tracing::warn!(path = %path.display(), line = i + 1, "ignoring a torn final journal line");
            }
            Err(source) => {
                return Err(EngineError::Journal {
                    path: path.display().to_string(),
                    line: i + 1,
                    source,
                });
            }
        }
    }
    Ok(records)
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
        }
    }

    fn restored() -> Event {
        Event::Restored {
            resource: "sysctl:kernel.kptr_restrict".into(),
        }
    }

    fn state(state: TxnState) -> Event {
        Event::State { state }
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
                backup: serde_json::json!({"kind": "sysctl", "key": "kernel.kptr_restrict", "value": "0"}),
            }),
            r#"{"at":7,"event":"backup","resource":"sysctl:kernel.kptr_restrict","backup":{"key":"kernel.kptr_restrict","kind":"sysctl","value":"0"}}"#
        );
        assert_eq!(
            line(state(TxnState::Applied)),
            r#"{"at":7,"event":"state","state":"applied"}"#
        );
        assert_eq!(
            line(state(rolled_back(RollbackReason::VerifyFailed))),
            r#"{"at":7,"event":"state","state":"rolled-back","reason":"verify-failed"}"#
        );
    }

    #[test]
    fn parse_round_trips() {
        let records = vec![
            rec(begin()),
            rec(Event::Backup {
                resource: "file:/etc/x".into(),
                backup: serde_json::json!({"kind": "file", "n": 1, "original": null}),
            }),
            rec(applied()),
            rec(restored()),
            rec(state(rolled_back(RollbackReason::ApplyFailed))),
        ];
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
                        resource: "r".into()
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
        let bytes = b"{\"at\":1,\"event\":\"state\",\"state\":\"confirmed\"}\n";
        assert!(parse(Path::new("j"), bytes).is_err());
    }

    #[test]
    fn replays_legal_sequences() {
        let applied_txn = [rec(begin()), rec(applied()), rec(state(TxnState::Applied))];
        assert_eq!(replay(&applied_txn).unwrap(), TxnState::Applied);

        let manual = [
            &applied_txn[..],
            &[
                rec(restored()),
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
        assert!(is_unfinished(&[]));
        assert!(is_unfinished(&[rec(begin())]));
        assert!(is_unfinished(&[rec(begin()), rec(applied())]));
        let done = [rec(begin()), rec(applied()), rec(state(TxnState::Applied))];
        assert!(!is_unfinished(&done));
        // A rollback that stopped after a restore.
        assert!(is_unfinished(&[&done[..], &[rec(restored())]].concat()));
    }
}
