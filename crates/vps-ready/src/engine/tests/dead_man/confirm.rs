//! `confirm` and `confirm --extend` on a pending transaction.

use std::net::SocketAddr;

use super::*;
use crate::engine::{Extended, Refusal, Watch, watch};
use crate::facts::Session;

/// The session of the apply; [`armable`] goes live at 1000 s since boot.
const APPLY: SessionId = SessionId {
    pid: 812,
    start: 90_000,
};

/// A login `secs` after boot through port 22, with sshd process `pid`.
fn login(pid: u32, secs: u64) -> Session {
    Session {
        id: SessionId {
            pid,
            start: secs * 100,
        },
        client: "198.51.100.7:50022".parse().unwrap(),
        server: "203.0.113.10:22".parse().unwrap(),
        uid: 1000,
        user: Some("admin".into()),
    }
}

/// A pending transaction applied from [`APPLY`].
fn applied(fs: &FakeFs) -> String {
    let mut facts = facts();
    facts.session = Some(Session {
        id: APPLY,
        ..login(0, 0)
    });
    let [lock, ..] = locking();
    let plan = plan_of(fs, &facts, &[&lock]);
    pending(fs, &plan).0
}

fn confirm(
    fs: &dyn Fs,
    runner: &FakeRunner,
    id: Option<&str>,
    session: &Session,
) -> Result<String, EngineError> {
    let state = state(fs);
    Engine::lock(&state, Sys { fs, runner })?.confirm(id, session, &[22])
}

fn extend(fs: &dyn Fs, runner: &FakeRunner, by: u64) -> Result<Extended, EngineError> {
    let state = state(fs);
    Engine::lock(&state, Sys { fs, runner })?.extend(None, Duration::from_secs(by), Path::new(BIN))
}

fn refusal(result: Result<impl std::fmt::Debug, EngineError>) -> Refusal {
    match result {
        Err(EngineError::Refused(r)) => r,
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_new_login_confirms_and_disarms() {
    let fs = armable();
    let txn = applied(&fs);
    let before = host_without_hook(&fs);
    set_uptime(&fs, 1100);

    let run = dm_runner();
    assert_eq!(confirm(&fs, &run, None, &login(951, 1050)).unwrap(), txn);
    assert_eq!(state_of(&fs, &txn), TxnState::Confirmed);
    let events = events(&fs, &txn);
    assert_eq!(
        events[events.len() - 2..],
        [
            Event::Confirmed {
                session: login(951, 1050).id,
                user: "admin".into(),
                client: "198.51.100.7".parse().unwrap(),
            },
            Event::state(TxnState::Confirmed),
        ]
    );
    let unit = format!("vps-ready-deadman-{txn}-2");
    assert_eq!(
        calls(&run),
        [
            format!("systemctl stop {unit}.timer {unit}.service"),
            DISABLE.to_owned()
        ]
    );
    // The changes stay; a timer or a boot hook that runs anyway leaves them.
    assert_eq!(host_without_hook(&fs), before);
    set_uptime(&fs, 5000);
    assert_eq!(
        timer(&fs, &dm_runner(), &txn).unwrap(),
        DeadmanOutcome::Finished(TxnState::Confirmed)
    );
    fs.write(Path::new(BOOT_ID), b"b\n").unwrap();
    assert!(boot_hook(&fs, &dm_runner()).unwrap().is_empty());
    assert_eq!(host_without_hook(&fs), before);
    assert_eq!(
        refusal(confirm(&fs, &dm_runner(), None, &login(952, 5000))),
        Refusal::NothingPending
    );
}

#[test]
fn only_a_new_login_through_the_hosts_sshd_confirms() {
    let fs = armable();
    let txn = applied(&fs);
    set_uptime(&fs, 1100);
    let run = dm_runner();
    let state = state(&fs);
    let engine = Engine::lock(
        &state,
        Sys {
            fs: &fs,
            runner: &run,
        },
    )
    .unwrap();
    let same = Session {
        id: APPLY,
        ..login(0, 0)
    };
    // A second terminal opened before the changes went live, also in the
    // same second.
    let cases = [
        (same, Refusal::SameSession),
        (login(900, 999), Refusal::OldSession),
        (login(901, 1000), Refusal::OldSession),
        (
            Session {
                server: SocketAddr::from(([203, 0, 113, 10], 2222)),
                ..login(902, 1050)
            },
            Refusal::OtherSshd {
                port: 2222,
                ports: vec![22],
            },
        ),
    ];
    for (session, expected) in cases {
        assert_eq!(
            refusal(engine.confirm(None, &session, &[22])),
            expected,
            "{session:?}"
        );
    }
    let err = refusal(engine.confirm(None, &login(903, 1050), &[]));
    assert_eq!(
        err.to_string(),
        "this SSH login came in on port 22, which the host's sshd does not listen on \
         (its ports are unknown)"
    );
    assert!(calls(&run).is_empty());
    assert!(matches!(
        state_of(&fs, &txn),
        TxnState::PendingConfirm { .. }
    ));
    // PID reuse: the same PID, started later, is a new login.
    engine
        .confirm(None, &login(812, 1050), &[22, 2222])
        .unwrap();
}

#[test]
fn a_confirm_is_refused_once_the_timer_is_due_or_rolled_back() {
    let fs = armable();
    let txn = applied(&fs);
    let new = login(951, 1050);

    // The deadline is 1300 s since boot.
    set_uptime(&fs, 1300);
    let err = refusal(confirm(&fs, &dm_runner(), None, &new));
    assert_eq!(
        err,
        Refusal::Expired {
            txn: txn.clone(),
            reason: RollbackReason::DeadmanTimeout
        }
    );
    assert_eq!(
        err.to_string(),
        format!("the deadline of transaction {txn} passed; its changes are being rolled back")
    );
    set_uptime(&fs, 1100);
    fs.write(Path::new(BOOT_ID), b"b\n").unwrap();
    assert!(matches!(
        refusal(confirm(&fs, &dm_runner(), None, &new)),
        Refusal::Expired {
            reason: RollbackReason::DeadmanReboot,
            ..
        }
    ));
    fs.write(Path::new(BOOT_ID), b"a\n").unwrap();

    // A rollback that stopped part way.
    let path = PathBuf::from(format!("{STATE}/txn/{txn}/journal.jsonl"));
    let journal = fs.read(&path).unwrap();
    fs.append_sync(
        &path,
        b"{\"at\":1,\"event\":\"rollback\",\"reason\":\"manual\"}\n",
    )
    .unwrap();
    assert_eq!(
        refusal(confirm(&fs, &dm_runner(), None, &new)),
        Refusal::RollingBack(txn.clone())
    );
    fs.write(&path, &journal).unwrap();

    // The timer won the race for the lock.
    set_uptime(&fs, 1300);
    timer(&fs, &dm_runner(), &txn).unwrap();
    assert_eq!(
        refusal(confirm(&fs, &dm_runner(), None, &new)),
        Refusal::NothingPending
    );
    assert_eq!(
        refusal(confirm(&fs, &dm_runner(), Some(&txn), &new)),
        Refusal::NotPending {
            txn: txn.clone(),
            state: rolled_back(RollbackReason::DeadmanTimeout)
        }
    );
    assert!(matches!(
        confirm(&fs, &dm_runner(), Some("20991231T000000Z"), &new),
        Err(EngineError::UnknownTxn(_))
    ));
}

#[test]
fn several_pending_transactions_need_txn() {
    let fs = armable();
    let txn = applied(&fs);
    let copy = state(&fs).create_txn(&fs, 1).unwrap();
    let journal = fs
        .read(Path::new(&format!("{STATE}/txn/{txn}/journal.jsonl")))
        .unwrap();
    fs.write(&copy.journal_path(), &journal).unwrap();
    set_uptime(&fs, 1100);
    let new = login(951, 1050);
    let err = refusal(confirm(&fs, &dm_runner(), None, &new));
    assert_eq!(
        err.to_string(),
        format!(
            "2 transactions are waiting for a confirm ({}, {txn}); pass --txn",
            copy.id()
        )
    );
    assert_eq!(confirm(&fs, &dm_runner(), Some(&txn), &new).unwrap(), txn);
}

#[test]
fn extend_re_arms_under_a_new_unit_within_both_caps() {
    let fs = armable();
    let txn = applied(&fs);
    let unit = |n: usize| format!("vps-ready-deadman-{txn}-{n}");

    set_uptime(&fs, 1100);
    let run = dm_runner();
    let done = extend(&fs, &run, 600).unwrap();
    assert_eq!(
        (done.deadline.boottime, done.left.as_secs(), done.capped),
        (1700, 600, false)
    );
    assert_eq!(
        calls(&run),
        [
            systemd_run(&txn, 3, 600),
            format!("systemctl stop {}.timer {}.service", unit(2), unit(2)),
        ]
    );
    assert!(matches!(
        events(&fs, &txn).last().unwrap(),
        Event::Extended { unit: u, deadline } if *u == unit(3) && deadline.boottime == 1700
    ));
    assert_eq!(
        watch(&state(&fs), &fs, &txn).unwrap(),
        Watch::Pending {
            deadline: done.deadline,
            left: Duration::from_secs(600)
        }
    );

    // At most 30 minutes ahead.
    let done = extend(&fs, &dm_runner(), 3600).unwrap();
    assert_eq!((done.deadline.boottime, done.capped), (2900, false));

    // At most 2 hours after the changes went live, at 1000 s, however
    // often it is extended.
    for now in [2800, 4500, 6200] {
        set_uptime(&fs, now);
        assert!(!extend(&fs, &dm_runner(), 1800).unwrap().capped);
    }
    set_uptime(&fs, 7900);
    let run = dm_runner();
    let done = extend(&fs, &run, 1800).unwrap();
    assert_eq!(
        (done.deadline.boottime, done.left.as_secs(), done.capped),
        (8200, 300, true)
    );
    assert_eq!(calls(&run)[0], systemd_run(&txn, 8, 300));
    set_uptime(&fs, 8200);
    let run = dm_runner();
    assert!(matches!(
        refusal(extend(&fs, &run, 60)),
        Refusal::Expired { .. }
    ));
    assert!(calls(&run).is_empty());

    // A timer of an earlier unit that fires anyway re-arms for the deadline.
    set_uptime(&fs, 8100);
    assert!(matches!(
        timer(&fs, &dm_runner(), &txn).unwrap(),
        DeadmanOutcome::Rearmed(d) if d.boottime == 8200
    ));
}

#[test]
fn a_failed_extend_keeps_the_old_timer() {
    let fs = armable();
    let txn = applied(&fs);
    set_uptime(&fs, 1100);
    let fail = runner(Output::success("")).on("systemd-run", Vec::<String>::new(), failed("no"));
    assert!(matches!(
        extend(&fs, &fail, 600),
        Err(EngineError::Deadman(_))
    ));
    assert_eq!(calls(&fail).len(), 1);
    assert!(matches!(
        events(&fs, &txn).last().unwrap(),
        Event::State {
            state: TxnState::PendingConfirm { .. },
            ..
        }
    ));
}

#[test]
fn history_shows_the_time_left() {
    let fs = armable();
    let txn = applied(&fs);
    let info = |fs: &FakeFs| history(&state(fs), fs).unwrap().remove(0);
    set_uptime(&fs, 1108);
    assert_eq!(info(&fs).id, txn);
    assert_eq!(info(&fs).reverts_in, Some(192));
    set_uptime(&fs, 1400);
    assert_eq!(info(&fs).reverts_in, Some(0));
    fs.write(Path::new(BOOT_ID), b"b\n").unwrap();
    set_uptime(&fs, 10);
    assert_eq!(info(&fs).reverts_in, Some(0));
    boot_hook(&fs, &dm_runner()).unwrap();
    assert_eq!(info(&fs).reverts_in, None);
}

#[test]
fn an_incomplete_boot_rollback_is_retried_by_a_timer() {
    let fs = armable();
    let txn = applied(&fs);
    fs.write(Path::new(BOOT_ID), b"b\n").unwrap();
    set_uptime(&fs, 10);
    // Restoring the drop-in fails until the disk has space again.
    fs.fail_from(Op::Rename, 1);
    let run = dm_runner();
    let err = boot_hook(&fs, &run).unwrap_err();
    assert!(
        matches!(err, EngineError::RollbackIncomplete { .. }),
        "{err:?}"
    );
    let retry = deadman::retry_name(&txn, 1);
    assert_eq!(
        calls(&run).last().unwrap(),
        &format!(
            "systemd-run --unit={retry} --on-active=60s --timer-property=AccuracySec=1s \
             --description=vps-ready: retry the rollback of transaction {txn} \
             {BIN} rollback --txn {txn} --deadman --attempt 1"
        )
    );
    // Still enabled: the next boot tries again too.
    assert!(!calls(&run).contains(&DISABLE.to_owned()));
    assert_eq!(names(&fs, &txn).last().unwrap(), "retry 1");

    fs.heal();
    set_uptime(&fs, 70);
    let state = state(&fs);
    let run = dm_runner();
    let outcome = Engine::lock(
        &state,
        Sys {
            fs: &fs,
            runner: &run,
        },
    )
    .unwrap()
    .deadman(&txn, Path::new(BIN), 1, &mut |_| {})
    .unwrap();
    assert!(
        matches!(outcome, DeadmanOutcome::RolledBack(_)),
        "{outcome:?}"
    );
    assert_eq!(
        state_of(&fs, &txn),
        rolled_back(RollbackReason::DeadmanReboot)
    );
    assert!(calls(&run).contains(&DISABLE.to_owned()));
}

#[test]
fn live_units_are_the_last_and_every_retry() {
    let rec = |event| Record { at: 0, event };
    let records = [
        rec(Event::Armed {
            unit: "u-1".into(),
            boot_id: "a".into(),
            deadline: Deadline {
                boottime: 1,
                wall: 1,
            },
        }),
        rec(Event::Retry {
            unit: "u-retry-1".into(),
            attempt: 1,
        }),
        rec(Event::Extended {
            unit: "u-2".into(),
            deadline: Deadline {
                boottime: 2,
                wall: 2,
            },
        }),
    ];
    assert_eq!(deadman::live_units(&records), ["u-retry-1", "u-2"]);
    assert_eq!(deadman::live_units(&records[..2]), ["u-retry-1"]);
    assert!(deadman::live_units(&[]).is_empty());
}
