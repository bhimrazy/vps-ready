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
    // With sshd's ports unknown, the port apply's session came in on counts.
    let rescue = Session {
        server: SocketAddr::from(([203, 0, 113, 10], 2222)),
        ..login(903, 1050)
    };
    let err = refusal(engine.confirm(None, &rescue, &[]));
    assert_eq!(
        err.to_string(),
        "this SSH login came in on port 2222, which the host's sshd does not listen on \
         (it listens on 22)"
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

/// The firewall accepts all of loopback whatever its rules, so a login from
/// there proves nothing about one from outside.
#[test]
fn a_login_from_loopback_does_not_confirm() {
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
    let from = |client: &str| Session {
        client: SocketAddr::new(client.parse().unwrap(), 50022),
        ..login(951, 1050)
    };
    for (client, shown) in [
        ("127.0.0.1", "127.0.0.1"),
        ("127.1.2.3", "127.1.2.3"),
        ("::1", "::1"),
        ("::ffff:127.0.0.1", "127.0.0.1"),
    ] {
        let err = refusal(engine.confirm(None, &from(client), &[22]));
        assert_eq!(err, Refusal::Local(shown.parse().unwrap()), "{client}");
    }
    assert_eq!(
        Refusal::Local("127.0.0.1".parse().unwrap()).to_string(),
        "this SSH login comes from 127.0.0.1, on this server itself, so it does not show \
         that the server can still be reached from outside"
    );
    assert!(calls(&run).is_empty());
    // QEMU's user networking: logins come from its gateway, 10.0.2.2.
    assert_eq!(engine.confirm(None, &from("10.0.2.2"), &[22]).unwrap(), txn);
}

/// Rewrites the admins of the `state pending-confirm` record of `txn`,
/// which [`applied`] journals as `["admin"]` (its session's user), to the
/// JSON array `admins`.
fn with_admins(fs: &FakeFs, txn: &str, admins: &str) {
    let path = PathBuf::from(format!("{STATE}/txn/{txn}/journal.jsonl"));
    let text = String::from_utf8(fs.read(&path).unwrap()).unwrap();
    assert!(text.contains(r#""admins":["admin"]"#), "{text}");
    let text = text.replace(r#""admins":["admin"]"#, &format!(r#""admins":{admins}"#));
    fs.write(&path, text.as_bytes()).unwrap();
}

#[test]
fn only_the_admins_the_plan_gave_keys_confirm() {
    let fs = armable();
    let txn = applied(&fs);
    with_admins(&fs, &txn, r#"["admin","deploy"]"#);
    set_uptime(&fs, 1100);
    let ubuntu = Session {
        user: Some("ubuntu".into()),
        ..login(951, 1050)
    };
    let err = refusal(confirm(&fs, &dm_runner(), None, &ubuntu));
    assert_eq!(
        err,
        Refusal::NotAdmin {
            user: Some("ubuntu".into()),
            admins: vec!["admin".into(), "deploy".into()],
        }
    );
    assert_eq!(
        err.to_string(),
        "this SSH login is ubuntu, but the changes give SSH keys to admin, deploy: log in \
         as admin or deploy to confirm"
    );
    let state = state(&fs);
    let run = dm_runner();
    let engine = Engine::lock(
        &state,
        Sys {
            fs: &fs,
            runner: &run,
        },
    )
    .unwrap();
    assert_eq!(
        engine.waiting(None).unwrap(),
        (txn.clone(), vec!["admin".to_owned(), "deploy".to_owned()])
    );
    let deploy = Session {
        user: Some("deploy".into()),
        ..login(952, 1050)
    };
    assert_eq!(engine.confirm(None, &deploy, &[22]).unwrap(), txn);
}

#[test]
fn with_no_port_known_a_confirm_is_refused() {
    let fs = armable();
    // Applied with no session, so no port is journaled.
    let [lock, ..] = locking();
    let facts = facts();
    let plan = plan_of(&fs, &facts, &[&lock]);
    let (txn, _) = pending(&fs, &plan);
    set_uptime(&fs, 1100);
    let err = refusal(confirm_ports(&fs, &login(951, 1050), &[]));
    assert_eq!(err, Refusal::PortsUnknown);
    assert_eq!(
        err.to_string(),
        "cannot tell which ports sshd listens on: fix `sshd -T`, or roll back with \
         `sudo vps-ready rollback --last`"
    );
    assert_eq!(confirm_ports(&fs, &login(951, 1050), &[22]).unwrap(), txn);
}

#[test]
fn an_interrupted_confirm_says_so() {
    let fs = armable();
    let txn = applied(&fs);
    set_uptime(&fs, 1100);
    let path = PathBuf::from(format!("{STATE}/txn/{txn}/journal.jsonl"));
    fs.append_sync(
        &path,
        br#"{"at":1,"event":"confirmed","session":{"pid":951,"start":105000},"user":"admin","client":"198.51.100.7"}
"#,
    )
    .unwrap();
    let err = refusal(confirm(&fs, &dm_runner(), None, &login(952, 1050)));
    assert_eq!(err, Refusal::Interrupted(txn.clone()));
    assert_eq!(
        err.to_string(),
        format!(
            "a confirm of transaction {txn} was interrupted before it finished, so it is not \
             confirmed; its timer reverts the changes"
        )
    );
}

/// The admins of a plan: the users its modules give keys, changed or not;
/// else, with the dead-man switch, the applying session's user unless root.
#[test]
fn admins_are_the_keyed_users_else_the_applying_user() {
    const KEY: &str = "ssh-ed25519 AAAA k";
    let admin = FileOwner {
        mode: 0o700,
        uid: 1001,
        gid: 1001,
    };
    // `admin`'s key is already in place, from an earlier apply.
    let fs = armable().with_dir("/home/admin/.ssh", admin).with_dir(
        "/root",
        FileOwner {
            uid: 0,
            gid: 0,
            ..admin
        },
    );
    fs.write_atomic(
        Path::new("/home/admin/.ssh/authorized_keys"),
        format!("{KEY}\n").as_bytes(),
        FileOwner {
            mode: 0o600,
            ..admin
        },
    )
    .unwrap();
    let runner = FakeRunner::new()
        .on(
            "getent",
            ["passwd", "admin"],
            Output::success("admin:x:1001:1001::/home/admin:/bin/bash\n"),
        )
        .on(
            "getent",
            ["passwd", "root"],
            Output::success("root:x:0:0:root:/root:/bin/bash\n"),
        );
    let keys = |user: &str| {
        Resource::AuthorizedKeys(crate::resource::AuthorizedKeys {
            user: user.into(),
            keys: vec![KEY.into()],
        })
    };
    let session = |user: &str| Session {
        user: Some(user.into()),
        ..login(812, 900)
    };
    let mut facts = facts();
    let plan_with = |facts: &Facts, modules: &[&dyn Module]| {
        let selected: Vec<Selected> = modules.iter().map(|m| Selected::new(*m)).collect();
        plan(
            &selected,
            facts,
            Sys {
                fs: &fs,
                runner: &runner,
            },
        )
        .unwrap()
        .admins()
    };
    let [lock, _, plain] = locking();
    let user_admin = module("test.admin", vec![keys("admin")]);
    let root_keys = module("test.root", vec![keys("root")]);

    facts.session = Some(session("ubuntu"));
    // An admin module with no change still names its user.
    assert_eq!(plan_with(&facts, &[&user_admin, &lock]), ["admin"]);
    // Root's keys do not count; then the applying user does.
    assert_eq!(plan_with(&facts, &[&root_keys, &lock]), ["ubuntu"]);
    facts.session = Some(session("root"));
    assert!(plan_with(&facts, &[&lock]).is_empty());
    facts.session = None;
    assert!(plan_with(&facts, &[&lock]).is_empty());
    // Without the dead-man switch, no fallback.
    facts.session = Some(session("ubuntu"));
    assert!(plan_with(&facts, &[&plain]).is_empty());
}

fn confirm_ports(fs: &FakeFs, session: &Session, ports: &[u16]) -> Result<String, EngineError> {
    let state = state(fs);
    let run = dm_runner();
    Engine::lock(&state, Sys { fs, runner: &run })?.confirm(None, session, ports)
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

/// The caller's binary is not the one re-armed: the copy that applied is,
/// even when the installed binary moved.
#[test]
fn extend_keeps_the_copy() {
    let fs = armable();
    let txn = applied(&fs);
    set_uptime(&fs, 1100);
    let run = dm_runner();
    extend(&fs, &run, 600).unwrap();
    let timer = calls(&run).remove(0);
    assert!(
        timer.contains(&format!("{COPY} rollback --txn {txn}")),
        "{timer}"
    );
}

#[test]
fn extend_makes_a_missing_copy_again() {
    let fs = armable();
    let txn = applied(&fs);
    fs.remove(Path::new(COPY)).unwrap();
    set_uptime(&fs, 1100);
    let run = dm_runner();
    extend(&fs, &run, 600).unwrap();
    assert!(fs.exists(Path::new(COPY)));
    let calls = calls(&run);
    assert_eq!(calls[0], format!("{COPY} version"));
    assert!(
        calls[1].contains(&format!("{COPY} rollback --txn {txn}")),
        "{calls:?}"
    );
}

/// A transaction armed by v0.4.0 has a hook that names the installed
/// binary. Extending it moves the hook and the timer onto a copy, so a
/// reboot in the extended window still rolls back.
#[test]
fn extend_moves_a_pre_copy_hook_onto_the_copy() {
    let fs = armable();
    let txn = applied(&fs);
    fs.remove(Path::new(COPY)).unwrap();
    fs.write(
        Path::new(deadman::HOOK),
        deadman::hook_unit(Path::new(BIN)).as_bytes(),
    )
    .unwrap();
    set_uptime(&fs, 1100);
    let run = dm_runner();
    extend(&fs, &run, 600).unwrap();
    let calls = calls(&run);
    assert_eq!(calls[0], format!("{COPY} version"));
    assert_eq!(calls[1], "systemctl daemon-reload");
    assert!(
        calls[3].contains(&format!("{COPY} rollback --txn {txn}")),
        "{calls:?}"
    );
    assert_eq!(
        fs.read(Path::new(deadman::HOOK)).unwrap(),
        deadman::hook_unit(Path::new(COPY)).as_bytes()
    );
    assert!(fs.exists(Path::new(COPY)));
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
             {COPY} rollback --txn {txn} --deadman --attempt 1"
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
    .deadman(&txn, Path::new(COPY), 1, &mut |_| {})
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
