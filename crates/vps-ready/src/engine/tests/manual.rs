//! A manual rollback of a transaction that created an account and reloaded
//! sshd: a failed `userdel` still reloads sshd, and the account of the user
//! who runs it is not removed.

use super::*;
use crate::facts::SessionId;

const ADMIN: &str = "admin:x:1001:1001::/home/admin:/bin/bash\n";

/// An applied transaction: `user.admin` created `admin` (uid 1001), then
/// a module set a sysctl and reloaded sshd.
fn applied(fs: &FakeFs) -> String {
    let state = state(fs);
    let txn = state.create_txn(fs, 1).unwrap();
    let rec = |event| Record { at: 1, event };
    let records = [
        rec(Event::Begin {
            version: "0.3.0".into(),
            modules: vec!["user.admin".into(), "ssh.server".into()],
        }),
        rec(Event::Backup {
            resource: "user:admin".into(),
            backup: Backup::User {
                name: "admin".into(),
                created: true,
                added_groups: Vec::new(),
            },
            force_restore: false,
        }),
        rec(Event::Applied {
            resource: "user:admin".into(),
            uid: Some(1001),
        }),
        rec(Event::Backup {
            resource: "sysctl:kernel.kptr_restrict".into(),
            backup: Backup::Sysctl {
                key: "kernel.kptr_restrict".into(),
                value: "0".into(),
                applied: "1".into(),
                boot_id: Some("a".into()),
            },
            force_restore: true,
        }),
        rec(Event::Applied {
            resource: "sysctl:kernel.kptr_restrict".into(),
            uid: None,
        }),
        rec(Event::Reloaded {
            reload: Reload::SshdReload,
        }),
        rec(Event::state(TxnState::Applied)),
    ];
    for r in &records {
        txn.append(fs, r).unwrap();
    }
    fs.write(Path::new(KPTR), b"1").unwrap();
    txn.id().to_owned()
}

fn host_fs() -> FakeFs {
    fixture().with_file(BOOT_ID, "a\n")
}

/// `admin` exists; `userdel` answers `userdel`.
fn users(userdel: Output) -> FakeRunner {
    runner(Output::success(""))
        .on("getent", ["passwd", "admin"], Output::success(ADMIN))
        .on("userdel", Vec::<String>::new(), userdel)
}

#[test]
fn a_failed_userdel_still_reloads_sshd() {
    let fs = host_fs();
    let txn = applied(&fs);
    let run = users(failed(
        "userdel: user admin is currently used by process 4242",
    ));
    let err = rollback_with(&fs, &run).unwrap_err();
    assert!(
        matches!(err, EngineError::RollbackIncomplete { .. }),
        "{err:?}"
    );
    let calls = calls(&run);
    let userdel = calls.iter().position(|c| c == "userdel admin").unwrap();
    // The sysctl and sshd's reload came before the account, which is
    // restored last; sshd runs its restored config.
    assert_eq!(
        calls[userdel + 1..],
        [SSHD_RELOAD[0], SSHD_RELOAD[1]].map(str::to_owned)
    );
    assert_eq!(fs.read(Path::new(KPTR)).unwrap(), b"0");
    let names = names(&fs, &txn);
    assert_eq!(
        names[names.len() - 3..],
        [
            "rollback",
            "restored sysctl:kernel.kptr_restrict",
            "reloaded sshd-reload",
        ]
    );

    // Once the account is free, a rerun finishes.
    let run = users(Output::success(""));
    rollback_with(&fs, &run).unwrap();
    assert_eq!(
        state_of(&fs, &txn),
        TxnState::RolledBack {
            reason: RollbackReason::Manual
        }
    );
}

#[test]
fn a_rollback_does_not_remove_the_account_running_it() {
    let fs = host_fs();
    let txn = applied(&fs);
    let run = users(Output::success(""));
    let state = state(&fs);
    let engine = Engine::lock(
        &state,
        Sys {
            fs: &fs,
            runner: &run,
        },
    )
    .unwrap();
    let own = ["admin".to_owned()];
    let err = engine
        .rollback_by(
            Target::Last,
            &Who {
                own: &own,
                ..Who::default()
            },
            &mut |_| {},
        )
        .unwrap_err();
    assert!(
        matches!(&err, EngineError::OwnAccount { user, .. } if user == "admin"),
        "{err:?}"
    );
    assert!(
        err.to_string().starts_with(&format!(
            "refusing to roll back transaction {txn}: it would remove the account admin"
        )),
        "{err}"
    );
    assert!(calls(&run).is_empty());
    assert_eq!(fs.read(Path::new(KPTR)).unwrap(), b"1");
    // Another account may.
    engine
        .rollback_by(
            Target::Last,
            &Who {
                own: &["ubuntu".to_owned()],
                ..Who::default()
            },
            &mut |_| {},
        )
        .unwrap();
}

/// A later transaction, at the same second, that ends `events`: one that
/// may have turned off root and password logins, relying on `admin`.
fn later(fs: &FakeFs, events: Vec<Event>) -> String {
    let txn = super::state(fs).create_txn(fs, 1).unwrap();
    let begin = Event::Begin {
        version: "0.3.0".into(),
        modules: vec!["ssh.server".into()],
    };
    for event in std::iter::once(begin).chain(events) {
        txn.append(fs, &Record { at: 2, event }).unwrap();
    }
    txn.id().to_owned()
}

#[test]
fn a_created_account_outlives_a_later_transaction() {
    let fs = host_fs();
    let older = applied(&fs);
    let pending = Event::state(TxnState::PendingConfirm {
        deadline: Deadline {
            boottime: 1300,
            wall: 1_792_932_341,
        },
        live_since: 1000,
        session: None,
    });
    let confirmed = vec![
        pending.clone(),
        Event::Confirmed {
            session: SessionId {
                pid: 951,
                start: 12655,
            },
            user: "admin".into(),
            client: "198.51.100.7".parse().unwrap(),
        },
        Event::state(TxnState::Confirmed),
    ];
    for events in [
        vec![Event::state(TxnState::Applied)],
        vec![pending],
        confirmed,
    ] {
        let newer = later(&fs, events);
        let run = users(Output::success(""));
        let state = state(&fs);
        let engine = Engine::lock(
            &state,
            Sys {
                fs: &fs,
                runner: &run,
            },
        )
        .unwrap();
        let err = engine
            .rollback(Target::Txn(&older), &mut |_| {})
            .unwrap_err();
        assert!(
            matches!(&err, EngineError::LaterTxn { user, later, .. }
                if user == "admin" && *later == newer),
            "{err:?}"
        );
        assert!(
            err.to_string()
                .ends_with(&format!("roll back {newer} first")),
            "{err}"
        );
        assert!(calls(&run).is_empty());
        // Once the later one is rolled back, the older one may be.
        let txn = state.txns(&fs).unwrap().pop().unwrap();
        for event in [
            Event::Rollback {
                reason: RollbackReason::Manual,
            },
            Event::state(TxnState::RolledBack {
                reason: RollbackReason::Manual,
            }),
        ] {
            txn.append(&fs, &Record { at: 3, event }).unwrap();
        }
    }
    let run = users(Output::success(""));
    let state = state(&fs);
    Engine::lock(
        &state,
        Sys {
            fs: &fs,
            runner: &run,
        },
    )
    .unwrap()
    .rollback(Target::Txn(&older), &mut |_| {})
    .unwrap();
    assert_eq!(
        state_of(&fs, &older),
        TxnState::RolledBack {
            reason: RollbackReason::Manual
        }
    );
}

/// A manual rollback has no timer, so one that would limit SSH to `wg0`
/// again runs only from a session through `wg0`.
#[test]
fn a_rollback_that_restores_ssh_via_needs_a_session_through_it() {
    use crate::facts::{Address, Interface};
    use crate::modules::firewall_inbound::RULESET;
    let via = "    iifname \"wg0\" tcp dport { 22 } accept\n";
    let fs = fixture()
        .with_dir("/etc/vps-ready", owner(0o755))
        .with_file(RULESET, via);
    let facts = facts();
    // A change that reopens public SSH: its rollback closes it again.
    let reopen = module(
        "test.reopen",
        vec![file(RULESET, "    tcp dport { 22 } accept\n", 0o644)],
    );
    let plan = plan_of(&fs, &facts, &[&reopen]);
    assert!(matches!(
        apply(&fs, &plan).unwrap(),
        ApplyOutcome::Applied { .. }
    ));
    let wg0 = [Interface {
        name: "wg0".into(),
        kind: Some("wireguard".into()),
        addresses: vec![Address {
            ip: "10.77.0.1".parse().unwrap(),
            prefix: 24,
        }],
        up: true,
    }];
    let state = state(&fs);
    let engine = Engine::lock(&state, sys(&fs)).unwrap();
    for server in [None, Some("192.0.2.10".parse().unwrap())] {
        let who = Who {
            server,
            interfaces: &wg0,
            ..Who::default()
        };
        let err = engine
            .rollback_by(Target::Last, &who, &mut |_| {})
            .unwrap_err();
        assert!(
            matches!(&err, EngineError::ViaRollback { via, .. } if via == "wg0"),
            "{err:?}"
        );
    }
    // Through wg0's address, but from the host itself: over lo.
    for client in ["10.77.0.1", "127.0.0.1"] {
        let who = Who {
            server: Some("10.77.0.1".parse().unwrap()),
            client: Some(client.parse().unwrap()),
            interfaces: &wg0,
            ..Who::default()
        };
        let err = engine
            .rollback_by(Target::Last, &who, &mut |_| {})
            .unwrap_err();
        assert!(
            matches!(err, EngineError::ViaRollback { .. }),
            "{client}: {err:?}"
        );
    }
    assert_ne!(fs.read(Path::new(RULESET)).unwrap(), via.as_bytes());
    let who = Who {
        server: Some("10.77.0.1".parse().unwrap()),
        client: Some("198.51.100.7".parse().unwrap()),
        interfaces: &wg0,
        ..Who::default()
    };
    engine.rollback_by(Target::Last, &who, &mut |_| {}).unwrap();
    assert_eq!(fs.read(Path::new(RULESET)).unwrap(), via.as_bytes());
}

fn state_of(fs: &dyn Fs, txn: &str) -> TxnState {
    let records: Vec<Record> = events(fs, txn)
        .into_iter()
        .map(|event| Record { at: 0, event })
        .collect();
    journal::replay(&records).unwrap()
}

/// A resumed rollback that already restored `tailscaled`, or ran
/// `tailscale down`, has nothing left to cut.
#[test]
fn a_restored_tailscaled_is_not_cut_again() {
    let record = |event| Record { at: 0, event };
    let backup = |resource: &str, backup| {
        record(Event::Backup {
            resource: resource.into(),
            backup,
            force_restore: false,
        })
    };
    let restored = |resource: &str| {
        record(Event::Restored {
            resource: resource.into(),
        })
    };
    let service = backup(
        "service:tailscaled.service",
        Backup::Service {
            unit: "tailscaled.service".into(),
            was_enabled: false,
            was_active: false,
            enabled: true,
            active: true,
        },
    );
    let up = backup("tailscale:up", Backup::TailscaleUp { was_running: false });
    let cuts = super::run::cuts_tailscale;
    assert!(cuts(std::slice::from_ref(&service)));
    assert!(cuts(std::slice::from_ref(&up)));
    assert!(!cuts(&[
        service.clone(),
        restored("service:tailscaled.service")
    ]));
    assert!(!cuts(&[up.clone(), restored("tailscale:up")]));
    assert!(cuts(&[service, up, restored("tailscale:up")]));
}
