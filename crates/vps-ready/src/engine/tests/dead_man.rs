//! The dead-man switch: arming, the timer's and the boot hook's rollbacks,
//! and the manual rollback of an armed transaction.

use std::time::Duration;

use super::*;
use crate::facts::SessionId;
use crate::resource::after_path;

const BIN: &str = "/usr/local/bin/vps-ready";
/// Where the timer and the boot hook run the binary from.
const COPY: &str = "/state/bin/vps-ready";
const UPTIME: &str = "/proc/uptime";
const WINDOW: Duration = Duration::from_secs(300);

/// [`fixture`] on a host that can arm: a boot ID, 1000 s since boot and
/// the binary.
fn armable() -> FakeFs {
    let fs = fixture()
        .with_file(BOOT_ID, "a\n")
        .with_file(UPTIME, "1000.25 900.00\n")
        .with_file(BIN, "\x7fELF");
    fs.create_dir_all(Path::new("/etc/systemd/system"), 0o755)
        .unwrap();
    fs
}

fn set_uptime(fs: &FakeFs, secs: u64) {
    fs.write(Path::new(UPTIME), format!("{secs}.50 0.00\n").as_bytes())
        .unwrap();
}

/// `test.lock` can lock the admin out, so a dead-man rollback restores it
/// even if it changed; it reloads sshd. `test.keys` needs the dead-man too
/// but is not forced. `test.plain` sets a sysctl.
fn locking() -> [Demo; 3] {
    [
        Demo {
            reloads: vec![Reload::SshdReload],
            deadman: true,
            force: true,
            ..module("test.lock", vec![file(CONF, "new\n", 0o600)])
        },
        Demo {
            deadman: true,
            ..module("test.keys", vec![file(NEW, "created\n", 0o644)])
        },
        module("test.plain", vec![sysctl("kernel.kptr_restrict", "1")]),
    ]
}

/// Answers `systemd-run`, `systemctl` and every check with success.
fn dm_runner() -> FakeRunner {
    runner(Output::success("")).on("systemd-run", Vec::<String>::new(), Output::success(""))
}

fn deadman_cfg() -> Deadman {
    Deadman {
        window: WINDOW,
        binary: BIN.into(),
    }
}

fn apply_dm(fs: &dyn Fs, runner: &FakeRunner, plan: &Plan) -> Result<ApplyOutcome, EngineError> {
    let state = state(fs);
    Engine::lock(&state, Sys { fs, runner })?.apply(plan, &deadman_cfg(), &mut |_| {})
}

fn timer(fs: &dyn Fs, runner: &FakeRunner, txn: &str) -> Result<DeadmanOutcome, EngineError> {
    let state = state(fs);
    Engine::lock(&state, Sys { fs, runner })?.deadman(txn, Path::new(COPY), 0, &mut |_| {})
}

fn boot_hook(fs: &dyn Fs, runner: &FakeRunner) -> Result<Vec<Rollback>, EngineError> {
    let state = state(fs);
    Engine::lock(&state, Sys { fs, runner })?.deadman_boot(Path::new(COPY), &mut |_| {})
}

fn manual(fs: &dyn Fs, runner: &FakeRunner) -> Result<Rollback, EngineError> {
    let state = state(fs);
    Engine::lock(&state, Sys { fs, runner })?.rollback(Target::Last, &mut |_| {})
}

/// Applies `plan` and expects it to wait for a confirm.
fn pending(fs: &dyn Fs, plan: &Plan) -> (String, Deadline) {
    match apply_dm(fs, &dm_runner(), plan).unwrap() {
        ApplyOutcome::Pending { txn, deadline } => (txn, deadline),
        other => panic!("{other:?}"),
    }
}

/// The host tree without the boot hook, which nothing removes, and the
/// clock and boot ID, which tests move.
fn host_without_hook(fs: &dyn Fs) -> Tree {
    let mut tree = host(fs);
    tree.remove(Path::new(deadman::HOOK));
    tree.remove(Path::new(COPY));
    tree.remove(Path::new(UPTIME));
    tree.remove(Path::new(BOOT_ID));
    tree
}

fn state_of(fs: &dyn Fs, txn: &str) -> TxnState {
    let records: Vec<Record> = events(fs, txn)
        .into_iter()
        .map(|event| Record { at: 0, event })
        .collect();
    journal::replay(&records).unwrap()
}

fn rolled_back(reason: RollbackReason) -> TxnState {
    TxnState::RolledBack { reason }
}

fn systemd_run(txn: &str, n: usize, secs: u64) -> String {
    format!(
        "systemd-run --unit=vps-ready-deadman-{txn}-{n} --on-active={secs}s \
         --timer-property=AccuracySec=1s \
         --description=vps-ready: roll back transaction {txn} unless confirmed \
         {COPY} rollback --txn {txn} --deadman"
    )
}

const DISABLE: &str = "systemctl disable vps-ready-deadman.service";

#[test]
fn arms_before_the_first_change_and_waits_for_a_confirm() {
    let fs = armable();
    let mut facts = facts();
    let session = SessionId {
        pid: 812,
        start: 10433,
    };
    facts.session = Some(crate::facts::Session {
        id: session,
        client: "198.51.100.7:50022".parse().unwrap(),
        server: "203.0.113.10:22".parse().unwrap(),
        uid: 1000,
        user: Some("admin".into()),
    });
    let [lock, keys, plain] = locking();
    let plan = plan_of(&fs, &facts, &[&lock, &keys, &plain]);
    assert!(plan.needs_deadman());
    let run = dm_runner();
    let outcome = apply_dm(&fs, &run, &plan).unwrap();
    let ApplyOutcome::Pending { txn, deadline } = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(deadline.boottime, 1300);

    // The window plus the command timeouts: the sshd reload (30 + 120 s),
    // a verify for each of the three modules (30 s each), then stopping the
    // first timer and starting the second (120 + 30 s). Files and sysctls
    // run no command.
    let first = 300 + 150 + 3 * 30 + 150;
    let unit = |n| format!("vps-ready-deadman-{txn}-{n}");
    assert_eq!(
        calls(&run),
        [
            "systemctl daemon-reload".to_owned(),
            "systemctl enable vps-ready-deadman.service".to_owned(),
            systemd_run(&txn, 1, first),
            "sshd -t".to_owned(),
            "systemctl try-reload-or-restart ssh.service".to_owned(),
            // The next timer first, then the old one goes.
            systemd_run(&txn, 2, 300),
            format!("systemctl stop {}.timer {}.service", unit(1), unit(1)),
        ]
    );
    assert_eq!(
        fs.read(Path::new(deadman::HOOK)).unwrap(),
        deadman::hook_unit(Path::new(COPY)).as_bytes()
    );
    assert_eq!(
        names(&fs, &txn),
        [
            "begin",
            "armed 1",
            "backup file:/etc/demo.conf",
            "applied file:/etc/demo.conf",
            "reloaded sshd-reload",
            "backup file:/etc/demo.d/new.conf",
            "applied file:/etc/demo.d/new.conf",
            "backup sysctl:kernel.kptr_restrict",
            "applied sysctl:kernel.kptr_restrict",
            "state pending-confirm",
        ]
    );
    let events = events(&fs, &txn);
    let Event::Armed {
        boot_id,
        deadline: armed,
        ..
    } = &events[1]
    else {
        panic!("{:?}", events[1]);
    };
    assert_eq!((boot_id.as_str(), armed.boottime), ("a", 1000 + first));
    let forced: Vec<bool> = events
        .iter()
        .filter_map(|e| match e {
            Event::Backup { force_restore, .. } => Some(*force_restore),
            _ => None,
        })
        .collect();
    assert_eq!(forced, [true, false, false]);
    assert_eq!(
        events.last().unwrap(),
        &Event::State {
            state: TxnState::PendingConfirm {
                deadline,
                live_since: 1000,
                session: Some(session),
            },
            unit: Some(unit(2)),
            admins: vec!["admin".into()],
            ssh_port: Some(22),
        }
    );

    // One pending transaction at a time, and the hook is not rewritten.
    let run = dm_runner();
    let err = apply_dm(&fs, &run, &plan).unwrap_err();
    assert!(
        matches!(&err, EngineError::Pending(id) if *id == txn),
        "{err:?}"
    );
    assert!(calls(&run).is_empty());
    let history = history(&state(&fs), &fs).unwrap();
    assert_eq!(history[0].state.to_string(), "pending-confirm");
}

#[test]
fn a_plan_without_a_dead_man_module_arms_nothing() {
    let fs = armable();
    let facts = facts();
    let [_, _, plain] = locking();
    let plan = plan_of(&fs, &facts, &[&plain]);
    let run = dm_runner();
    assert!(matches!(
        apply_dm(&fs, &run, &plan).unwrap(),
        ApplyOutcome::Applied { .. }
    ));
    assert!(calls(&run).is_empty());
    assert!(!fs.exists(Path::new(deadman::HOOK)));
}

#[test]
fn a_failed_systemd_run_ends_the_transaction_before_any_backup() {
    let fs = armable();
    let facts = facts();
    let before = host_without_hook(&fs);
    let [lock, ..] = locking();
    let plan = plan_of(&fs, &facts, &[&lock]);
    let run = runner(Output::success("")).on(
        "systemd-run",
        Vec::<String>::new(),
        failed("Failed to start transient timer unit"),
    );
    let outcome = apply_dm(&fs, &run, &plan).unwrap();
    let ApplyOutcome::RolledBack { txn, reason, cause } = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(reason, RollbackReason::ApplyFailed);
    assert!(
        cause
            .to_string()
            .starts_with("dead-man switch: `systemd-run"),
        "{cause}"
    );
    assert_eq!(
        names(&fs, &txn),
        ["begin", "rollback", "state rolled-back (apply-failed)"]
    );
    assert_eq!(calls(&run).last().unwrap(), DISABLE);
    assert_eq!(host_without_hook(&fs), before);
}

#[test]
fn a_failed_verify_rolls_back_and_disarms() {
    let fs = armable();
    let facts = facts();
    let before = host_without_hook(&fs);
    let [lock, ..] = locking();
    let lock = Demo {
        unverified: Some("sshd -T shows passwordauthentication yes"),
        ..lock
    };
    let plan = plan_of(&fs, &facts, &[&lock]);
    let run = dm_runner();
    let outcome = apply_dm(&fs, &run, &plan).unwrap();
    let ApplyOutcome::RolledBack { txn, reason, .. } = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(reason, RollbackReason::VerifyFailed);
    assert_eq!(host_without_hook(&fs), before);
    let unit = format!("vps-ready-deadman-{txn}-1");
    let calls = calls(&run);
    assert_eq!(
        calls[calls.len() - 2..],
        [
            format!("systemctl stop {unit}.timer {unit}.service"),
            DISABLE.to_owned(),
        ]
    );
}

#[test]
fn refuses_an_unsafe_binary_before_anything_changes() {
    let fs = armable().with_file("/tmp/vps-ready", "\x7fELF");
    let facts = facts();
    let [lock, ..] = locking();
    let plan = plan_of(&fs, &facts, &[&lock]);
    let state = state(&fs);
    let run = dm_runner();
    let cfg = Deadman {
        binary: "/tmp/vps-ready".into(),
        ..deadman_cfg()
    };
    let err = Engine::lock(
        &state,
        Sys {
            fs: &fs,
            runner: &run,
        },
    )
    .unwrap()
    .apply(&plan, &cfg, &mut |_| {})
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "refusing to arm the dead-man switch with /tmp/vps-ready: it is under /tmp. \
         Install vps-ready to /usr/local/bin first, or, where that is group-writable \
         (root:staff 2775 on older Debian), to /usr/bin or /opt/vps-ready/bin"
    );
    assert!(state.txns(&fs).unwrap().is_empty());
    assert!(calls(&run).is_empty());
}

#[test]
fn the_timer_rolls_back_a_pending_transaction_unless_it_moved_or_finished() {
    let fs = armable();
    let facts = facts();
    let before = host_without_hook(&fs);
    let [lock, keys, plain] = locking();
    let plan = plan_of(&fs, &facts, &[&lock, &keys, &plain]);
    let (txn, deadline) = pending(&fs, &plan);

    // Fired before the deadline, e.g. a stale timer after an extend.
    set_uptime(&fs, 1200);
    let run = dm_runner();
    assert_eq!(
        timer(&fs, &run, &txn).unwrap(),
        DeadmanOutcome::Rearmed(deadline)
    );
    assert_eq!(
        calls(&run),
        [
            systemd_run(&txn, 3, 100),
            format!("systemctl stop --no-block vps-ready-deadman-{txn}-2.timer"),
        ]
    );
    assert_eq!(names(&fs, &txn).last().unwrap(), "extended 3");

    set_uptime(&fs, 1300);
    let run = dm_runner();
    let DeadmanOutcome::RolledBack(done) = timer(&fs, &run, &txn).unwrap() else {
        panic!("not rolled back");
    };
    assert_eq!(done.restored, 3);
    assert_eq!(host_without_hook(&fs), before);
    assert_eq!(
        state_of(&fs, &txn),
        rolled_back(RollbackReason::DeadmanTimeout)
    );
    assert_eq!(
        calls(&run),
        [
            "sshd -t".to_owned(),
            "systemctl try-reload-or-restart ssh.service".to_owned(),
            // Only the timer: the service is this process.
            format!("systemctl stop --no-block vps-ready-deadman-{txn}-3.timer"),
            DISABLE.to_owned(),
        ]
    );

    // A timer that fires once it is all over does nothing.
    let run = dm_runner();
    assert_eq!(
        timer(&fs, &run, &txn).unwrap(),
        DeadmanOutcome::Finished(rolled_back(RollbackReason::DeadmanTimeout))
    );
    assert!(calls(&run).is_empty());
}

#[test]
fn an_edited_forced_file_is_restored_and_its_edit_kept() {
    let fs = armable();
    let facts = facts();
    let before = host_without_hook(&fs);
    let [lock, keys, plain] = locking();
    let plan = plan_of(&fs, &facts, &[&lock, &keys, &plain]);
    let (txn, _) = pending(&fs, &plan);
    fs.write(Path::new(CONF), b"edited during the window\n")
        .unwrap();
    fs.write(Path::new(NEW), b"edited too\n").unwrap();

    set_uptime(&fs, 5000);
    let state = state(&fs);
    let run = dm_runner();
    let mut shown = Vec::new();
    let outcome = Engine::lock(
        &state,
        Sys {
            fs: &fs,
            runner: &run,
        },
    )
    .unwrap()
    .deadman(&txn, Path::new(COPY), 0, &mut |p| match p {
        Progress::During { copy, .. } => shown.push(format!("during {}", copy.display())),
        Progress::Skip(step) => shown.push(format!("skip {step}")),
        _ => {}
    })
    .unwrap();
    let DeadmanOutcome::RolledBack(done) = outcome else {
        panic!("{outcome:?}");
    };
    let during = PathBuf::from(format!("{STATE}/txn/{txn}/files/1.during"));
    let left = ByHand {
        resource: format!("file:{NEW}"),
        step: format!("remove {NEW}"),
    };
    assert_eq!(done.during, std::slice::from_ref(&during));
    assert_eq!(done.skipped, std::slice::from_ref(&left));
    assert_eq!(
        shown,
        [
            format!("skip {left}"),
            format!("during {}", during.display())
        ]
    );
    assert_eq!(fs.read(&during).unwrap(), b"edited during the window\n");
    assert_eq!(fs.metadata(&during).unwrap().mode, 0o600);

    // Only the unforced file is left, with its edit.
    let mut expected = before;
    expected.insert(NEW.into(), (b"edited too\n".to_vec(), owner(0o644)));
    assert_eq!(host_without_hook(&fs), expected);
    let names = names(&fs, &txn);
    assert_eq!(
        names[names.len() - 6..],
        [
            "rollback",
            "restored sysctl:kernel.kptr_restrict",
            "skipped file:/etc/demo.d/new.conf",
            "restored file:/etc/demo.conf",
            "reloaded sshd-reload",
            "state rolled-back (deadman-timeout)",
        ]
    );
    assert_eq!(history(&state, &fs).unwrap()[0].skipped, [left]);
}

#[test]
fn a_full_disk_does_not_stop_the_dead_man_restores() {
    let fs = armable();
    let facts = facts();
    let before = host_without_hook(&fs);
    let [lock, ..] = locking();
    let plan = plan_of(&fs, &facts, &[&lock]);
    let (txn, _) = pending(&fs, &plan);
    fs.write(Path::new(CONF), b"edited\n").unwrap();
    let lines = names(&fs, &txn).len();

    // Every journal line fails, and so does the `.during` copy, the next write.
    set_uptime(&fs, 5000);
    fs.fail_from(Op::Append, 1);
    fs.fail_next(Op::Write);
    let run = dm_runner();
    let err = timer(&fs, &run, &txn).unwrap_err();
    assert!(
        matches!(&err, EngineError::RollbackIncomplete { left: Some(left), .. } if left.is_empty()),
        "{err:?}"
    );
    assert_eq!(host_without_hook(&fs), before);
    assert!(!fs.exists(&PathBuf::from(format!("{STATE}/txn/{txn}/files/1.during"))));
    assert_eq!(names(&fs, &txn).len(), lines);
    // The hook stays enabled for the next boot, which converges too.
    assert!(!calls(&run).contains(&DISABLE.to_owned()));

    // With space again, a rerun finishes it with the dead-man reason.
    fs.heal();
    let run = dm_runner();
    let DeadmanOutcome::RolledBack(done) = timer(&fs, &run, &txn).unwrap() else {
        panic!("not rolled back");
    };
    assert_eq!(done.restored, 1);
    assert_eq!(host_without_hook(&fs), before);
    assert_eq!(
        state_of(&fs, &txn),
        rolled_back(RollbackReason::DeadmanTimeout)
    );
}

#[test]
fn a_failed_restore_does_not_stop_the_others() {
    let fs = armable();
    let facts = facts();
    let [lock, keys, plain] = locking();
    let plan = plan_of(&fs, &facts, &[&lock, &keys, &plain]);
    let (txn, _) = pending(&fs, &plan);
    set_uptime(&fs, 5000);
    // The first restore is the sysctl's write.
    fs.fail_next(Op::Write);
    let run = dm_runner();
    let err = timer(&fs, &run, &txn).unwrap_err();
    let EngineError::RollbackIncomplete {
        left: Some(left), ..
    } = &err
    else {
        panic!("{err:?}");
    };
    assert_eq!(
        left,
        &[ByHand {
            resource: "sysctl:kernel.kptr_restrict".into(),
            step: "sysctl -w 'kernel.kptr_restrict=0'".into(),
        }]
    );
    assert_eq!(fs.read(Path::new(CONF)).unwrap(), b"old\n");
    assert!(!fs.exists(Path::new(NEW)));
    assert_eq!(fs.read(Path::new(KPTR)).unwrap(), b"1");

    let DeadmanOutcome::RolledBack(done) = timer(&fs, &dm_runner(), &txn).unwrap() else {
        panic!("not rolled back");
    };
    assert_eq!(done.restored, 1);
    assert_eq!(fs.read(Path::new(KPTR)).unwrap(), b"0");
}

#[test]
fn a_crash_after_armed_is_finished_by_the_timer_and_by_the_boot_hook() {
    let facts = facts();
    let [lock, keys, plain] = locking();
    let modules: [&dyn Module; 3] = [&lock, &keys, &plain];
    let plan = plan_of(&armable(), &facts, &modules);
    let original = host_without_hook(&armable());

    let fs = armable();
    let (txn, _) = pending(&fs, &plan);
    let applied = tree(&fs);
    let journal = PathBuf::from(format!("{STATE}/txn/{txn}/journal.jsonl"));
    let lines: Vec<Vec<u8>> = applied[&journal]
        .0
        .split_inclusive(|b| *b == b'\n')
        .map(<[u8]>::to_vec)
        .collect();
    let target = |id: &str| match id.strip_prefix("file:") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(KPTR),
    };

    // From `begin` alone to the pending state; a resource with a `backup`
    // line and no `applied` line is taken as changed.
    for kept in 1..=lines.len() {
        let records = journal::parse(&journal, &lines[..kept].concat()).unwrap();
        for boot in ["timer", "boot"] {
            let mut tree = applied.clone();
            for step in plan.steps() {
                let id = &step.change.id;
                let backed_up = records
                    .iter()
                    .any(|r| matches!(&r.event, Event::Backup { resource, .. } if resource == id));
                let path = target(id);
                if !backed_up {
                    match original.get(&path) {
                        Some(entry) => tree.insert(path, entry.clone()),
                        None => tree.remove(&path),
                    };
                }
            }
            tree.get_mut(&journal).unwrap().0 = lines[..kept].concat();
            let fs = load(&tree);
            let case = format!("{kept} lines, {boot}");
            let run = dm_runner();
            if boot == "timer" {
                set_uptime(&fs, 5000);
                let outcome = timer(&fs, &run, &txn).unwrap_or_else(|e| panic!("{case}: {e}"));
                assert!(matches!(outcome, DeadmanOutcome::RolledBack(_)), "{case}");
                assert_eq!(
                    state_of(&fs, &txn),
                    rolled_back(RollbackReason::DeadmanTimeout),
                    "{case}"
                );
            } else {
                // The reboot: a new boot ID, and the boot config's sysctls.
                fs.write(Path::new(BOOT_ID), b"b\n").unwrap();
                fs.write(Path::new(KPTR), b"0").unwrap();
                let done = boot_hook(&fs, &run).unwrap_or_else(|e| panic!("{case}: {e}"));
                // Only an armed transaction is the boot hook's.
                let armed = kept >= 2;
                assert_eq!(done.len(), usize::from(armed), "{case}");
                if !armed {
                    continue;
                }
                assert_eq!(
                    state_of(&fs, &txn),
                    rolled_back(RollbackReason::DeadmanReboot),
                    "{case}"
                );
                assert_eq!(calls(&run).last().unwrap(), DISABLE, "{case}");
                // At boot every command is bounded well under the hook's 120 s.
                assert!(
                    run.calls()
                        .iter()
                        .all(|c| c.timeout <= Duration::from_secs(20)),
                    "{case}"
                );
            }
            assert_eq!(host_without_hook(&fs), original, "{case}");
        }
    }
}

#[test]
fn a_timer_that_fires_mid_apply_waits_for_the_lock() {
    let fs = armable();
    let facts = facts();
    let [lock, ..] = locking();
    let plan = plan_of(&fs, &facts, &[&lock]);
    let state = state(&fs);
    let run = dm_runner();
    let held = Engine::lock(
        &state,
        Sys {
            fs: &fs,
            runner: &run,
        },
    )
    .unwrap();
    std::thread::scope(|s| {
        let waiting = s.spawn(|| {
            let engine = Engine::lock_wait(
                &state,
                Sys {
                    fs: &fs,
                    runner: &run,
                },
            )
            .unwrap();
            let txn = state.txns(&fs).unwrap().pop().unwrap();
            engine.deadman(txn.id(), Path::new(COPY), 0, &mut |_| {})
        });
        // Apply under the lock; the timer's rollback cannot start meanwhile.
        let outcome = held.apply(&plan, &deadman_cfg(), &mut |_| {}).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(!waiting.is_finished());
        assert!(matches!(outcome, ApplyOutcome::Pending { .. }));
        drop(held);
        // It then sees the pending state before its deadline and re-arms.
        let outcome = waiting.join().unwrap().unwrap();
        assert!(matches!(outcome, DeadmanOutcome::Rearmed(_)), "{outcome:?}");
    });
}

#[test]
fn the_boot_hook_leaves_a_transaction_of_this_boot() {
    let fs = armable();
    let facts = facts();
    let [lock, ..] = locking();
    let plan = plan_of(&fs, &facts, &[&lock]);
    let (txn, _) = pending(&fs, &plan);
    let run = dm_runner();
    assert!(boot_hook(&fs, &run).unwrap().is_empty());
    assert!(calls(&run).is_empty());
    assert!(matches!(
        state_of(&fs, &txn),
        TxnState::PendingConfirm { .. }
    ));

    // Nothing armed at all: the hook disables itself.
    let fs = armable();
    let run = dm_runner();
    assert!(boot_hook(&fs, &run).unwrap().is_empty());
    assert_eq!(calls(&run), [DISABLE]);
}

/// sshd has not started when the hook runs, so it reads the restored
/// config anyway; the hook neither checks nor reloads it.
#[test]
fn the_boot_hook_does_not_reload_sshd() {
    let fs = armable();
    let facts = facts();
    let before = host_without_hook(&fs);
    let [lock, ..] = locking();
    let plan = plan_of(&fs, &facts, &[&lock]);
    let (txn, _) = pending(&fs, &plan);
    fs.write(Path::new(BOOT_ID), b"b\n").unwrap();
    let run = dm_runner();
    assert_eq!(boot_hook(&fs, &run).unwrap().len(), 1);
    assert_eq!(calls(&run), [DISABLE]);
    assert_eq!(host_without_hook(&fs), before);
    assert_eq!(
        state_of(&fs, &txn),
        rolled_back(RollbackReason::DeadmanReboot)
    );
}

#[test]
fn a_manual_rollback_of_a_pending_transaction_disarms() {
    let fs = armable();
    let facts = facts();
    let before = host_without_hook(&fs);
    let [lock, keys, plain] = locking();
    let plan = plan_of(&fs, &facts, &[&lock, &keys, &plain]);
    let (txn, _) = pending(&fs, &plan);

    // The all-or-nothing check stays for a manual rollback.
    fs.write(Path::new(NEW), b"edited\n").unwrap();
    let run = dm_runner();
    let err = manual(&fs, &run).unwrap_err();
    assert!(
        matches!(err, EngineError::Changed { armed: true, .. }),
        "{err:?}"
    );
    assert!(
        err.to_string().ends_with(&format!(
            "\nIts dead-man rollback (the timer, or `vps-ready rollback --txn {txn} --deadman`) \
             still restores the files that can lock you out, changed or not."
        )),
        "{err}"
    );
    assert!(calls(&run).is_empty());
    fs.write(Path::new(NEW), b"created\n").unwrap();

    let run = dm_runner();
    manual(&fs, &run).unwrap();
    assert_eq!(host_without_hook(&fs), before);
    assert_eq!(state_of(&fs, &txn), rolled_back(RollbackReason::Manual));
    let unit = format!("vps-ready-deadman-{txn}-2");
    let calls = calls(&run);
    assert_eq!(
        calls[calls.len() - 2..],
        [
            format!("systemctl stop {unit}.timer {unit}.service"),
            DISABLE.to_owned(),
        ]
    );
}

#[test]
fn the_timer_and_the_boot_hook_run_a_private_copy_of_the_binary() {
    let fs = armable();
    let facts = facts();
    let [lock, ..] = locking();
    let plan = plan_of(&fs, &facts, &[&lock]);
    let run = dm_runner();
    let ApplyOutcome::Pending { txn, .. } = apply_dm(&fs, &run, &plan).unwrap() else {
        panic!("not pending");
    };

    assert_eq!(
        fs.read(Path::new(COPY)).unwrap(),
        fs.read(Path::new(BIN)).unwrap()
    );
    let meta = fs.metadata(Path::new(COPY)).unwrap();
    assert_eq!((meta.mode, meta.uid), (0o755, 0));
    assert_eq!(
        fs.read(Path::new(deadman::HOOK)).unwrap(),
        deadman::hook_unit(Path::new(COPY)).as_bytes()
    );
    assert_eq!(deadman::hook_binary(&fs).as_deref(), Some(Path::new(COPY)));
    let timers: Vec<String> = calls(&run)
        .into_iter()
        .filter(|c| c.starts_with("systemd-run"))
        .collect();
    assert_eq!(timers.len(), 2);
    for t in &timers {
        assert!(
            t.ends_with(&format!("{COPY} rollback --txn {txn} --deadman")),
            "{t}"
        );
    }

    // Moving or removing the installed binary changes nothing: the timer
    // and the boot hook run the copy.
    fs.remove(Path::new(BIN)).unwrap();
    set_uptime(&fs, 1400);
    let state = state(&fs);
    let run = dm_runner();
    let out = Engine::lock(
        &state,
        Sys {
            fs: &fs,
            runner: &run,
        },
    )
    .unwrap()
    .deadman(&txn, Path::new(COPY), 0, &mut |_| {})
    .unwrap();
    assert!(matches!(out, DeadmanOutcome::RolledBack(_)), "{out:?}");
    assert_eq!(
        state_of(&fs, &txn),
        rolled_back(RollbackReason::DeadmanTimeout)
    );
    // Kept, not removed: the next apply overwrites it.
    assert!(fs.exists(Path::new(COPY)));
}

#[test]
fn the_boot_hook_rolls_back_without_the_installed_binary() {
    let fs = armable();
    let facts = facts();
    let [lock, ..] = locking();
    let plan = plan_of(&fs, &facts, &[&lock]);
    let (txn, _) = pending(&fs, &plan);
    fs.remove(Path::new(BIN)).unwrap();
    fs.write(Path::new(BOOT_ID), b"b\n").unwrap();
    let state = state(&fs);
    let run = dm_runner();
    let done = Engine::lock(
        &state,
        Sys {
            fs: &fs,
            runner: &run,
        },
    )
    .unwrap()
    .deadman_boot(Path::new(COPY), &mut |_| {})
    .unwrap();
    assert_eq!(done.len(), 1);
    assert_eq!(
        state_of(&fs, &txn),
        rolled_back(RollbackReason::DeadmanReboot)
    );
}

#[test]
fn a_manual_rollback_never_depends_on_the_binary_path() {
    let fs = armable();
    let facts = facts();
    let [lock, ..] = locking();
    let plan = plan_of(&fs, &facts, &[&lock]);
    let (txn, _) = pending(&fs, &plan);
    fs.remove(Path::new(BIN)).unwrap();
    manual(&fs, &dm_runner()).unwrap();
    assert_eq!(state_of(&fs, &txn), rolled_back(RollbackReason::Manual));
    assert!(fs.exists(Path::new(COPY)));
}

#[test]
fn a_copy_left_by_a_failed_arm_does_not_break_the_next_apply() {
    let fs = armable();
    let facts = facts();
    let [lock, ..] = locking();
    let plan = plan_of(&fs, &facts, &[&lock]);
    let failing = runner(Output::success("")).on(
        "systemd-run",
        Vec::<String>::new(),
        failed("Failed to start transient timer unit"),
    );
    let outcome = apply_dm(&fs, &failing, &plan).unwrap();
    assert!(
        matches!(outcome, ApplyOutcome::RolledBack { .. }),
        "{outcome:?}"
    );
    assert!(fs.exists(Path::new(COPY)));
    // A newer binary replaces the stale copy.
    fs.write_atomic(
        Path::new(BIN),
        b"\x7fELF-new",
        FileOwner {
            mode: 0o755,
            uid: 0,
            gid: 0,
        },
    )
    .unwrap();
    pending(&fs, &plan);
    assert_eq!(fs.read(Path::new(COPY)).unwrap(), b"\x7fELF-new");
}

#[test]
fn an_unsafe_binary_is_refused_before_it_is_copied() {
    let fs = armable();
    let facts = facts();
    let [lock, ..] = locking();
    let plan = plan_of(&fs, &facts, &[&lock]);
    fs.write_atomic(
        Path::new(BIN),
        b"\x7fELF",
        FileOwner {
            mode: 0o777,
            uid: 0,
            gid: 0,
        },
    )
    .unwrap();
    let err = apply_dm(&fs, &dm_runner(), &plan).unwrap_err();
    assert!(matches!(err, EngineError::UnsafeBinary { .. }), "{err:?}");
    assert!(!fs.exists(Path::new(COPY)));
}

#[test]
fn a_resumed_rollback_of_an_armed_transaction_keeps_the_dead_man_reason() {
    let facts = facts();
    let [lock, ..] = locking();
    // (boot ID, uptime) at the manual rollback, and the reason it records.
    let cases = [
        ("a", 1100, RollbackReason::Manual),
        ("a", 5000, RollbackReason::DeadmanTimeout),
        ("b", 10, RollbackReason::DeadmanReboot),
    ];
    for (boot, uptime, reason) in cases {
        // A pending transaction, and one that stopped part way.
        for stopped in [false, true] {
            let fs = armable();
            let plan = plan_of(&fs, &facts, &[&lock]);
            let (txn, _) = pending(&fs, &plan);
            if stopped {
                let path = PathBuf::from(format!("{STATE}/txn/{txn}/journal.jsonl"));
                let bytes = fs.read(&path).unwrap();
                let lines: Vec<&[u8]> = bytes.split_inclusive(|b| *b == b'\n').collect();
                fs.write(&path, &lines[..lines.len() - 1].concat()).unwrap();
            }
            fs.write(Path::new(BOOT_ID), format!("{boot}\n").as_bytes())
                .unwrap();
            set_uptime(&fs, uptime);
            manual(&fs, &dm_runner()).unwrap();
            assert_eq!(
                state_of(&fs, &txn),
                rolled_back(reason),
                "{boot} {uptime} {stopped}"
            );
        }
    }
}

#[test]
fn a_created_account_whose_name_was_taken_since_is_not_removed() {
    let fs = armable();
    let state = state(&fs);
    let txn = state.create_txn(&fs, 1).unwrap();
    let rec = |event| Record { at: 1, event };
    let resource = "user:admin".to_owned();
    let records = [
        rec(Event::Begin {
            version: "0.3.0".into(),
            modules: vec!["user.admin".into()],
        }),
        rec(Event::Armed {
            unit: deadman::unit_name(txn.id(), 1),
            boot_id: "a".into(),
            deadline: Deadline {
                boottime: 1100,
                wall: 1,
            },
        }),
        rec(Event::Backup {
            resource: resource.clone(),
            backup: Backup::User {
                name: "admin".into(),
                created: true,
                added_groups: Vec::new(),
            },
            force_restore: false,
        }),
        rec(Event::Applied {
            resource: resource.clone(),
            uid: Some(1001),
        }),
    ];
    for r in &records {
        txn.append(&fs, r).unwrap();
    }
    // The account apply created is gone; another one has its name.
    let run = dm_runner()
        .on(
            "getent",
            ["passwd", "admin"],
            Output::success("admin:x:1002:1002::/home/admin:/bin/bash\n"),
        )
        .on("userdel", Vec::<String>::new(), Output::success(""));
    let err = manual(&fs, &run).unwrap_err();
    assert!(matches!(err, EngineError::Changed { .. }), "{err:?}");

    set_uptime(&fs, 5000);
    let DeadmanOutcome::RolledBack(done) = timer(&fs, &run, txn.id()).unwrap() else {
        panic!("not rolled back");
    };
    assert_eq!(
        done.skipped,
        [ByHand {
            resource,
            step: "pkill -u admin; userdel admin".into(),
        }]
    );
    assert!(!calls(&run).iter().any(|c| c.starts_with("userdel")));
}

/// `user.admin` then `ssh.server`, as a plan that sets up an admin and
/// turns off root and password login journals them.
#[test]
fn a_failed_forced_restore_keeps_the_admin_it_relies_on() {
    let fs = armable();
    let state = state(&fs);
    let txn = state.create_txn(&fs, 1).unwrap();
    let dir = txn.dir().to_path_buf();
    let rec = |event| Record { at: 1, event };
    let applied = |resource: &str, uid| {
        rec(Event::Applied {
            resource: resource.into(),
            uid,
        })
    };
    let keys = "/home/admin/.ssh/authorized_keys";
    let drop_in = crate::modules::ssh_server::DROP_IN;
    let records = [
        rec(Event::Begin {
            version: "0.3.0".into(),
            modules: vec!["user.admin".into(), "ssh.server".into()],
        }),
        rec(Event::Armed {
            unit: deadman::unit_name(txn.id(), 1),
            boot_id: "a".into(),
            deadline: Deadline {
                boottime: 1100,
                wall: 1,
            },
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
        applied("user:admin", Some(1001)),
        rec(Event::Backup {
            resource: "authorized-keys:admin".into(),
            backup: Backup::AuthorizedKeys {
                user: "admin".into(),
                path: keys.into(),
                n: 1,
                original: None,
                created_dir: true,
            },
            force_restore: false,
        }),
        applied("authorized-keys:admin", None),
        rec(Event::Backup {
            resource: format!("file:{drop_in}"),
            backup: Backup::File {
                path: drop_in.into(),
                n: 2,
                original: None,
            },
            force_restore: true,
        }),
        applied(&format!("file:{drop_in}"), None),
        rec(Event::Reloaded {
            reload: Reload::SshdReload,
        }),
    ];
    for r in &records {
        txn.append(&fs, r).unwrap();
    }
    let key = owner(0o600);
    for (path, after, bytes) in [
        (keys, after_path(&dir, 1), "ssh-ed25519 AAAA admin\n"),
        (drop_in, after_path(&dir, 2), "PermitRootLogin no\n"),
    ] {
        let path = Path::new(path);
        fs.create_dir_all(path.parent().unwrap(), 0o700).unwrap();
        fs.write_atomic(&after, bytes.as_bytes(), key).unwrap();
        fs.write_atomic(path, bytes.as_bytes(), key).unwrap();
    }
    let run = dm_runner()
        .on(
            "getent",
            ["passwd", "admin"],
            Output::success("admin:x:1001:1001::/home/admin:/bin/bash\n"),
        )
        .on("userdel", Vec::<String>::new(), Output::success(""));

    // The drop-in's removal, the first restore, fails.
    set_uptime(&fs, 5000);
    fs.fail_next(Op::Remove);
    let err = timer(&fs, &run, txn.id()).unwrap_err();
    let EngineError::RollbackIncomplete {
        left: Some(left), ..
    } = &err
    else {
        panic!("{err:?}");
    };
    let steps: Vec<String> = left.iter().map(ToString::to_string).collect();
    assert_eq!(
        steps,
        [
            format!("file:{drop_in}: remove {drop_in}"),
            format!(
                "authorized-keys:admin: only after the steps above succeed, remove {keys}, \
                 then rmdir /home/admin/.ssh"
            ),
            "user:admin: only after the steps above succeed, pkill -u admin; userdel admin"
                .to_owned(),
        ]
    );
    assert!(fs.exists(Path::new(drop_in)));
    assert!(fs.exists(Path::new(keys)));
    assert!(!calls(&run).iter().any(|c| c.starts_with("userdel")));

    // A rerun that can remove the drop-in restores the rest as well.
    let DeadmanOutcome::RolledBack(done) = timer(&fs, &run, txn.id()).unwrap() else {
        panic!("not rolled back");
    };
    assert_eq!(done.restored, 3);
    assert!(!fs.exists(Path::new(drop_in)));
    assert!(!fs.exists(Path::new(keys)));
    assert!(calls(&run).contains(&"userdel admin".to_owned()));
}

#[test]
fn rollback_last_picks_pending_then_the_newest_applied_or_confirmed() {
    let fs = armable();
    let state = state(&fs);
    let rec = |event| Record { at: 1, event };
    let begin = || {
        rec(Event::Begin {
            version: "0.3.0".into(),
            modules: Vec::new(),
        })
    };
    let pending_state = TxnState::PendingConfirm {
        deadline: Deadline {
            boottime: 1300,
            wall: 1,
        },
        live_since: 1000,
        session: None,
    };
    let journals: [(u64, Vec<Record>); 3] = [
        (10, vec![begin(), rec(Event::state(TxnState::Applied))]),
        (
            20,
            vec![
                begin(),
                rec(Event::state(pending_state)),
                rec(Event::state(TxnState::Confirmed)),
            ],
        ),
        (5, vec![begin(), rec(Event::state(pending_state))]),
    ];
    let mut ids = Vec::new();
    for (at, records) in &journals {
        let txn = state.create_txn(&fs, *at).unwrap();
        for r in records {
            txn.append(&fs, r).unwrap();
        }
        ids.push(txn.id().to_owned());
    }
    let order: Vec<String> = (0..3)
        .map(|_| manual(&fs, &dm_runner()).unwrap().txn)
        .collect();
    // The pending one, though oldest; then the confirmed, then the applied.
    assert_eq!(order, [ids[2].clone(), ids[1].clone(), ids[0].clone()]);
    assert!(matches!(
        manual(&fs, &dm_runner()),
        Err(EngineError::NothingToRollBack)
    ));
}

/// [`dm_runner`], except that the `n`-th `systemd-run` fails; then, with
/// `fs`, every rename fails too, so a rollback cannot complete.
struct FailingArm<'a> {
    inner: FakeRunner,
    n: usize,
    seen: std::sync::Mutex<usize>,
    fs: Option<&'a FakeFs>,
}

impl<'a> FailingArm<'a> {
    fn new(n: usize, fs: Option<&'a FakeFs>) -> Self {
        Self {
            inner: dm_runner(),
            n,
            seen: std::sync::Mutex::new(0),
            fs,
        }
    }
}

impl crate::sys::Runner for FailingArm<'_> {
    fn run(&self, cmd: &crate::sys::Cmd) -> Result<Output, crate::sys::SysError> {
        if cmd.program == "systemd-run" {
            let mut seen = self.seen.lock().unwrap();
            *seen += 1;
            if *seen == self.n {
                if let Some(fs) = self.fs {
                    fs.fail_from(Op::Rename, 1);
                }
                return Ok(failed("Failed to start transient timer unit"));
            }
        }
        self.inner.run(cmd)
    }
}

#[test]
fn a_failed_re_arm_keeps_the_first_timer_until_the_rollback_finished() {
    let facts = facts();
    let [lock, ..] = locking();
    for incomplete in [false, true] {
        let fs = armable();
        let before = host_without_hook(&fs);
        let plan = plan_of(&fs, &facts, &[&lock]);
        let run = FailingArm::new(2, incomplete.then_some(&fs));
        let state = state(&fs);
        let result = Engine::lock(
            &state,
            Sys {
                fs: &fs,
                runner: &run,
            },
        )
        .unwrap()
        .apply(&plan, &deadman_cfg(), &mut |_| {});
        let txn = state.txns(&fs).unwrap().pop().unwrap();
        let first = format!("vps-ready-deadman-{}-1", txn.id());
        let stops: Vec<String> = calls(&run.inner)
            .into_iter()
            .filter(|c| c.starts_with("systemctl stop") || c == DISABLE)
            .collect();
        if incomplete {
            // The host is still changed: the first timer must stay to finish it.
            assert!(
                matches!(result, Err(EngineError::RollbackIncomplete { .. })),
                "{result:?}"
            );
            assert_eq!(stops, Vec::<String>::new());
        } else {
            let outcome = result.unwrap();
            assert!(
                matches!(
                    outcome,
                    ApplyOutcome::RolledBack {
                        reason: RollbackReason::ApplyFailed,
                        ..
                    }
                ),
                "{outcome:?}"
            );
            assert_eq!(host_without_hook(&fs), before);
            assert_eq!(
                stops,
                [
                    format!("systemctl stop {first}.timer {first}.service"),
                    DISABLE.to_owned(),
                ]
            );
        }
    }
}

#[test]
fn an_incomplete_timer_rollback_is_retried_a_few_times() {
    let fs = armable();
    let facts = facts();
    let [lock, ..] = locking();
    let plan = plan_of(&fs, &facts, &[&lock]);
    let (txn, _) = pending(&fs, &plan);
    set_uptime(&fs, 5000);
    // Restoring the drop-in fails until the disk has space again.
    fs.fail_from(Op::Rename, 1);
    let state = state(&fs);
    let attempt = |n: u32, run: &FakeRunner| {
        Engine::lock(
            &state,
            Sys {
                fs: &fs,
                runner: run,
            },
        )
        .unwrap()
        .deadman(&txn, Path::new(COPY), n, &mut |_| {})
    };

    let run = dm_runner();
    let err = attempt(0, &run).unwrap_err();
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
    assert_eq!(names(&fs, &txn).last().unwrap(), "retry 1");
    assert!(!calls(&run).contains(&DISABLE.to_owned()));

    // The last retry gives up and leaves the rest to the boot hook.
    let run = dm_runner();
    assert!(attempt(5, &run).is_err());
    assert!(!calls(&run).iter().any(|c| c.starts_with("systemd-run")));

    fs.heal();
    let run = dm_runner();
    let outcome = attempt(1, &run).unwrap();
    assert!(
        matches!(outcome, DeadmanOutcome::RolledBack(_)),
        "{outcome:?}"
    );
    assert_eq!(
        state_of(&fs, &txn),
        rolled_back(RollbackReason::DeadmanTimeout)
    );
    // The timer of the retry is the last unit: only it is stopped, by itself.
    assert!(calls(&run).contains(&format!("systemctl stop --no-block {retry}.timer")));
}

#[test]
fn every_command_of_the_boot_hook_is_bounded() {
    let fs = armable();
    let state = state(&fs);
    let txn = state.create_txn(&fs, 1).unwrap();
    let rec = |event| Record { at: 1, event };
    let applied = |resource: &str| {
        rec(Event::Applied {
            resource: resource.into(),
            uid: None,
        })
    };
    let records = [
        rec(Event::Begin {
            version: "0.3.0".into(),
            modules: vec!["user.admin".into(), "ssh.bruteforce".into()],
        }),
        rec(Event::Armed {
            unit: deadman::unit_name(txn.id(), 1),
            boot_id: "a".into(),
            deadline: Deadline {
                boottime: 1100,
                wall: 1,
            },
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
        applied("user:admin"),
        rec(Event::Backup {
            resource: "service:fail2ban.service".into(),
            backup: Backup::Service {
                unit: "fail2ban.service".into(),
                was_enabled: false,
                was_active: false,
                enabled: true,
                active: true,
            },
            force_restore: false,
        }),
        applied("service:fail2ban.service"),
        rec(Event::Reloaded {
            reload: Reload::Fail2banRestart,
        }),
    ];
    for r in &records {
        txn.append(&fs, r).unwrap();
    }
    fs.write(Path::new(BOOT_ID), b"b\n").unwrap();
    // The first matching rule answers, so `show` goes before `systemctl`.
    let run = FakeRunner::new()
        .on(
            "systemctl",
            ["show"],
            Output::success("LoadState=loaded\nUnitFileState=enabled\nActiveState=active\n"),
        )
        .on("systemctl", Vec::<String>::new(), Output::success(""))
        .on(
            "getent",
            ["passwd", "admin"],
            Output::success("admin:x:1001:1001::/home/admin:/bin/bash\n"),
        )
        .on("fail2ban-client", ["-t"], Output::success(""))
        .on("userdel", Vec::<String>::new(), Output::success(""));
    let done = boot_hook(&fs, &run).unwrap();
    assert_eq!(done.len(), 1);
    let calls = calls(&run);
    for expected in [
        "systemctl stop fail2ban.service",
        "systemctl disable fail2ban.service",
        "userdel admin",
        DISABLE,
    ] {
        assert!(calls.iter().any(|c| c == expected), "{expected}: {calls:?}");
    }
    let unbounded: Vec<String> = run
        .calls()
        .iter()
        .filter(|c| c.timeout > Duration::from_secs(20))
        .map(|c| format!("{} {}", c.program, c.args.join(" ")))
        .collect();
    assert_eq!(unbounded, Vec::<String>::new());
}

#[test]
fn the_first_deadline_covers_package_installs_and_verify_probes() {
    let fs = armable();
    let facts = facts();
    let pkg = Demo {
        deadman: true,
        ..module(
            "test.pkg",
            vec![Resource::Package(crate::resource::Package {
                name: "nftables".into(),
            })],
        )
    };
    let run = dm_runner()
        .on("dpkg-query", ["-W"], Output::success("not-installed"))
        .on("apt-get", Vec::<String>::new(), Output::success(""));
    let sys = Sys {
        fs: &fs,
        runner: &run,
    };
    let plan = plan(&[Selected::new(&pkg)], &facts, sys).unwrap();
    let state = state(&fs);
    // dpkg-query still says not installed, so verify fails; the first timer
    // is armed by then.
    Engine::lock(&state, sys)
        .unwrap()
        .apply(&plan, &deadman_cfg(), &mut |_| {})
        .unwrap();
    let txn = state.txns(&fs).unwrap().pop().unwrap();
    // The window; dpkg-query and two apt-get runs (30 + 2 * 600 s), and
    // dpkg-query again in verify (30 s); the module's verify (30 s); the
    // re-arm (120 + 30 s).
    let first = 300 + 1230 + 30 + 30 + 150;
    assert!(
        calls(&run).contains(&systemd_run(txn.id(), 1, first)),
        "{:?}",
        calls(&run)
    );
}

mod confirm;
