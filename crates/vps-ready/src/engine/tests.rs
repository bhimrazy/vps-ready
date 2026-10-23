//! Apply, rollback and history on a [`FakeFs`], compared as trees of files.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::*;
use crate::facts::Facts;
use crate::modules::{Applicability, Module, ModuleError};
use crate::resource::sysctl::BOOT_ID;
use crate::resource::{Backup, File, Resource, Sysctl};
use crate::sys::fake::{FakeFs, FakeRunner, Op};
use crate::sys::{FileKind, FileOwner, Fs, Sys};

const STATE: &str = "/state";
const CONF: &str = "/etc/demo.conf";
const NEW: &str = "/etc/demo.d/new.conf";
const KPTR: &str = "/proc/sys/kernel/kptr_restrict";

struct Demo {
    id: &'static str,
    resources: Vec<Resource>,
    applicable: bool,
}

impl Module for Demo {
    fn id(&self) -> &'static str {
        self.id
    }
    fn title(&self) -> &'static str {
        "Demo"
    }
    fn why(&self) -> &'static str {
        "For tests."
    }
    fn applicable(&self, _: &Facts) -> Applicability {
        if self.applicable {
            Applicability::Applicable
        } else {
            Applicability::NotApplicable {
                reason: "not here".into(),
            }
        }
    }
    fn plan(&self, _: &Facts, _: Sys) -> Result<Vec<Resource>, ModuleError> {
        Ok(self.resources.clone())
    }
}

fn owner(mode: u32) -> FileOwner {
    FileOwner {
        mode,
        uid: 0,
        gid: 0,
    }
}

fn file(path: &str, content: &str, mode: u32) -> Resource {
    Resource::File(File {
        path: path.into(),
        content: content.into(),
        owner: owner(mode),
        validate: None,
    })
}

fn sysctl(key: &str, value: &str) -> Resource {
    Resource::Sysctl(Sysctl {
        key: key.into(),
        value: value.into(),
    })
}

fn module(id: &'static str, resources: Vec<Resource>) -> Demo {
    Demo {
        id,
        resources,
        applicable: true,
    }
}

/// Changes an existing file (content and mode), creates one, and changes one
/// sysctl; a second sysctl is already as desired.
fn demo() -> Demo {
    module(
        "test.demo",
        vec![
            file(CONF, "new\n", 0o600),
            file(NEW, "created\n", 0o644),
            sysctl("kernel.kptr_restrict", "1"),
            sysctl("kernel.dmesg_restrict", "1"),
        ],
    )
}

fn fixture() -> FakeFs {
    FakeFs::new()
        .with_file(CONF, "old\n")
        .with_file("/etc/demo.d/keep", "keep\n")
        .with_file(KPTR, "0")
        .with_file("/proc/sys/kernel/dmesg_restrict", "1")
}

fn facts() -> Facts {
    crate::facts::fixtures::host("debian-13", &[])
}

fn sys(fs: &dyn Fs) -> Sys<'_> {
    static RUNNER: std::sync::LazyLock<FakeRunner> = std::sync::LazyLock::new(FakeRunner::new);
    Sys {
        fs,
        runner: &*RUNNER,
    }
}

fn state(fs: &dyn Fs) -> StateDir {
    StateDir::create(fs, STATE, 0).unwrap()
}

fn plan_of(fs: &dyn Fs, facts: &Facts, modules: &[&dyn Module]) -> Plan {
    plan(modules, facts, sys(fs)).unwrap()
}

fn apply(fs: &dyn Fs, plan: &Plan) -> Result<ApplyOutcome, EngineError> {
    let state = state(fs);
    Engine::lock(&state, sys(fs))?.apply(plan, &mut |_| {})
}

fn rollback(fs: &dyn Fs, target: Target) -> Result<Rollback, EngineError> {
    let state = state(fs);
    Engine::lock(&state, sys(fs))?.rollback(target, &mut |_| {})
}

fn events(fs: &dyn Fs, id: &str) -> Vec<Event> {
    let txn = state(fs)
        .txns(fs)
        .unwrap()
        .into_iter()
        .find(|t| t.id() == id)
        .unwrap();
    txn.read(fs).unwrap().into_iter().map(|r| r.event).collect()
}

/// Every file with its bytes, mode and owner.
type Tree = BTreeMap<PathBuf, (Vec<u8>, FileOwner)>;

fn tree(fs: &dyn Fs) -> Tree {
    fn walk(fs: &dyn Fs, dir: &Path, out: &mut Tree) {
        for path in fs.read_dir(dir).unwrap() {
            let meta = fs.metadata(&path).unwrap();
            match meta.kind {
                FileKind::Dir => walk(fs, &path, out),
                FileKind::File => {
                    out.insert(path.clone(), (fs.read(&path).unwrap(), meta.owner()));
                }
                kind => panic!("{} is {kind:?}", path.display()),
            }
        }
    }
    let mut out = Tree::new();
    walk(fs, Path::new("/"), &mut out);
    out
}

/// The tree outside the state directory.
fn host(fs: &dyn Fs) -> Tree {
    let mut tree = tree(fs);
    tree.retain(|p, _| !p.starts_with(STATE));
    tree
}

fn load(tree: &Tree) -> FakeFs {
    let fs = tree.iter().fold(FakeFs::new(), |fs, (path, (bytes, _))| {
        fs.with_file(path, bytes.clone())
    });
    for (path, (bytes, owner)) in tree {
        fs.write_atomic(path, bytes, *owner).unwrap();
    }
    fs
}

fn ids(plan: &Plan) -> Vec<&str> {
    plan.steps().map(|s| s.change.id.as_str()).collect()
}

#[test]
fn plans_changes_and_lists_modules_that_do_not_apply() {
    let fs = fixture();
    let facts = facts();
    let other = Demo {
        applicable: false,
        ..module("test.other", vec![file("/etc/other", "x", 0o644)])
    };
    let plan = plan_of(&fs, &facts, &[&demo(), &other]);
    assert_eq!(
        ids(&plan),
        [
            "file:/etc/demo.conf",
            "file:/etc/demo.d/new.conf",
            "sysctl:kernel.kptr_restrict"
        ]
    );
    assert_eq!(plan.changed_modules(), ["test.demo"]);
    let json = serde_json::to_value(&plan).unwrap();
    assert_eq!(json["modules"][0]["status"], "applicable");
    assert_eq!(
        json["modules"][0]["changes"][2]["summary"],
        "kernel.kptr_restrict 0 -> 1"
    );
    assert_eq!(
        json["modules"][1],
        serde_json::json!({"id": "test.other", "title": "Demo", "status": "not-applicable", "reason": "not here"})
    );
}

#[test]
fn applies_then_rolls_back_to_the_original_tree() {
    let fs = fixture();
    let facts = facts();
    let before = host(&fs);
    let plan = plan_of(&fs, &facts, &[&demo()]);

    let ApplyOutcome::Applied { txn } = apply(&fs, &plan).unwrap() else {
        panic!("not applied");
    };
    assert_eq!(fs.read(Path::new(CONF)).unwrap(), b"new\n");
    assert_eq!(fs.metadata(Path::new(CONF)).unwrap().mode, 0o600);
    assert_eq!(fs.read(Path::new(NEW)).unwrap(), b"created\n");
    assert_eq!(fs.read(Path::new(KPTR)).unwrap(), b"1");
    assert!(ids(&plan_of(&fs, &facts, &[&demo()])).is_empty());

    let done = rollback(&fs, Target::Last).unwrap();
    assert_eq!(
        done,
        Rollback {
            txn: txn.clone(),
            restored: 3,
            at_next_boot: Vec::new(),
        }
    );
    assert_eq!(host(&fs), before);

    let names: Vec<String> = events(&fs, &txn)
        .iter()
        .map(|e| match e {
            Event::Backup { resource, .. }
            | Event::Applied { resource }
            | Event::Restored { resource } => format!("{} {resource}", e.name()),
            Event::State { state } => format!("state {state}"),
            Event::Begin { .. } => "begin".into(),
            Event::Rollback { .. } => "rollback".into(),
        })
        .collect();
    assert_eq!(
        names,
        [
            "begin",
            "backup file:/etc/demo.conf",
            "applied file:/etc/demo.conf",
            "backup file:/etc/demo.d/new.conf",
            "applied file:/etc/demo.d/new.conf",
            "backup sysctl:kernel.kptr_restrict",
            "applied sysctl:kernel.kptr_restrict",
            "state applied",
            "rollback",
            "restored sysctl:kernel.kptr_restrict",
            "restored file:/etc/demo.d/new.conf",
            "restored file:/etc/demo.conf",
            "state rolled-back (manual)",
        ]
    );

    assert!(matches!(
        rollback(&fs, Target::Last),
        Err(EngineError::NothingToRollBack)
    ));
    assert!(matches!(
        rollback(&fs, Target::Txn(&txn)),
        Err(EngineError::AlreadyRolledBack(id)) if id == txn
    ));
    assert!(matches!(
        rollback(&fs, Target::Txn("20261023T114246Z")),
        Err(EngineError::UnknownTxn(_))
    ));
}

#[test]
fn an_empty_plan_creates_no_transaction() {
    let fs = fixture();
    let facts = facts();
    let done = module("test.done", vec![sysctl("kernel.dmesg_restrict", "1")]);
    let plan = plan_of(&fs, &facts, &[&done]);
    assert!(matches!(apply(&fs, &plan), Ok(ApplyOutcome::NothingToDo)));
    assert!(state(&fs).txns(&fs).unwrap().is_empty());
}

#[test]
fn a_plan_that_changed_after_it_was_shown_aborts() {
    let fs = fixture();
    let facts = facts();
    let plan = plan_of(&fs, &facts, &[&demo()]);
    fs.write(Path::new(CONF), b"edited\n").unwrap();
    let edited = host(&fs);
    let err = apply(&fs, &plan).unwrap_err();
    assert!(
        matches!(&err, EngineError::PlanChanged(id) if id == "file:/etc/demo.conf"),
        "{err:?}"
    );
    assert!(state(&fs).txns(&fs).unwrap().is_empty());
    assert_eq!(host(&fs), edited);
}

#[test]
fn a_failed_verify_rolls_back() {
    // Both keys are one file, so the second write undoes the first.
    let fs = FakeFs::new()
        .with_file("/proc/sys/test/a", "0")
        .with_symlink("/proc/sys/test/b", "/proc/sys/test/a");
    let facts = facts();
    let both = module(
        "test.both",
        vec![sysctl("test.a", "1"), sysctl("test.b", "2")],
    );
    let plan = plan_of(&fs, &facts, &[&both]);
    let outcome = apply(&fs, &plan).unwrap();
    let ApplyOutcome::RolledBack { reason, cause, .. } = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(reason, RollbackReason::VerifyFailed);
    assert!(matches!(&cause, EngineError::VerifyFailed(ids) if ids == &["sysctl:test.a"]));
    assert_eq!(fs.read(Path::new("/proc/sys/test/a")).unwrap(), b"0");
    let history = history(&state(&fs), &fs).unwrap();
    assert_eq!(
        history[0].state,
        TxnState::RolledBack {
            reason: RollbackReason::VerifyFailed
        }
    );
}

/// Every backup in the journal has a `restored` line.
fn all_restored(fs: &dyn Fs, id: &str) -> bool {
    let events = events(fs, id);
    events.iter().all(|e| match e {
        Event::Backup { resource, .. } => events
            .iter()
            .any(|r| matches!(r, Event::Restored { resource: x } if x == resource)),
        _ => true,
    })
}

#[test]
fn a_failure_at_any_write_rename_remove_or_append_is_rolled_back() {
    let facts = facts();
    let plan = plan_of(&fixture(), &facts, &[&demo()]);
    let original = host(&fixture());

    // Calls of each op that fail apply, then rollback, for `demo()`.
    let expected = [
        (Op::Write, 6, 2),
        (Op::Rename, 5, 1),
        (Op::Remove, 0, 1),
        (Op::Append, 9, 5),
    ];
    for (op, apply_calls, rollback_calls) in expected {
        let (mut in_apply, mut in_rollback) = (0, 0);
        for n in 1.. {
            assert!(n < 100, "{op:?} never stopped failing");
            let fs = fixture().fail(op, n);
            match apply(&fs, &plan) {
                Ok(ApplyOutcome::Applied { txn }) => match rollback(&fs, Target::Last) {
                    // Past the last call of `op`.
                    Ok(_) => break,
                    Err(EngineError::RollbackIncomplete { .. }) => {
                        in_rollback += 1;
                        // Unfinished unless the `rollback` line itself failed,
                        // in which case nothing was restored.
                        let started = events(&fs, &txn)
                            .iter()
                            .any(|e| matches!(e, Event::Rollback { .. }));
                        if started {
                            assert!(
                                matches!(apply(&fs, &plan), Err(EngineError::Unfinished(_))),
                                "{op:?} {n}"
                            );
                        }
                        rollback(&fs, Target::Last).unwrap();
                    }
                    Err(e) => panic!("{op:?} {n}: {e:?}"),
                },
                Ok(ApplyOutcome::RolledBack { txn, reason, .. }) => {
                    in_apply += 1;
                    assert_eq!(reason, RollbackReason::ApplyFailed, "{op:?} {n}");
                    assert!(all_restored(&fs, &txn), "{op:?} {n}");
                    assert_eq!(
                        history(&state(&fs), &fs).unwrap()[0].state,
                        TxnState::RolledBack {
                            reason: RollbackReason::ApplyFailed
                        }
                    );
                }
                // Creating the transaction or its `begin` line failed.
                Err(EngineError::Sys(_)) => {
                    in_apply += 1;
                    assert!(history(&state(&fs), &fs).unwrap().is_empty());
                }
                other => panic!("{op:?} {n}: {other:?}"),
            }
            assert_eq!(host(&fs), original, "{op:?} {n}");
            assert!(state(&fs).unfinished(&fs).unwrap().is_empty());
        }
        assert_eq!(
            (in_apply, in_rollback),
            (apply_calls, rollback_calls),
            "{op:?}"
        );
    }
}

#[test]
fn a_failed_first_restored_line_leaves_the_transaction_unfinished() {
    let facts = facts();
    let plan = plan_of(&fixture(), &facts, &[&demo()]);
    let original = host(&fixture());
    // Apply appends 9 lines (the empty journal counts); then `rollback`, then
    // the first `restored`.
    let fs = fixture().fail(Op::Append, 11);
    let ApplyOutcome::Applied { txn } = apply(&fs, &plan).unwrap() else {
        panic!("not applied");
    };
    let err = rollback(&fs, Target::Last).unwrap_err();
    assert!(
        matches!(&err, EngineError::RollbackIncomplete { left: Some(left), .. } if left.len() == 3),
        "{err:?}"
    );
    assert!(matches!(
        apply(&fs, &plan),
        Err(EngineError::Unfinished(id)) if id == txn
    ));
    rollback(&fs, Target::Last).unwrap();
    assert_eq!(host(&fs), original);
}

#[test]
fn a_plan_that_changes_a_resource_twice_is_refused() {
    let fs = fixture();
    let facts = facts();
    let twice = module(
        "test.twice",
        vec![file(CONF, "v1\n", 0o644), file(CONF, "v2\n", 0o644)],
    );
    let plan = plan_of(&fs, &facts, &[&twice]);
    let err = apply(&fs, &plan).unwrap_err();
    assert!(
        matches!(&err, EngineError::DuplicateResource(id) if id == "file:/etc/demo.conf"),
        "{err:?}"
    );
    assert!(state(&fs).txns(&fs).unwrap().is_empty());
}

#[test]
fn a_failed_rollback_after_a_failed_apply_finishes_on_a_rerun() {
    let facts = facts();
    let plan = plan_of(&fixture(), &facts, &[&demo()]);
    let original = host(&fixture());
    let mut incomplete = 0;
    for n in 1..100 {
        // Removing the created file is the rollback's only remove.
        let fs = fixture().fail(Op::Write, n).fail(Op::Remove, 1);
        match apply(&fs, &plan) {
            Ok(ApplyOutcome::Applied { .. }) => break,
            Err(EngineError::RollbackIncomplete { txn, left, .. }) => {
                incomplete += 1;
                let left = left.unwrap();
                assert_eq!(left.last().unwrap().step, format!("remove {NEW}"));
                assert!(matches!(apply(&fs, &plan), Err(EngineError::Unfinished(_))));
                rollback(&fs, Target::Last).unwrap();
                // The rerun keeps the reason of the rollback it resumed.
                assert_eq!(
                    history(&state(&fs), &fs).unwrap()[0].state,
                    TxnState::RolledBack {
                        reason: RollbackReason::ApplyFailed
                    },
                    "{txn}"
                );
            }
            Ok(ApplyOutcome::RolledBack { .. }) | Err(EngineError::Sys(_)) => {}
            Ok(other) => panic!("{n}: {other:?}"),
            Err(e) => panic!("{n}: {e:?}"),
        }
        assert_eq!(host(&fs), original, "{n}");
    }
    assert!(incomplete > 0);
}

#[test]
fn a_crash_at_any_point_is_refused_by_apply_and_undone_by_rollback() {
    let facts = facts();
    let original_fs = fixture();
    let plan = plan_of(&original_fs, &facts, &[&demo()]);
    let original = tree(&original_fs);

    let fs = fixture();
    let ApplyOutcome::Applied { txn } = apply(&fs, &plan).unwrap() else {
        panic!("not applied");
    };
    let applied = tree(&fs);
    let journal = PathBuf::from(format!("{STATE}/txn/{txn}/journal.jsonl"));
    let bytes = &applied[&journal].0;
    let lines: Vec<&[u8]> = bytes.split_inclusive(|b| *b == b'\n').collect();
    let target = |id: &str| match id.strip_prefix("file:") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(format!(
            "/proc/sys/{}",
            id.trim_start_matches("sysctl:").replace('.', "/")
        )),
    };

    for kept in 0..=lines.len() {
        let torn: &[&[u8]] = match lines.get(kept) {
            Some(line) => &[b"", &line[..line.len() / 2]],
            None => &[b""],
        };
        let records: Vec<Event> = journal::parse(&journal, &lines[..kept].concat())
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect();
        let has = |name: &str, id: &str| {
            records.iter().any(|e| match e {
                Event::Backup { resource, .. } | Event::Applied { resource } => {
                    e.name() == name && resource == id
                }
                _ => false,
            })
        };
        // A resource with a `backup` line but no `applied` line may or may
        // not have been changed when the crash came.
        for changed_unjournaled in [false, true] {
            for torn in torn {
                let mut tree = applied.clone();
                for step in plan.steps() {
                    let id = &step.change.id;
                    let changed = has("applied", id) || (changed_unjournaled && has("backup", id));
                    let path = target(id);
                    match (changed, original.get(&path)) {
                        (true, _) => {}
                        (false, Some(entry)) => {
                            tree.insert(path, entry.clone());
                        }
                        (false, None) => {
                            tree.remove(&path);
                        }
                    }
                }
                tree.get_mut(&journal).unwrap().0 = [&lines[..kept].concat(), *torn].concat();
                let fs = load(&tree);
                let case = format!("{kept} lines, torn {}, {changed_unjournaled}", torn.len());

                let st = state(&fs);
                let finished = Engine::lock(&st, sys(&fs)).unwrap().ensure_finished();
                if kept == 0 {
                    // No `begin` line: nothing changed and nothing is unfinished.
                    finished.unwrap();
                    assert!(matches!(
                        rollback(&fs, Target::Last),
                        Err(EngineError::NothingToRollBack)
                    ));
                } else {
                    if kept < lines.len() {
                        assert!(
                            matches!(&finished, Err(EngineError::Unfinished(id)) if *id == txn),
                            "{case}: {finished:?}"
                        );
                        assert!(
                            matches!(apply(&fs, &plan), Err(EngineError::Unfinished(_))),
                            "{case}"
                        );
                    }
                    rollback(&fs, Target::Last).unwrap_or_else(|e| panic!("{case}: {e}"));
                }
                assert_eq!(host(&fs), host(&original_fs), "{case}");
                assert!(st.unfinished(&fs).unwrap().is_empty(), "{case}");
            }
        }
    }
}

#[test]
fn rollback_refuses_a_changed_file() {
    let fs = fixture();
    let facts = facts();
    apply(&fs, &plan_of(&fs, &facts, &[&demo()])).unwrap();
    fs.write(Path::new(CONF), b"edited\n").unwrap();
    fs.write(Path::new(NEW), b"edited\n").unwrap();
    let edited = host(&fs);

    let err = rollback(&fs, Target::Last).unwrap_err();
    let EngineError::Changed { txn, changed } = &err else {
        panic!("{err:?}");
    };
    let files = format!("{STATE}/txn/{txn}/files");
    assert_eq!(
        changed,
        &[
            ByHand {
                resource: "file:/etc/demo.conf".into(),
                step: format!("copy {files}/1.before to {CONF} (mode 0644, owner 0:0)"),
            },
            ByHand {
                resource: "file:/etc/demo.d/new.conf".into(),
                step: format!("remove {NEW}; it no longer matches {files}/2.after"),
            }
        ]
    );
    let message = err.to_string();
    assert!(message.contains("nothing was restored"), "{message}");
    assert!(
        message.contains(&format!("rollback --txn {txn}` again")),
        "{message}"
    );
    assert_eq!(host(&fs), edited);

    // Back as apply left them, the rollback goes ahead.
    fs.write(Path::new(CONF), b"new\n").unwrap();
    fs.remove(Path::new(NEW)).unwrap();
    rollback(&fs, Target::Last).unwrap();
    assert_eq!(fs.read(Path::new(CONF)).unwrap(), b"old\n");
}

#[test]
fn rollback_refuses_a_changed_sysctl() {
    let fs = fixture();
    let facts = facts();
    apply(&fs, &plan_of(&fs, &facts, &[&demo()])).unwrap();
    fs.write(Path::new(KPTR), b"2\n").unwrap();
    let edited = host(&fs);

    let err = rollback(&fs, Target::Last).unwrap_err();
    let EngineError::Changed { changed, .. } = &err else {
        panic!("{err:?}");
    };
    assert_eq!(
        changed,
        &[ByHand {
            resource: "sysctl:kernel.kptr_restrict".into(),
            step: "sysctl -w 'kernel.kptr_restrict=0'".into(),
        }]
    );
    assert_eq!(host(&fs), edited);
    // Without a boot ID, as in a journal from before 0.2.1, the check applies.
    let id = &state(&fs).txns(&fs).unwrap()[0].id().to_owned();
    assert!(events(&fs, id).iter().any(|e| matches!(
        e,
        Event::Backup {
            backup: Backup::Sysctl { boot_id: None, .. },
            ..
        }
    )));
}

#[test]
fn rollback_after_a_reboot_leaves_sysctls_to_the_boot_config() {
    let fs = fixture().with_file(BOOT_ID, "a\n");
    let facts = facts();
    let ApplyOutcome::Applied { txn } = apply(&fs, &plan_of(&fs, &facts, &[&demo()])).unwrap()
    else {
        panic!("not applied");
    };
    // After a reboot, a later sysctl.d file set the key.
    fs.write(Path::new(BOOT_ID), b"b\n").unwrap();
    fs.write(Path::new(KPTR), b"2").unwrap();

    let done = rollback(&fs, Target::Last).unwrap();
    assert_eq!(
        done,
        Rollback {
            txn: txn.clone(),
            restored: 2,
            at_next_boot: vec!["kernel.kptr_restrict".into()],
        }
    );
    assert_eq!(fs.read(Path::new(CONF)).unwrap(), b"old\n");
    assert!(!fs.exists(Path::new(NEW)));
    assert_eq!(fs.read(Path::new(KPTR)).unwrap(), b"2");
    let events = events(&fs, &txn);
    let restored: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            Event::Restored { resource } => Some(resource.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        restored,
        [
            "sysctl:kernel.kptr_restrict",
            "file:/etc/demo.d/new.conf",
            "file:/etc/demo.conf"
        ]
    );
}

#[test]
fn rollback_accepts_a_created_file_that_is_gone() {
    let fs = fixture();
    let facts = facts();
    let original = host(&fs);
    apply(&fs, &plan_of(&fs, &facts, &[&demo()])).unwrap();
    fs.remove(Path::new(NEW)).unwrap();
    rollback(&fs, Target::Last).unwrap();
    assert_eq!(host(&fs), original);
}

#[test]
fn an_older_transaction_cannot_undo_a_newer_one() {
    let fs = fixture();
    let facts = facts();
    let original = host(&fs);
    let apply_conf = |content: &str| {
        let m = module("test.conf", vec![file(CONF, content, 0o644)]);
        match apply(&fs, &plan_of(&fs, &facts, &[&m])).unwrap() {
            ApplyOutcome::Applied { txn } => txn,
            other => panic!("{other:?}"),
        }
    };
    let first = apply_conf("v1\n");
    let second = apply_conf("v2\n");

    let err = rollback(&fs, Target::Txn(&first)).unwrap_err();
    assert!(matches!(err, EngineError::Changed { .. }), "{err:?}");
    assert_eq!(fs.read(Path::new(CONF)).unwrap(), b"v2\n");

    assert_eq!(rollback(&fs, Target::Last).unwrap().txn, second);
    assert_eq!(rollback(&fs, Target::Last).unwrap().txn, first);
    assert_eq!(host(&fs), original);
}

#[test]
fn history_lists_transactions_newest_first() {
    let fs = fixture();
    let facts = facts();
    let plan = plan_of(&fs, &facts, &[&demo()]);
    let ApplyOutcome::Applied { txn: first } = apply(&fs, &plan).unwrap() else {
        panic!("not applied");
    };
    rollback(&fs, Target::Last).unwrap();
    let ApplyOutcome::Applied { txn: second } = apply(&fs, &plan).unwrap() else {
        panic!("not applied");
    };
    // A transaction without a `begin` line changed nothing and is not listed.
    state(&fs).create_txn(&fs, id::now()).unwrap();

    let history = history(&state(&fs), &fs).unwrap();
    let rows: Vec<(&str, TxnState, bool, &[String], usize)> = history
        .iter()
        .map(|t| {
            (
                t.id.as_str(),
                t.state,
                t.unfinished,
                t.modules.as_slice(),
                t.changes,
            )
        })
        .collect();
    let modules = ["test.demo".to_owned()];
    assert_eq!(
        rows,
        [
            (second.as_str(), TxnState::Applied, false, &modules[..], 3),
            (
                first.as_str(),
                TxnState::RolledBack {
                    reason: RollbackReason::Manual
                },
                false,
                &modules[..],
                3
            ),
        ]
    );
    assert!(history[0].started > 0);
}

#[test]
fn a_second_engine_is_busy() {
    let fs = fixture();
    let state = state(&fs);
    let _held = Engine::lock(&state, sys(&fs)).unwrap();
    assert!(matches!(
        Engine::lock(&state, sys(&fs)),
        Err(EngineError::Busy)
    ));
}
