//! Journal compatibility. `tests/fixtures/journal/<major>.<minor>/<case>/`
//! holds journals written by that 0.x (`journal.jsonl`, and the `files/`
//! beside it when the case backs up a file). Each new 0.x adds a directory,
//! and every case in every directory must still read and roll back. Fixtures
//! of released versions are never edited.

use super::dead_man::{armable, boot_hook, dm_runner, locking, pending, timer};
use super::manual::state_of;
use super::*;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/journal");

struct Case {
    /// `(major, minor)` of the directory.
    version: (u32, u32),
    name: String,
    journal: Vec<u8>,
    /// `files/<n>.before` and `<n>.after`, by file name.
    files: Vec<(String, Vec<u8>)>,
}

fn dirs(of: &Path) -> Vec<(String, PathBuf)> {
    let mut dirs: Vec<_> = std::fs::read_dir(of)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .map(|path| {
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                path,
            )
        })
        .collect();
    dirs.sort();
    dirs
}

/// Every case, oldest version first.
fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for (dir, path) in dirs(Path::new(FIXTURES)) {
        let (major, minor) = dir.split_once('.').expect("<major>.<minor>");
        let version = (major.parse().unwrap(), minor.parse().unwrap());
        for (name, case) in dirs(&path) {
            let files = std::fs::read_dir(case.join("files"))
                .into_iter()
                .flatten()
                .map(|f| f.unwrap().path())
                .map(|f| {
                    let name = f.file_name().unwrap().to_string_lossy().into_owned();
                    (name, std::fs::read(f).unwrap())
                })
                .collect();
            cases.push(Case {
                version,
                name,
                journal: std::fs::read(case.join("journal.jsonl")).unwrap(),
                files,
            });
        }
    }
    cases.sort_by(|a, b| (a.version, &a.name).cmp(&(b.version, &b.name)));
    cases
}

/// A host that can arm, as the journal left it, with `journal` as a
/// transaction.
fn host_with(journal: &[u8], files: &[(String, Vec<u8>)]) -> (FakeFs, String) {
    let fs = armable();
    let txn = state(&fs).create_txn(&fs, 1).unwrap();
    fs.append_sync(&txn.journal_path(), journal).unwrap();
    for (name, bytes) in files {
        let path = Path::new(STATE).join(format!("txn/{}/files/{name}", txn.id()));
        fs.write_atomic(&path, bytes, owner(0o600)).unwrap();
    }
    if String::from_utf8_lossy(journal).contains("sysctl:") {
        fs.write(Path::new(KPTR), b"1").unwrap();
    }
    if !files.is_empty() {
        fs.write(Path::new(CONF), b"new\n").unwrap();
    }
    (fs, txn.id().to_owned())
}

#[test]
fn every_fixture_rolls_back() {
    let all = cases();
    assert!(all.iter().any(|c| c.version == (0, 6)));
    assert!(all.iter().any(|c| c.files.len() == 2));
    for case in all {
        let name = format!("{:?} {}", case.version, case.name);
        let (fs, txn) = host_with(&case.journal, &case.files);
        rollback_with(&fs, &dm_runner()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(fs.read(Path::new(KPTR)).unwrap(), b"0", "{name}");
        assert_eq!(fs.read(Path::new(CONF)).unwrap(), b"old\n", "{name}");
        assert_eq!(
            state_of(&fs, &txn),
            TxnState::RolledBack {
                reason: RollbackReason::Manual
            },
            "{name}"
        );
    }
}

/// A journal with the clock and the writer's version taken out.
fn normalized(records: &[Record]) -> String {
    records
        .iter()
        .map(|r| {
            let mut r = r.clone();
            r.at = 0;
            if let Event::Begin { version, .. } = &mut r.event {
                version.clear();
            }
            serde_json::to_string(&r).unwrap() + "\n"
        })
        .collect()
}

#[test]
fn the_newest_fixture_is_what_this_version_writes() {
    let all = cases();
    let newest = all.last().unwrap().version;
    let case = all
        .iter()
        .find(|c| c.version == newest && c.name == "sysctl")
        .unwrap();
    let parsed = journal::parse(Path::new("fixture"), &case.journal).unwrap();

    let fs = fixture().with_file(BOOT_ID, "a\n");
    let plain = module("test.plain", vec![sysctl("kernel.kptr_restrict", "1")]);
    let facts = facts();
    apply(&fs, &plan_of(&fs, &facts, &[&plain])).unwrap();
    let txn = state(&fs).txns(&fs).unwrap().pop().unwrap();
    let written = txn.read(&fs).unwrap();

    // At the first format bump this changes: `format` is compared, so the
    // new 0.x adds fixtures at the new format, and the newest `sysctl` case
    // must match what the engine then writes.
    assert!(matches!(
        written[0].event,
        Event::Begin {
            format: journal::FORMAT,
            ..
        }
    ));
    assert_eq!(normalized(&written), normalized(&parsed));
}

#[test]
fn fixtures_since_0_7_reserialize_unchanged() {
    let all: Vec<_> = cases()
        .into_iter()
        .filter(|c| c.version >= (0, 7))
        .collect();
    assert!(!all.is_empty());
    for case in all {
        let records = journal::parse(Path::new("fixture"), &case.journal).unwrap();
        assert!(matches!(
            records[0].event,
            Event::Begin {
                format: journal::FORMAT,
                ..
            }
        ));
        let again: String = records
            .iter()
            .map(|r| serde_json::to_string(r).unwrap() + "\n")
            .collect();
        assert_eq!(again.as_bytes(), case.journal, "{}", case.name);
    }
}

#[test]
fn a_journal_without_a_format_reads_as_format_0() {
    let old: Vec<_> = cases().into_iter().filter(|c| c.version < (0, 7)).collect();
    assert!(!old.is_empty());
    for case in old {
        let records = journal::parse(Path::new("journal"), &case.journal).unwrap();
        assert!(matches!(records[0].event, Event::Begin { format: 0, .. }));
    }
}

/// A journal from a format this version does not know, with a record kind it
/// does not know after the `begin`.
fn newer(begin_fields: &str) -> Vec<u8> {
    format!(
        "{{\"at\":1,\"event\":\"begin\",{begin_fields},\"modules\":[\"kernel.sysctl\"]}}\n\
         {{\"at\":1,\"event\":\"a-record-from-the-future\"}}\n"
    )
    .into_bytes()
}

#[test]
fn a_newer_format_is_refused_by_name() {
    let err =
        journal::parse(Path::new("j"), &newer(r#""format":2,"version":"9.9.9""#)).unwrap_err();
    assert_eq!(
        err.to_string(),
        "j uses journal format 2, written by vps-ready 9.9.9; use that version or newer"
    );
}

#[test]
fn a_format_or_version_of_the_wrong_type_is_still_refused_by_name() {
    for (fields, format, writer) in [
        (r#""format":2,"version":7"#, "2", "a newer vps-ready"),
        (r#""format":2"#, "2", "a newer vps-ready"),
        (
            r#""format":4294967296,"version":"9.9.9""#,
            "4294967296",
            "vps-ready 9.9.9",
        ),
        (
            r#""format":18446744073709551616,"version":"9.9.9""#,
            "1.8446744073709552e+19",
            "vps-ready 9.9.9",
        ),
        (
            r#""format":"2","version":"9.9.9""#,
            r#""2""#,
            "vps-ready 9.9.9",
        ),
        (
            r#""format":2.0,"version":"9.9.9""#,
            "2.0",
            "vps-ready 9.9.9",
        ),
        (r#""format":-1,"version":"9.9.9""#, "-1", "vps-ready 9.9.9"),
        (
            r#""format":true,"version":null"#,
            "true",
            "a newer vps-ready",
        ),
    ] {
        let err = journal::parse(Path::new("j"), &newer(fields)).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "j uses journal format {format}, written by {writer}; use that version or newer"
            ),
            "{fields}"
        );
    }
}

#[test]
fn a_newer_format_restores_nothing() {
    let (fs, txn) = host_with(&newer(r#""format":2,"version":"9.9.9""#), &[]);
    fs.write(Path::new(KPTR), b"1").unwrap();
    let run = dm_runner();
    let err = rollback_with(&fs, &run).unwrap_err();
    assert!(matches!(err, EngineError::JournalFormat { .. }), "{err:?}");
    assert_eq!(fs.read(Path::new(KPTR)).unwrap(), b"1");
    assert!(calls(&run).is_empty());

    let err = timer(&fs, &run, &txn).unwrap_err();
    assert!(matches!(err, EngineError::JournalFormat { .. }), "{err:?}");
    assert_eq!(fs.read(Path::new(KPTR)).unwrap(), b"1");
    assert!(calls(&run).is_empty());

    let err = crate::engine::history(&state(&fs), &fs).unwrap_err();
    assert!(matches!(err, EngineError::JournalFormat { .. }), "{err:?}");
}

#[test]
fn the_boot_hook_skips_a_newer_journal_keeps_itself_and_rolls_back_the_rest() {
    let facts = facts();
    let [lock, ..] = locking();
    let fs = armable();
    let plan = plan_of(&fs, &facts, &[&lock]);
    let (older, _) = pending(&fs, &plan);

    let txn = state(&fs).create_txn(&fs, 5).unwrap();
    let journal = newer(r#""format":2,"version":"9.9.9""#);
    fs.append_sync(&txn.journal_path(), &journal).unwrap();

    // A new boot.
    fs.write(Path::new(BOOT_ID), b"b\n").unwrap();
    let run = dm_runner();
    let err = boot_hook(&fs, &run).unwrap_err();
    assert!(matches!(err, EngineError::JournalFormat { .. }), "{err:?}");
    assert_eq!(
        state_of(&fs, &older),
        TxnState::RolledBack {
            reason: RollbackReason::DeadmanReboot
        }
    );
    assert_eq!(fs.read(Path::new(CONF)).unwrap(), b"old\n");
    // The hook stays enabled for the newer transaction.
    assert!(!calls(&run).contains(&"systemctl disable vps-ready-deadman.service".to_owned()));
    assert_eq!(fs.read(&txn.journal_path()).unwrap(), journal);
}
