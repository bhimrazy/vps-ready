//! Journal compatibility: `tests/fixtures/journal/<minor>/journal.jsonl` is
//! a journal written by that 0.x. Each new 0.x adds a directory and every
//! one must still read and roll back.

use super::manual::state_of;
use super::*;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/journal");

/// The fixture journals, oldest name first.
fn fixtures() -> Vec<(String, Vec<u8>)> {
    let mut found: Vec<_> = std::fs::read_dir(FIXTURES)
        .unwrap()
        .map(|dir| {
            let dir = dir.unwrap().path();
            let name = dir.file_name().unwrap().to_string_lossy().into_owned();
            (name, std::fs::read(dir.join("journal.jsonl")).unwrap())
        })
        .collect();
    found.sort();
    found
}

/// A host where the sysctl the fixtures set is at `1`, with `journal` as its
/// only transaction.
fn host_with(journal: &[u8]) -> (FakeFs, String) {
    let fs = fixture().with_file(BOOT_ID, "a\n");
    let txn = state(&fs).create_txn(&fs, 1).unwrap();
    fs.append_sync(&txn.journal_path(), journal).unwrap();
    fs.write(Path::new(KPTR), b"1").unwrap();
    (fs, txn.id().to_owned())
}

#[test]
fn every_fixture_rolls_back() {
    let all = fixtures();
    assert!(all.len() >= 2);
    for (name, journal) in all {
        let (fs, txn) = host_with(&journal);
        rollback_with(&fs, &runner(Output::success(""))).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(fs.read(Path::new(KPTR)).unwrap(), b"0", "{name}");
        assert_eq!(
            state_of(&fs, &txn),
            TxnState::RolledBack {
                reason: RollbackReason::Manual
            },
            "{name}"
        );
    }
}

#[test]
fn a_fixture_since_0_7_is_what_this_version_writes() {
    for (name, journal) in fixtures().into_iter().filter(|(n, _)| n.as_str() >= "0.7") {
        let records = journal::parse(Path::new(&name), &journal).unwrap();
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
        assert_eq!(again.as_bytes(), journal, "{name}");
    }
}

#[test]
fn a_journal_without_a_format_reads_as_format_0() {
    let (_, old) = &fixtures()[0];
    let records = journal::parse(Path::new("journal"), old).unwrap();
    assert!(matches!(records[0].event, Event::Begin { format: 0, .. }));
}

#[test]
fn a_newer_format_is_refused_by_name_and_nothing_is_restored() {
    let newer =
        br#"{"at":1,"event":"begin","format":2,"version":"9.9.9","modules":["kernel.sysctl"]}
{"at":1,"event":"a-record-from-the-future"}
"#;
    let (fs, _) = host_with(newer);
    let err = rollback_with(&fs, &runner(Output::success(""))).unwrap_err();
    assert!(
        matches!(err, EngineError::JournalFormat { format: 2, .. }),
        "{err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("format 2") && msg.contains("vps-ready 9.9.9"),
        "{msg}"
    );
    assert_eq!(fs.read(Path::new(KPTR)).unwrap(), b"1");
}
