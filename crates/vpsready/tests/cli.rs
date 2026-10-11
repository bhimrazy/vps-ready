//! End-to-end tests of the `vpsready` binary.

use assert_cmd::Command;
use predicates::prelude::*;

fn vpsready() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vpsready"));
    cmd.env("NO_COLOR", "1").env_remove("RUST_LOG");
    cmd
}

#[test]
fn version_prints_version() {
    vpsready()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with(format!(
            "vpsready {} (",
            env!("CARGO_PKG_VERSION")
        )));
}

#[test]
fn version_json_is_valid() {
    let out = vpsready()
        .args(["version", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn detect_reads_a_fixture_root() {
    let root = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/os-release/ubuntu-24.04"
    );
    vpsready()
        .args(["detect", "--json", "--root", root])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""family": "debian""#));
}

#[test]
fn unknown_command_is_a_usage_error() {
    vpsready()
        .arg("audit")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unrecognized subcommand"));
}
