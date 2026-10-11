//! End-to-end tests of the `vps-ready` binary.

use assert_cmd::Command;
use predicates::prelude::*;

fn vps_ready() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vps-ready"));
    cmd.env("NO_COLOR", "1").env_remove("RUST_LOG");
    cmd
}

#[test]
fn version_prints_version() {
    vps_ready()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with(format!(
            "vps-ready {} (",
            env!("CARGO_PKG_VERSION")
        )));
}

#[test]
fn version_json_is_valid() {
    let out = vps_ready()
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
    vps_ready()
        .args(["detect", "--json", "--root", root])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""family": "debian""#));
}

/// Wherever tests run, some control fails (stock sshd config) or cannot be
/// checked (`sshd -T` needs root), so the exit code is 1, never 0 or 2.
#[test]
fn audit_json_reports_every_control() {
    let out = vps_ready()
        .args(["audit", "--json"])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert!(!findings.is_empty());
    assert!(
        findings
            .iter()
            .all(|f| f["id"].is_string() && f["status"].is_string())
    );
}

#[test]
fn unknown_command_is_a_usage_error() {
    vps_ready()
        .arg("frobnicate")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unrecognized subcommand"));
}
