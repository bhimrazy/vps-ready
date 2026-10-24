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

/// Whether these tests run as root, read as `vps-ready` reads it.
fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status").is_ok_and(|s| {
        s.lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|ids| ids.split_whitespace().nth(1))
            == Some("0")
    })
}

#[test]
fn apply_without_root_exits_2_and_changes_nothing() {
    if is_root() {
        return;
    }
    let state = std::path::Path::new("/var/lib/vps-ready");
    let existed = state.exists();
    vps_ready()
        .args(["apply", "--yes"])
        .assert()
        .code(2)
        .stdout("")
        .stderr("error: apply needs root; run it with sudo\n");
    assert_eq!(state.exists(), existed);
}

#[test]
fn plan_json_parses() {
    let out = vps_ready()
        .args(["plan", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let modules = json["modules"].as_array().unwrap();
    assert!(modules.iter().any(|m| m["id"] == "kernel.sysctl"));
}

#[test]
fn rollback_needs_last_or_txn() {
    vps_ready()
        .arg("rollback")
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "required arguments were not provided",
        ));
    vps_ready()
        .args(["rollback", "--last", "--txn", "20261023T114246Z"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn unknown_module_is_a_usage_error() {
    vps_ready()
        .args(["plan", "--module", "nope"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid value 'nope'"));
}

#[test]
fn bare_command_prints_help_with_the_first_run() {
    vps_ready()
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Usage: vps-ready"))
        .stderr(predicate::str::ends_with(
            "Typical first run, as root:\n\
             \x20 vps-ready detect          what this server is\n\
             \x20 vps-ready audit           what fails and why\n\
             \x20 vps-ready plan            what apply would change (read-only)\n\
             \x20 vps-ready apply           make the changes; undo with `rollback --last`\n",
        ));
}

/// Notices are plain lines by default and log lines with `-v`.
#[test]
fn notices_have_no_log_labels_by_default() {
    let root = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/os-release/ubuntu-24.04"
    );
    vps_ready()
        .args(["detect", "--root", root])
        .assert()
        .success()
        .stderr(predicate::str::contains("vps-ready: /proc/sys not found"))
        .stderr(predicate::str::contains("WARN").not())
        // A mounted tree has no process table, so no session is looked for.
        .stderr(predicate::str::contains("no SSH session").not());
    vps_ready()
        .args(["detect", "-v", "--root", root])
        .assert()
        .success()
        .stderr(predicate::str::contains("WARN /proc/sys not found"))
        .stderr(predicate::str::contains("vps-ready: ").not());
}

/// `apply --dry-run` is `plan`: same output, same exit code, no root needed.
#[test]
fn apply_dry_run_is_plan() {
    for args in [&[][..], &["--module", "kernel.sysctl"][..]] {
        let plan = vps_ready().arg("plan").args(args).output().unwrap();
        for flag in ["--dry-run", "-n"] {
            let dry = vps_ready()
                .args(["apply", flag])
                .args(args)
                .output()
                .unwrap();
            assert_eq!(dry.status.code(), plan.status.code());
            assert_eq!(dry.stdout, plan.stdout);
        }
    }
    vps_ready()
        .args(["apply", "--dry-run", "--yes"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}
