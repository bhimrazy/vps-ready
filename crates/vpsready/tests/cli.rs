//! The alias binary runs the same command as `vps-ready`.

use std::process::Command;

#[test]
fn vpsready_runs_vps_ready() {
    let out = Command::new(env!("CARGO_BIN_EXE_vpsready"))
        .arg("version")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with(&format!("vps-ready {} (", env!("CARGO_PKG_VERSION"))),
        "{stdout}"
    );
}
