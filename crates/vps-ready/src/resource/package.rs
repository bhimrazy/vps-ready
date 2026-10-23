//! The [`Package`] resource.

use std::time::Duration;

use super::{Backup, ResourceError};
use crate::sys::{Cmd, Output, Sys};

/// An apt package that must be installed. Debian family only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// A plain Debian package name, e.g. `unattended-upgrades`: no apt
    /// suffix (`-`, `+`, `=version`, `/suite`) and no pattern characters.
    pub name: String,
}

/// cloud-init may still hold the dpkg lock on first boot; wait for it.
const LOCK_TIMEOUT: &str = "DPkg::Lock::Timeout=300";

/// Kill timeout of each `apt-get` command. It kills `apt-get`, not `dpkg`,
/// so the dpkg database may then need `dpkg --configure -a`, which rollback
/// does not run.
const APT_TIMEOUT: Duration = Duration::from_secs(600);

impl Package {
    /// The summary of the change, or `None`.
    pub(super) fn diff(&self, sys: Sys) -> Result<Option<(String, Option<String>)>, ResourceError> {
        Ok((!self.installed(sys)?).then(|| (format!("install {}", self.name), None)))
    }

    pub(super) fn snapshot(&self, sys: Sys) -> Result<Backup, ResourceError> {
        Ok(Backup::Package {
            name: self.name.clone(),
            was_installed: self.installed(sys)?,
        })
    }

    /// Refreshes the package lists, which a fresh image may lack, then
    /// installs without recommends and keeps any existing config file. A
    /// source that `apt-get update` fails on with an error (exit 100) fails
    /// the apply; one it reports only as a warning does not.
    pub(super) fn apply(&self, sys: Sys) -> Result<(), ResourceError> {
        run(sys, &apt_get(["update"]))?;
        run(
            sys,
            &apt_get([
                "install",
                "-y",
                "--no-install-recommends",
                "-o",
                "Dpkg::Options::=--force-confdef",
                "-o",
                "Dpkg::Options::=--force-confold",
                &self.name,
            ]),
        )
    }

    /// Whether dpkg has the package fully installed. A package dpkg does not
    /// know, or one only partly installed, is not.
    fn installed(&self, sys: Sys) -> Result<bool, ResourceError> {
        let out = sys.runner.run(&dpkg_query(&self.name))?;
        match out.status {
            0 => Ok(out.stdout_str()?.trim() == "installed"),
            // No package matched the name.
            1 => Ok(false),
            _ => Err(failed("dpkg-query", &out)),
        }
    }
}

fn dpkg_query(name: &str) -> Cmd {
    Cmd::new("dpkg-query").args(["-W", "--showformat=${db:Status-Status}", name])
}

fn apt_get<'a>(args: impl IntoIterator<Item = &'a str>) -> Cmd {
    Cmd::new("apt-get")
        .args(["-o", LOCK_TIMEOUT])
        .args(args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .timeout(APT_TIMEOUT)
}

fn run(sys: Sys, cmd: &Cmd) -> Result<(), ResourceError> {
    let out = sys.runner.run(cmd)?;
    if out.ok() {
        Ok(())
    } else {
        Err(failed(&cmd.program, &out))
    }
}

fn failed(program: &str, out: &Output) -> ResourceError {
    ResourceError::Command {
        program: program.to_owned(),
        status: out.status,
        stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::super::{Change, Resource, Reversibility, restore};
    use super::*;
    use crate::sys::fake::{FakeFs, FakeRunner};

    const NAME: &str = "unattended-upgrades";
    const TXN: &str = "/var/lib/vps-ready/txn/20261023T114246Z";

    fn package() -> Resource {
        Resource::Package(Package { name: NAME.into() })
    }

    fn exit(status: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            status,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    /// Diffs [`package`] with `dpkg-query` answering `out`; checks the argv.
    fn diff_with(out: Output) -> Result<Option<Change>, ResourceError> {
        let fs = FakeFs::new();
        let runner = FakeRunner::new().on("dpkg-query", ["-W"], out);
        let result = package().diff(Sys {
            fs: &fs,
            runner: &runner,
        });
        assert_eq!(
            runner.calls(),
            [Cmd::new("dpkg-query").args(["-W", "--showformat=${db:Status-Status}", NAME])]
        );
        result
    }

    fn install() -> Option<Change> {
        Some(Change {
            id: format!("package:{NAME}"),
            summary: format!("install {NAME}"),
            diff: None,
            reversibility: Reversibility::Partial,
        })
    }

    #[test]
    fn diff_is_none_when_installed() {
        assert_eq!(diff_with(Output::success("installed")).unwrap(), None);
    }

    #[test]
    fn diff_installs_when_not_installed() {
        for status in ["not-installed", "config-files", "half-configured"] {
            assert_eq!(diff_with(Output::success(status)).unwrap(), install());
        }
    }

    #[test]
    fn diff_installs_an_unknown_package() {
        let out = exit(
            1,
            "",
            "dpkg-query: no packages found matching unattended-upgrades\n",
        );
        assert_eq!(diff_with(out).unwrap(), install());
    }

    #[test]
    fn diff_fails_on_a_dpkg_error() {
        let err = diff_with(exit(2, "", "dpkg-query: error: parsing file\n")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "`dpkg-query` exited with status 2: dpkg-query: error: parsing file"
        );
    }

    #[test]
    fn reversibility_serializes_as_partial() {
        assert_eq!(
            serde_json::to_string(&Reversibility::Partial).unwrap(),
            r#""partial""#
        );
    }

    #[test]
    fn snapshot_records_whether_it_was_installed() {
        let fs = FakeFs::new();
        let runner = FakeRunner::new().on("dpkg-query", ["-W"], Output::success("not-installed"));
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        assert_eq!(
            package().snapshot(sys, Path::new(TXN), 1).unwrap(),
            Backup::Package {
                name: NAME.into(),
                was_installed: false,
            }
        );
    }

    fn expected_apply() -> [Cmd; 2] {
        let apt = |args: &[&str]| {
            Cmd::new("apt-get")
                .args(["-o", "DPkg::Lock::Timeout=300"])
                .args(args.iter().copied())
                .env("DEBIAN_FRONTEND", "noninteractive")
                .timeout(Duration::from_secs(600))
        };
        [
            apt(&["update"]),
            apt(&[
                "install",
                "-y",
                "--no-install-recommends",
                "-o",
                "Dpkg::Options::=--force-confdef",
                "-o",
                "Dpkg::Options::=--force-confold",
                NAME,
            ]),
        ]
    }

    #[test]
    fn apply_updates_then_installs() {
        let fs = FakeFs::new();
        let runner = FakeRunner::new().on("apt-get", ["-o"], Output::success(""));
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        package().apply(sys).unwrap();
        assert_eq!(runner.calls(), expected_apply());
    }

    #[test]
    fn apply_stops_when_update_fails() {
        let fs = FakeFs::new();
        let runner = FakeRunner::new().on(
            "apt-get",
            ["-o", LOCK_TIMEOUT, "update"],
            exit(100, "", "E: Could not get lock\n"),
        );
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let err = package().apply(sys).unwrap_err();
        assert_eq!(
            err.to_string(),
            "`apt-get` exited with status 100: E: Could not get lock"
        );
        assert_eq!(runner.calls(), expected_apply()[..1]);
    }

    #[test]
    fn apply_fails_when_install_fails() {
        let fs = FakeFs::new();
        let runner = FakeRunner::new()
            .on(
                "apt-get",
                ["-o", LOCK_TIMEOUT, "update"],
                Output::success(""),
            )
            .on(
                "apt-get",
                ["-o", LOCK_TIMEOUT, "install"],
                exit(100, "", "E: Unable to locate package unattended-upgrades\n"),
            );
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let err = package().apply(sys).unwrap_err();
        assert!(
            matches!(err, ResourceError::Command { ref program, status: 100, ref stderr }
                if program == "apt-get" && stderr == "E: Unable to locate package unattended-upgrades"),
            "{err:?}"
        );
        assert_eq!(runner.calls(), expected_apply());
    }

    #[test]
    fn restore_is_a_no_op() {
        let fs = FakeFs::new();
        let runner = FakeRunner::new();
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        for was_installed in [false, true] {
            let backup = Backup::Package {
                name: NAME.into(),
                was_installed,
            };
            restore(sys, Path::new(TXN), &backup).unwrap();
        }
        assert_eq!(runner.calls(), []);
    }
}
