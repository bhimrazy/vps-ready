//! The [`Package`] resource.

use std::time::Duration;

use super::{Backup, ResourceError, failed, run};
use crate::sys::{Cmd, Sys};

/// Apt packages that must be installed, with one `apt-get update` and one
/// `apt-get install` for all of them. Debian family only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// Plain Debian package names, e.g. `unattended-upgrades`: no apt
    /// suffix (`-`, `+`, `=version`, `/suite`) and no pattern characters.
    pub names: Vec<String>,
}

/// cloud-init may still hold the dpkg lock on first boot; wait for it.
const LOCK_TIMEOUT: &str = "DPkg::Lock::Timeout=300";

/// Kill timeout of each `apt-get` command. It kills `apt-get`, not `dpkg`,
/// so the dpkg database may then need `dpkg --configure -a`, which rollback
/// does not run.
const APT_TIMEOUT: Duration = Duration::from_secs(600);

impl Package {
    /// The longest snapshot and apply may run: `dpkg-query` for each
    /// package in both, then `apt-get update` and `install`.
    pub(super) fn timeout(&self) -> Duration {
        2 * self.diff_timeout() + 2 * APT_TIMEOUT
    }

    /// The longest diff may run: `dpkg-query` for each package.
    pub(super) fn diff_timeout(&self) -> Duration {
        Cmd::DEFAULT_TIMEOUT * u32::try_from(self.names.len()).unwrap_or(u32::MAX)
    }

    /// The summary of the change, e.g. `install a, b`, or `None`.
    pub(super) fn diff(&self, sys: Sys) -> Result<Option<(String, Option<String>)>, ResourceError> {
        let missing = self.missing(sys)?;
        Ok((!missing.is_empty()).then(|| (format!("install {}", missing.join(", ")), None)))
    }

    /// Journals the names separated by spaces in `name`, the field a single
    /// package had in v0.4.0, so either version reads the other's journal.
    pub(super) fn snapshot(&self, sys: Sys) -> Result<Backup, ResourceError> {
        Ok(Backup::Package {
            name: self.names.join(" "),
            was_installed: self.missing(sys)?.is_empty(),
        })
    }

    /// Refreshes the package lists, which a fresh image may lack, then
    /// installs the packages not yet installed, without recommends and
    /// keeping any existing config file; naming an installed one would
    /// upgrade it. A source that `apt-get update` fails on with an error
    /// (exit 100) fails the apply; one it reports only as a warning does not.
    pub(super) fn apply(&self, sys: Sys) -> Result<(), ResourceError> {
        let missing = self.missing(sys)?;
        if missing.is_empty() {
            return Ok(());
        }
        run(sys, &apt_get(["update"]))?;
        let install = [
            "install",
            "-y",
            "--no-install-recommends",
            "-o",
            "Dpkg::Options::=--force-confdef",
            "-o",
            "Dpkg::Options::=--force-confold",
        ];
        run(sys, &apt_get(install.into_iter().chain(missing)))?;
        Ok(())
    }

    /// The names dpkg does not have fully installed, in order.
    fn missing(&self, sys: Sys) -> Result<Vec<&str>, ResourceError> {
        let mut missing = Vec::new();
        for name in &self.names {
            if !installed(sys, name)? {
                missing.push(name.as_str());
            }
        }
        Ok(missing)
    }
}

/// Whether dpkg has the package fully installed. A package dpkg does not
/// know, or one only partly installed, is not.
fn installed(sys: Sys, name: &str) -> Result<bool, ResourceError> {
    let out = sys.runner.run(&dpkg_query(name))?;
    match out.status {
        0 => Ok(out.stdout_str()?.trim() == "installed"),
        // No package matched the name.
        1 => Ok(false),
        _ => Err(failed("dpkg-query", &out)),
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::super::{Change, Resource, Reversibility, restore};
    use super::*;
    use crate::sys::Output;
    use crate::sys::fake::{FakeFs, FakeRunner};

    const NAME: &str = "unattended-upgrades";
    const TXN: &str = "/var/lib/vps-ready/txn/20261023T114246Z";

    fn package() -> Resource {
        Resource::Package(Package {
            names: vec![NAME.into()],
        })
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

    fn not_installed() -> FakeRunner {
        FakeRunner::new().on("dpkg-query", ["-W"], Output::success("not-installed"))
    }

    fn expected_apply(names: &[&str]) -> [Cmd; 2] {
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
                &[
                    "install",
                    "-y",
                    "--no-install-recommends",
                    "-o",
                    "Dpkg::Options::=--force-confdef",
                    "-o",
                    "Dpkg::Options::=--force-confold",
                ],
                names,
            ]
            .concat()),
        ]
    }

    #[test]
    fn apply_updates_then_installs() {
        let fs = FakeFs::new();
        let runner = not_installed().on("apt-get", ["-o"], Output::success(""));
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        package().apply(sys).unwrap();
        assert_eq!(runner.calls()[1..], expected_apply(&[NAME]));
    }

    #[test]
    fn apply_runs_no_apt_when_installed_since_the_plan() {
        let fs = FakeFs::new();
        let runner = FakeRunner::new().on("dpkg-query", ["-W"], Output::success("installed"));
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        package().apply(sys).unwrap();
        assert_eq!(runner.calls().len(), 1);
    }

    #[test]
    fn apply_stops_when_update_fails() {
        let fs = FakeFs::new();
        let runner = not_installed().on(
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
        assert_eq!(runner.calls()[1..], expected_apply(&[NAME])[..1]);
    }

    #[test]
    fn apply_fails_when_install_fails() {
        let fs = FakeFs::new();
        let runner = not_installed()
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
        assert_eq!(runner.calls()[1..], expected_apply(&[NAME]));
    }

    const DOCKER: [&str; 3] = ["docker-ce", "docker-ce-cli", "containerd.io"];

    /// [`DOCKER`], of which only `docker-ce-cli` is installed.
    fn several() -> (Resource, FakeRunner) {
        let package = Resource::Package(Package {
            names: DOCKER.iter().map(|n| (*n).to_owned()).collect(),
        });
        let query = |name| ["-W", "--showformat=${db:Status-Status}", name];
        let runner = FakeRunner::new()
            .on("dpkg-query", query("docker-ce"), exit(1, "", ""))
            .on(
                "dpkg-query",
                query("docker-ce-cli"),
                Output::success("installed"),
            )
            .on(
                "dpkg-query",
                query("containerd.io"),
                Output::success("config-files"),
            )
            .on("apt-get", ["-o"], Output::success(""));
        (package, runner)
    }

    #[test]
    fn several_packages_install_together() {
        let fs = FakeFs::new();
        let (package, runner) = several();
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        assert_eq!(
            package.id(),
            "package:docker-ce,docker-ce-cli,containerd.io"
        );
        let change = package.diff(sys).unwrap().unwrap();
        assert_eq!(change.summary, "install docker-ce, containerd.io");
        assert_eq!(change.reversibility, Reversibility::Partial);
        assert_eq!(
            package.snapshot(sys, Path::new(TXN), 1).unwrap(),
            Backup::Package {
                name: "docker-ce docker-ce-cli containerd.io".into(),
                was_installed: false,
            }
        );
        let queries = runner.calls().len();
        package.apply(sys).unwrap();
        // The queries again, then one update and one install of the two
        // missing, which leaves docker-ce-cli at its version.
        let calls = runner.calls();
        assert_eq!(calls[queries..queries + 3], calls[..3]);
        assert_eq!(
            calls[queries + 3..],
            expected_apply(&["docker-ce", "containerd.io"])
        );
    }

    #[test]
    fn timeouts_grow_with_the_queries_not_the_apt_calls() {
        let query = Cmd::DEFAULT_TIMEOUT;
        let (docker, _) = several();
        assert_eq!(docker.diff_timeout(), 3 * query);
        assert_eq!(docker.timeout(), 6 * query + 2 * APT_TIMEOUT);
        assert_eq!(package().diff_timeout(), query);
        assert_eq!(package().timeout(), 2 * query + 2 * APT_TIMEOUT);
    }

    #[test]
    fn restore_is_a_no_op() {
        let fs = FakeFs::new();
        let runner = FakeRunner::new();
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        // One name as v0.4.0 journaled it, or several.
        for name in [NAME, "docker-ce docker-ce-cli"] {
            for was_installed in [false, true] {
                let backup = Backup::Package {
                    name: name.into(),
                    was_installed,
                };
                restore(sys, Path::new(TXN), &backup).unwrap();
            }
        }
        assert_eq!(runner.calls(), []);
    }
}
