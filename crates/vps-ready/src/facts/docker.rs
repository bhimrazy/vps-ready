//! Docker Engine on the Debian family: the packages that matter to
//! `deploy.docker`, `/etc/docker/daemon.json`, and what the running daemon
//! says about itself. Only read-only commands: `dpkg-query`, `docker info`,
//! `docker ps` and `docker network ls`.

use std::path::Path;

use serde::Serialize;

use super::{Probe, probe};
use crate::sys::{Cmd, Fs, Runner, SysError};

/// Docker's configuration file.
pub const DAEMON_JSON: &str = "/etc/docker/daemon.json";

/// Docker's daemon. Its package and the static release both put it here.
pub const DOCKERD: &str = "/usr/bin/dockerd";

/// The packages asked about: Docker Engine from Docker's repository, then
/// the distro's packages that conflict with it.
pub const PACKAGES: [&str; 5] = [
    "docker-ce",
    "docker.io",
    "podman-docker",
    "containerd",
    "runc",
];

/// Docker Engine and the packages around it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DockerEngine {
    /// The installed packages among [`PACKAGES`], in that order.
    pub packages: Vec<String>,
    /// Whether [`DOCKERD`] exists.
    pub dockerd: bool,
    /// [`DAEMON_JSON`].
    pub daemon_json: DaemonJson,
    /// The running daemon. `None` when Docker is not installed, a
    /// conflicting package is, or the daemon did not answer.
    pub daemon: Option<DockerDaemon>,
}

impl DockerEngine {
    /// Whether Docker Engine is installed: Docker's package, or a daemon
    /// where the package puts it.
    #[must_use]
    pub fn installed(&self) -> bool {
        self.dockerd || self.packages.iter().any(|p| p == "docker-ce")
    }
}

/// The state of [`DAEMON_JSON`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum DaemonJson {
    /// There is none.
    Missing,
    /// A JSON object.
    Valid,
    /// It cannot be merged into, and why.
    Unusable {
        /// E.g. `not valid JSON: expected value at line 1 column 1`.
        reason: String,
    },
}

/// What the running daemon says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DockerDaemon {
    /// Whether containers keep running while the daemon restarts.
    pub live_restore: bool,
    /// Whether this node is part of a swarm.
    pub swarm: bool,
    /// Names of the running containers.
    pub running: Vec<String>,
    /// Names of the user-defined bridge networks.
    pub networks: Vec<String>,
}

/// `None` when `dpkg-query` is missing or fails.
pub(super) fn detect(
    fs: &dyn Fs,
    runner: &dyn Runner,
    docker: bool,
    notices: &mut Vec<String>,
) -> Option<DockerEngine> {
    let packages = installed(runner, notices)?;
    let daemon_json = daemon_json(fs);
    let conflicts = packages.iter().any(|p| p != "docker-ce");
    let daemon = (docker && !conflicts)
        .then(|| daemon(runner, notices))
        .flatten();
    Some(DockerEngine {
        packages,
        dockerd: fs.exists(Path::new(DOCKERD)),
        daemon_json,
        daemon,
    })
}

/// The installed packages among [`PACKAGES`]. A package in any state but
/// `not-installed` or `config-files` counts, since it is in the way of
/// Docker's packages as well.
fn installed(runner: &dyn Runner, notices: &mut Vec<String>) -> Option<Vec<String>> {
    let cmd = Cmd::new("dpkg-query")
        .args(["-W", "--showformat=${Package} ${db:Status-Status}\\n"])
        .args(PACKAGES);
    let out = match probe(runner, &cmd, notices) {
        // Exit 1: some of the names matched no package.
        Probe::Ran(out) if matches!(out.status, 0 | 1) => out,
        Probe::Ran(out) => {
            notices.push(format!(
                "`dpkg-query` exited with {}; Docker's packages are unknown",
                out.status
            ));
            return None;
        }
        Probe::Missing | Probe::Failed => return None,
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let present: Vec<&str> = text
        .lines()
        .filter_map(|l| l.split_once(' '))
        .filter(|(_, status)| !matches!(*status, "not-installed" | "config-files"))
        .map(|(name, _)| name)
        .collect();
    Some(
        PACKAGES
            .iter()
            .filter(|p| present.contains(p))
            .map(|p| (*p).to_owned())
            .collect(),
    )
}

fn daemon_json(fs: &dyn Fs) -> DaemonJson {
    match fs.read(Path::new(DAEMON_JSON)) {
        Ok(bytes) => match parse_daemon_json(&bytes) {
            Ok(_) => DaemonJson::Valid,
            Err(reason) => DaemonJson::Unusable { reason },
        },
        Err(SysError::NotFound(_)) => DaemonJson::Missing,
        Err(err) => DaemonJson::Unusable {
            reason: format!("cannot be read: {err}"),
        },
    }
}

/// The top-level object of a `daemon.json`, or why it is not one.
///
/// # Errors
///
/// Why, e.g. `is not valid JSON: ...`.
pub fn parse_daemon_json(
    bytes: &[u8],
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    match serde_json::from_slice(bytes) {
        Ok(serde_json::Value::Object(map)) => Ok(map),
        Ok(_) => Err("is not a JSON object".to_owned()),
        Err(e) => Err(format!("is not valid JSON: {e}")),
    }
}

/// Asks the daemon. One that does not answer, e.g. because it is stopped,
/// gets a notice and `None`.
fn daemon(runner: &dyn Runner, notices: &mut Vec<String>) -> Option<DockerDaemon> {
    let info = ask(
        runner,
        &[
            "info",
            "--format",
            "{{.LiveRestoreEnabled}} {{.Swarm.LocalNodeState}}",
        ],
        notices,
    )?;
    let (live_restore, swarm) = info.trim().split_once(' ')?;
    let running = ask(runner, &["ps", "--format", "{{.Names}}"], notices)?;
    let networks = ask(
        runner,
        &[
            "network",
            "ls",
            "--filter",
            "driver=bridge",
            "--filter",
            "type=custom",
            "--format",
            "{{.Name}}",
        ],
        notices,
    )?;
    let lines = |s: &str| {
        s.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect()
    };
    Some(DockerDaemon {
        live_restore: live_restore == "true",
        // `pending`, `active`, `error` and `locked` are in a swarm.
        swarm: !matches!(swarm, "inactive" | ""),
        running: lines(&running),
        networks: lines(&networks),
    })
}

/// `docker <args>`'s stdout, or `None` with a notice.
fn ask(runner: &dyn Runner, args: &[&str], notices: &mut Vec<String>) -> Option<String> {
    let cmd = Cmd::new("docker").args(args.iter().copied());
    match probe(runner, &cmd, notices) {
        Probe::Ran(out) if out.ok() => Some(String::from_utf8_lossy(&out.stdout).into_owned()),
        Probe::Ran(out) => {
            notices.push(format!(
                "`docker {}` exited with {}: {}; the Docker daemon's state is unknown",
                args[0],
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
            None
        }
        Probe::Missing | Probe::Failed => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::Output;
    use crate::sys::fake::{FakeFs, FakeRunner};

    const DPKG: &[&str] = &[
        "-W",
        "--showformat=${Package} ${db:Status-Status}\\n",
        "docker-ce",
        "docker.io",
        "podman-docker",
        "containerd",
        "runc",
    ];

    fn exit(status: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            status,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    fn daemon_runner(info: Output) -> FakeRunner {
        FakeRunner::new()
            .on(
                "dpkg-query",
                DPKG.iter().copied(),
                exit(1, "docker-ce installed\n", ""),
            )
            .on("docker", ["info"], info)
            .on("docker", ["ps"], Output::success("web\ndb\n"))
            .on("docker", ["network"], Output::success("app_default\n"))
    }

    /// The commands are read-only and fixed, as the facts' own list.
    #[test]
    fn asks_dpkg_then_the_daemon() {
        let runner = daemon_runner(Output::success("false inactive\n"));
        let mut notices = Vec::new();
        let engine = detect(&FakeFs::new(), &runner, true, &mut notices).unwrap();
        assert!(notices.is_empty(), "{notices:?}");
        assert_eq!(
            engine,
            DockerEngine {
                packages: vec!["docker-ce".to_owned()],
                dockerd: false,
                daemon_json: DaemonJson::Missing,
                daemon: Some(DockerDaemon {
                    live_restore: false,
                    swarm: false,
                    running: vec!["web".to_owned(), "db".to_owned()],
                    networks: vec!["app_default".to_owned()],
                }),
            }
        );
        let ran: Vec<Vec<String>> = runner
            .calls()
            .into_iter()
            .map(|c| std::iter::once(c.program).chain(c.args).collect())
            .collect();
        let want: [&[&str]; 4] = [
            &[&["dpkg-query"], DPKG].concat(),
            &[
                "docker",
                "info",
                "--format",
                "{{.LiveRestoreEnabled}} {{.Swarm.LocalNodeState}}",
            ],
            &["docker", "ps", "--format", "{{.Names}}"],
            &[
                "docker",
                "network",
                "ls",
                "--filter",
                "driver=bridge",
                "--filter",
                "type=custom",
                "--format",
                "{{.Name}}",
            ],
        ];
        assert_eq!(ran, want);
    }

    #[test]
    fn a_daemon_that_does_not_answer_is_unknown() {
        let runner = daemon_runner(exit(
            1,
            "",
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock\n",
        ));
        let mut notices = Vec::new();
        let engine = detect(&FakeFs::new(), &runner, true, &mut notices).unwrap();
        assert_eq!(engine.daemon, None);
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert!(notices[0].contains("Cannot connect"), "{notices:?}");
    }

    #[test]
    fn swarm_and_live_restore() {
        let runner = daemon_runner(Output::success("true active\n"));
        let engine = detect(&FakeFs::new(), &runner, true, &mut Vec::new()).unwrap();
        let daemon = engine.daemon.unwrap();
        assert!(daemon.live_restore && daemon.swarm);
    }

    /// Without Docker, or with a conflicting package, the daemon is not
    /// asked: `docker` may be Podman.
    #[test]
    fn asks_the_daemon_only_for_docker() {
        let runner = FakeRunner::new().on(
            "dpkg-query",
            DPKG.iter().copied(),
            exit(
                1,
                "docker.io installed\nrunc installed\ncontainerd config-files\n",
                "dpkg-query: no packages found matching docker-ce\n",
            ),
        );
        let engine = detect(&FakeFs::new(), &runner, true, &mut Vec::new()).unwrap();
        assert_eq!(engine.packages, ["docker.io", "runc"]);
        assert_eq!(engine.daemon, None);
        assert_eq!(runner.calls().len(), 1);

        let runner = daemon_runner(Output::success("false inactive\n"));
        let engine = detect(&FakeFs::new(), &runner, false, &mut Vec::new()).unwrap();
        assert_eq!(engine.daemon, None);
        assert_eq!(runner.calls().len(), 1);
    }

    #[test]
    fn unknown_without_dpkg() {
        let mut notices = Vec::new();
        assert_eq!(
            detect(&FakeFs::new(), &FakeRunner::new(), false, &mut notices),
            None
        );
        let runner = FakeRunner::new().on("dpkg-query", ["-W"], exit(2, "", "error\n"));
        assert_eq!(detect(&FakeFs::new(), &runner, false, &mut notices), None);
        assert_eq!(notices.len(), 1, "{notices:?}");
    }

    #[test]
    fn reads_daemon_json() {
        let state = |content: &str| daemon_json(&FakeFs::new().with_file(DAEMON_JSON, content));
        assert_eq!(state("{\"debug\": true}\n"), DaemonJson::Valid);
        assert_eq!(state("{}"), DaemonJson::Valid);
        assert_eq!(
            state("[]"),
            DaemonJson::Unusable {
                reason: "is not a JSON object".to_owned()
            }
        );
        assert!(matches!(
            state("{\"debug\": true,}"),
            DaemonJson::Unusable { reason } if reason.starts_with("is not valid JSON: ")
        ));
        assert_eq!(daemon_json(&FakeFs::new()), DaemonJson::Missing);
    }
}
