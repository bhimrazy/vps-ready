//! Docker Engine on the Debian family: the packages that matter to
//! `deploy.docker`, `docker.service`, `/etc/docker/daemon.json`, and what
//! the running daemon says about itself. Only read-only commands:
//! `dpkg-query`, `systemctl show`, `docker info`, `docker ps` and
//! `docker network ls`. The daemon is asked only while `docker.service` is
//! active, since `docker` would otherwise start it through `docker.socket`.

use std::path::Path;

use serde::Serialize;

use super::{Probe, probe, prop, systemctl_show};
use crate::sys::{Cmd, Fs, Runner, SysError};

/// Docker's configuration file.
pub const DAEMON_JSON: &str = "/etc/docker/daemon.json";

/// Docker's daemon. Its package and the static release both put it here.
const DOCKERD: &str = "/usr/bin/dockerd";

/// Docker Engine's package from Docker's repository.
const DOCKER_CE: &str = "docker-ce";

/// The packages asked about: Docker Engine from Docker's repository, then
/// the distro's packages that conflict with it.
pub const PACKAGES: [&str; 5] = [
    DOCKER_CE,
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
    /// The version of `docker-ce`, e.g. `5:29.0.1-1~debian.13~trixie`.
    pub docker_ce_version: Option<String>,
    /// `docker.service`. `None` when there is no sign of Docker, a
    /// conflicting package is installed, or systemd could not be asked.
    pub service: Option<DockerService>,
    /// [`DAEMON_JSON`].
    pub daemon_json: DaemonJson,
    /// The running daemon. `None` unless `docker.service` is active and
    /// the daemon answered.
    pub daemon: Option<DockerDaemon>,
}

impl DockerEngine {
    /// Whether Docker Engine is installed: Docker's package, or another
    /// install that has a `docker.service` unit.
    #[must_use]
    pub fn installed(&self) -> bool {
        self.from_package() || self.service.as_ref().is_some_and(|s| s.loaded)
    }

    /// Whether `docker-ce` is installed.
    #[must_use]
    pub fn from_package(&self) -> bool {
        self.packages.iter().any(|p| p == DOCKER_CE)
    }

    /// The major version of `docker-ce`, e.g. 29.
    #[must_use]
    pub fn major(&self) -> Option<u32> {
        let version = self.docker_ce_version.as_deref()?;
        // Without the epoch: `5:29.0.1-1~...` is 29.
        let upstream = version.split_once(':').map_or(version, |(_, v)| v);
        let digits: String = upstream.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    }
}

/// The state of `docker.service`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DockerService {
    /// Whether systemd has the unit.
    pub loaded: bool,
    /// Whether it runs.
    pub active: bool,
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

/// `None` when `dpkg-query` is missing or fails. `docker` is whether
/// Docker's socket or CLI exists.
pub(super) fn detect(
    fs: &dyn Fs,
    runner: &dyn Runner,
    docker: bool,
    notices: &mut Vec<String>,
) -> Option<DockerEngine> {
    let installed = installed(runner, notices)?;
    let packages: Vec<String> = installed.iter().map(|(p, _)| p.clone()).collect();
    let docker_ce_version = installed
        .into_iter()
        .find(|(p, _)| p == DOCKER_CE)
        .and_then(|(_, v)| v);
    let daemon_json = daemon_json(fs);
    let conflicts = packages.iter().any(|p| p != DOCKER_CE);
    let sign = docker || docker_ce_version.is_some() || fs.exists(Path::new(DOCKERD));
    let service = (sign && !conflicts)
        .then(|| service(runner, notices))
        .flatten();
    let daemon = match service {
        Some(DockerService { active: true, .. }) => daemon(runner, notices),
        Some(DockerService { loaded: true, .. }) => {
            notices.push(
                "docker.service is not running; its containers and networks are unknown".to_owned(),
            );
            None
        }
        _ => None,
    };
    Some(DockerEngine {
        packages,
        docker_ce_version,
        service,
        daemon_json,
        daemon,
    })
}

/// The installed packages among [`PACKAGES`], in that order, with their
/// versions. A package in any state but `not-installed` or `config-files`
/// counts, since it is in the way of Docker's packages as well.
fn installed(
    runner: &dyn Runner,
    notices: &mut Vec<String>,
) -> Option<Vec<(String, Option<String>)>> {
    let cmd = Cmd::new("dpkg-query")
        .args([
            "-W",
            "--showformat=${Package} ${db:Status-Status} ${Version}\\n",
        ])
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
    let present: Vec<(&str, Option<&str>)> = text
        .lines()
        .filter_map(|l| {
            let mut fields = l.split_whitespace();
            Some((fields.next()?, fields.next()?, fields.next()))
        })
        .filter(|(_, status, _)| !matches!(*status, "not-installed" | "config-files"))
        .map(|(name, _, version)| (name, version))
        .collect();
    Some(
        PACKAGES
            .iter()
            .filter_map(|p| {
                let (_, version) = present.iter().find(|(name, _)| name == p)?;
                Some(((*p).to_owned(), version.map(str::to_owned)))
            })
            .collect(),
    )
}

/// `docker.service` from `systemctl show`; `None` with a notice when that
/// fails.
fn service(runner: &dyn Runner, notices: &mut Vec<String>) -> Option<DockerService> {
    let units = systemctl_show(
        runner,
        &["docker.service"],
        "docker.service is unknown",
        notices,
    )?;
    let unit = units.first()?;
    Some(DockerService {
        loaded: prop(unit, "LoadState") == "loaded",
        active: prop(unit, "ActiveState") == "active",
    })
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

/// Asks the daemon. One that does not answer gets a notice and `None`.
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
        "--showformat=${Package} ${db:Status-Status} ${Version}\\n",
        "docker-ce",
        "docker.io",
        "podman-docker",
        "containerd",
        "runc",
    ];

    const SHOW: &[&str] = &[
        "show",
        "--property=Id,LoadState,ActiveState,UnitFileState",
        "docker.service",
    ];

    const VERSION: &str = "5:29.0.1-1~debian.13~trixie";

    fn exit(status: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            status,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    fn unit(active: &str) -> Output {
        Output::success(format!(
            "Id=docker.service\nLoadState=loaded\nActiveState={active}\nUnitFileState=enabled\n"
        ))
    }

    fn daemon_runner(info: Output) -> FakeRunner {
        FakeRunner::new()
            .on(
                "dpkg-query",
                DPKG.iter().copied(),
                exit(1, &format!("docker-ce installed {VERSION}\n"), ""),
            )
            .on("systemctl", SHOW.iter().copied(), unit("active"))
            .on("docker", ["info"], info)
            .on("docker", ["ps"], Output::success("web\ndb\n"))
            .on("docker", ["network"], Output::success("app_default\n"))
    }

    /// The commands are read-only and fixed, as the facts' own list.
    #[test]
    fn asks_dpkg_systemd_then_the_daemon() {
        let runner = daemon_runner(Output::success("false inactive\n"));
        let mut notices = Vec::new();
        let engine = detect(&FakeFs::new(), &runner, true, &mut notices).unwrap();
        assert!(notices.is_empty(), "{notices:?}");
        assert_eq!(
            engine,
            DockerEngine {
                packages: vec!["docker-ce".to_owned()],
                docker_ce_version: Some(VERSION.to_owned()),
                service: Some(DockerService {
                    loaded: true,
                    active: true
                }),
                daemon_json: DaemonJson::Missing,
                daemon: Some(DockerDaemon {
                    live_restore: false,
                    swarm: false,
                    running: vec!["web".to_owned(), "db".to_owned()],
                    networks: vec!["app_default".to_owned()],
                }),
            }
        );
        assert_eq!(engine.major(), Some(29));
        assert!(engine.installed() && engine.from_package());
        let ran: Vec<Vec<String>> = runner
            .calls()
            .into_iter()
            .map(|c| std::iter::once(c.program).chain(c.args).collect())
            .collect();
        let want: [&[&str]; 5] = [
            &[&["dpkg-query"], DPKG].concat(),
            &[&["systemctl"], SHOW].concat(),
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

    /// A stopped Docker is not asked: `docker` would start it through
    /// `docker.socket`.
    #[test]
    fn a_stopped_docker_is_not_asked() {
        let runner = FakeRunner::new()
            .on(
                "dpkg-query",
                DPKG.iter().copied(),
                exit(1, &format!("docker-ce installed {VERSION}\n"), ""),
            )
            .on("systemctl", SHOW.iter().copied(), unit("inactive"));
        let mut notices = Vec::new();
        let engine = detect(&FakeFs::new(), &runner, true, &mut notices).unwrap();
        assert_eq!(engine.daemon, None);
        assert_eq!(runner.calls().len(), 2);
        assert_eq!(
            notices,
            ["docker.service is not running; its containers and networks are unknown"]
        );
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

    /// Without a sign of Docker, or with a conflicting package, neither
    /// systemd nor the daemon is asked: `docker` may be Podman.
    #[test]
    fn asks_only_about_docker() {
        let runner = FakeRunner::new().on(
            "dpkg-query",
            DPKG.iter().copied(),
            exit(
                1,
                "docker.io installed 26.1.5+dfsg1-9\nrunc installed 1.1.15\n\
                 containerd config-files 1.7.24\n",
                "dpkg-query: no packages found matching docker-ce\n",
            ),
        );
        let engine = detect(&FakeFs::new(), &runner, true, &mut Vec::new()).unwrap();
        assert_eq!(engine.packages, ["docker.io", "runc"]);
        assert_eq!((engine.service, &engine.daemon), (None, &None));
        assert_eq!(runner.calls().len(), 1);

        let runner = FakeRunner::new().on("dpkg-query", ["-W"], exit(1, "", ""));
        let engine = detect(&FakeFs::new(), &runner, false, &mut Vec::new()).unwrap();
        assert_eq!((engine.service, &engine.daemon), (None, &None));
        assert!(!engine.installed());
        assert_eq!(runner.calls().len(), 1);
    }

    #[test]
    fn major_versions() {
        let major = |v: &str| {
            DockerEngine {
                packages: vec![DOCKER_CE.to_owned()],
                docker_ce_version: Some(v.to_owned()),
                service: None,
                daemon_json: DaemonJson::Missing,
                daemon: None,
            }
            .major()
        };
        assert_eq!(major(VERSION), Some(29));
        assert_eq!(major("5:20.10.24~3-0~debian-bullseye"), Some(20));
        assert_eq!(major("23.0.0-1"), Some(23));
        assert_eq!(major("odd"), None);
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
