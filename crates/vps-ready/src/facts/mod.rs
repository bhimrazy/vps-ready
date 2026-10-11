//! Read-only discovery of what the host is.
//!
//! [`collect`] gathers [`Facts`] through the [`Fs`] and [`Runner`] traits.
//! Missing sources and failed probes are not errors: the fact becomes unknown
//! and a notice is recorded, so `vps-ready detect` also works on a developer
//! laptop or in a minimal container.

use std::fmt;
use std::path::Path;

use serde::Serialize;

use crate::sys::{Cmd, Fs, Output, Runner, SysError};

pub mod listeners;
pub mod os_release;
pub mod session;
pub mod ssh;
pub mod virt;

pub use listeners::{Listener, Proto};
pub use os_release::{OsFamily, OsRelease};
pub use session::{Env, SshSession};
pub use ssh::{Ssh, SshActivation, SshdConfig};
pub use virt::{Virt, Virtualization};

/// Paths whose presence means Docker is installed.
const DOCKER_PATHS: [&str; 3] = [
    "/run/docker.sock",
    "/var/run/docker.sock",
    "/usr/bin/docker",
];

/// Everything `vps-ready` knows about the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Facts {
    /// Operating system identification from `os-release`.
    pub os: OsRelease,
    /// Init system running as PID 1.
    pub init: Init,
    /// Container and VM detection.
    pub virtualization: Virtualization,
    /// The SSH server.
    pub ssh: Ssh,
    /// Listening TCP and UDP sockets.
    pub listeners: Vec<Listener>,
    /// The SSH session `vps-ready` runs in, if any.
    pub session: Option<SshSession>,
    /// Whether Docker is installed. Docker changes firewall and sysctl rules.
    pub docker: bool,
    /// Human-readable notes about facts that could not be determined.
    pub notices: Vec<String>,
}

/// The init system running as PID 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Init {
    /// systemd.
    Systemd,
    /// OpenRC (Alpine, Gentoo).
    OpenRc,
    /// Something else, e.g. a shell or `tini` in a container.
    Other(String),
    /// `/proc/1/comm` could not be read.
    Unknown,
}

impl fmt::Display for Init {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Systemd => f.write_str("systemd"),
            Self::OpenRc => f.write_str("openrc"),
            Self::Other(name) => write!(f, "other ({name})"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

/// Errors that stop fact collection. A *missing* source is not an error.
#[derive(Debug, thiserror::Error)]
pub enum FactsError {
    /// A source exists but could not be read (e.g. permission denied).
    #[error("reading {path}")]
    Read {
        /// Path on the inspected system.
        path: String,
        /// Underlying error.
        #[source]
        source: SysError,
    },
}

/// Collects facts about the system behind `fs` and `runner`, plus the
/// session described by `env`.
///
/// # Errors
///
/// [`FactsError::Read`] if a source exists but cannot be read.
pub fn collect(fs: &dyn Fs, runner: &dyn Runner, env: &Env) -> Result<Facts, FactsError> {
    let mut notices = Vec::new();
    let os = detect_os(fs, &mut notices)?;
    let init = detect_init(fs, &mut notices)?;
    let virtualization = virt::detect(fs, runner, &mut notices);
    let ssh = ssh::detect(runner, &mut notices);
    let listeners = listeners::detect(runner, &mut notices);
    let session = session::detect(env, &mut notices);
    let docker = DOCKER_PATHS.iter().any(|p| fs.exists(Path::new(p)));
    Ok(Facts {
        os,
        init,
        virtualization,
        ssh,
        listeners,
        session,
        docker,
        notices,
    })
}

/// The outcome of running a probe command, or of interpreting its output.
enum Probe<T = Output> {
    /// The command ran. A non-zero exit status is for the caller to judge.
    Ran(T),
    /// The program is not installed. Many probes exist only on some distros,
    /// so the caller decides whether this deserves a notice.
    Missing,
    /// The command could not be run; a notice has already been recorded.
    Failed,
}

fn probe(runner: &dyn Runner, cmd: &Cmd, notices: &mut Vec<String>) -> Probe {
    match runner.run(cmd) {
        Ok(out) => Probe::Ran(out),
        Err(SysError::NotFound(_)) => {
            tracing::debug!(program = %cmd.program, "probe not found");
            Probe::Missing
        }
        Err(err) => {
            notices.push(format!("running `{}`: {err}", cmd.program));
            Probe::Failed
        }
    }
}

/// Reads `path`, mapping "not found" to `None`.
fn read_optional(fs: &dyn Fs, path: &str) -> Result<Option<Vec<u8>>, FactsError> {
    match fs.read(Path::new(path)) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(SysError::NotFound(_)) => Ok(None),
        Err(source) => Err(FactsError::Read {
            path: path.to_owned(),
            source,
        }),
    }
}

fn detect_os(fs: &dyn Fs, notices: &mut Vec<String>) -> Result<OsRelease, FactsError> {
    for path in os_release::PATHS {
        if let Some(bytes) = read_optional(fs, path)? {
            return Ok(OsRelease::parse(&String::from_utf8_lossy(&bytes)));
        }
    }
    notices.push(format!(
        "no os-release found ({}); OS is unknown",
        os_release::PATHS.join(", ")
    ));
    Ok(OsRelease::unknown())
}

fn detect_init(fs: &dyn Fs, notices: &mut Vec<String>) -> Result<Init, FactsError> {
    let Some(bytes) = read_optional(fs, "/proc/1/comm")? else {
        notices.push("/proc/1/comm not found; init system is unknown".to_owned());
        return Ok(Init::Unknown);
    };
    let comm = String::from_utf8_lossy(&bytes).trim().to_owned();
    Ok(match comm.as_str() {
        "systemd" => Init::Systemd,
        "openrc-init" => Init::OpenRc,
        // Alpine boots busybox `init`, which then starts OpenRC.
        "init" if fs.exists(Path::new("/sbin/openrc")) => Init::OpenRc,
        "" => Init::Unknown,
        _ => Init::Other(comm),
    })
}

/// Captured hosts, shared with the tests of the layers built on facts.
#[cfg(test)]
pub(crate) mod fixtures {
    use std::path::{Path, PathBuf};

    use super::{Env, Facts, collect};
    use crate::sys::RealFs;
    use crate::sys::fake::FakeRunner;

    /// Hosts captured by `test/capture-host-fixtures.sh`.
    pub(crate) const HOSTS: [&str; 3] = ["ubuntu-24.04", "debian-12", "debian-13"];

    pub(crate) fn testdata(path: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join(path)
    }

    /// Facts for a captured host, answering commands from its fixture.
    /// `prefer` selects a scenario, e.g. `["sshd-T-before-login"]`.
    pub(crate) fn host(name: &str, prefer: &[&str]) -> Facts {
        let dir = testdata(&format!("hosts/{name}"));
        let runner = FakeRunner::from_fixture(&dir, prefer).unwrap();
        let env_file = std::fs::read_to_string(dir.join("env")).unwrap();
        let env = Env {
            ssh_connection: env_file
                .trim()
                .strip_prefix("SSH_CONNECTION=")
                .map(str::to_owned),
        };
        collect(&RealFs::new(dir.join("root")), &runner, &env).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{HOSTS, host, testdata};
    use super::*;
    use crate::sys::RealFs;
    use crate::sys::fake::{FakeFs, FakeRunner};

    /// Parser fixtures for distros we cannot capture yet.
    const OS_RELEASE_FIXTURES: [&str; 5] = [
        "ubuntu-24.04",
        "debian-13",
        "rocky-9",
        "alpine-3.22",
        "fedora-42",
    ];

    /// `detect` and `audit` must never change the host, so collecting facts
    /// runs exactly these read-only commands. A new probe has to be added
    /// here, where review sees it.
    const READ_ONLY_COMMANDS: [&[&str]; 6] = [
        &["systemd-detect-virt", "--container"],
        &["systemd-detect-virt", "--vm"],
        &["ssh", "-V"],
        &["sshd", "-T"],
        &[
            "systemctl",
            "show",
            "--property=Id,LoadState,ActiveState,UnitFileState",
            "ssh.socket",
            "sshd.socket",
            "ssh.service",
            "sshd.service",
        ],
        &["ss", "-tulnpH"],
    ];

    #[test]
    fn runs_only_read_only_commands() {
        let dir = testdata("hosts/ubuntu-24.04");
        let runner = FakeRunner::from_fixture(&dir, &[]).unwrap();
        collect(&RealFs::new(dir.join("root")), &runner, &Env::default()).unwrap();
        let mut ran: Vec<Vec<String>> = runner
            .calls()
            .into_iter()
            .inspect(|c| assert!(c.env.is_empty(), "{c:?}"))
            .map(|c| std::iter::once(c.program).chain(c.args).collect())
            .collect();
        let mut allowed: Vec<Vec<String>> = READ_ONLY_COMMANDS
            .iter()
            .map(|argv| argv.iter().map(|a| (*a).to_owned()).collect())
            .collect();
        ran.sort();
        allowed.sort();
        assert_eq!(ran, allowed);
    }

    #[test]
    fn os_release_fixtures_snapshot() {
        for name in OS_RELEASE_FIXTURES {
            let root = testdata(&format!("os-release/{name}"));
            let facts = collect(&RealFs::new(root), &FakeRunner::new(), &Env::default()).unwrap();
            insta::assert_yaml_snapshot!(name, facts.os);
        }
    }

    #[test]
    fn hosts_snapshot() {
        for name in HOSTS {
            insta::assert_yaml_snapshot!(format!("host-{name}"), host(name, &[]));
        }
    }

    #[test]
    fn captured_hosts_are_complete() {
        for name in HOSTS {
            let facts = host(name, &[]);
            assert_eq!(facts.os.family, OsFamily::Debian, "{name}");
            assert_eq!(facts.init, Init::Systemd, "{name}");
            assert!(facts.virtualization.in_container(), "{name}");
            assert!(facts.ssh.version.is_some(), "{name}");
            assert!(facts.ssh.effective.is_some(), "{name}");
            assert!(
                facts
                    .listeners
                    .iter()
                    .any(|l| l.port == 22 && l.proto == Proto::Tcp),
                "{name}"
            );
            assert_eq!(facts.session.map(|s| s.server.port()), Some(22), "{name}");
            assert!(facts.notices.is_empty(), "{name}: {:?}", facts.notices);
        }
    }

    #[test]
    fn ubuntu_uses_socket_activation_and_debian_does_not() {
        assert_eq!(
            host("ubuntu-24.04", &[]).ssh.activation,
            SshActivation::Socket
        );
        assert_eq!(
            host("debian-12", &[]).ssh.activation,
            SshActivation::Service
        );
        assert_eq!(
            host("debian-13", &[]).ssh.activation,
            SshActivation::Service
        );
    }

    /// Before the first connection only systemd holds port 22 on Ubuntu, so a
    /// check for "is SSH listening" must not look for an sshd process.
    #[test]
    fn ubuntu_port_22_belongs_to_systemd_before_first_login() {
        let facts = host("ubuntu-24.04", &["listeners-before-login"]);
        let ssh_port: Vec<_> = facts.listeners.iter().filter(|l| l.port == 22).collect();
        assert!(!ssh_port.is_empty());
        assert!(
            ssh_port.iter().all(|l| l.processes == ["systemd"]),
            "{ssh_port:?}"
        );
    }

    #[test]
    fn unknown_fixture_scenario_is_an_error() {
        let dir = testdata("hosts/ubuntu-24.04");
        assert!(FakeRunner::from_fixture(&dir, &["sshd-T-dropin-9"]).is_err());
    }

    #[test]
    fn ubuntu_sshd_t_fails_before_first_login() {
        let facts = host("ubuntu-24.04", &["sshd-T-before-login"]);
        assert_eq!(facts.ssh.effective, None);
        let notice = facts.notices.join("\n");
        assert!(notice.contains("until the first SSH login"), "{notice}");
    }

    /// sshd keeps the first value it reads. A provider's 50-cloud-init.conf
    /// beats a later 99- drop-in, but loses to an earlier 00- drop-in.
    #[test]
    fn first_sshd_dropin_wins() {
        for name in HOSTS {
            let password_auth = |scenario| {
                host(name, &[scenario])
                    .ssh
                    .effective
                    .unwrap()
                    .get("passwordauthentication")
                    .map(str::to_owned)
            };
            assert_eq!(
                password_auth("sshd-T-dropin-99").as_deref(),
                Some("yes"),
                "{name}"
            );
            assert_eq!(
                password_auth("sshd-T-dropin-00").as_deref(),
                Some("no"),
                "{name}"
            );
        }
    }

    #[test]
    fn empty_system_is_unknown_with_notices() {
        let facts = collect(&FakeFs::new(), &FakeRunner::new(), &Env::default()).unwrap();
        assert_eq!(facts.os.family, OsFamily::Unknown);
        assert_eq!(facts.init, Init::Unknown);
        assert_eq!(facts.virtualization.vm, Virt::Unknown);
        assert_eq!(facts.ssh.activation, SshActivation::Unknown);
        assert!(facts.listeners.is_empty());
        assert!(!facts.docker);
        // os-release, init, virtualization, ssh version, sshd activation,
        // sshd config, ss, SSH_CONNECTION.
        assert_eq!(facts.notices.len(), 8, "{:?}", facts.notices);
    }

    #[test]
    fn container_marker_without_systemd() {
        let fs = FakeFs::new().with_file("/.dockerenv", "");
        let facts = collect(&fs, &FakeRunner::new(), &Env::default()).unwrap();
        assert_eq!(
            facts.virtualization.container,
            Virt::Detected("docker".into())
        );
    }

    #[test]
    fn detects_docker() {
        let fs = FakeFs::new().with_file("/usr/bin/docker", "");
        assert!(
            collect(&fs, &FakeRunner::new(), &Env::default())
                .unwrap()
                .docker
        );
    }

    #[test]
    fn falls_back_to_usr_lib() {
        let fs = FakeFs::new().with_file("/usr/lib/os-release", "ID=arch\n");
        let facts = collect(&fs, &FakeRunner::new(), &Env::default()).unwrap();
        assert_eq!(facts.os.family, OsFamily::Arch);
    }

    #[test]
    fn detects_init() {
        let cases: [(&[(&str, &str)], Init); 4] = [
            (&[("/proc/1/comm", "systemd\n")], Init::Systemd),
            (
                &[("/proc/1/comm", "init\n"), ("/sbin/openrc", "")],
                Init::OpenRc,
            ),
            (&[("/proc/1/comm", "init\n")], Init::Other("init".into())),
            (&[("/proc/1/comm", "bash\n")], Init::Other("bash".into())),
        ];
        for (files, want) in cases {
            let fs = files
                .iter()
                .fold(FakeFs::new(), |fs, (p, c)| fs.with_file(*p, *c));
            let facts = collect(&fs, &FakeRunner::new(), &Env::default()).unwrap();
            assert_eq!(facts.init, want, "{files:?}");
        }
    }
}
