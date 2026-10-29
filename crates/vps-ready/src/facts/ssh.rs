//! The SSH server: version, how systemd starts it, and its effective config.
//!
//! The effective config comes from `sshd -T`, which prints every setting after
//! sshd has applied its own first-match-wins rules across `sshd_config` and its
//! drop-ins. Reading the files ourselves would get those rules wrong, so
//! `sshd -T` is the only source of truth for SSH checks. The files are read
//! only to decide whether a drop-in is read early enough to win.

use std::path::Path;
use std::time::Duration;
use std::{fmt, io};

use serde::Serialize;
use sshd_config::{Config, SshdConfig};

use super::{Probe, Unit, probe, prop, systemctl_show};
use crate::sys::{Cmd, Fs, Runner, SysError};

/// The main server configuration file.
pub const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";

/// Units queried to find out how sshd is started. Debian and Ubuntu call them
/// `ssh.*`; Fedora and RHEL call them `sshd.*`.
const UNITS: [&str; 4] = ["ssh.socket", "sshd.socket", "ssh.service", "sshd.service"];

/// What `vps-ready` knows about the SSH server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ssh {
    /// OpenSSH version from `ssh -V`, e.g. `9.6p1`.
    pub version: Option<String>,
    /// How systemd starts sshd.
    pub activation: SshActivation,
    /// Effective configuration from `sshd -T`, if it could be read.
    pub effective: Option<SshdConfig>,
    /// Ports `ssh.socket` listens on, from `systemctl show --property=Listen
    /// ssh.socket`, whether or not it is active. Under socket activation
    /// they, not `sshd -T`, are where sshd accepts connections.
    pub socket_ports: Vec<u16>,
    /// [`SSHD_CONFIG`] and the files it includes; `None` if it could not be
    /// read.
    #[serde(skip)]
    pub files: Option<Config>,
    /// Whether fail2ban's `sshd` jail runs, from `fail2ban-client status
    /// sshd`: `false` when fail2ban is not installed, not running or has no
    /// such jail; `None` when it could not be asked, e.g. without root.
    pub fail2ban: Option<bool>,
}

/// How sshd is started. This matters for port changes: with socket
/// activation the listening port lives in `ssh.socket`, not in `sshd_config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SshActivation {
    /// A systemd socket unit listens and starts sshd on demand (Ubuntu 22.10+).
    Socket,
    /// sshd runs as a normal service.
    Service,
    /// The units exist but nothing is running.
    Inactive,
    /// systemd is not available or the units could not be queried.
    Unknown,
}

impl fmt::Display for SshActivation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Socket => "socket activation",
            Self::Service => "service",
            Self::Inactive => "inactive",
            Self::Unknown => "unknown activation",
        })
    }
}

impl Ssh {
    /// Every port sshd accepts connections on now: `port` and
    /// `listenaddress` from `sshd -T`, and `ssh.socket`'s while it is the
    /// running unit. Sorted, without duplicates.
    #[must_use]
    pub fn ports(&self) -> Vec<u16> {
        let mut ports = Vec::new();
        if let Some(config) = &self.effective {
            ports.extend(
                config
                    .get_all("port")
                    .iter()
                    .filter_map(|p| p.parse::<u16>().ok()),
            );
            ports.extend(
                config
                    .get_all("listenaddress")
                    .iter()
                    .filter_map(|a| last_port(a)),
            );
        }
        if self.activation == SshActivation::Socket {
            ports.extend(&self.socket_ports);
        }
        ports.sort_unstable();
        ports.dedup();
        ports
    }
}

pub(super) fn detect(fs: &dyn Fs, runner: &dyn Runner, notices: &mut Vec<String>) -> Ssh {
    let ssh = Ssh {
        version: version(runner, notices),
        activation: activation(runner, notices),
        effective: effective(runner, notices),
        socket_ports: socket_ports(runner, notices),
        files: files(fs, notices),
        fail2ban: fail2ban(runner, notices),
    };
    if ssh.activation == SshActivation::Socket && ssh.socket_ports.is_empty() {
        notices.push(
            "`systemctl show --property=Listen ssh.socket` showed no port; the ports \
             ssh.socket listens on are unknown"
                .to_owned(),
        );
    }
    ssh
}

/// [`Fs`] as a source for the `sshd_config` reader.
pub(crate) struct FsSource<'a>(pub(crate) &'a dyn Fs);

impl sshd_config::Source for FsSource<'_> {
    fn read(&self, path: &Path) -> io::Result<String> {
        let bytes = self.0.read(path).map_err(to_io)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn list(&self, dir: &Path) -> io::Result<Vec<String>> {
        Ok(self
            .0
            .read_dir(dir)
            .map_err(to_io)?
            .iter()
            .filter_map(|p| Some(p.file_name()?.to_string_lossy().into_owned()))
            .collect())
    }
}

fn to_io(err: SysError) -> io::Error {
    let kind = match err {
        SysError::NotFound(_) => io::ErrorKind::NotFound,
        SysError::Permission(_) => io::ErrorKind::PermissionDenied,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, err.to_string())
}

/// A missing main file gets no notice: `sshd -T` already reports a host
/// without sshd.
fn files(fs: &dyn Fs, notices: &mut Vec<String>) -> Option<Config> {
    match Config::read(&FsSource(fs), Path::new(SSHD_CONFIG)) {
        Ok(config) => Some(config),
        Err(sshd_config::Error::Io { path, source })
            if source.kind() == io::ErrorKind::NotFound && path == Path::new(SSHD_CONFIG) =>
        {
            None
        }
        Err(err) => {
            notices.push(format!("reading {SSHD_CONFIG}: {err}"));
            None
        }
    }
}

fn fail2ban(runner: &dyn Runner, notices: &mut Vec<String>) -> Option<bool> {
    let cmd = Cmd::new("fail2ban-client")
        .args(["status", "sshd"])
        .timeout(Duration::from_secs(10));
    match probe(runner, &cmd, notices) {
        Probe::Ran(out) if out.ok() => Some(true),
        // Its socket is root's: "Permission denied to socket: ...".
        Probe::Ran(out) if String::from_utf8_lossy(&out.stderr).contains("Permission denied") => {
            notices.push(
                "`fail2ban-client` needs root; whether fail2ban's sshd jail runs is unknown"
                    .to_owned(),
            );
            None
        }
        Probe::Ran(_) | Probe::Missing => Some(false),
        Probe::Failed => None,
    }
}

/// `ssh -V` prints e.g. `OpenSSH_9.6p1 Ubuntu-3ubuntu13.19, OpenSSL ...` to
/// stderr. The client and server come from the same source package and version on every
/// supported distro, so this is also the server version.
fn version(runner: &dyn Runner, notices: &mut Vec<String>) -> Option<String> {
    match probe(runner, &Cmd::new("ssh").arg("-V"), notices) {
        Probe::Ran(out) => {
            let text = if out.stderr.is_empty() {
                &out.stdout
            } else {
                &out.stderr
            };
            let version = parse_version(&String::from_utf8_lossy(text));
            if version.is_none() {
                notices.push("unrecognized `ssh -V` output; OpenSSH version is unknown".to_owned());
            }
            version
        }
        Probe::Missing => {
            notices.push("ssh not found; OpenSSH version is unknown".to_owned());
            None
        }
        Probe::Failed => None,
    }
}

fn parse_version(text: &str) -> Option<String> {
    let rest = text.trim().strip_prefix("OpenSSH_")?;
    let end = rest.find([' ', ',']).unwrap_or(rest.len());
    let version = rest.get(..end)?;
    (!version.is_empty()).then(|| version.to_owned())
}

fn effective(runner: &dyn Runner, notices: &mut Vec<String>) -> Option<SshdConfig> {
    let cmd = Cmd::new("sshd").arg("-T").timeout(Duration::from_secs(10));
    let out = match probe(runner, &cmd, notices) {
        Probe::Ran(out) => out,
        Probe::Missing => {
            notices.push("sshd not found; is openssh-server installed?".to_owned());
            return None;
        }
        Probe::Failed => return None,
    };
    if out.ok() {
        return Some(SshdConfig::parse(&String::from_utf8_lossy(&out.stdout)));
    }
    notices.push(sshd_t_failure(&String::from_utf8_lossy(&out.stderr)));
    None
}

/// Explains a failed `sshd -T`. sshd prints a line per unreadable host key
/// before the fatal one, so the whole of stderr is searched and the last line
/// is shown.
fn sshd_t_failure(stderr: &str) -> String {
    let reason = stderr
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or("no error output");
    let mut notice = format!("`sshd -T` failed ({reason}); effective SSH config is unknown");
    if stderr.contains("Missing privilege separation directory") {
        notice.push_str(
            ". This is normal on Ubuntu with ssh.socket until the first SSH login has started sshd",
        );
    } else if stderr.contains("no hostkeys available") || stderr.contains("Could not load host key")
    {
        notice.push_str(". `sshd -T` needs root");
    }
    notice
}

/// No notice when this fails: [`activation`] has one for that.
fn socket_ports(runner: &dyn Runner, notices: &mut Vec<String>) -> Vec<u16> {
    let cmd = Cmd::new("systemctl").args(["show", "--property=Listen", "ssh.socket"]);
    match probe(runner, &cmd, notices) {
        Probe::Ran(out) if out.ok() => parse_listen(&String::from_utf8_lossy(&out.stdout)),
        _ => Vec::new(),
    }
}

/// `Listen=[::]:22 (Stream)`, one line per socket; other kinds, such as a
/// `(Datagram)` or a path, are skipped.
fn parse_listen(text: &str) -> Vec<u16> {
    let mut ports: Vec<u16> = text
        .lines()
        .filter_map(|line| {
            let addr = line.strip_prefix("Listen=")?.strip_suffix(" (Stream)")?;
            addr.contains(':').then(|| last_port(addr))?
        })
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// The port after the last `:` of `[::]:22` or `0.0.0.0:22`, or a bare `22`.
fn last_port(addr: &str) -> Option<u16> {
    addr.rsplit(':').next()?.parse().ok()
}

fn activation(runner: &dyn Runner, notices: &mut Vec<String>) -> SshActivation {
    match systemctl_show(runner, &UNITS, "sshd activation is unknown", notices) {
        Some(units) => activation_from_units(&units, notices),
        None => SshActivation::Unknown,
    }
}

/// Unit states in which the unit is (or is becoming) live.
const RUNNING: [&str; 3] = ["active", "activating", "reloading"];

/// Decides from what is running now, not from what starts at boot: the
/// running unit is the one that owns the port today.
fn activation_from_units(units: &[Unit], notices: &mut Vec<String>) -> SshActivation {
    let loaded: Vec<&Unit> = units
        .iter()
        .filter(|u| prop(u, "LoadState") == "loaded")
        .collect();
    let is = |u: &Unit, suffix: &str| prop(u, "Id").ends_with(suffix);
    let running = |u: &Unit| RUNNING.contains(&prop(u, "ActiveState"));

    let activation = if loaded.iter().any(|u| is(u, ".socket") && running(u)) {
        SshActivation::Socket
    } else if loaded.iter().any(|u| is(u, ".service") && running(u)) {
        SshActivation::Service
    } else if loaded.is_empty() {
        SshActivation::Unknown
    } else {
        SshActivation::Inactive
    };

    if activation != SshActivation::Socket {
        for unit in loaded.iter().filter(|u| {
            is(u, ".socket") && !running(u) && prop(u, "UnitFileState").starts_with("enabled")
        }) {
            notices.push(format!(
                "{} is enabled at boot but not running; after a reboot sshd will start via \
                 socket activation",
                prop(unit, "Id")
            ));
        }
    }
    activation
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::parse_units;

    #[test]
    fn parses_versions() {
        let cases = [
            (
                "OpenSSH_9.6p1 Ubuntu-3ubuntu13.19, OpenSSL 3.0.13 30 Jan 2024\n",
                Some("9.6p1"),
            ),
            (
                "OpenSSH_10.0p2 Debian-7+deb13u4, OpenSSL 3.5.7",
                Some("10.0p2"),
            ),
            ("OpenSSH_9.8p1, LibreSSL 3.3.6", Some("9.8p1")),
            ("Sun_SSH_1.1", None),
            ("OpenSSH_", None),
            ("", None),
        ];
        for (input, want) in cases {
            assert_eq!(parse_version(input).as_deref(), want, "{input:?}");
        }
    }

    /// `(Id, LoadState, ActiveState, UnitFileState)` of one unit.
    type Row<'a> = (&'a str, &'a str, &'a str, &'a str);

    /// Builds `systemctl show` output from rows.
    fn units(rows: &[Row<'_>]) -> Vec<Unit> {
        let text = rows
            .iter()
            .map(|(id, load, active, file)| {
                format!("Id={id}\nLoadState={load}\nActiveState={active}\nUnitFileState={file}\n")
            })
            .collect::<Vec<_>>()
            .join("\n");
        parse_units(&text)
    }

    fn decide(rows: &[Row<'_>]) -> (SshActivation, Vec<String>) {
        let mut notices = Vec::new();
        (activation_from_units(&units(rows), &mut notices), notices)
    }

    #[test]
    fn activation_follows_running_units() {
        let cases: [(&[Row<'_>], SshActivation, usize); 7] = [
            // Ubuntu after a login: socket and the service it started.
            (
                &[
                    ("ssh.socket", "loaded", "active", "enabled"),
                    ("ssh.service", "loaded", "active", "disabled"),
                ],
                SshActivation::Socket,
                0,
            ),
            // RHEL: plain service, socket unit present but unused.
            (
                &[
                    ("sshd.socket", "loaded", "inactive", "disabled"),
                    ("sshd.service", "loaded", "active", "enabled"),
                ],
                SshActivation::Service,
                0,
            ),
            // Socket enabled for boot, but the admin started the service by hand.
            (
                &[
                    ("ssh.socket", "loaded", "inactive", "enabled"),
                    ("ssh.service", "loaded", "active", "disabled"),
                ],
                SshActivation::Service,
                1,
            ),
            // Socket failed to bind; enabled-runtime counts as enabled.
            (
                &[
                    ("ssh.socket", "loaded", "failed", "enabled-runtime"),
                    ("ssh.service", "loaded", "active", "enabled"),
                ],
                SshActivation::Service,
                1,
            ),
            // A masked socket is not loaded and is ignored.
            (
                &[
                    ("ssh.socket", "masked", "inactive", "masked"),
                    ("ssh.service", "loaded", "reloading", "enabled"),
                ],
                SshActivation::Service,
                0,
            ),
            (
                &[("ssh.service", "loaded", "inactive", "disabled")],
                SshActivation::Inactive,
                0,
            ),
            (
                &[("ssh.socket", "not-found", "inactive", "")],
                SshActivation::Unknown,
                0,
            ),
        ];
        for (rows, want, notice_count) in cases {
            let (got, notices) = decide(rows);
            assert_eq!(got, want, "{rows:?}");
            assert_eq!(notices.len(), notice_count, "{rows:?}: {notices:?}");
        }
        assert_eq!(decide(&[]).0, SshActivation::Unknown);
    }

    #[test]
    fn explains_sshd_t_failures() {
        let not_root = "Could not load host key: /etc/ssh/ssh_host_rsa_key\n\
                        Could not load host key: /etc/ssh/ssh_host_ed25519_key\n\
                        sshd: no hostkeys available -- exiting.\n";
        let notice = sshd_t_failure(not_root);
        assert!(
            notice.contains("(sshd: no hostkeys available -- exiting.)"),
            "{notice}"
        );
        assert!(notice.ends_with("needs root"), "{notice}");

        let ubuntu = sshd_t_failure("Missing privilege separation directory: /run/sshd\n");
        assert!(ubuntu.contains("until the first SSH login"), "{ubuntu}");

        assert!(sshd_t_failure("").contains("(no error output)"));
    }

    #[test]
    fn asks_fail2ban_for_its_sshd_jail() {
        use crate::sys::Output;
        use crate::sys::fake::FakeRunner;

        let ask = |runner: FakeRunner| {
            let mut notices = Vec::new();
            (fail2ban(&runner, &mut notices), notices.len())
        };
        let exits = |status, stderr: &str| {
            FakeRunner::new().on(
                "fail2ban-client",
                ["status", "sshd"],
                Output {
                    status,
                    stdout: Vec::new(),
                    stderr: stderr.as_bytes().to_vec(),
                },
            )
        };
        assert_eq!(ask(exits(0, "")), (Some(true), 0));
        assert_eq!(
            ask(exits(
                255,
                "ERROR  Failed to access socket path: /var/run/fail2ban/fail2ban.sock. \
                 Is fail2ban running?\n"
            )),
            (Some(false), 0)
        );
        assert_eq!(
            ask(exits(
                255,
                "ERROR  Permission denied to socket: /var/run/fail2ban/fail2ban.sock, \
                 (you must be root)\n"
            )),
            (None, 1)
        );
        assert_eq!(ask(FakeRunner::new()), (Some(false), 0));
    }

    #[test]
    fn reads_the_socket_ports() {
        let text = "Listen=0.0.0.0:22 (Stream)\nListen=[::]:22 (Stream)\n\
                    Listen=[::]:2222 (Stream)\nListen=/run/x.sock (Stream)\n\
                    Listen=[::]:53 (Datagram)\n";
        assert_eq!(parse_listen(text), [22, 2222]);
        assert!(parse_listen("").is_empty());
    }

    #[test]
    fn ports_are_sshd_t_and_the_running_socket() {
        let mut ssh = Ssh {
            version: None,
            activation: SshActivation::Service,
            effective: Some(SshdConfig::parse(
                "port 22\nlistenaddress [::]:2222\nlistenaddress 0.0.0.0:22\n",
            )),
            socket_ports: vec![22, 2200],
            files: None,
            fail2ban: None,
        };
        assert_eq!(ssh.ports(), [22, 2222]);
        ssh.activation = SshActivation::Socket;
        assert_eq!(ssh.ports(), [22, 2200, 2222]);
    }

    proptest::proptest! {
        #[test]
        fn parsers_never_panic(s in "\\PC*") {
            let _ = parse_listen(&s);
            let _ = parse_version(&s);
            let _ = activation_from_units(&parse_units(&s), &mut Vec::new());
            let _ = sshd_t_failure(&s);
        }
    }
}
