//! The SSH server: version, how systemd starts it, and its effective config.
//!
//! The effective config comes from `sshd -T`, which prints every setting after
//! sshd has applied its own first-match-wins rules across `sshd_config` and its
//! drop-ins. Reading the files ourselves would get those rules wrong, so
//! `sshd -T` is the only source of truth for SSH checks.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::probe;
use crate::sys::{Cmd, Runner};

/// Units queried to find out how sshd is started. Debian and Ubuntu call them
/// `ssh.*`; Fedora and RHEL call them `sshd.*`.
const UNITS: [&str; 4] = ["ssh.socket", "sshd.socket", "ssh.service", "sshd.service"];

/// What `vpsready` knows about the SSH server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ssh {
    /// OpenSSH version from `ssh -V`, e.g. `9.6p1`.
    pub version: Option<String>,
    /// How systemd starts sshd.
    pub activation: SshActivation,
    /// Effective configuration from `sshd -T`, if it could be read.
    pub effective: Option<SshdConfig>,
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

/// The output of `sshd -T`: lowercase keywords mapped to their values.
/// Keywords that can repeat (`listenaddress`, `hostkey`, ...) keep every value
/// in order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SshdConfig(BTreeMap<String, Vec<String>>);

impl SshdConfig {
    /// Parses `sshd -T` output. Lines are `keyword value...`; blank lines are
    /// skipped.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let (key, value) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            map.entry(key.to_ascii_lowercase())
                .or_default()
                .push(value.trim().to_owned());
        }
        Self(map)
    }

    /// The first value of `key` (lowercase), e.g. `get("passwordauthentication")`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key)?.first().map(String::as_str)
    }

    /// Every value of a repeatable `key`, in order.
    #[must_use]
    pub fn get_all(&self, key: &str) -> &[String] {
        self.0.get(key).map_or(&[], Vec::as_slice)
    }
}

pub(super) fn detect(runner: &dyn Runner, notices: &mut Vec<String>) -> Ssh {
    Ssh {
        version: version(runner, notices),
        activation: activation(runner, notices),
        effective: effective(runner, notices),
    }
}

/// `ssh -V` prints e.g. `OpenSSH_9.6p1 Ubuntu-3ubuntu13.19, OpenSSL ...` to
/// stderr. The client and server come from the same package on every
/// supported distro, so this is also the server version.
fn version(runner: &dyn Runner, notices: &mut Vec<String>) -> Option<String> {
    let out = probe(runner, &Cmd::new("ssh").arg("-V"), notices)?;
    let text = if out.stderr.is_empty() {
        &out.stdout
    } else {
        &out.stderr
    };
    parse_version(&String::from_utf8_lossy(text))
}

fn parse_version(text: &str) -> Option<String> {
    let rest = text.trim().strip_prefix("OpenSSH_")?;
    let end = rest.find([' ', ',']).unwrap_or(rest.len());
    let version = rest.get(..end)?;
    (!version.is_empty()).then(|| version.to_owned())
}

fn effective(runner: &dyn Runner, notices: &mut Vec<String>) -> Option<SshdConfig> {
    let cmd = Cmd::new("sshd").arg("-T").timeout(Duration::from_secs(10));
    let Some(out) = probe(runner, &cmd, notices) else {
        notices.push("sshd not found; is openssh-server installed?".to_owned());
        return None;
    };
    if out.ok() {
        return Some(SshdConfig::parse(&String::from_utf8_lossy(&out.stdout)));
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let reason = stderr.lines().next().unwrap_or("no error output").trim();
    let mut notice = format!("`sshd -T` failed ({reason}); effective SSH config is unknown");
    if reason.contains("Missing privilege separation directory") {
        notice.push_str(
            ". This is normal on Ubuntu with ssh.socket until the first SSH login has started sshd",
        );
    } else if reason.contains("no hostkeys available") {
        notice.push_str(". `sshd -T` needs root");
    }
    notices.push(notice);
    None
}

fn activation(runner: &dyn Runner, notices: &mut Vec<String>) -> SshActivation {
    let cmd = Cmd::new("systemctl")
        .args(["show", "--property=Id,LoadState,ActiveState,UnitFileState"])
        .args(UNITS);
    match probe(runner, &cmd, notices) {
        Some(out) if out.ok() => {
            activation_from_units(&parse_units(&String::from_utf8_lossy(&out.stdout)))
        }
        _ => SshActivation::Unknown,
    }
}

/// One unit from `systemctl show`: `Property=value` lines, units separated by
/// a blank line.
type Unit = BTreeMap<String, String>;

fn parse_units(text: &str) -> Vec<Unit> {
    text.split("\n\n")
        .map(|block| {
            block
                .lines()
                .filter_map(|line| line.split_once('='))
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect::<Unit>()
        })
        .filter(|unit| !unit.is_empty())
        .collect()
}

fn prop<'a>(unit: &'a Unit, key: &str) -> &'a str {
    unit.get(key).map_or("", String::as_str)
}

fn activation_from_units(units: &[Unit]) -> SshActivation {
    let loaded: Vec<&Unit> = units
        .iter()
        .filter(|u| prop(u, "LoadState") == "loaded")
        .collect();
    let kind = |u: &Unit, suffix: &str| prop(u, "Id").ends_with(suffix);

    if loaded.iter().any(|u| {
        kind(u, ".socket")
            && (prop(u, "UnitFileState") == "enabled" || prop(u, "ActiveState") == "active")
    }) {
        SshActivation::Socket
    } else if loaded
        .iter()
        .any(|u| kind(u, ".service") && prop(u, "ActiveState") == "active")
    {
        SshActivation::Service
    } else if loaded.is_empty() {
        SshActivation::Unknown
    } else {
        SshActivation::Inactive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn sshd_config_keeps_repeated_keys() {
        let config = SshdConfig::parse(
            "port 22\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:22\n\nbanner none\nflagonly\n",
        );
        assert_eq!(config.get("port"), Some("22"));
        assert_eq!(config.get_all("listenaddress"), ["[::]:22", "0.0.0.0:22"]);
        assert_eq!(config.get("flagonly"), Some(""));
        assert_eq!(config.get("missing"), None);
        assert!(config.get_all("missing").is_empty());
    }

    #[test]
    fn rhel_style_service_activation() {
        let units = parse_units(
            "Id=sshd.socket\nLoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n\n\
             Id=sshd.service\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\n",
        );
        assert_eq!(activation_from_units(&units), SshActivation::Service);
    }

    #[test]
    fn nothing_loaded_is_unknown() {
        let units = parse_units("Id=ssh.socket\nLoadState=not-found\nActiveState=inactive\n");
        assert_eq!(activation_from_units(&units), SshActivation::Unknown);
        assert_eq!(activation_from_units(&[]), SshActivation::Unknown);
    }

    proptest::proptest! {
        #[test]
        fn parsers_never_panic(s in "\\PC*") {
            let _ = SshdConfig::parse(&s);
            let _ = parse_version(&s);
            let _ = activation_from_units(&parse_units(&s));
        }
    }
}
