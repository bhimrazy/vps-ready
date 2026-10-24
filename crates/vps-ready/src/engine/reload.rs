//! Reloads: what makes a daemon pick up the files a module changed.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::sys::{Cmd, Sys};

/// A reload a module needs after its resources are applied. A closed set,
/// so the journal records it by name and a rollback in a later process
/// runs the same commands from that name alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reload {
    /// `sshd -t`, then `systemctl try-reload-or-restart ssh.service`.
    SshdReload,
    /// `nft -c -f /etc/vps-ready/firewall.nft`, then
    /// `systemctl try-reload-or-restart vps-ready-firewall.service`.
    FirewallReload,
    /// `fail2ban-client -t`, then `systemctl restart fail2ban.service`.
    Fail2banRestart,
    /// `systemctl daemon-reload`, with no check.
    DaemonReload,
}

/// Longer than systemd's default start and stop timeout (90 s), so systemd
/// reports a hung unit before the command is killed.
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(120);

impl Reload {
    /// The name the journal records, e.g. `sshd-reload`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::SshdReload => "sshd-reload",
            Self::FirewallReload => "firewall-reload",
            Self::Fail2banRestart => "fail2ban-restart",
            Self::DaemonReload => "daemon-reload",
        }
    }

    /// What must pass before the reload runs, if anything.
    #[must_use]
    pub fn check(self) -> Option<Cmd> {
        match self {
            Self::SshdReload => Some(Cmd::new("sshd").arg("-t")),
            Self::FirewallReload => {
                Some(Cmd::new("nft").args(["-c", "-f", "/etc/vps-ready/firewall.nft"]))
            }
            Self::Fail2banRestart => Some(Cmd::new("fail2ban-client").arg("-t")),
            Self::DaemonReload => None,
        }
    }

    /// The reload itself.
    #[must_use]
    pub fn command(self) -> Cmd {
        let args: &[&str] = match self {
            Self::SshdReload => &["try-reload-or-restart", "ssh.service"],
            Self::FirewallReload => &["try-reload-or-restart", "vps-ready-firewall.service"],
            Self::Fail2banRestart => &["restart", "fail2ban.service"],
            Self::DaemonReload => &["daemon-reload"],
        };
        Cmd::new("systemctl")
            .args(args.iter().copied())
            .timeout(SYSTEMCTL_TIMEOUT)
    }
}

impl fmt::Display for Reload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Runs `cmd`; `Err` holds its exit status and stderr, or why it could not
/// run.
pub(super) fn run(sys: Sys, cmd: &Cmd) -> Result<(), String> {
    match sys.runner.run(cmd) {
        Ok(out) if out.ok() => Ok(()),
        Ok(out) => Err(format!(
            "`{}` exited with status {}: {}",
            line(cmd),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        Err(e) => Err(format!("`{}` could not run: {e}", line(cmd))),
    }
}

fn line(cmd: &Cmd) -> String {
    std::iter::once(cmd.program.as_str())
        .chain(cmd.args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Reload; 4] = [
        Reload::SshdReload,
        Reload::FirewallReload,
        Reload::Fail2banRestart,
        Reload::DaemonReload,
    ];

    #[test]
    fn serializes_by_name() {
        for reload in ALL {
            let json = serde_json::to_string(&reload).unwrap();
            assert_eq!(json, format!("\"{}\"", reload.name()));
            assert_eq!(serde_json::from_str::<Reload>(&json).unwrap(), reload);
        }
        assert!(serde_json::from_str::<Reload>("\"reboot\"").is_err());
    }

    #[test]
    fn commands_are_fixed() {
        let lines: Vec<(Option<String>, String)> = ALL
            .iter()
            .map(|r| (r.check().as_ref().map(line), line(&r.command())))
            .collect();
        assert_eq!(
            lines,
            [
                (
                    Some("sshd -t".into()),
                    "systemctl try-reload-or-restart ssh.service".into()
                ),
                (
                    Some("nft -c -f /etc/vps-ready/firewall.nft".into()),
                    "systemctl try-reload-or-restart vps-ready-firewall.service".into()
                ),
                (
                    Some("fail2ban-client -t".into()),
                    "systemctl restart fail2ban.service".into()
                ),
                (None, "systemctl daemon-reload".into()),
            ]
        );
    }
}
