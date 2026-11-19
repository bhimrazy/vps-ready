//! Reloads: what makes a daemon pick up the files a module changed.

use std::fmt;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::journal::{Event, Record};
use crate::resource::Backup;
use crate::sys::{Cmd, Sys};

const FIREWALL_UNIT: &str = "vps-ready-firewall.service";

/// A reload a module needs after its resources are applied. A closed set,
/// so the journal records it by name and a rollback in a later process
/// runs the same commands from that name alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reload {
    /// `sshd -t`, then `systemctl try-reload-or-restart ssh.service`.
    SshdReload,
    /// `nft -c -f /etc/vps-ready/firewall.nft`, then
    /// `systemctl try-reload-or-restart vps-ready-firewall.service`; a
    /// rollback starts it if it was active before (see
    /// [`Reload::rollback_steps`]).
    FirewallReload,
    /// `fail2ban-client -t`, then `systemctl try-restart fail2ban.service`:
    /// only a running fail2ban, so a rollback that stopped it leaves it off.
    Fail2banRestart,
    /// `systemctl daemon-reload`, with no check.
    DaemonReload,
    /// `dockerd --validate`, then `systemctl try-restart docker.service`:
    /// the `daemon.json` keys vps-ready sets are not reloaded on SIGHUP.
    /// The check reads the default config file, `/etc/docker/daemon.json`,
    /// and also passes when there is none, as after a rollback that removed
    /// it; with `--config-file` it would fail then and skip the restart.
    DockerRestart,
    /// `caddy validate`, then `systemctl reload-or-restart caddy.service`:
    /// also a stopped Caddy, e.g. after a rollback, so that apply leaves it
    /// serving. A rollback that removed the Caddyfile stops and disables
    /// Caddy instead (see [`Reload::rollback_steps`]).
    CaddyReload,
}

/// The Caddyfile [`Reload::CaddyReload`] checks, and the one Caddy's unit
/// reads.
pub const CADDYFILE: &str = "/etc/caddy/Caddyfile";

/// Longer than systemd's default start and stop timeout (90 s), so systemd
/// reports a hung unit before the command is killed.
pub(super) const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(120);

impl Reload {
    /// The name the journal records, e.g. `sshd-reload`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::SshdReload => "sshd-reload",
            Self::FirewallReload => "firewall-reload",
            Self::Fail2banRestart => "fail2ban-restart",
            Self::DaemonReload => "daemon-reload",
            Self::DockerRestart => "docker-restart",
            Self::CaddyReload => "caddy-reload",
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
            Self::DockerRestart => Some(Cmd::new("dockerd").arg("--validate")),
            Self::CaddyReload => Some(Cmd::new("caddy").args([
                "validate",
                "--config",
                CADDYFILE,
                "--adapter",
                "caddyfile",
            ])),
        }
    }

    /// The reload itself.
    #[must_use]
    pub fn command(self) -> Cmd {
        let args: &[&str] = match self {
            Self::SshdReload => &["try-reload-or-restart", "ssh.service"],
            Self::FirewallReload => &["try-reload-or-restart", FIREWALL_UNIT],
            Self::Fail2banRestart => &["try-restart", "fail2ban.service"],
            Self::DaemonReload => &["daemon-reload"],
            Self::DockerRestart => &["try-restart", "docker.service"],
            Self::CaddyReload => &["reload-or-restart", "caddy.service"],
        };
        Cmd::new("systemctl")
            .args(args.iter().copied())
            .timeout(SYSTEMCTL_TIMEOUT)
    }

    /// The check and the command a rollback runs. Caddy cannot start or
    /// reload without its Caddyfile, and the check would fail and leave it
    /// serving the removed one, so once a rollback removed the file,
    /// `systemctl disable --now caddy.service` runs instead, with no check,
    /// and the next boot does not try to start it either. The firewall's
    /// unit gets `reload-or-restart` when it was active before the
    /// transaction (`records`): stopped since, its table is deleted, and
    /// `try-reload-or-restart` would leave no firewall until the next boot.
    /// One that was stopped before stays stopped, as an admin may have
    /// stopped it to get in. Others are [`Reload::check`] and
    /// [`Reload::command`].
    #[must_use]
    pub fn rollback_steps(self, sys: Sys, records: &[Record]) -> (Option<Cmd>, Cmd) {
        if self == Self::CaddyReload && !sys.fs.exists(Path::new(CADDYFILE)) {
            let stop = Cmd::new("systemctl")
                .args(["disable", "--now", "caddy.service"])
                .timeout(SYSTEMCTL_TIMEOUT);
            return (None, stop);
        }
        if self == Self::FirewallReload && firewall_was_active(records) {
            let start = Cmd::new("systemctl")
                .args(["reload-or-restart", FIREWALL_UNIT])
                .timeout(SYSTEMCTL_TIMEOUT);
            return (self.check(), start);
        }
        (self.check(), self.command())
    }

    /// The longest the check and the reload may run, by their timeouts.
    #[must_use]
    pub fn timeout(self) -> Duration {
        self.check().map_or(Duration::ZERO, |c| c.timeout) + self.command().timeout
    }
}

impl fmt::Display for Reload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Whether the firewall's unit was active before the transaction of
/// `records`. firewall.inbound, the only module with this reload, plans it
/// enabled and active, so without a backup of it apply found it so.
fn firewall_was_active(records: &[Record]) -> bool {
    records
        .iter()
        .find_map(|r| match &r.event {
            Event::Backup {
                backup: Backup::Service {
                    unit, was_active, ..
                },
                ..
            } if unit == FIREWALL_UNIT => Some(*was_active),
            _ => None,
        })
        .unwrap_or(true)
}

/// Runs `cmd`; `Err` holds its exit status and output (stderr, else
/// stdout), or why it could not run.
pub(super) fn run(sys: Sys, cmd: &Cmd) -> Result<(), String> {
    match sys.runner.run(cmd) {
        Ok(out) if out.ok() => Ok(()),
        Ok(out) => {
            let mut reason = format!("`{}` exited with status {}", line(cmd), out.status);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            if let Some(said) = [stderr.trim(), stdout.trim()]
                .into_iter()
                .find(|s| !s.is_empty())
            {
                reason += ": ";
                reason += said;
            }
            Err(reason)
        }
        Err(e) => Err(format!("`{}` could not run: {e}", line(cmd))),
    }
}

/// `cmd` as a shell line, for messages.
pub(super) fn line(cmd: &Cmd) -> String {
    std::iter::once(cmd.program.as_str())
        .chain(cmd.args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::Output;
    use crate::sys::fake::{FakeFs, FakeRunner};

    /// A failed check's reason has the command, the status and any output,
    /// e.g. the firewall check after a rollback removed `firewall.nft`.
    #[test]
    fn failure_reason_is_never_empty() {
        let check = |stdout: &str, stderr: &str| {
            let out = Output {
                status: 1,
                stdout: stdout.into(),
                stderr: stderr.into(),
            };
            let runner = FakeRunner::new().on("nft", ["-c"], out);
            let fs = FakeFs::new();
            let sys = Sys {
                fs: &fs,
                runner: &runner,
            };
            run(sys, &Reload::FirewallReload.check().unwrap()).unwrap_err()
        };
        let cmd = "`nft -c -f /etc/vps-ready/firewall.nft` exited with status 1";
        assert_eq!(check("", ""), cmd);
        assert_eq!(check("out\n", " \n"), format!("{cmd}: out"));
        assert_eq!(check("out", "err\n"), format!("{cmd}: err"));
    }

    const ALL: [Reload; 6] = [
        Reload::SshdReload,
        Reload::FirewallReload,
        Reload::Fail2banRestart,
        Reload::DaemonReload,
        Reload::DockerRestart,
        Reload::CaddyReload,
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
                    "systemctl try-restart fail2ban.service".into()
                ),
                (None, "systemctl daemon-reload".into()),
                (
                    Some("dockerd --validate".into()),
                    "systemctl try-restart docker.service".into()
                ),
                (
                    Some("caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile".into()),
                    "systemctl reload-or-restart caddy.service".into()
                ),
            ]
        );
    }

    /// Without its Caddyfile, a rollback stops and disables Caddy; with one,
    /// it checks and reloads as apply does.
    #[test]
    fn caddy_rollback_stops_caddy_without_its_caddyfile() {
        let runner = FakeRunner::new();
        let steps = |fs: &FakeFs| {
            let sys = Sys {
                fs,
                runner: &runner,
            };
            let (check, command) = Reload::CaddyReload.rollback_steps(sys, &[]);
            (check.as_ref().map(line), line(&command))
        };
        assert_eq!(
            steps(&FakeFs::new()),
            (None, "systemctl disable --now caddy.service".into())
        );
        let fs = FakeFs::new().with_file(CADDYFILE, "app.example.com {\n}\n");
        assert_eq!(
            steps(&fs),
            (
                Reload::CaddyReload.check().as_ref().map(line),
                line(&Reload::CaddyReload.command())
            )
        );
        // The firewall's: `a_rollback_restarts_the_firewall_unit_if_it_was_active`.
        let others = ALL
            .into_iter()
            .filter(|r| !matches!(r, Reload::CaddyReload | Reload::FirewallReload));
        for reload in others {
            let sys = Sys {
                fs: &FakeFs::new(),
                runner: &runner,
            };
            let (check, command) = reload.rollback_steps(sys, &[]);
            assert_eq!(check, reload.check());
            assert_eq!(command, reload.command());
        }
    }
}
