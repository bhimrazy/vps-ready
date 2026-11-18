//! The `ssh.bruteforce` module: fail2ban's `sshd` jail, reading failed logins
//! from the journal and banning their source in nftables.

use std::net::IpAddr;

use super::firewall_inbound::{SSH_PORT_UNKNOWN, ssh_ports};
use super::{Applicability, Module, ModuleError, ModuleSteps, NoParams, PlanCx};
use crate::engine::Reload;
use crate::facts::{Facts, Init, OsFamily};
use crate::resource::{File, Package, Resource, Service};
use crate::sys::{FileOwner, Sys};

/// The drop-in. fail2ban reads `jail.d/*.local` last, after `jail.local`,
/// so it wins over the package's `defaults-debian.conf` and the admin's
/// `jail.local`.
pub const DROP_IN: &str = "/etc/fail2ban/jail.d/90-vps-ready.local";

/// In install order. Debian 12+ has no `auth.log`, so the sshd jail reads the
/// journal, through `python3-systemd`, which not every release's fail2ban
/// depends on. `nftables` provides `nft` for `banaction = nftables`; Debian
/// 13's cloud image lacks it, and fail2ban only recommends it.
const PACKAGES: [&str; 3] = ["nftables", "python3-systemd", "fail2ban"];

const UNIT: &str = "fail2ban.service";

/// Only `[sshd]`: a `[DEFAULT]` here would override the admin's defaults
/// for every jail. `banaction` and `backend` are set because Debian 12's
/// packaged defaults set neither.
const HEADER: &str = "\
# Written by vps-ready (ssh.bruteforce). `vps-ready rollback --last`
# restores the previous state; edits here are replaced by the next apply.
[sshd]
enabled = true
banaction = nftables
backend = systemd
";

/// Never banned: loopback, plus the address of the applying session.
const IGNORE: &str = "127.0.0.1/8 ::1";

/// Installs fail2ban and enables its `sshd` jail. Debian family with systemd
/// only. It needs no dead-man: the worst it does is ban an address, and the
/// applying session's is exempt.
#[derive(Debug, Clone, Copy)]
pub struct SshBruteforce {
    uid: u32,
    gid: u32,
}

impl SshBruteforce {
    /// The drop-in owned by root:root.
    pub const ROOT: Self = Self { uid: 0, gid: 0 };

    /// The drop-in owned by `uid:gid`, for tests that cannot `chown` to root.
    #[cfg(test)]
    const fn owned_by(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }
}

impl Module for SshBruteforce {
    fn id(&self) -> &'static str {
        "ssh.bruteforce"
    }

    fn title(&self) -> &'static str {
        "Ban addresses that keep failing to log in over SSH"
    }

    fn why(&self) -> &'static str {
        "Bots try common passwords all day. fail2ban bans an address after a few \
         failed logins, which cuts the log noise and slows down a guess at a weak \
         password. OpenSSH 9.8+ does something similar with PerSourcePenalties."
    }

    fn applicable(&self, facts: &Facts) -> Applicability {
        let reason = if facts.os.family != OsFamily::Debian {
            "fail2ban is set up only on Debian and Ubuntu so far"
        } else if facts.init != Init::Systemd {
            "the sshd jail reads the systemd journal, and systemd is not running"
        } else if facts.updates.is_none() {
            "apt not found, or `apt-config` failed"
        } else if ssh_ports(facts).is_empty() {
            SSH_PORT_UNKNOWN
        } else {
            return Applicability::Applicable;
        };
        Applicability::NotApplicable {
            reason: reason.to_owned(),
        }
    }

    fn notes(&self, facts: &Facts) -> Vec<String> {
        let exempt = match client(facts) {
            Some(ip) => format!("the jail never bans {ip}, the address of this SSH session"),
            None => "no SSH session found, so only localhost is exempt from bans".to_owned(),
        };
        // The package enables the unit before the `Service` step records
        // its state, so rollback sees it as enabled already.
        vec![
            exempt,
            "the jail's ignoreip replaces any that jail.local sets".to_owned(),
            "if this installs fail2ban, rollback leaves it installed and enabled, as the \
             package sets it up, so it runs the distro's own jails after a reboot; \
             `systemctl disable --now fail2ban` turns it off"
                .to_owned(),
        ]
    }

    /// `fail2ban-client -t` checks the whole configuration once the drop-in
    /// is written, before the restart: it cannot check one file on its own.
    fn plan(&self, cx: &PlanCx, _: Sys) -> Result<ModuleSteps, ModuleError> {
        let NoParams {} = cx.params()?;
        let mut resources = vec![Resource::Package(Package {
            names: PACKAGES.iter().map(|name| (*name).to_owned()).collect(),
        })];
        resources.push(Resource::File(File {
            path: DROP_IN.into(),
            content: drop_in(cx.facts).into_bytes(),
            owner: FileOwner {
                mode: 0o644,
                uid: self.uid,
                gid: self.gid,
            },
            validate: None,
            describe: None,
        }));
        resources.push(Resource::Service(Service {
            unit: UNIT.to_owned(),
            enabled: true,
            active: true,
        }));
        Ok(ModuleSteps {
            resources,
            reloads: vec![Reload::Fail2banRestart],
            notes: Vec::new(),
        })
    }
}

/// The admin's address, as sshd logs it: an IPv4-mapped address as IPv4.
fn client(facts: &Facts) -> Option<IpAddr> {
    facts.session.as_ref().map(|s| s.client.ip().to_canonical())
}

/// `port` lists sshd's ports: the inherited `port = ssh` bans only 22.
/// `ignoreip` does not extend the inherited list with `%(known/ignoreip)s`:
/// that fails the whole configuration when nothing else sets `ignoreip`.
fn drop_in(facts: &Facts) -> String {
    let ports = ssh_ports(facts)
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut ignore = IGNORE.to_owned();
    if let Some(ip) = client(facts) {
        ignore.push_str(&format!(" {ip}"));
    }
    format!("{HEADER}port = {ports}\nignoreip = {ignore}\n")
}

#[cfg(test)]
mod tests;
