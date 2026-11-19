//! The checks before `ssh_via` limits SSH to one interface: after it, a
//! broken path through that interface means no SSH at all.

use std::net::IpAddr;
use std::path::Path;

use crate::facts::{Facts, parse_units, prop};
use crate::modules::{ModuleError, refuse};
use crate::sys::{Cmd, Sys};

const TAILSCALE: &str = "tailscale0";

/// Checks `ssh_via = via`. Refuses a path that is never private (loopback,
/// Docker's bridges, the default route). The rest, refusals unless `same`
/// (the loaded ruleset already limits SSH to `via`, so the SSH rule does
/// not change and an apply from the console still works), is: `via` is up
/// with an address, this is an SSH session through it, it comes back after
/// a reboot, and for Tailscale its node key does not expire. Returns the
/// notes, the console recovery one last.
pub(super) fn check(
    facts: &Facts,
    via: &str,
    same: bool,
    sys: Sys,
) -> Result<Vec<String>, ModuleError> {
    if let Some(why) = not_private(facts, via) {
        return refuse(&format!("`ssh_via = \"{via}\"`: {why}, not a private path"));
    }
    let mut problems = Vec::new();
    let iface = facts.interfaces.iter().find(|i| i.name == via);
    match iface {
        None => problems.push(format!("{via} does not exist")),
        Some(i) if !i.up => problems.push(format!("{via} is down")),
        Some(i) if i.addresses.is_empty() => problems.push(format!("{via} has no address")),
        Some(_) => {}
    }
    match &facts.session {
        None => problems.push(format!(
            "`ssh_via` needs an SSH login through {via}, and this is not an SSH login (the \
             console, cloud-init)"
        )),
        Some(s) => {
            let server = s.server.ip().to_canonical();
            if !iface.is_some_and(|i| i.addresses.iter().any(|a| a.ip == server)) {
                let user = s.user.as_deref().unwrap_or("<user>");
                let to = address(facts, via)
                    .map_or_else(|| format!("<address of {via}>"), |ip| ip.to_string());
                problems.push(format!(
                    "this SSH session came in on {server}, not through {via}: connect through \
                     {via} first and apply from there (`ssh -t {user}@{to} sudo vps-ready \
                     apply ...`)"
                ));
            }
        }
    }
    let mut notes = Vec::new();
    match boot_unit(via, sys) {
        Some(unit) => {
            if enabled(sys, &unit) != Some(true) {
                problems.push(format!(
                    "{unit} is not enabled, so {via} would not come back after a reboot: \
                     `sudo systemctl enable {unit}`"
                ));
            }
            notes.push(format!(
                "{unit} brings {via} up at boot; SSH is unreachable from boot until it is up"
            ));
        }
        None => notes.push(format!(
            "vps-ready cannot tell which unit brings {via} up at boot: make sure it comes back \
             after a reboot, since SSH is unreachable until it is up"
        )),
    }
    if via == TAILSCALE {
        problems.extend(key_expiry(facts));
    }
    if same {
        notes.extend(problems.into_iter().map(|p| {
            format!("{p} (not refused: the loaded ruleset already limits SSH to {via})")
        }));
    } else if !problems.is_empty() {
        return refuse(&problems.join("; "));
    }
    notes.push(console(facts, via, sys));
    Ok(notes)
}

/// Why `via` is never a private path, if it is not.
fn not_private(facts: &Facts, via: &str) -> Option<String> {
    let default = facts
        .routes
        .iter()
        // The main table: a VPN's own table may hold a default route for
        // its clients without being the host's way out.
        .any(|r| r.dst == "default" && r.table.is_none() && r.dev.as_deref() == Some(via));
    if via == "lo" {
        Some("lo is loopback".to_owned())
    } else if via == "docker0" || via.starts_with("br-") {
        Some(format!("{via} is a bridge for containers"))
    } else if default {
        Some(format!("{via} holds the host's default route"))
    } else {
        None
    }
}

/// An address of `via`, IPv4 first, for the `ssh` command.
fn address(facts: &Facts, via: &str) -> Option<IpAddr> {
    let mut ips: Vec<IpAddr> = facts
        .interfaces
        .iter()
        .filter(|i| i.name == via)
        .flat_map(|i| i.addresses.iter().map(|a| a.ip))
        .filter(|ip| !matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local()))
        .collect();
    ips.sort_by_key(IpAddr::is_ipv6);
    ips.first().copied()
}

/// The unit that brings `via` up at boot, when vps-ready can tell.
fn boot_unit(via: &str, sys: Sys) -> Option<String> {
    if via == TAILSCALE {
        Some("tailscaled.service".to_owned())
    } else if sys
        .fs
        .exists(Path::new(&format!("/etc/wireguard/{via}.conf")))
    {
        Some(format!("wg-quick@{via}.service"))
    } else {
        None
    }
}

/// Whether `unit` is enabled; `None` when systemd cannot tell.
fn enabled(sys: Sys, unit: &str) -> Option<bool> {
    let cmd = Cmd::new("systemctl")
        .args(["show", "--property=UnitFileState"])
        .arg(unit);
    let out = sys.runner.run(&cmd).ok().filter(|o| o.ok())?;
    let units = parse_units(out.stdout_str().ok()?);
    Some(prop(units.first()?, "UnitFileState").starts_with("enabled"))
}

/// Refusal 5: a node key that expires closes SSH on that date.
fn key_expiry(facts: &Facts) -> Option<String> {
    match &facts.tailscale {
        Some(t) if t.backend_state == "Running" => t.key_expiry.as_ref().map(|at| {
            format!(
                "this node's Tailscale key expires at {at}, and then {TAILSCALE} stops \
                 working: disable key expiry for this machine in the Tailscale admin console \
                 (or join with a tagged auth key), then apply again"
            )
        }),
        Some(t) => Some(format!(
            "Tailscale is {}, so whether this node's key expires is unknown",
            t.backend_state
        )),
        None => Some(
            "Tailscale's state is unknown (`tailscale status` failed), so whether this \
             node's key expires is unknown"
                .to_owned(),
        ),
    }
}

/// How to get back in from the provider's console, and whether a sudo user
/// has a password to log in there with.
fn console(facts: &Facts, via: &str, sys: Sys) -> String {
    let user = facts
        .session
        .as_ref()
        .and_then(|s| s.user.clone())
        .filter(|u| u != "root")
        .unwrap_or_else(|| "admin".to_owned());
    let password = match with_password(sys) {
        Some(users) if !users.is_empty() => format!("{} can log in there", users.join(", ")),
        Some(_) => format!(
            "no sudo user has a password yet, so set one (`sudo passwd {user}`); without it, \
             recovery needs the provider's rescue mode"
        ),
        None => format!(
            "set a password for a sudo user (`sudo passwd {user}`) if you have not; without \
             it, recovery needs the provider's rescue mode"
        ),
    };
    format!(
        "if {via} stops working, SSH is closed. Your provider's web console logs in with a \
         password: {password}. From the console, `sudo systemctl stop vps-ready-firewall` \
         opens everything until the next boot, and `sudo vps-ready rollback --txn <id>` (see \
         `sudo vps-ready history`) undoes this change"
    )
}

/// Root and the members of `sudo` that have a password hash, by
/// `/etc/shadow`; `None` when it cannot be read. Reads only whether the
/// field is a hash, never keeps it.
fn with_password(sys: Sys) -> Option<Vec<String>> {
    let shadow = sys.fs.read(Path::new("/etc/shadow")).ok()?;
    let group = sys.fs.read(Path::new("/etc/group")).unwrap_or_default();
    let sudo: Vec<String> = String::from_utf8_lossy(&group)
        .lines()
        .find_map(|l| l.strip_prefix("sudo:"))
        .and_then(|rest| rest.splitn(3, ':').nth(2))
        .map(|members| {
            members
                .split(',')
                .filter(|m| !m.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let users = String::from_utf8_lossy(&shadow)
        .lines()
        .filter_map(|l| {
            let mut fields = l.split(':');
            let (name, hash) = (fields.next()?, fields.next()?);
            // Locked (`!...`), `*` and empty fields are no password to log
            // in with.
            let usable = !hash.is_empty() && !hash.starts_with(['!', '*']);
            (usable && (name == "root" || sudo.iter().any(|m| m == name))).then(|| name.to_owned())
        })
        .collect();
    Some(users)
}
