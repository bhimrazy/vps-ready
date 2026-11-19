//! The checks before `ssh_via` limits SSH to one interface: after it, a
//! broken path through that interface means no SSH at all.

use std::net::IpAddr;
use std::path::Path;

use crate::facts::{Facts, Interface, parse_units, prop};
use crate::modules::{ModuleError, refuse};
use crate::sys::{Cmd, Sys};

const TAILSCALE: &str = "tailscale0";

/// Interface name prefixes of bridges and virtual links for local guests
/// and containers (libvirt, LXC, Podman, CNI, veth pairs), besides Docker's.
const LOCAL_BRIDGES: [&str; 6] = ["br-", "virbr", "lxcbr", "podman", "cni", "veth"];

/// Checks `ssh_via = via`. Refuses a path that is never private (loopback,
/// local bridges, the default route). The rest, refusals unless `same` (the
/// loaded ruleset already has this SSH rule, so it does not change), is:
/// `via` is up with an address, this is an SSH session through it from
/// elsewhere, it comes back after a reboot, and for Tailscale its node key
/// does not expire. Returns the notes, the console recovery one last.
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
            let how = format!(
                "connect through {via} first and apply from there (`{}`)",
                apply_through(facts, via)
            );
            if !on(facts, via, server) {
                problems.push(format!(
                    "this SSH session came in on {server}, not through {via}: {how}"
                ));
            } else if local(facts) {
                problems.push(format!(
                    "this SSH session comes from {}, on this server itself, so {via} did \
                     not carry it: {how}",
                    s.client.ip().to_canonical()
                ));
            }
        }
    }
    let tailscale = is_tailscale(facts, via);
    let mut notes = Vec::new();
    match boot_unit(via, tailscale, sys) {
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
    if tailscale {
        problems.extend(key_expiry(facts, via));
    }
    if same {
        notes.extend(
            problems.into_iter().map(|p| {
                format!("{p} (not refused: the loaded ruleset already has this SSH rule)")
            }),
        );
    } else if !problems.is_empty() {
        return refuse(&problems.join("; "));
    }
    notes.push(console(facts, via));
    Ok(notes)
}

/// Whether this is an SSH session that came in through `via` from
/// elsewhere: the opposite of refusals 2 and 3.
pub(crate) fn through(facts: &Facts, via: &str) -> bool {
    facts
        .session
        .as_ref()
        .is_some_and(|s| on(facts, via, s.server.ip().to_canonical()) && !local(facts))
}

/// The note of step 1 of a staged `ssh_via`, which keeps SSH public.
pub(super) fn step_one(facts: &Facts, via: &str) -> String {
    format!(
        "step 1 of 2: SSH stays public until you apply this profile again from a login \
         through {via} (`{}`)",
        apply_through(facts, via)
    )
}

/// Whether `ip` is an address of `via`.
fn on(facts: &Facts, via: &str, ip: IpAddr) -> bool {
    facts
        .interfaces
        .iter()
        .filter(|i| i.name == via)
        .any(|i| i.addresses.iter().any(|a| a.ip == ip))
}

/// Whether the session comes from this host: a login to its own VPN
/// address travels over lo.
fn local(facts: &Facts) -> bool {
    facts.session.as_ref().is_some_and(|s| {
        let client = s.client.ip().to_canonical();
        client.is_loopback()
            || facts
                .interfaces
                .iter()
                .any(|i| i.addresses.iter().any(|a| a.ip == client))
    })
}

/// The command that applies again through `via`.
fn apply_through(facts: &Facts, via: &str) -> String {
    let user = facts
        .session
        .as_ref()
        .and_then(|s| s.user.as_deref())
        .unwrap_or("<user>");
    let to = address(facts, via).map_or_else(|| format!("<address of {via}>"), |ip| ip.to_string());
    format!("ssh -t {user}@{to} sudo vps-ready apply ...")
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
    } else if via == "docker0" || LOCAL_BRIDGES.iter().any(|p| via.starts_with(p)) {
        Some(format!(
            "{via} is a bridge or link for local containers or guests"
        ))
    } else if default {
        Some(format!("{via} holds the host's default route"))
    } else {
        None
    }
}

/// The interface the loaded `vps_ready` table limits SSH to, when it is
/// one `ssh_via` takes as private and has only addresses the internet does
/// not route. Audit counts it as a VPN's, since a NetBird or ZeroTier link
/// has no type that says so. `None` without the routes or the interface:
/// then nothing shows it is not the way out.
pub(crate) fn private_via(facts: &Facts) -> Option<String> {
    let routed = facts
        .routes
        .iter()
        .any(|r| r.dst == "default" && r.table.is_none());
    if !routed {
        return None;
    }
    let ssh = super::ssh_ports(facts);
    let name = facts
        .firewall
        .as_ref()?
        .input_chains
        .iter()
        .filter(|c| c.family == "inet" && c.table == "vps_ready")
        .flat_map(|c| &c.interface_ports)
        .find_map(|p| match p.interfaces.as_slice() {
            [name] if ssh.iter().any(|&port| p.ports.contains("tcp", port)) => Some(name),
            _ => None,
        })?;
    let iface = facts.interfaces.iter().find(|i| &i.name == name)?;
    let local = !iface.addresses.is_empty() && iface.addresses.iter().all(|a| local_ip(a.ip));
    (local && not_private(facts, name).is_none()).then(|| name.clone())
}

/// Whether the internet does not route `ip`: RFC 1918, shared
/// (100.64.0.0/10, Tailscale's), link-local, or IPv6 unique local.
fn local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private() || v4.is_link_local() || (a == 100 && b & 0xc0 == 64)
        }
        IpAddr::V6(v6) => v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

/// Whether `via` is Tailscale's interface: by its name, or by holding one
/// of the node's Tailscale addresses (`--tun` can rename it). See
/// [`Interface::is_tailscale`] for the name alone.
pub(crate) fn is_tailscale(facts: &Facts, via: &str) -> bool {
    let ips = facts.tailscale.as_ref().map_or(&[][..], |t| &t.ips);
    is_tailscale_in(&facts.interfaces, ips, via)
}

/// [`is_tailscale`] from the interfaces and the node's Tailscale addresses.
pub(crate) fn is_tailscale_in(interfaces: &[Interface], ips: &[IpAddr], via: &str) -> bool {
    via == TAILSCALE
        || interfaces
            .iter()
            .filter(|i| i.name == via)
            .flat_map(|i| &i.addresses)
            .any(|a| ips.contains(&a.ip))
}

/// An address of `via`, IPv4 first, for the `ssh` command.
pub(crate) fn address(facts: &Facts, via: &str) -> Option<IpAddr> {
    let mut ips: Vec<IpAddr> = facts
        .interfaces
        .iter()
        .filter(|i| i.name == via)
        .flat_map(|i| i.addresses.iter().map(|a| a.ip))
        // A link-local address needs a zone (`%wg0`) to be used.
        .filter(|ip| !matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local()))
        .collect();
    ips.sort_by_key(IpAddr::is_ipv6);
    ips.first().copied()
}

/// The unit that brings `via` up at boot, when vps-ready can tell.
fn boot_unit(via: &str, tailscale: bool, sys: Sys) -> Option<String> {
    if tailscale {
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

/// Whether `unit` is enabled for good; `enabled-runtime` is lost at the
/// next boot. `None` when systemd cannot tell.
fn enabled(sys: Sys, unit: &str) -> Option<bool> {
    let cmd = Cmd::new("systemctl")
        .args(["show", "--property=UnitFileState"])
        .arg(unit);
    let out = sys.runner.run(&cmd).ok().filter(|o| o.ok())?;
    let units = parse_units(out.stdout_str().ok()?);
    Some(prop(units.first()?, "UnitFileState") == "enabled")
}

/// Refusal 5: a node key that expires closes SSH on that date.
fn key_expiry(facts: &Facts, via: &str) -> Option<String> {
    match &facts.tailscale {
        Some(t) if t.backend_state == "Running" => t.key_expiry.as_ref().map(|at| {
            format!(
                "this node's Tailscale key expires at {at}, and then {via} stops working: \
                 disable key expiry for this machine in the Tailscale admin console (or join \
                 with a tagged auth key), then apply again"
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

/// How to get back in from the provider's console.
pub(crate) fn console(facts: &Facts, via: &str) -> String {
    let user = facts
        .session
        .as_ref()
        .and_then(|s| s.user.clone())
        .filter(|u| u != "root")
        .unwrap_or_else(|| "admin".to_owned());
    format!(
        "if {via} stops working, SSH is closed. Your provider's web console logs in with a \
         password, so make sure a sudo user has one (`sudo passwd {user}`); without it, \
         recovery needs the provider's rescue mode. From the console, `sudo systemctl stop \
         vps-ready-firewall` opens everything until the next boot, and `sudo vps-ready \
         rollback --txn <id>` (see `sudo vps-ready history`) undoes this change. While SSH \
         depends on {via}, every later change that arms the safety timer needs a confirm \
         through {via}, so one applied from the console while {via} is down rolls back"
    )
}
