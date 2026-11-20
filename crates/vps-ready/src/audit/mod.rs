//! Checks the host against the controls catalog.
//!
//! Controls are data, not code: each file in `controls/` lists controls whose
//! [`Check`] comes from a closed vocabulary, so the policy can be reviewed
//! without reading Rust. The files are embedded at build time and a unit test
//! parses every one, so a typo fails CI instead of a user's audit.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::facts::network::{Interface, WireguardDir, interface_with};
use crate::facts::ssh::MatchOverride;
use crate::facts::sysctl::Ipv4Conf;
use crate::facts::{
    AptUpdates, Facts, Firewall, InputChain, InterfacePorts, OsFamily, Proto, SSHD_CONFIG,
};

/// The embedded catalog, as `(file name, contents)`.
const CATALOG: [(&str, &str); 6] = [
    ("ssh.toml", include_str!("controls/ssh.toml")),
    ("kernel.toml", include_str!("controls/kernel.toml")),
    ("network.toml", include_str!("controls/network.toml")),
    ("updates.toml", include_str!("controls/updates.toml")),
    ("firewall.toml", include_str!("controls/firewall.toml")),
    ("mac.toml", include_str!("controls/mac.toml")),
];

/// One security control.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    /// Stable ID, e.g. `SSH-002`. IDs are never reused for another control.
    pub id: String,
    /// How much a failure matters.
    pub severity: Severity,
    /// What a passing host looks like, e.g. "Password authentication disabled".
    pub title: String,
    /// The threat the control addresses, in a sentence or two.
    pub why: String,
    /// How the control is checked.
    pub check: Check,
    /// ID of the module that fixes a failure, e.g. `kernel.sysctl`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

/// How much a failed control matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Worth fixing; rarely exploitable on its own.
    Low,
    /// Raises the risk of a compromise.
    Medium,
    /// Directly exploitable, e.g. by brute force.
    High,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        })
    }
}

/// How a control is checked. The set is closed, so an unknown `kind` in a
/// catalog file is a parse error. Kinds are added when a control needs one.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Check {
    /// A keyword of the effective sshd config (`sshd -T`) has this value,
    /// and no `Match` block in `sshd_config` or its includes sets another.
    /// A `Match` block that does fails the control whatever its criteria,
    /// and its `fix` module is not named: no module edits `Match` blocks.
    /// [`Finding::manual_fix`] says to edit the block by hand instead.
    SshdEffective {
        /// Keyword in lowercase, as `sshd -T` prints it.
        key: String,
        /// Expected value.
        equals: String,
    },
    /// Repeated failed SSH logins are slowed down: the effective sshd config
    /// has `persourcepenalties` other than `no` (on by default since
    /// OpenSSH 9.8), or fail2ban's `sshd` jail runs.
    SshRateLimited,
    /// A kernel setting under `/proc/sys` has one of these values. Skipped
    /// in a container, where the kernel belongs to the host.
    Sysctl {
        /// Setting name as `sysctl` prints it, e.g. `kernel.kptr_restrict`.
        /// Must be one of [`crate::facts::sysctl::KEYS`].
        key: String,
        /// Accepted values.
        one_of: Vec<String>,
        /// A kernel without the setting passes: it lacks the feature the
        /// setting turns off.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        absent_ok: bool,
    },
    /// Security updates are installed automatically: `unattended-upgrades`
    /// is installed, apt's `APT::Periodic` settings run it, and systemd
    /// starts apt's daily jobs (timers active and enabled, services not
    /// masked). Debian and Ubuntu only so far, where it is unknown without
    /// systemd; skipped on other distros.
    AutoUpdates,
    /// No reboot is pending: `/run/reboot-required` is absent and no
    /// installed kernel of the running flavor is newer than the running one
    /// or was written over the running one's image after boot.
    /// Debian and Ubuntu only; skipped inside a container and when `/boot`
    /// holds no kernel image.
    RebootRequired,
    /// The firewall drops incoming packets that no rule accepted, for IPv4
    /// and, when the host has a global IPv6 address, for IPv6. Read from
    /// the nftables ruleset, which needs root.
    InboundDefaultDeny,
    /// Docker publishes no port that the input firewall would block: its
    /// DNAT sends that traffic down the forward path, past the input rules
    /// of ufw and firewalld. Unknown when the user's own forward rules
    /// (`DOCKER-USER`) may filter it, or a rule for one input interface or
    /// one whose ports nft does not show may allow it; skipped without
    /// Docker.
    PublishedPorts,
    /// No port is open to the internet but SSH's, TCP 80 and 443, UDP 443,
    /// the DHCP clients' (UDP 68 and 546) and WireGuard's listen ports: a
    /// listening socket beyond loopback, link-local and private interfaces
    /// (`lo`, `tailscale0`, WireGuard, Docker's bridges, the `ssh_via`
    /// interface of vps-ready's table), that the input chains let in on an
    /// interface that is not private. Docker's
    /// published ports are left to [`Check::PublishedPorts`]. The open
    /// ports are in the finding's note either way; unknown when a rule nft
    /// does not show may open one. WireGuard's listen ports need
    /// wireguard-tools (`wg`).
    ExposedListeners,
    /// SSH is accepted only through a VPN: the input chains drop every SSH
    /// port unless it arrives on `lo`, `tailscale0`, a WireGuard interface
    /// or the `ssh_via` interface of vps-ready's table (`nb0`). Skipped
    /// when the host has none of the last three. The
    /// finding's note warns when SSH depends on `tailscale0` and the node's
    /// key expires.
    SshPrivateOnly,
    /// The kernel has AppArmor enabled. Debian and Ubuntu only so far;
    /// skipped elsewhere and inside a container.
    Apparmor,
    /// Every regular file in `/etc/wireguard` is owned by root and has no
    /// group or other permission bits: its configs and keys hold private
    /// keys. From metadata only, never the contents; skipped without
    /// `/etc/wireguard`.
    WireguardKeyFiles,
    /// Every interface filters packets by reverse path: the larger of
    /// `net.ipv4.conf.all.rp_filter` and the interface's own is 1 (strict)
    /// or 2 (loose). Like the next two, it also checks `default`, the values
    /// a new interface starts with, and is skipped inside a container.
    ReversePathFilter,
    /// No interface accepts ICMP redirects. With forwarding on the interface,
    /// it accepts them when both `all` and its own `accept_redirects` are
    /// on; with forwarding off, when either is.
    IcmpRedirectsIgnored,
    /// No interface sends ICMP redirects: the kernel sends them only for
    /// packets it forwards, so from an interface with forwarding on and
    /// either `all` or its own `send_redirects` on.
    IcmpRedirectsNotSent,
}

/// The result of checking one control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum Outcome {
    /// The host meets the control.
    Pass,
    /// The host does not meet the control.
    Fail {
        /// The value found on the host, or what is wrong when the check
        /// has no single value, e.g. `unattended-upgrades is not installed`.
        found: String,
    },
    /// The control could not be checked, e.g. because `sshd -T` needs root.
    Unknown {
        /// Why it could not be checked.
        reason: String,
    },
    /// The control does not apply to this host, e.g. a kernel setting
    /// inside a container.
    Skip {
        /// Why it does not apply.
        reason: String,
    },
}

/// A control and its outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// The control that was checked.
    #[serde(flatten)]
    pub control: Control,
    /// What the check found.
    #[serde(flatten)]
    pub outcome: Outcome,
    /// How to fix a failure no module fixes, for the text report, e.g. for
    /// a `Match` block. Not in the JSON, where `found` names the same line.
    #[serde(skip)]
    pub manual_fix: Option<String>,
    /// What the check saw beyond its outcome, e.g. every port open to the
    /// internet, also when only some fail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Finding {
    /// A one-line explanation of an outcome other than pass, e.g.
    /// `passwordauthentication is yes, expected no`.
    #[must_use]
    pub fn detail(&self) -> Option<String> {
        match (&self.outcome, &self.control.check) {
            (Outcome::Pass, _) => None,
            (Outcome::Fail { found }, Check::SshdEffective { key, equals }) => {
                Some(format!("{key} is {found}, expected {equals}"))
            }
            (Outcome::Fail { found }, Check::Sysctl { key, one_of, .. }) => {
                Some(format!("{key} is {found}, expected {}", or_list(one_of)))
            }
            (
                Outcome::Fail { found },
                Check::SshRateLimited
                | Check::AutoUpdates
                | Check::RebootRequired
                | Check::InboundDefaultDeny
                | Check::PublishedPorts
                | Check::ExposedListeners
                | Check::SshPrivateOnly
                | Check::Apparmor
                | Check::WireguardKeyFiles
                | Check::ReversePathFilter
                | Check::IcmpRedirectsIgnored
                | Check::IcmpRedirectsNotSent,
            ) => Some(found.clone()),
            (Outcome::Unknown { reason } | Outcome::Skip { reason }, _) => Some(reason.clone()),
        }
    }
}

/// Counts of outcomes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Controls the host meets.
    pub passed: usize,
    /// Controls the host does not meet.
    pub failed: usize,
    /// Controls that could not be checked.
    pub unknown: usize,
    /// Controls that do not apply to this host.
    pub skipped: usize,
}

/// The result of an audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// One finding per control, in catalog order.
    pub findings: Vec<Finding>,
    /// Counts of outcomes.
    pub summary: Summary,
    /// Every notice from fact collection. Those about SSH and root-only
    /// kernel settings explain unknown outcomes; the rest concern facts no
    /// control uses yet.
    pub notices: Vec<String>,
}

impl Report {
    /// Whether every control passed or was skipped. Unknown outcomes do not
    /// count as passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.summary.failed == 0 && self.summary.unknown == 0
    }
}

/// An embedded catalog file failed to parse.
#[derive(Debug, thiserror::Error)]
#[error("parsing controls/{file}")]
pub struct CatalogError {
    /// File name within `controls/`.
    pub file: &'static str,
    /// Underlying parse error.
    #[source]
    pub source: toml::de::Error,
}

/// The controls of every embedded catalog file, in order.
///
/// # Errors
///
/// [`CatalogError`] if a file does not parse. A unit test parses them all, so
/// this does not happen in a released binary.
pub fn catalog() -> Result<Vec<Control>, CatalogError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct File {
        control: Vec<Control>,
    }

    let mut controls = Vec::new();
    for (file, text) in CATALOG {
        let parsed: File = toml::from_str(text).map_err(|source| CatalogError { file, source })?;
        controls.extend(parsed.control);
    }
    Ok(controls)
}

/// Checks each control against `facts`.
#[must_use]
pub fn run(controls: Vec<Control>, facts: &Facts) -> Report {
    let mut summary = Summary::default();
    let findings = controls
        .into_iter()
        .map(|mut control| {
            let (outcome, note) = match control.check {
                Check::ExposedListeners => exposed_listeners(facts),
                Check::SshPrivateOnly => (ssh_private_only(facts), ssh_private_note(facts)),
                _ => (evaluate(&control.check, facts), None),
            };
            let mut manual_fix = None;
            if matches!(outcome, Outcome::Fail { .. }) && control.check == Check::ExposedListeners {
                manual_fix = Some(
                    "make the service listen on 127.0.0.1, or block the port in the firewall \
                     (with firewall.inbound: leave it out of `allow`)"
                        .to_owned(),
                );
            }
            if matches!(outcome, Outcome::Fail { .. })
                && let Some(m) = unfixable_override(&control.check, facts)
            {
                control.fix = None;
                manual_fix = Some(format!(
                    "edit the Match block at {}:{} by hand (vps-ready does not edit Match \
                     blocks)",
                    m.file.display(),
                    m.line
                ));
            }
            match outcome {
                Outcome::Pass => summary.passed += 1,
                Outcome::Fail { .. } => summary.failed += 1,
                Outcome::Unknown { .. } => summary.unknown += 1,
                Outcome::Skip { .. } => summary.skipped += 1,
            }
            Finding {
                control,
                outcome,
                manual_fix,
                note,
            }
        })
        .collect();
    Report {
        findings,
        summary,
        notices: facts.notices.clone(),
    }
}

pub(crate) fn evaluate(check: &Check, facts: &Facts) -> Outcome {
    match check {
        Check::SshdEffective { key, equals } => {
            let Some(config) = &facts.ssh.effective else {
                return Outcome::Unknown {
                    reason: "effective SSH config is unknown".to_owned(),
                };
            };
            match config.get(key) {
                Some(found) if found == equals => {
                    if facts.ssh.files.is_none() {
                        Outcome::Unknown {
                            reason: format!(
                                "{SSHD_CONFIG} could not be read to check its Match blocks"
                            ),
                        }
                    } else if let Some(found) = facts.ssh.match_override(key, equals) {
                        Outcome::Fail {
                            found: found.to_string(),
                        }
                    } else {
                        Outcome::Pass
                    }
                }
                Some(found) => Outcome::Fail {
                    found: found.to_owned(),
                },
                None => Outcome::Unknown {
                    reason: format!("`sshd -T` did not print {key}"),
                },
            }
        }
        Check::SshRateLimited => ssh_rate_limited(facts),
        Check::Sysctl {
            key,
            one_of,
            absent_ok,
        } => {
            if facts.virtualization.in_container() {
                return Outcome::Skip {
                    reason: "kernel settings are not checked inside a container".to_owned(),
                };
            }
            if facts.sysctl.as_ref().is_some_and(|s| s.is_unreadable(key)) {
                return Outcome::Unknown {
                    reason: format!("{key} is readable only by root on this kernel"),
                };
            }
            match facts.sysctl.as_ref().and_then(|s| s.get(key)) {
                Some(found) if one_of.iter().any(|ok| ok == found) => Outcome::Pass,
                Some(found) => Outcome::Fail {
                    found: found.to_owned(),
                },
                None if *absent_ok && facts.sysctl.is_some() => Outcome::Pass,
                None => Outcome::Unknown {
                    reason: format!("{key} not found under /proc/sys"),
                },
            }
        }
        Check::RebootRequired => reboot_required(facts),
        Check::AutoUpdates => match &facts.updates {
            Some(apt) => {
                let problems = apt_update_problems(apt);
                if !problems.is_empty() {
                    Outcome::Fail {
                        found: problems.join("; "),
                    }
                } else if apt.units.is_none() {
                    Outcome::Unknown {
                        reason: "could not confirm that apt's daily jobs run; they are checked \
                                 only under systemd so far"
                            .to_owned(),
                    }
                } else {
                    Outcome::Pass
                }
            }
            None if facts.os.family == OsFamily::Debian => Outcome::Unknown {
                reason: "automatic updates could not be checked".to_owned(),
            },
            None => Outcome::Skip {
                reason: "automatic updates are checked only on Debian and Ubuntu so far".to_owned(),
            },
        },
        Check::InboundDefaultDeny => match &facts.firewall {
            Some(firewall) => inbound_default_deny(firewall, facts.ipv6),
            None => Outcome::Unknown {
                reason: "the firewall ruleset could not be read".to_owned(),
            },
        },
        Check::ExposedListeners => exposed_listeners(facts).0,
        Check::SshPrivateOnly => ssh_private_only(facts),
        Check::Apparmor => {
            if facts.virtualization.in_container() {
                Outcome::Skip {
                    reason: "kernel settings are not checked inside a container".to_owned(),
                }
            } else if facts.os.family != OsFamily::Debian {
                Outcome::Skip {
                    reason: "AppArmor is checked only on Debian and Ubuntu so far".to_owned(),
                }
            } else {
                match facts.apparmor {
                    Some(true) => Outcome::Pass,
                    Some(false) => Outcome::Fail {
                        found: "AppArmor is not enabled in the kernel".to_owned(),
                    },
                    None => Outcome::Unknown {
                        reason: "AppArmor's state could not be read".to_owned(),
                    },
                }
            }
        }
        Check::WireguardKeyFiles => wireguard_key_files(facts),
        Check::PublishedPorts => match &facts.firewall {
            Some(firewall) => match published_ports(firewall, facts.ipv6, facts.docker) {
                // Docker with iptables-legacy publishes ports in rules that
                // nft does not show.
                Outcome::Pass
                    if facts.docker
                        && (firewall.legacy_filter_v4
                            || (facts.ipv6 && firewall.legacy_filter_v6)) =>
                {
                    Outcome::Unknown {
                        reason: "Docker is installed and the filter table of iptables-legacy \
                                 is loaded; vps-ready does not read its rules, which may hold \
                                 the ports Docker publishes"
                            .to_owned(),
                    }
                }
                outcome => outcome,
            },
            None if facts.docker => Outcome::Unknown {
                reason: "the firewall ruleset could not be read".to_owned(),
            },
            None => docker_absent(),
        },
        // ip-sysctl.rst: "The max value from conf/{all,interface}/rp_filter
        // is used when doing source validation on the {interface}."
        Check::ReversePathFilter => per_interface(
            facts,
            "reverse path filtering is not 1 (strict) or 2 (loose) on",
            |all, dev| !matches!(all.rp_filter.max(dev.rp_filter), 1 | 2),
            &["rp_filter"],
        ),
        // ip-sysctl.rst: "accept_redirects for the interface will be enabled
        // if: both conf/{all,interface}/accept_redirects are TRUE in the case
        // forwarding for the interface is enabled or at least one of
        // conf/{all,interface}/accept_redirects is TRUE in the case
        // forwarding for the interface is disabled".
        // secure_redirects only narrows which redirects are accepted, and
        // shared_media (on by default) overrides it, so it is not consulted.
        Check::IcmpRedirectsIgnored => per_interface(
            facts,
            "ICMP redirects are accepted on",
            |all, dev| {
                if dev.forwarding != 0 {
                    all.accept_redirects != 0 && dev.accept_redirects != 0
                } else {
                    all.accept_redirects != 0 || dev.accept_redirects != 0
                }
            },
            &["accept_redirects", "forwarding"],
        ),
        // ip-sysctl.rst: "send_redirects for the interface will be enabled if
        // at least one of conf/{all,interface}/send_redirects is set to
        // TRUE". The kernel sends a redirect only for a packet it forwards
        // out of the interface it arrived on, and forwarding "controls
        // whether packets received _on_ this interface can be forwarded".
        Check::IcmpRedirectsNotSent => per_interface(
            facts,
            "ICMP redirects can be sent from",
            |all, dev| dev.forwarding != 0 && (all.send_redirects != 0 || dev.send_redirects != 0),
            &["send_redirects", "forwarding"],
        ),
    }
}

/// The settings of one directory under `/proc/sys/net/ipv4/conf`, as the
/// integers the kernel stores. A boolean is on when it is not 0.
#[derive(Clone, Copy)]
struct DevConf {
    accept_redirects: i64,
    forwarding: i64,
    rp_filter: i64,
    send_redirects: i64,
}

impl DevConf {
    fn parse(conf: &Ipv4Conf) -> Option<Self> {
        let get = |key: &str| conf.get(key)?.parse().ok();
        Some(Self {
            accept_redirects: get("accept_redirects")?,
            forwarding: get("forwarding")?,
            rp_filter: get("rp_filter")?,
            send_redirects: get("send_redirects")?,
        })
    }
}

/// How many interfaces a failure names before `and N more`.
const MAX_NAMED: usize = 5;

/// Fails when `offends(all, interface)` holds for an interface, or for
/// `default`, which new interfaces copy. `what` leads the failure, e.g.
/// `ICMP redirects are accepted on`, and `keys` are the values it lists.
fn per_interface(
    facts: &Facts,
    what: &str,
    offends: impl Fn(DevConf, DevConf) -> bool,
    keys: &[&str],
) -> Outcome {
    if facts.virtualization.in_container() {
        return Outcome::Skip {
            reason: "kernel settings are not checked inside a container".to_owned(),
        };
    }
    let Some((confs, all_conf, all)) = facts.sysctl.as_ref().and_then(|s| {
        let all_conf = s.ipv4_conf.get("all")?;
        Some((&s.ipv4_conf, all_conf, DevConf::parse(all_conf)?))
    }) else {
        return Outcome::Unknown {
            reason: "/proc/sys/net/ipv4/conf/all could not be read".to_owned(),
        };
    };
    let (mut offending, mut unreadable) = (Vec::new(), Vec::new());
    // `default` first, so a long list of interfaces does not hide it.
    let dirs = confs.get_key_value("default").into_iter().chain(
        confs
            .iter()
            .filter(|(n, _)| !matches!(n.as_str(), "all" | "default")),
    );
    for (name, conf) in dirs {
        match DevConf::parse(conf) {
            Some(dev) if offends(all, dev) => offending.push((name.as_str(), conf)),
            Some(_) => {}
            None => unreadable.push(name.as_str()),
        }
    }
    if offending.is_empty() {
        return if unreadable.is_empty() {
            Outcome::Pass
        } else {
            Outcome::Unknown {
                reason: format!(
                    "the settings under /proc/sys/net/ipv4/conf could not be read for {}",
                    unreadable.join(", ")
                ),
            }
        };
    }
    let shown = &offending[..offending.len().min(MAX_NAMED)];
    let mut names: Vec<&str> = shown
        .iter()
        .map(|&(n, _)| {
            if n == "default" {
                "new interfaces (default)"
            } else {
                n
            }
        })
        .collect();
    let more = format!("{} more", offending.len() - shown.len());
    if offending.len() > shown.len() {
        names.push(&more);
    }
    let get = |conf: &Ipv4Conf, key: &str| conf.get(key).map_or("", String::as_str).to_owned();
    let values: Vec<String> = keys
        .iter()
        .map(|&key| {
            // `all` has no say in forwarding: the kernel reads the interface's own.
            let all = (key != "forwarding").then(|| get(all_conf, key));
            let first = get(offending[0].1, key);
            if offending.len() > 1 && offending.iter().all(|&(_, c)| get(c, key) == first) {
                return match all {
                    Some(all) if all == first => format!("{key} {all} in all and on each"),
                    Some(all) => format!("{key} {all} in all and {first} on each"),
                    None => format!("{key} {first} on each"),
                };
            }
            let pairs: Vec<String> = all
                .map(|v| format!("all={v}"))
                .into_iter()
                .chain(
                    shown
                        .iter()
                        .map(|&(dir, c)| format!("{dir}={}", get(c, key))),
                )
                .collect();
            format!("{key} {}", pairs.join(" "))
        })
        .collect();
    Outcome::Fail {
        found: format!("{what} {}: {}", and_list(&names), values.join(", ")),
    }
}

/// `["a", "b", "c"]` as `a, b and c`.
fn and_list(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [only] => (*only).to_owned(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

fn docker_absent() -> Outcome {
    Outcome::Skip {
        reason: "Docker is not installed".to_owned(),
    }
}

/// After the ports FW-002 fails on.
const LOOPBACK_HINT: &str = "with deploy.docker, a port published without an address binds to \
     127.0.0.1; one published with an address, or on a network created before, keeps it";

/// Fails on ports Docker publishes that an input chain would otherwise block.
fn published_ports(firewall: &Firewall, ipv6: bool, docker: bool) -> Outcome {
    if firewall.published.is_empty() && !docker {
        return docker_absent();
    }
    let (mut bypassing, mut maybe, mut user_filtered) = (Vec::new(), Vec::new(), Vec::new());
    for p in firewall
        .published
        .iter()
        .filter(|p| p.family == "ip" || ipv6)
    {
        let verdicts: Vec<Option<bool>> = firewall
            .input_chains
            .iter()
            .filter(|c| c.covers(p.family == "ip6"))
            .map(|c| c.blocks(&p.proto, p.port))
            .collect();
        let port = (p.proto.as_str(), p.port, p.address.as_deref());
        if verdicts.contains(&Some(true)) {
            if p.filtered {
                user_filtered.push(port);
            } else {
                bypassing.push(port);
            }
        } else if verdicts.contains(&None) {
            maybe.push(port);
        }
    }
    if !bypassing.is_empty() {
        Outcome::Fail {
            found: format!(
                "Docker publishes ports the firewall would otherwise block: {}; {LOOPBACK_HINT}",
                port_list(&bypassing)
            ),
        }
    } else if !maybe.is_empty() {
        Outcome::Unknown {
            reason: format!(
                "a firewall rule for one input interface, or one whose ports nft does not \
                 show (iptables multiport), may allow ports Docker publishes: {}",
                port_list(&maybe)
            ),
        }
    } else if !user_filtered.is_empty() {
        Outcome::Unknown {
            reason: format!(
                "your DOCKER-USER or forward rules, which vps-ready cannot judge, may filter \
                 ports Docker publishes past the firewall: {}",
                port_list(&user_filtered)
            ),
        }
    } else {
        Outcome::Pass
    }
}

/// `tcp/80, udp/60000-60005, tcp/5432 on 10.8.0.1`: sorted, deduplicated,
/// consecutive ports on the same address joined.
fn port_list(ports: &[(&str, u16, Option<&str>)]) -> String {
    let mut ports = ports.to_vec();
    ports.sort_unstable_by_key(|&(proto, port, address)| (address, proto, port));
    ports.dedup();
    let mut ranges: Vec<(&str, u16, u16, Option<&str>)> = Vec::new();
    for (proto, port, address) in ports {
        match ranges.last_mut() {
            Some((p, _, last, a))
                if *p == proto && *a == address && u32::from(*last) + 1 == u32::from(port) =>
            {
                *last = port;
            }
            _ => ranges.push((proto, port, port, address)),
        }
    }
    ranges
        .iter()
        .map(|&(proto, first, last, address)| {
            let mut s = format!("{proto}/{first}");
            if last != first {
                s.push_str(&format!("-{last}"));
            }
            if let Some(a) = address {
                s.push_str(&format!(" on {a}"));
            }
            s
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Ports open to the internet that need no reason: TCP 80 and 443, UDP 443
/// (HTTP/3) and the DHCP clients (UDP 68, and 546 for DHCPv6).
const EXPECTED_PORTS: [(Proto, u16); 5] = [
    (Proto::Tcp, 80),
    (Proto::Tcp, 443),
    (Proto::Udp, 443),
    (Proto::Udp, 68),
    (Proto::Udp, 546),
];

/// Whether a socket bound to `addr` receives IPv4 and IPv6 packets from
/// beyond the host: not on loopback, link-local or a `private` interface,
/// by its `%dev` suffix (`127.0.0.53%lo`) or the interface that holds the
/// address. `*` is both; an address that does not parse counts as both.
fn public_families(
    addr: &str,
    interfaces: &[Interface],
    private: impl Fn(&str) -> bool,
) -> (bool, bool) {
    let (ip, device) = addr.split_once('%').unwrap_or((addr, ""));
    if private(device) {
        return (false, false);
    }
    let Ok(ip) = ip.parse::<IpAddr>() else {
        return (true, true);
    };
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    if interface_with(interfaces, ip).is_some_and(|i| private(&i.name)) {
        return (false, false);
    }
    match ip {
        IpAddr::V4(ip) => (!ip.is_loopback() && !ip.is_link_local(), false),
        IpAddr::V6(ip) => (false, !ip.is_loopback() && !ip.is_unicast_link_local()),
    }
}

/// Whether the input chains let packets to a port in from the internet.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Reach {
    Blocked,
    /// A rule or table that is not read may let them in.
    Maybe,
    /// On the named interfaces only, or on any when empty.
    Open(BTreeSet<String>),
}

fn admitted(
    firewall: &Firewall,
    proto: Proto,
    port: u16,
    v6: bool,
    private: impl Fn(&str) -> bool + Copy,
) -> Reach {
    let proto = proto.to_string();
    let chains: Vec<&InputChain> = firewall
        .input_chains
        .iter()
        .filter(|c| c.covers(v6))
        .collect();
    let verdicts: Vec<Option<bool>> = chains
        .iter()
        .map(|c| c.blocks_public(&proto, port, private))
        .collect();
    let legacy = if v6 {
        firewall.legacy_filter_v6
    } else {
        firewall.legacy_filter_v4
    };
    if verdicts.contains(&Some(true)) {
        return Reach::Blocked;
    }
    if verdicts.contains(&None) || (legacy && !chains.iter().any(|c| c.drops_unmatched)) {
        // As for FW-001: iptables-legacy may drop what nft lets in.
        return Reach::Maybe;
    }
    // A packet passes every chain, so the first that opens the port on some
    // interfaces only names where it is open; an unnamed one names none.
    let scoped = chains
        .iter()
        .find(|c| c.drops_unmatched && !c.open_ports.iter().any(|p| p.contains(&proto, port)));
    let names = scoped.map_or_else(BTreeSet::new, |c| {
        let public: Vec<&InterfacePorts> = c
            .interface_ports
            .iter()
            .filter(|p| p.ports.contains(&proto, port))
            .filter(|p| p.interfaces.is_empty() || !p.interfaces.iter().all(|i| private(i)))
            .collect();
        if public.iter().any(|p| p.interfaces.is_empty()) {
            return BTreeSet::new();
        }
        public
            .iter()
            .flat_map(|p| &p.interfaces)
            .filter(|i| !private(i))
            .cloned()
            .collect()
    });
    Reach::Open(names)
}

/// A port open to the internet, or that may be.
#[derive(Default)]
struct Exposed {
    processes: Vec<String>,
    /// The interfaces it is open on; empty for any.
    interfaces: BTreeSet<String>,
    /// Open on any interface through one of its sockets.
    anywhere: bool,
}

/// FW-003's outcome, and the ports open to the internet.
fn exposed_listeners(facts: &Facts) -> (Outcome, Option<String>) {
    let Some(firewall) = &facts.firewall else {
        let reason = "the firewall ruleset could not be read".to_owned();
        return (Outcome::Unknown { reason }, None);
    };
    // sshd listens on every host vps-ready hardens, so none means `ss`
    // could not be read.
    if facts.listeners.is_empty() {
        let cause = facts
            .notices
            .iter()
            .find(|n| n.ends_with("listening sockets are unknown"))
            .and_then(|n| n.split(';').next());
        let reason = match cause {
            Some(cause) => format!("the listening sockets could not be read: {cause}"),
            None => "the listening sockets could not be read".to_owned(),
        };
        return (Outcome::Unknown { reason }, None);
    }
    // Interfaces known not to face the internet; the names stand in when
    // `ip` is missing. Docker's bridges carry its containers' traffic.
    let via = crate::modules::firewall_inbound::private_via(facts);
    let private = |name: &str| {
        matches!(name, "lo" | "tailscale0")
            || via.as_deref() == Some(name)
            || facts
                .interfaces
                .iter()
                .any(|i| i.name == name && i.is_vpn())
            || facts.bridges.iter().any(|b| b.docker && b.name == name)
    };
    let ssh = crate::modules::firewall_inbound::ssh_ports(facts);
    let (mut open, mut maybe) = (BTreeMap::new(), BTreeMap::new());
    for l in &facts.listeners {
        if l.processes.iter().any(|p| p == "docker-proxy") {
            continue;
        }
        let (v4, v6) = public_families(&l.addr, &facts.interfaces, private);
        let reaches: Vec<Reach> = [(v4, false), (v6 && facts.ipv6, true)]
            .into_iter()
            .filter(|&(public, _)| public)
            .map(|(_, v6)| admitted(firewall, l.proto, l.port, v6, private))
            .collect();
        let opened: Vec<&BTreeSet<String>> = reaches
            .iter()
            .filter_map(|r| match r {
                Reach::Open(names) => Some(names),
                _ => None,
            })
            .collect();
        let entry: &mut Exposed = if !opened.is_empty() {
            let entry: &mut Exposed = open.entry((l.proto, l.port)).or_default();
            for names in opened {
                entry.anywhere |= names.is_empty();
                entry.interfaces.extend(names.iter().cloned());
            }
            entry
        } else if reaches.contains(&Reach::Maybe) {
            maybe.entry((l.proto, l.port)).or_default()
        } else {
            continue;
        };
        for p in &l.processes {
            if !entry.processes.contains(p) {
                entry.processes.push(p.clone());
            }
        }
    }
    maybe.retain(|k, _| !open.contains_key(k));
    let wireguard: Vec<u16> = facts.wireguard.listen_ports.values().copied().collect();
    let expected = |&(proto, port): &(Proto, u16)| {
        EXPECTED_PORTS.contains(&(proto, port))
            || (proto == Proto::Tcp && ssh.contains(&port))
            || (proto == Proto::Udp && wireguard.contains(&port))
    };
    let list = |ports: &BTreeMap<(Proto, u16), Exposed>, only_unexpected: bool| {
        ports
            .iter()
            .filter(|(k, _)| !only_unexpected || !expected(k))
            .map(|((proto, port), e)| {
                let mut s = format!("{proto}/{port}");
                if !e.processes.is_empty() {
                    s.push_str(&format!(" ({})", e.processes.join(", ")));
                }
                if !e.anywhere && !e.interfaces.is_empty() {
                    let names: Vec<&str> = e.interfaces.iter().map(String::as_str).collect();
                    s.push_str(&format!(" on {}", and_list(&names)));
                }
                s
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let note = if open.is_empty() {
        "no port is open to the internet".to_owned()
    } else {
        format!("open to the internet: {}", list(&open, false))
    };
    let (unexpected, unsure) = (list(&open, true), list(&maybe, true));
    let outcome = if !unexpected.is_empty() {
        Outcome::Fail {
            found: format!("ports other than SSH, web, DHCP and WireGuard are open: {unexpected}"),
        }
    } else if !unsure.is_empty() {
        Outcome::Unknown {
            reason: format!(
                "a firewall rule whose ports nft does not show (iptables multiport), or the \
                 filter table of iptables-legacy, which vps-ready does not read, may open \
                 {unsure}"
            ),
        }
    } else {
        Outcome::Pass
    };
    (outcome, Some(note))
}

/// NET-008: no file in `/etc/wireguard` is readable by anyone but root.
fn wireguard_key_files(facts: &Facts) -> Outcome {
    let files = match &facts.wireguard.dir {
        WireguardDir::Missing => {
            return Outcome::Skip {
                reason: "/etc/wireguard does not exist".to_owned(),
            };
        }
        WireguardDir::Unreadable => {
            return Outcome::Unknown {
                reason: "/etc/wireguard could not be read (it needs root)".to_owned(),
            };
        }
        WireguardDir::Read { files, .. } => files,
    };
    let open: Vec<String> = files
        .iter()
        .filter(|f| f.uid != 0 || f.mode & 0o077 != 0)
        .map(|f| {
            format!(
                "{} (mode {:04o}, uid {})",
                f.path.display(),
                f.mode & 0o7777,
                f.uid
            )
        })
        .collect();
    if open.is_empty() {
        Outcome::Pass
    } else {
        Outcome::Fail {
            found: format!(
                "readable by others than root: {}; `chown root:root` and `chmod 600` them",
                open.join(", ")
            ),
        }
    }
}

/// SSH-009: no SSH port is accepted on an interface other than a VPN's.
fn ssh_private_only(facts: &Facts) -> Outcome {
    if let Some(found) = ssh_limited_to_missing(facts) {
        return Outcome::Fail { found };
    }
    let via = crate::modules::firewall_inbound::private_via(facts);
    if via.is_none() && !facts.interfaces.iter().any(crate::facts::Interface::is_vpn) {
        let reason = match crate::modules::firewall_inbound::uncounted_via(facts) {
            Some((name, why)) => format!(
                "there is no VPN interface (WireGuard or tailscale0), and the `ssh_via` \
                 interface {name} is not counted as private: {why}"
            ),
            None => "there is no VPN interface (WireGuard or tailscale0) and no `ssh_via` rule"
                .to_owned(),
        };
        return Outcome::Skip { reason };
    }
    let Some(firewall) = &facts.firewall else {
        let reason = "the firewall ruleset could not be read".to_owned();
        return Outcome::Unknown { reason };
    };
    let vpn = |name: &str| {
        matches!(name, "lo" | "tailscale0")
            || via.as_deref() == Some(name)
            || facts
                .interfaces
                .iter()
                .any(|i| i.name == name && i.is_wireguard())
    };
    let (mut open, mut maybe) = (Vec::new(), Vec::new());
    for port in crate::modules::firewall_inbound::ssh_ports(facts) {
        for v6 in [false, true].into_iter().filter(|&v6| !v6 || facts.ipv6) {
            match admitted(firewall, Proto::Tcp, port, v6, vpn) {
                Reach::Blocked => {}
                Reach::Maybe => maybe.push(format!("tcp/{port}")),
                Reach::Open(names) if names.is_empty() => {
                    open.push(format!("tcp/{port} from any interface"));
                }
                Reach::Open(names) => {
                    let names: Vec<&str> = names.iter().map(String::as_str).collect();
                    open.push(format!("tcp/{port} on {}", and_list(&names)));
                }
            }
        }
    }
    open.dedup();
    maybe.dedup();
    if !open.is_empty() {
        Outcome::Fail {
            found: format!("SSH is accepted beyond a VPN: {}", open.join(", ")),
        }
    } else if !maybe.is_empty() {
        Outcome::Unknown {
            reason: format!(
                "a firewall rule whose ports nft does not show, or the filter table of \
                 iptables-legacy, may accept SSH ({})",
                maybe.join(", ")
            ),
        }
    } else {
        Outcome::Pass
    }
}

/// The interfaces that the loaded rules accept SSH ports on, by name; a
/// wildcard and `lo` left out.
fn ssh_interfaces(facts: &Facts) -> BTreeSet<String> {
    let ssh = crate::modules::firewall_inbound::ssh_ports(facts);
    facts
        .firewall
        .iter()
        .flat_map(|f| &f.input_chains)
        .flat_map(|c| &c.interface_ports)
        .filter(|p| ssh.iter().any(|&port| p.ports.contains("tcp", port)))
        .flat_map(|p| &p.interfaces)
        .filter(|n| *n != "lo" && !n.contains('*'))
        .cloned()
        .collect()
}

/// When no rule accepts SSH on every interface and a rule limits it to
/// interfaces that are absent or down: SSH is closed, VPN or not.
fn ssh_limited_to_missing(facts: &Facts) -> Option<String> {
    let firewall = facts.firewall.as_ref()?;
    // Without `ip`, nothing is known about the interfaces.
    if facts.interfaces.is_empty() {
        return None;
    }
    let ssh = crate::modules::firewall_inbound::ssh_ports(facts);
    let anywhere = firewall.input_chains.iter().any(|c| {
        c.open_ports
            .iter()
            .any(|p| ssh.iter().any(|&port| p.contains("tcp", port)))
    });
    let broken: Vec<String> = ssh_interfaces(facts)
        .into_iter()
        .filter_map(|n| match facts.interfaces.iter().find(|i| i.name == n) {
            None => Some(format!("{n}, which does not exist")),
            Some(i) if !i.up => Some(format!("{n}, which is down")),
            Some(_) => None,
        })
        .collect();
    (!anywhere && !broken.is_empty()).then(|| format!("SSH is limited to {}", broken.join("; ")))
}

/// SSH-009's note: the Tailscale warning, and a caveat while a tunnel
/// connector runs, whose routes the inbound rules do not see.
fn ssh_private_note(facts: &Facts) -> Option<String> {
    let tunnel = facts.cloudflared.connector_runs().then(|| {
        "a Cloudflare Tunnel connector runs on this host; its account can route to SSH on \
         loopback"
            .to_owned()
    });
    match (tailscale_expiry(facts), tunnel) {
        (Some(a), Some(b)) => Some(format!("{a}; {b}")),
        (a, b) => a.or(b),
    }
}

/// A warning when the loaded rules accept SSH on Tailscale's interface and
/// SSH through it may stop: this node's key expires, or Tailscale is not
/// running.
pub(crate) fn tailscale_expiry(facts: &Facts) -> Option<String> {
    let names = ssh_interfaces(facts);
    let ips = facts
        .tailscale
        .as_ref()
        .map(|t| t.ips.as_slice())
        .unwrap_or_default();
    let on = names.iter().find(|n| {
        *n == "tailscale0"
            || facts
                .interfaces
                .iter()
                .any(|i| &i.name == *n && i.addresses.iter().any(|a| ips.contains(&a.ip)))
    })?;
    match &facts.tailscale {
        Some(t) if t.backend_state == "Running" => t.key_expiry.as_ref().map(|at| {
            format!(
                "warning: this node's Tailscale key expires at {at}, and SSH through {on} \
                 stops then; disable key expiry for this machine in the Tailscale admin \
                 console"
            )
        }),
        Some(t) => Some(format!(
            "warning: SSH is limited to {on}, and Tailscale is {}, so SSH through it may not \
             work",
            t.backend_state
        )),
        None => Some(format!(
            "warning: SSH is limited to {on}, and Tailscale's state is unknown (`tailscale \
             status` failed)"
        )),
    }
}

/// Which incoming traffic no chain drops by default, e.g. `IPv6`.
fn inbound_default_deny(firewall: &Firewall, ipv6: bool) -> Outcome {
    let drops = |v6: bool| {
        firewall
            .input_chains
            .iter()
            .any(|c| c.covers(v6) && c.drops_unmatched)
    };
    // A family whose iptables-legacy filter table is loaded may be filtered
    // by rules that are not read, so it is unknown rather than a failure.
    let (mut accepted, mut unread) = (Vec::new(), Vec::new());
    for (v6, name, legacy) in [
        (false, "IPv4", firewall.legacy_filter_v4),
        (true, "IPv6", firewall.legacy_filter_v6),
    ] {
        if (!v6 || ipv6) && !drops(v6) {
            if legacy { &mut unread } else { &mut accepted }.push(name);
        }
    }
    let no_chains = firewall.input_chains.is_empty();
    if !accepted.is_empty() {
        Outcome::Fail {
            found: if no_chains {
                "no firewall rules filter incoming traffic".to_owned()
            } else {
                format!(
                    "incoming {} traffic that no rule allows is accepted",
                    accepted.join(" and ")
                )
            },
        }
    } else if !unread.is_empty() {
        let seen = if no_chains {
            "nft shows no rules that filter incoming traffic".to_owned()
        } else {
            format!(
                "nft shows incoming {} traffic that no rule allows as accepted",
                unread.join(" and ")
            )
        };
        Outcome::Unknown {
            reason: format!(
                "{seen}, and the filter table of iptables-legacy is loaded for {}; vps-ready \
                 does not read its rules",
                unread.join(" and ")
            ),
        }
    } else {
        Outcome::Pass
    }
}

fn ssh_rate_limited(facts: &Facts) -> Outcome {
    let penalties = facts
        .ssh
        .effective
        .as_ref()
        .and_then(|c| c.get("persourcepenalties"));
    if penalties.is_some_and(|v| v != "no") || facts.ssh.fail2ban == Some(true) {
        return Outcome::Pass;
    }
    if facts.ssh.effective.is_none() {
        return Outcome::Unknown {
            reason: "effective SSH config is unknown".to_owned(),
        };
    }
    if facts.ssh.fail2ban.is_none() {
        return Outcome::Unknown {
            reason: "fail2ban's sshd jail could not be checked".to_owned(),
        };
    }
    let sshd = if penalties.is_some() {
        "persourcepenalties is no"
    } else {
        "sshd has no PerSourcePenalties (OpenSSH before 9.8)"
    };
    Outcome::Fail {
        found: format!("{sshd} and fail2ban's sshd jail is not running"),
    }
}

/// A pending reboot: the flag file, or a newer kernel in `/boot` than the one
/// running.
fn reboot_required(facts: &Facts) -> Outcome {
    if facts.virtualization.in_container() {
        return Outcome::Skip {
            reason: "kernel settings are not checked inside a container".to_owned(),
        };
    }
    if facts.os.family != OsFamily::Debian {
        return Outcome::Skip {
            reason: "pending reboots are checked only on Debian and Ubuntu so far".to_owned(),
        };
    }
    let Some(reboot) = &facts.reboot else {
        return Outcome::Unknown {
            reason: "pending reboots could not be checked".to_owned(),
        };
    };
    let mut problems = Vec::new();
    if reboot.flagged {
        problems.push("/run/reboot-required exists".to_owned());
    }
    if let (Some(newest), Some(running)) = (reboot.newer_kernel(), &reboot.running) {
        problems.push(format!(
            "running kernel {running}, newest installed {newest}"
        ));
    }
    if let (Some(true), Some(running)) = (reboot.image_replaced, &reboot.running) {
        problems.push(format!(
            "the running kernel's image was replaced after boot ({running})"
        ));
    }
    if !problems.is_empty() {
        return Outcome::Fail {
            found: problems.join("; "),
        };
    }
    if reboot.running.is_none() {
        Outcome::Unknown {
            reason: "the running kernel's release could not be read".to_owned(),
        }
    } else if reboot.installed.is_empty() {
        Outcome::Skip {
            reason: "no kernel image in /boot to compare with".to_owned(),
        }
    } else {
        Outcome::Pass
    }
}

/// What keeps apt from installing updates on its own, e.g.
/// `unattended-upgrades is not installed`. Empty when nothing does.
fn apt_update_problems(apt: &AptUpdates) -> Vec<String> {
    let mut problems = Vec::new();
    if !apt.unattended_upgrades {
        problems.push("unattended-upgrades is not installed".to_owned());
    }
    // `Enable` defaults to on and turns every periodic job off when `0`.
    if apt.periodic.get("Enable").is_some_and(|v| v == "0") {
        problems.push("APT::Periodic::Enable is 0".to_owned());
    }
    // Without fresh package lists, unattended-upgrade sees no new updates.
    // apt treats any value but `0`, even an empty one, as an interval.
    for key in ["Update-Package-Lists", "Unattended-Upgrade"] {
        match apt.periodic.get(key).map(String::as_str) {
            None => problems.push(format!("APT::Periodic::{key} is not set")),
            Some("0") => problems.push(format!("APT::Periodic::{key} is 0")),
            Some(_) => {}
        }
    }
    for (unit, state) in apt.units.iter().flatten() {
        if state != "ok" {
            problems.push(format!("{unit} is {state}"));
        }
    }
    problems
}

/// For a failed [`Check::SshdEffective`], the `Match` block line that no
/// module can fix: any, when the `sshd -T` value passes; a `Match all` one
/// otherwise, since plain `sshd -T` applies `Match all` and shows its value.
fn unfixable_override(check: &Check, facts: &Facts) -> Option<MatchOverride> {
    let Check::SshdEffective { key, equals } = check else {
        return None;
    };
    let passes = facts.ssh.effective.as_ref()?.get(key) == Some(equals.as_str());
    facts
        .ssh
        .match_override(key, equals)
        .filter(|m| passes || m.criteria.eq_ignore_ascii_case("all"))
}

/// `["1", "2", "3"]` as `1, 2 or 3`.
fn or_list(values: &[String]) -> String {
    match values {
        [] => String::new(),
        [only] => only.clone(),
        [rest @ .., last] => format!("{} or {last}", rest.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::facts::fixtures::{HOSTS, host};
    use crate::facts::{PublishedPort, SshdConfig, Virt, sysctl};
    use crate::sys::fake::{FakeFs, FakeRunner};

    #[test]
    fn catalog_parses_with_unique_well_formed_ids() {
        let controls = catalog().unwrap();
        assert!(!controls.is_empty());
        let mut seen = BTreeSet::new();
        for c in &controls {
            let (prefix, number) = c.id.split_once('-').unwrap();
            assert!(
                prefix.chars().all(|ch| ch.is_ascii_uppercase())
                    && number.len() == 3
                    && number.chars().all(|ch| ch.is_ascii_digit()),
                "malformed id {:?}",
                c.id
            );
            assert!(seen.insert(&c.id), "duplicate id {}", c.id);
            assert!(!c.title.is_empty() && !c.why.is_empty(), "{}", c.id);
        }
    }

    /// A key that is never read would make a control permanently unknown:
    /// sshd keys must appear in a real `sshd -T` capture, and sysctl keys
    /// must be among the settings facts collection reads.
    #[test]
    fn check_keys_are_collected() {
        let facts = host("ubuntu-24.04", &[]);
        let config = facts.ssh.effective.as_ref().unwrap();
        for c in catalog().unwrap() {
            match &c.check {
                Check::SshdEffective { key, .. } => {
                    assert!(config.get(key).is_some(), "{}: {key}", c.id);
                }
                Check::Sysctl { key, one_of, .. } => {
                    assert!(sysctl::KEYS.contains(&key.as_str()), "{}: {key}", c.id);
                    assert!(!one_of.is_empty(), "{}", c.id);
                }
                Check::SshRateLimited => assert!(facts.ssh.fail2ban.is_some(), "{}", c.id),
                Check::AutoUpdates => assert!(facts.updates.is_some(), "{}", c.id),
                Check::InboundDefaultDeny | Check::PublishedPorts => {
                    assert!(facts.firewall.is_some(), "{}", c.id);
                }
                Check::ExposedListeners => {
                    assert!(
                        facts.firewall.is_some() && !facts.listeners.is_empty(),
                        "{}",
                        c.id
                    );
                }
                // The captured hosts have no VPN; `evaluates_ssh_private_only` covers it.
                Check::SshPrivateOnly => {}
                Check::Apparmor => assert!(facts.apparmor.is_some(), "{}", c.id),
                // The captured hosts have no WireGuard; `evaluates_wireguard_key_files` covers it.
                Check::WireguardKeyFiles => {}

                // The captured hosts are containers, which have no `reboot` fact.
                Check::RebootRequired => {}
                // The captured hosts are containers, which do not read
                // `/proc/sys`; the `evaluates_*` tests below cover these.
                Check::ReversePathFilter
                | Check::IcmpRedirectsIgnored
                | Check::IcmpRedirectsNotSent => {}
            }
        }
    }

    /// Each rejected input has every required field, so only the unknown
    /// kind or the extra field can make it fail.
    #[test]
    fn unknown_kind_and_fields_are_rejected() {
        let parse = |extra: &str, check: &str| {
            toml::from_str::<Control>(&format!(
                "id = \"X-001\"\nseverity = \"low\"\ntitle = \"t\"\nwhy = \"w\"\n{extra}\ncheck = {check}"
            ))
        };
        let valid = r#"{ kind = "sshd_effective", key = "port", equals = "22" }"#;
        assert!(parse("", valid).is_ok());
        assert!(parse("fix = \"x\"", valid).is_ok());
        assert!(parse("refs = \"x\"", valid).is_err());
        assert!(
            parse(
                "",
                r#"{ kind = "sshd_whatever", key = "port", equals = "22" }"#
            )
            .is_err()
        );
        assert!(
            parse(
                "",
                r#"{ kind = "sshd_effective", key = "port", equals = "22", extra = "x" }"#
            )
            .is_err()
        );
    }

    #[test]
    fn earlier_dropin_fixes_password_auth() {
        for name in HOSTS {
            let status = |scenario| {
                let report = run(catalog().unwrap(), &host(name, &[scenario]));
                report
                    .findings
                    .into_iter()
                    .find(|f| f.control.id == "SSH-002")
                    .unwrap()
                    .outcome
            };
            assert_eq!(
                status("sshd-T-dropin-99"),
                Outcome::Fail {
                    found: "yes".to_owned()
                },
                "{name}"
            );
            assert_eq!(status("sshd-T-dropin-00"), Outcome::Pass, "{name}");
        }
    }

    #[test]
    fn unreadable_sshd_config_is_unknown_not_pass() {
        let report = run(
            catalog().unwrap(),
            &host("ubuntu-24.04", &["sshd-T-before-login"]),
        );
        let ssh_controls = report
            .findings
            .iter()
            .filter(|f| {
                matches!(
                    f.control.check,
                    Check::SshdEffective { .. } | Check::SshRateLimited
                )
            })
            .count();
        assert_eq!(report.summary.unknown, ssh_controls);
        assert!(!report.all_passed());
        assert!(!report.notices.is_empty());
    }

    #[test]
    fn evaluates_sshd_effective() {
        let mut facts = host("debian-13", &[]);
        let check = |key: &str, equals: &str| Check::SshdEffective {
            key: key.to_owned(),
            equals: equals.to_owned(),
        };
        facts.ssh.effective = Some(SshdConfig::parse("passwordauthentication no\n"));
        assert_eq!(
            evaluate(&check("passwordauthentication", "no"), &facts),
            Outcome::Pass
        );
        assert_eq!(
            evaluate(&check("passwordauthentication", "yes"), &facts),
            Outcome::Fail {
                found: "no".to_owned()
            }
        );
        assert!(matches!(
            evaluate(&check("x11forwarding", "no"), &facts),
            Outcome::Unknown { .. }
        ));
    }

    /// Facts whose `sshd -T` passes SSH-001 to SSH-007 and whose
    /// `sshd_config` is `main`, with `files` beside it.
    fn with_sshd_config(main: &str, files: &[(&str, &str)]) -> Facts {
        use sshd_config::Config;

        use crate::facts::SSHD_CONFIG;
        use crate::facts::ssh::FsSource;

        let mut facts = host("debian-13", &[]);
        let keys = catalog()
            .unwrap()
            .into_iter()
            .filter_map(|c| match c.check {
                Check::SshdEffective { key, equals } => Some(format!("{key} {equals}\n")),
                _ => None,
            });
        facts.ssh.effective = Some(SshdConfig::parse(&keys.collect::<String>()));
        let fs = files
            .iter()
            .fold(FakeFs::new().with_file(SSHD_CONFIG, main), |fs, (p, c)| {
                fs.with_file(*p, *c)
            });
        facts.ssh.files =
            Some(Config::read(&FsSource(&fs), std::path::Path::new(SSHD_CONFIG)).unwrap());
        facts
    }

    /// The SSH-001 to SSH-007 findings that are not a pass.
    fn sshd_findings(facts: &Facts) -> Vec<Finding> {
        run(catalog().unwrap(), facts)
            .findings
            .into_iter()
            .filter(|f| {
                matches!(f.control.check, Check::SshdEffective { .. }) && f.outcome != Outcome::Pass
            })
            .collect()
    }

    #[test]
    fn a_match_block_with_a_failing_value_fails() {
        let facts = with_sshd_config(
            "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n",
            &[(
                "/etc/ssh/sshd_config.d/50-cloud.conf",
                "# cloud\nMatch Address *\n    passwordauthentication YES\n",
            )],
        );
        let findings = sshd_findings(&facts);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].control.id, "SSH-002");
        assert_eq!(
            findings[0].detail().unwrap(),
            "passwordauthentication is YES in a Match block \
             (/etc/ssh/sshd_config.d/50-cloud.conf:3, Match Address *), expected no"
        );
        // ssh.server writes only global settings, so it is not the fix.
        assert_eq!(findings[0].control.fix, None);
        assert_eq!(
            findings[0].manual_fix.as_deref(),
            Some(
                "edit the Match block at /etc/ssh/sshd_config.d/50-cloud.conf:3 by hand \
                 (vps-ready does not edit Match blocks)"
            )
        );
    }

    #[test]
    fn a_match_block_with_a_passing_value_changes_nothing() {
        let facts = with_sshd_config(
            "PermitRootLogin no\nMatch User bob\n  PermitRootLogin No\n  X11Forwarding no\n\
             Match all\n  AllowTcpForwarding yes\n",
            &[],
        );
        assert_eq!(sshd_findings(&facts), []);
    }

    #[test]
    fn match_blocks_are_followed_through_includes() {
        let facts = with_sshd_config(
            "Include /etc/ssh/sshd_config.d/*.conf\nMatch Group admins\n\
             Include /etc/ssh/match.conf\n",
            &[
                // A Match block in a drop-in ends with it.
                (
                    "/etc/ssh/sshd_config.d/10-x.conf",
                    "Match User deploy\nX11Forwarding yes\n",
                ),
                ("/etc/ssh/sshd_config.d/20-y.conf", "X11Forwarding no\n"),
                ("/etc/ssh/match.conf", "Include /etc/ssh/nested.conf\n"),
                (
                    "/etc/ssh/nested.conf",
                    "ChallengeResponseAuthentication yes\nPermitRootLogin=prohibit-password\n",
                ),
            ],
        );
        let found: Vec<(String, String)> = sshd_findings(&facts)
            .iter()
            .map(|f| (f.control.id.clone(), f.detail().unwrap()))
            .collect();
        assert_eq!(
            found,
            [
                (
                    "SSH-001".to_owned(),
                    "permitrootlogin is prohibit-password in a Match block \
                     (/etc/ssh/nested.conf:2, Match Group admins), expected no"
                        .to_owned()
                ),
                (
                    "SSH-003".to_owned(),
                    "kbdinteractiveauthentication is yes in a Match block \
                     (/etc/ssh/nested.conf:1, Match Group admins), expected no"
                        .to_owned()
                ),
                (
                    "SSH-005".to_owned(),
                    "x11forwarding is yes in a Match block \
                     (/etc/ssh/sshd_config.d/10-x.conf:2, Match User deploy), expected no"
                        .to_owned()
                ),
            ]
        );
    }

    #[test]
    fn a_failing_global_value_is_reported_first_and_keeps_its_fix() {
        let mut facts = with_sshd_config("Match User bob\nX11Forwarding yes\n", &[]);
        facts.ssh.effective = Some(SshdConfig::parse("x11forwarding yes\n"));
        let finding = run(catalog().unwrap(), &facts)
            .findings
            .into_iter()
            .find(|f| f.control.id == "SSH-005")
            .unwrap();
        assert_eq!(
            finding.outcome,
            Outcome::Fail {
                found: "yes".to_owned()
            }
        );
        assert_eq!(finding.control.fix.as_deref(), Some("ssh.server"));
    }

    /// Plain `sshd -T` applies `Match all`, so its value is the effective
    /// one, and ssh.server's drop-in cannot win over it.
    #[test]
    fn a_failing_match_all_is_not_claimed_by_a_module() {
        let mut facts = with_sshd_config("Match ALL\n  X11Forwarding yes\n", &[]);
        facts.ssh.effective = Some(SshdConfig::parse("x11forwarding yes\n"));
        let finding = run(catalog().unwrap(), &facts)
            .findings
            .into_iter()
            .find(|f| f.control.id == "SSH-005")
            .unwrap();
        assert_eq!(
            finding.outcome,
            Outcome::Fail {
                found: "yes".to_owned()
            }
        );
        assert_eq!(finding.control.fix, None);
        assert_eq!(
            finding.manual_fix.as_deref(),
            Some(
                "edit the Match block at /etc/ssh/sshd_config:2 by hand \
                 (vps-ready does not edit Match blocks)"
            )
        );
    }

    #[test]
    fn unreadable_sshd_config_leaves_match_blocks_unknown() {
        let mut facts = with_sshd_config("", &[]);
        facts.ssh.files = None;
        let findings = sshd_findings(&facts);
        assert_eq!(findings.len(), 7);
        assert!(
            findings
                .iter()
                .all(|f| matches!(f.outcome, Outcome::Unknown { .. }))
        );
    }

    #[test]
    fn evaluates_ssh_rate_limited() {
        let eval = |facts: &Facts| evaluate(&Check::SshRateLimited, facts);
        // OpenSSH 10.0 has PerSourcePenalties on; 9.2 and 9.6 lack it.
        assert_eq!(eval(&host("debian-13", &[])), Outcome::Pass);
        for name in ["debian-12", "ubuntu-24.04"] {
            let mut facts = host(name, &[]);
            assert_eq!(
                eval(&facts),
                Outcome::Fail {
                    found: "sshd has no PerSourcePenalties (OpenSSH before 9.8) and \
                            fail2ban's sshd jail is not running"
                        .to_owned()
                },
                "{name}"
            );
            facts.ssh.fail2ban = Some(true);
            assert_eq!(eval(&facts), Outcome::Pass, "{name}");
            facts.ssh.fail2ban = None;
            assert!(matches!(eval(&facts), Outcome::Unknown { .. }), "{name}");
        }

        let mut facts = host("debian-13", &[]);
        facts.ssh.effective = Some(SshdConfig::parse("persourcepenalties no\n"));
        assert_eq!(
            eval(&facts),
            Outcome::Fail {
                found: "persourcepenalties is no and fail2ban's sshd jail is not running"
                    .to_owned()
            }
        );
        facts.ssh.fail2ban = Some(true);
        assert_eq!(eval(&facts), Outcome::Pass);
        facts.ssh.effective = None;
        assert_eq!(eval(&facts), Outcome::Pass);
        facts.ssh.fail2ban = Some(false);
        assert!(matches!(eval(&facts), Outcome::Unknown { .. }));
    }

    /// Facts of a VM whose `/proc/sys` holds `files`.
    fn vm(files: &[(&str, &str)]) -> Facts {
        let fs = files.iter().fold(
            FakeFs::new().with_file("/proc/sys/kernel/osrelease", "6.8.0\n"),
            |fs, (path, value)| fs.with_file(*path, *value),
        );
        let mut facts =
            crate::facts::collect(&fs, &FakeRunner::new(), &Default::default()).unwrap();
        facts.virtualization.container = Virt::None;
        facts
    }

    #[test]
    fn evaluates_sysctl() {
        let check = |key: &str, one_of: &[&str]| Check::Sysctl {
            key: key.to_owned(),
            one_of: one_of.iter().map(|v| (*v).to_owned()).collect(),
            absent_ok: false,
        };
        let facts = vm(&[("/proc/sys/kernel/kptr_restrict", "1\n")]);
        let eval = |key, one_of| evaluate(&check(key, one_of), &facts);
        assert_eq!(eval("kernel.kptr_restrict", &["1", "2"]), Outcome::Pass);
        assert_eq!(
            eval("kernel.kptr_restrict", &["2"]),
            Outcome::Fail {
                found: "1".to_owned()
            }
        );
        assert!(matches!(
            eval("kernel.dmesg_restrict", &["1"]),
            Outcome::Unknown { .. }
        ));

        let mut container = facts.clone();
        container.virtualization.container = Virt::Detected("lxc".to_owned());
        assert!(matches!(
            evaluate(&check("kernel.kptr_restrict", &["2"]), &container),
            Outcome::Skip { .. }
        ));
    }

    #[test]
    fn absent_setting_passes_when_allowed() {
        let check = Check::Sysctl {
            key: "net.mptcp.enabled".to_owned(),
            one_of: vec!["0".to_owned()],
            absent_ok: true,
        };
        let facts = vm(&[("/proc/sys/kernel/kptr_restrict", "1\n")]);
        assert_eq!(evaluate(&check, &facts), Outcome::Pass);
        let on = vm(&[("/proc/sys/net/mptcp/enabled", "1\n")]);
        assert_eq!(
            evaluate(&check, &on),
            Outcome::Fail {
                found: "1".to_owned()
            }
        );
        let off = vm(&[("/proc/sys/net/mptcp/enabled", "0\n")]);
        assert_eq!(evaluate(&check, &off), Outcome::Pass);
    }

    /// Facts of a Debian VM with the given reboot state.
    fn rebooting(flagged: bool, running: Option<&str>, installed: &[&str]) -> Facts {
        let mut facts = host("debian-13", &[]);
        facts.virtualization.container = Virt::None;
        facts.reboot = Some(crate::facts::Reboot {
            flagged,
            running: running.map(str::to_owned),
            installed: installed.iter().map(|s| (*s).to_owned()).collect(),
            image_replaced: Some(false),
        });
        facts
    }

    #[test]
    fn evaluates_reboot_required() {
        let eval = |facts: &Facts| evaluate(&Check::RebootRequired, facts);
        let same = ["6.12.57+deb13-amd64"];
        let run = Some("6.12.57+deb13-amd64");
        assert_eq!(eval(&rebooting(false, run, &same)), Outcome::Pass);

        assert_eq!(
            eval(&rebooting(true, run, &same)),
            Outcome::Fail {
                found: "/run/reboot-required exists".to_owned()
            }
        );
        // Debian without the flag file: only the kernel comparison sees it.
        assert_eq!(
            eval(&rebooting(
                false,
                run,
                &["6.12.57+deb13-amd64", "6.12.117+deb13-amd64"]
            )),
            Outcome::Fail {
                found: "running kernel 6.12.57+deb13-amd64, newest installed \
                        6.12.117+deb13-amd64"
                    .to_owned()
            }
        );
        let both = eval(&rebooting(true, run, &["6.12.117+deb13-amd64"]));
        assert!(matches!(both, Outcome::Fail { found } if found.contains("; running kernel")));

        // Same release name, image overwritten by an update.
        let mut replaced = rebooting(false, run, &same);
        replaced.reboot.as_mut().unwrap().image_replaced = Some(true);
        assert_eq!(
            eval(&replaced),
            Outcome::Fail {
                found: "the running kernel's image was replaced after boot \
                        (6.12.57+deb13-amd64)"
                    .to_owned()
            }
        );

        // No kernel image, as on a VPS that boots a provider kernel.
        assert!(matches!(
            eval(&rebooting(false, run, &[])),
            Outcome::Skip { .. }
        ));
        assert!(matches!(
            eval(&rebooting(false, None, &same)),
            Outcome::Unknown { .. }
        ));

        let mut facts = rebooting(false, run, &same);
        facts.reboot = None;
        assert!(matches!(eval(&facts), Outcome::Unknown { .. }));
        let mut container = rebooting(true, run, &same);
        container.virtualization.container = Virt::Detected("lxc".to_owned());
        assert!(matches!(eval(&container), Outcome::Skip { .. }));
    }

    #[test]
    fn sysctl_detail_names_the_accepted_values() {
        let facts = vm(&[("/proc/sys/kernel/yama/ptrace_scope", "0\n")]);
        let report = run(catalog().unwrap(), &facts);
        let finding = report
            .findings
            .iter()
            .find(|f| f.control.id == "KRN-004")
            .unwrap();
        assert_eq!(
            finding.detail().unwrap(),
            "kernel.yama.ptrace_scope is 0, expected 1, 2 or 3"
        );
    }

    /// Checks of kernel settings under `/proc/sys`, skipped in a container.
    fn reads_proc_sys(check: &Check) -> bool {
        matches!(
            check,
            Check::Sysctl { .. }
                | Check::ReversePathFilter
                | Check::IcmpRedirectsIgnored
                | Check::IcmpRedirectsNotSent
        )
    }

    /// Facts of a VM with these directories under `/proc/sys/net/ipv4/conf`,
    /// each with `[accept_redirects, forwarding, rp_filter, send_redirects]`.
    fn vm_conf(dirs: &[(&str, [u8; 4])]) -> Facts {
        let files: Vec<(String, String)> = dirs
            .iter()
            .flat_map(|(dir, values)| {
                sysctl::CONF_KEYS.iter().zip(values).map(move |(key, v)| {
                    (
                        format!("/proc/sys/net/ipv4/conf/{dir}/{key}"),
                        format!("{v}\n"),
                    )
                })
            })
            .collect();
        let files: Vec<(&str, &str)> = files
            .iter()
            .map(|(p, v)| (p.as_str(), v.as_str()))
            .collect();
        vm(&files)
    }

    fn fail(found: &str) -> Outcome {
        Outcome::Fail {
            found: found.to_owned(),
        }
    }

    /// The effective value is the larger of `all` and the interface's.
    #[test]
    fn evaluates_reverse_path_filter() {
        let eval = |dirs: &[(&str, [u8; 4])]| evaluate(&Check::ReversePathFilter, &vm_conf(dirs));
        // Upstream systemd's 50-default.conf: default and every interface 2,
        // all left at 0.
        assert_eq!(
            eval(&[
                ("all", [1, 0, 0, 1]),
                ("default", [1, 0, 2, 1]),
                ("eth0", [1, 0, 2, 1]),
                ("lo", [1, 0, 2, 1]),
            ]),
            Outcome::Pass
        );
        // Ubuntu's 10-network-security.conf: all and default 2, which
        // covers an interface left at 0.
        assert_eq!(
            eval(&[
                ("all", [1, 0, 2, 1]),
                ("default", [1, 0, 2, 1]),
                ("eth0", [1, 0, 0, 1]),
            ]),
            Outcome::Pass
        );
        // Debian sets nothing: the kernel's 0 everywhere.
        assert_eq!(
            eval(&[
                ("all", [1, 0, 0, 1]),
                ("default", [1, 0, 0, 1]),
                ("eth0", [1, 0, 0, 1]),
            ]),
            fail(
                "reverse path filtering is not 1 (strict) or 2 (loose) on new interfaces (default) and \
                 eth0: rp_filter 0 in all and on each"
            )
        );
        // Strict on eth0 alone leaves interfaces created later unfiltered.
        assert_eq!(
            eval(&[
                ("all", [1, 0, 0, 1]),
                ("default", [1, 0, 0, 1]),
                ("eth0", [1, 0, 1, 1]),
            ]),
            fail(
                "reverse path filtering is not 1 (strict) or 2 (loose) on new interfaces (default): \
                 rp_filter all=0 default=0"
            )
        );
    }

    /// With forwarding on, both `all` and the interface must accept
    /// redirects; with it off, either is enough.
    #[test]
    fn evaluates_icmp_redirects_ignored() {
        let eval =
            |dirs: &[(&str, [u8; 4])]| evaluate(&Check::IcmpRedirectsIgnored, &vm_conf(dirs));
        // Debian's defaults: the kernel's 1 everywhere, no forwarding.
        assert_eq!(
            eval(&[
                ("all", [1, 0, 0, 1]),
                ("default", [1, 0, 0, 1]),
                ("eth0", [1, 0, 0, 1]),
            ]),
            fail(
                "ICMP redirects are accepted on new interfaces (default) and eth0: \
                 accept_redirects 1 in all and on each, forwarding 0 on each"
            )
        );
        // Without forwarding, `all` at 1 is enough.
        assert_eq!(
            eval(&[
                ("all", [1, 0, 0, 1]),
                ("default", [0, 0, 0, 1]),
                ("eth0", [1, 0, 0, 1]),
            ]),
            fail(
                "ICMP redirects are accepted on new interfaces (default) and eth0: \
                 accept_redirects all=1 default=0 eth0=1, forwarding 0 on each"
            )
        );
        // Nor is `all` at 0.
        assert_eq!(
            eval(&[
                ("all", [0, 0, 0, 1]),
                ("default", [1, 0, 0, 1]),
                ("eth0", [1, 0, 0, 1]),
            ]),
            fail(
                "ICMP redirects are accepted on new interfaces (default) and eth0: \
                 accept_redirects 0 in all and 1 on each, forwarding 0 on each"
            )
        );
        // `all` at 0 is not enough without forwarding.
        assert_eq!(
            eval(&[
                ("all", [0, 0, 0, 1]),
                ("default", [0, 0, 0, 1]),
                ("eth0", [1, 0, 0, 1]),
            ]),
            fail(
                "ICMP redirects are accepted on eth0: \
                 accept_redirects all=0 eth0=1, forwarding eth0=0"
            )
        );
        // Docker turned forwarding on, which also set all to 0.
        assert_eq!(
            eval(&[
                ("all", [0, 1, 0, 1]),
                ("default", [1, 1, 0, 1]),
                ("docker0", [1, 1, 0, 1]),
                ("eth0", [1, 1, 0, 1]),
            ]),
            Outcome::Pass
        );
        assert_eq!(
            eval(&[
                ("all", [1, 1, 0, 1]),
                ("default", [0, 1, 0, 1]),
                ("eth0", [1, 1, 0, 1]),
            ]),
            fail(
                "ICMP redirects are accepted on eth0: \
                 accept_redirects all=1 eth0=1, forwarding eth0=1"
            )
        );
        assert_eq!(
            eval(&[
                ("all", [0, 0, 0, 1]),
                ("default", [0, 0, 0, 1]),
                ("eth0", [0, 0, 0, 1]),
            ]),
            Outcome::Pass
        );
    }

    /// Only an interface that forwards sends redirects, when `all` or its
    /// own `send_redirects` is on.
    #[test]
    fn evaluates_icmp_redirects_not_sent() {
        let eval =
            |dirs: &[(&str, [u8; 4])]| evaluate(&Check::IcmpRedirectsNotSent, &vm_conf(dirs));
        // Debian's defaults: send_redirects is 1, but nothing forwards.
        assert_eq!(
            eval(&[
                ("all", [1, 0, 0, 1]),
                ("default", [1, 0, 0, 1]),
                ("eth0", [1, 0, 0, 1]),
            ]),
            Outcome::Pass
        );
        // A Docker host with the defaults.
        assert_eq!(
            eval(&[
                ("all", [0, 1, 0, 1]),
                ("default", [1, 1, 0, 1]),
                ("docker0", [1, 1, 0, 1]),
                ("eth0", [1, 1, 0, 1]),
            ]),
            fail(
                "ICMP redirects can be sent from new interfaces (default), docker0 and eth0: \
                 send_redirects 1 in all and on each, forwarding 1 on each"
            )
        );
        // `all` at 0 alone leaves the interfaces' own 1.
        assert_eq!(
            eval(&[
                ("all", [0, 1, 0, 0]),
                ("default", [1, 1, 0, 0]),
                ("eth0", [1, 1, 0, 1]),
            ]),
            fail(
                "ICMP redirects can be sent from eth0: \
                 send_redirects all=0 eth0=1, forwarding eth0=1"
            )
        );
        assert_eq!(
            eval(&[
                ("all", [0, 1, 0, 0]),
                ("default", [1, 1, 0, 0]),
                ("eth0", [1, 1, 0, 0]),
            ]),
            Outcome::Pass
        );
    }

    #[test]
    fn per_interface_lists_at_most_five_and_reports_unknown() {
        let mut dirs = vec![("all", [0, 1, 0, 1]), ("default", [0, 1, 0, 1])];
        let names = ["veth1", "veth2", "veth3", "veth4", "veth5", "veth6"];
        dirs.extend(names.iter().map(|n| (*n, [0, 1, 0, 1])));
        assert_eq!(
            evaluate(&Check::IcmpRedirectsNotSent, &vm_conf(&dirs)),
            fail(
                "ICMP redirects can be sent from new interfaces (default), veth1, veth2, veth3, veth4 and \
                 2 more: send_redirects 1 in all and on each, forwarding 1 on each"
            )
        );

        let mut facts = vm_conf(&[("all", [0, 0, 0, 0]), ("eth0", [0, 0, 0, 0])]);
        let conf = &mut facts.sysctl.as_mut().unwrap().ipv4_conf;
        conf.get_mut("eth0")
            .unwrap()
            .insert("forwarding".to_owned(), "x".to_owned());
        assert!(matches!(
            evaluate(&Check::IcmpRedirectsNotSent, &facts),
            Outcome::Unknown { reason } if reason.ends_with("for eth0")
        ));
        facts.sysctl.as_mut().unwrap().ipv4_conf.remove("all");
        assert!(matches!(
            evaluate(&Check::ReversePathFilter, &facts),
            Outcome::Unknown { .. }
        ));
        facts.virtualization.container = Virt::Detected("docker".to_owned());
        assert!(matches!(
            evaluate(&Check::ReversePathFilter, &facts),
            Outcome::Skip { .. }
        ));
    }

    /// Kernel settings belong to the host, so in a container they are
    /// skipped, and skipping does not fail the audit.
    #[test]
    fn container_skips_kernel_controls_without_failing() {
        let mut facts = host("debian-13", &["sshd-T-dropin-00"]);
        facts.ssh.effective = Some(SshdConfig::parse(
            "permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\n\
             permitemptypasswords no\nx11forwarding no\nhostbasedauthentication no\n\
             permituserenvironment no\npersourcepenalties authfail:5\n",
        ));
        facts.updates = Some(updating());
        facts.firewall = Some(Firewall {
            input_chains: vec![crate::facts::InputChain {
                family: "inet".to_owned(),
                table: "filter".to_owned(),
                name: "input".to_owned(),
                drops_unmatched: true,
                open_ports: Vec::new(),
                interface_ports: Vec::new(),
                unread_ports: Vec::new(),
            }],
            ..Firewall::default()
        });
        let report = run(catalog().unwrap(), &facts);
        let sysctl_controls = report
            .findings
            .iter()
            .filter(|f| reads_proc_sys(&f.control.check))
            .count();
        assert!(sysctl_controls > 0);
        // Plus MAC-001 and UPD-002 (in a container), FW-002 (no Docker),
        // SSH-009 (no VPN) and NET-008 (no /etc/wireguard).
        assert_eq!(report.summary.skipped, sysctl_controls + 5);
        assert!(report.all_passed(), "{:?}", report.summary);
    }

    /// apt settings of a host that installs updates on its own.
    fn updating() -> AptUpdates {
        let units = [
            "apt-daily.timer",
            "apt-daily-upgrade.timer",
            "apt-daily.service",
            "apt-daily-upgrade.service",
        ];
        AptUpdates {
            unattended_upgrades: true,
            periodic: [("Update-Package-Lists", "1"), ("Unattended-Upgrade", "1")]
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .into(),
            units: Some(units.map(|u| (u.to_owned(), "ok".to_owned())).into()),
        }
    }

    #[test]
    fn evaluates_auto_updates() {
        let mut facts = host("debian-13", &[]);
        let eval = |facts: &Facts| evaluate(&Check::AutoUpdates, facts);
        facts.updates = Some(updating());
        assert_eq!(eval(&facts), Outcome::Pass);

        // A masked service, or `Enable "0"` as Docker's Ubuntu image sets
        // it, stops updates however the rest is set.
        let mut apt = updating();
        if let Some(units) = &mut apt.units {
            units.insert("apt-daily-upgrade.service".to_owned(), "masked".to_owned());
        }
        apt.periodic.insert("Enable".to_owned(), "0".to_owned());
        facts.updates = Some(apt);
        assert_eq!(
            eval(&facts),
            Outcome::Fail {
                found: "APT::Periodic::Enable is 0; apt-daily-upgrade.service is masked".to_owned()
            }
        );

        let mut apt = updating();
        apt.unattended_upgrades = false;
        apt.periodic
            .insert("Unattended-Upgrade".to_owned(), "0".to_owned());
        apt.periodic.remove("Update-Package-Lists");
        facts.updates = Some(apt);
        assert_eq!(
            eval(&facts),
            Outcome::Fail {
                found: "unattended-upgrades is not installed; \
                        APT::Periodic::Update-Package-Lists is not set; \
                        APT::Periodic::Unattended-Upgrade is 0"
                    .to_owned()
            }
        );

        // Without systemd nothing proves the jobs run, but a setting that
        // turns them off still fails.
        let mut apt = updating();
        apt.units = None;
        facts.updates = Some(apt.clone());
        assert!(matches!(eval(&facts), Outcome::Unknown { reason } if reason.contains("systemd")));
        apt.unattended_upgrades = false;
        facts.updates = Some(apt);
        assert!(matches!(eval(&facts), Outcome::Fail { .. }));

        facts.updates = None;
        assert!(matches!(eval(&facts), Outcome::Unknown { .. }));
        facts.os.family = OsFamily::Rhel;
        assert!(
            matches!(eval(&facts), Outcome::Skip { reason } if reason.contains("only on Debian"))
        );
    }

    #[test]
    fn evaluates_inbound_default_deny() {
        let chain = |family: &str, drops_unmatched| crate::facts::InputChain {
            family: family.to_owned(),
            table: "t".to_owned(),
            name: "input".to_owned(),
            drops_unmatched,
            open_ports: Vec::new(),
            interface_ports: Vec::new(),
            unread_ports: Vec::new(),
        };
        let mut facts = host("debian-13", &[]);
        let mut eval = |chains: Vec<crate::facts::InputChain>, ipv6| {
            facts.firewall = Some(Firewall {
                input_chains: chains,
                ..Firewall::default()
            });
            facts.ipv6 = ipv6;
            evaluate(&Check::InboundDefaultDeny, &facts)
        };
        let fail = |found: &str| Outcome::Fail {
            found: found.to_owned(),
        };
        assert_eq!(
            eval(vec![], false),
            fail("no firewall rules filter incoming traffic")
        );
        assert_eq!(eval(vec![chain("inet", true)], true), Outcome::Pass);
        // A chain that accepts does not undo one that drops.
        assert_eq!(
            eval(vec![chain("ip", false), chain("ip", true)], false),
            Outcome::Pass
        );
        // IPv6 counts only when the host has a global IPv6 address.
        assert_eq!(
            eval(vec![chain("ip", true)], true),
            fail("incoming IPv6 traffic that no rule allows is accepted")
        );
        assert_eq!(
            eval(vec![chain("inet", false)], true),
            fail("incoming IPv4 and IPv6 traffic that no rule allows is accepted")
        );

        facts.firewall = None;
        assert!(matches!(
            evaluate(&Check::InboundDefaultDeny, &facts),
            Outcome::Unknown { .. }
        ));
    }

    /// Rules in iptables-legacy are not in nftables: without a nft chain
    /// that drops, FW-001 and FW-002 cannot tell.
    #[test]
    fn iptables_legacy_makes_unseen_rules_unknown() {
        let chain = |drops_unmatched| crate::facts::InputChain {
            family: "inet".to_owned(),
            table: "t".to_owned(),
            name: "input".to_owned(),
            drops_unmatched,
            open_ports: Vec::new(),
            interface_ports: Vec::new(),
            unread_ports: Vec::new(),
        };
        let mut facts = host("debian-13", &[]);
        facts.docker = true;
        facts.ipv6 = false;
        let mut eval = |check: &Check, chains: Vec<crate::facts::InputChain>| {
            facts.firewall = Some(Firewall {
                input_chains: chains,
                legacy_filter_v4: true,
                legacy_filter_v6: true,
                ..Firewall::default()
            });
            evaluate(check, &facts)
        };
        assert_eq!(
            eval(&Check::InboundDefaultDeny, vec![]),
            Outcome::Unknown {
                reason: "nft shows no rules that filter incoming traffic, and the filter table \
                         of iptables-legacy is loaded for IPv4; vps-ready does not read its \
                         rules"
                    .to_owned()
            }
        );
        assert_eq!(
            eval(&Check::InboundDefaultDeny, vec![chain(false)]),
            Outcome::Unknown {
                reason: "nft shows incoming IPv4 traffic that no rule allows as accepted, and \
                         the filter table of iptables-legacy is loaded for IPv4; vps-ready does \
                         not read its rules"
                    .to_owned()
            }
        );
        // A nft chain that drops decides: a packet passes both.
        assert_eq!(
            eval(&Check::InboundDefaultDeny, vec![chain(true)]),
            Outcome::Pass
        );
        assert!(matches!(
            eval(&Check::PublishedPorts, vec![chain(true)]),
            Outcome::Unknown { reason } if reason.contains("iptables-legacy")
        ));
        facts.docker = false;
        assert!(matches!(
            evaluate(&Check::PublishedPorts, &facts),
            Outcome::Skip { .. }
        ));
    }

    /// FW-002 is unknown only when the legacy table of a family Docker
    /// could publish in is loaded.
    #[test]
    fn published_ports_unknown_only_for_loaded_legacy_family() {
        let mut facts = host("debian-13", &[]);
        facts.docker = true;
        let mut eval = |(v4, v6): (bool, bool), ipv6| {
            facts.firewall = Some(Firewall {
                legacy_filter_v4: v4,
                legacy_filter_v6: v6,
                ..Firewall::default()
            });
            facts.ipv6 = ipv6;
            evaluate(&Check::PublishedPorts, &facts)
        };
        assert!(matches!(
            eval((true, false), false),
            Outcome::Unknown { .. }
        ));
        assert!(matches!(eval((false, true), true), Outcome::Unknown { .. }));
        assert_eq!(eval((false, true), false), Outcome::Pass);
        assert_eq!(eval((false, false), true), Outcome::Pass);
    }

    /// Only a family whose own iptables-legacy filter table is loaded is
    /// downgraded from Fail to Unknown.
    #[test]
    fn iptables_legacy_is_judged_per_family() {
        let chain = |family: &str, drops_unmatched| crate::facts::InputChain {
            family: family.to_owned(),
            table: "t".to_owned(),
            name: "input".to_owned(),
            drops_unmatched,
            open_ports: Vec::new(),
            interface_ports: Vec::new(),
            unread_ports: Vec::new(),
        };
        let mut facts = host("debian-13", &[]);
        let mut eval = |chains, (v4, v6): (bool, bool), ipv6| {
            facts.firewall = Some(Firewall {
                input_chains: chains,
                legacy_filter_v4: v4,
                legacy_filter_v6: v6,
                ..Firewall::default()
            });
            facts.ipv6 = ipv6;
            evaluate(&Check::InboundDefaultDeny, &facts)
        };
        // Only IPv4 has legacy rules, and nft drops IPv4 but not IPv6.
        assert_eq!(
            eval(vec![chain("ip", true)], (true, false), true),
            Outcome::Fail {
                found: "incoming IPv6 traffic that no rule allows is accepted".to_owned()
            }
        );
        // Only IPv6 has legacy rules, nft has nothing, and the host has no IPv6.
        assert_eq!(
            eval(vec![], (false, true), false),
            Outcome::Fail {
                found: "no firewall rules filter incoming traffic".to_owned()
            }
        );
        // With IPv6 present and loaded, IPv4 still fails.
        assert!(matches!(
            eval(vec![], (false, true), true),
            Outcome::Fail { .. }
        ));
        // Each family with its own table loaded is unknown.
        assert!(matches!(
            eval(vec![chain("ip", true)], (false, true), true),
            Outcome::Unknown { reason } if reason.contains("for IPv6;")
        ));
    }

    #[test]
    fn evaluates_published_ports() {
        // An input chain that drops all but tcp/22, as `ufw allow 22/tcp`.
        let ufw = crate::facts::InputChain {
            family: "inet".to_owned(),
            table: "t".to_owned(),
            name: "input".to_owned(),
            drops_unmatched: true,
            open_ports: vec![crate::facts::Ports {
                proto: "tcp".to_owned(),
                first: 22,
                last: 22,
            }],
            interface_ports: Vec::new(),
            unread_ports: Vec::new(),
        };
        let port = |family: &str, port, filtered| PublishedPort {
            family: family.to_owned(),
            proto: "tcp".to_owned(),
            port,
            address: None,
            filtered,
        };
        let mut facts = host("debian-13", &[]);
        facts.docker = true;
        let mut eval = |published: Vec<PublishedPort>, ipv6| {
            facts.firewall = Some(Firewall {
                input_chains: vec![ufw.clone()],
                published,
                ..Firewall::default()
            });
            facts.ipv6 = ipv6;
            evaluate(&Check::PublishedPorts, &facts)
        };
        assert_eq!(eval(vec![], false), Outcome::Pass);
        // A port the firewall allows anyway is not a bypass.
        assert_eq!(eval(vec![port("ip", 22, false)], false), Outcome::Pass);
        assert_eq!(
            eval(
                vec![
                    port("ip", 5432, false),
                    port("ip6", 5432, false),
                    port("ip", 9000, false),
                    port("ip", 9001, false),
                ],
                true
            ),
            Outcome::Fail {
                found: format!(
                    "Docker publishes ports the firewall would otherwise block: \
                     tcp/5432, tcp/9000-9001; {LOOPBACK_HINT}"
                )
            }
        );
        // A private address may be a cloud server's primary one, so it counts.
        let mut bound = port("ip", 5432, false);
        bound.address = Some("10.8.0.1".to_owned());
        assert_eq!(
            eval(vec![bound], false),
            Outcome::Fail {
                found: format!(
                    "Docker publishes ports the firewall would otherwise block: \
                     tcp/5432 on 10.8.0.1; {LOOPBACK_HINT}"
                )
            }
        );
        // IPv6 counts only when the host has a global IPv6 address.
        assert_eq!(eval(vec![port("ip6", 5432, false)], false), Outcome::Pass);
        assert!(matches!(
            eval(vec![port("ip", 5432, true)], false),
            Outcome::Unknown { .. }
        ));

        // A multiport rule (`ufw allow 80,443/tcp`) may allow any TCP port.
        let mut multiport = ufw.clone();
        multiport.unread_ports = vec!["tcp".to_owned()];
        facts.firewall = Some(Firewall {
            input_chains: vec![multiport],
            published: vec![port("ip", 443, false)],
            ..Firewall::default()
        });
        assert!(matches!(
            evaluate(&Check::PublishedPorts, &facts),
            Outcome::Unknown { .. }
        ));

        // No input chain drops by default: FW-001 reports it, not FW-002.
        facts.firewall = Some(Firewall {
            input_chains: vec![],
            published: vec![port("ip", 5432, false)],
            ..Firewall::default()
        });
        assert_eq!(evaluate(&Check::PublishedPorts, &facts), Outcome::Pass);

        facts.firewall = None;
        assert!(matches!(
            evaluate(&Check::PublishedPorts, &facts),
            Outcome::Unknown { .. }
        ));
        facts.docker = false;
        assert!(matches!(
            evaluate(&Check::PublishedPorts, &facts),
            Outcome::Skip { .. }
        ));
    }

    /// A default-deny `inet` input chain that opens `open` to all and
    /// `(ports, interfaces)` on those interfaces only.
    fn deny_but(open: &[(&str, u16)], scoped: &[(&str, u16, &[&str])]) -> crate::facts::InputChain {
        let ports = |proto: &str, port| crate::facts::Ports {
            proto: proto.to_owned(),
            first: port,
            last: port,
        };
        crate::facts::InputChain {
            family: "inet".to_owned(),
            table: "t".to_owned(),
            name: "input".to_owned(),
            drops_unmatched: true,
            open_ports: open
                .iter()
                .map(|&(proto, port)| ports(proto, port))
                .collect(),
            interface_ports: scoped
                .iter()
                .map(|&(proto, port, interfaces)| crate::facts::InterfacePorts {
                    interfaces: interfaces.iter().map(|i| (*i).to_owned()).collect(),
                    ports: ports(proto, port),
                })
                .collect(),
            unread_ports: Vec::new(),
        }
    }

    fn listening(proto: Proto, addr: &str, port: u16, process: &str) -> crate::facts::Listener {
        crate::facts::Listener {
            proto,
            addr: addr.to_owned(),
            port,
            processes: vec![process.to_owned()],
        }
    }

    /// FW-003's finding, through [`run`] for the note on a pass.
    fn exposed(facts: &Facts) -> Finding {
        let control = catalog()
            .unwrap()
            .into_iter()
            .find(|c| c.check == Check::ExposedListeners)
            .unwrap();
        run(vec![control], facts).findings.remove(0)
    }

    #[test]
    fn evaluates_exposed_listeners() {
        let mut facts = host("debian-13", &[]);
        facts.ipv6 = false;
        facts.ssh.listening = vec![2222];
        facts.listeners = vec![
            listening(Proto::Tcp, "0.0.0.0", 2222, "sshd"),
            listening(Proto::Tcp, "::", 2222, "sshd"),
            listening(Proto::Tcp, "*", 80, "caddy"),
            listening(Proto::Tcp, "*", 443, "caddy"),
            listening(Proto::Udp, "*", 443, "caddy"),
            listening(Proto::Udp, "0.0.0.0%eth0", 68, "dhclient"),
            listening(Proto::Udp, "::", 546, "dhclient"),
            // Not reachable from beyond the host or its link.
            listening(Proto::Udp, "127.0.0.53%lo", 53, "systemd-resolve"),
            listening(Proto::Tcp, "::ffff:127.0.0.1", 8080, "node"),
            listening(Proto::Tcp, "::1", 8081, "node"),
            listening(Proto::Udp, "fe80::1%eth0", 546, "dhclient"),
            listening(Proto::Tcp, "198.51.100.7%tailscale0", 9000, "app"),
            // FW-002's.
            listening(Proto::Tcp, "0.0.0.0", 8443, "docker-proxy"),
        ];
        let open = "open to the internet: tcp/80 (caddy), tcp/443 (caddy), tcp/2222 (sshd), \
                    udp/68 (dhclient), udp/443 (caddy)";
        // Without a default-deny chain, every listener counts.
        facts.firewall = Some(Firewall::default());
        let finding = exposed(&facts);
        assert_eq!(finding.outcome, Outcome::Pass);
        assert_eq!(finding.note.as_deref(), Some(open));
        let json = serde_json::to_value(&finding).unwrap();
        assert_eq!(json["note"], open);

        // A database on all addresses: `found` names it, the note all.
        facts
            .listeners
            .push(listening(Proto::Tcp, "0.0.0.0", 5432, "postgres"));
        let finding = exposed(&facts);
        assert_eq!(
            finding.outcome,
            Outcome::Fail {
                found: "ports other than SSH, web, DHCP and WireGuard are open: \
                        tcp/5432 (postgres)"
                    .to_owned()
            }
        );
        assert_eq!(
            finding.note.as_deref(),
            Some(
                "open to the internet: tcp/80 (caddy), tcp/443 (caddy), tcp/2222 (sshd), \
                 tcp/5432 (postgres), udp/68 (dhclient), udp/443 (caddy)"
            )
        );
        assert!(
            finding
                .manual_fix
                .unwrap()
                .contains("leave it out of `allow`")
        );

        let mut eval = |chains: Vec<crate::facts::InputChain>| {
            facts.firewall = Some(Firewall {
                input_chains: chains,
                ..Firewall::default()
            });
            exposed(&facts)
        };
        // The firewall drops it.
        let finding = eval(vec![deny_but(&[("tcp", 2222)], &[])]);
        assert_eq!(finding.outcome, Outcome::Pass);
        assert_eq!(
            finding.note.as_deref(),
            Some("open to the internet: tcp/2222 (sshd)")
        );
        // Open on tailscale0 or lo only: not to the internet.
        let private: &[&str] = &["tailscale0", "lo"];
        assert_eq!(
            eval(vec![deny_but(&[], &[("tcp", 5432, private)])]).outcome,
            Outcome::Pass
        );
        // On another interface it counts, and the finding names it.
        assert_eq!(
            eval(vec![deny_but(
                &[],
                &[("tcp", 5432, &["tailscale0", "eth1"])]
            )])
            .outcome,
            Outcome::Fail {
                found: "ports other than SSH, web, DHCP and WireGuard are open: \
                        tcp/5432 (postgres) on eth1"
                    .to_owned()
            }
        );
        // On one that is not named (`iifname != "eth0"`), anywhere.
        assert!(matches!(
            eval(vec![deny_but(&[], &[("tcp", 5432, &[])])]).outcome,
            Outcome::Fail { found } if found.ends_with("tcp/5432 (postgres)")
        ));
        // A chain that opens it does not undo one that drops it.
        assert_eq!(
            eval(vec![deny_but(&[("tcp", 5432)], &[]), deny_but(&[], &[])]).outcome,
            Outcome::Pass
        );
        // A multiport rule may open it.
        let mut multiport = deny_but(&[], &[]);
        multiport.unread_ports = vec!["tcp".to_owned()];
        let finding = eval(vec![multiport]);
        assert!(matches!(
            finding.outcome,
            Outcome::Unknown { reason } if reason.ends_with("may open tcp/5432 (postgres)")
        ));
        assert_eq!(
            finding.note.as_deref(),
            Some("no port is open to the internet")
        );
    }

    fn interface(name: &str, kind: Option<&str>, ip: &str) -> Interface {
        Interface {
            name: name.to_owned(),
            kind: kind.map(str::to_owned),
            addresses: vec![crate::facts::network::Address {
                ip: ip.parse().unwrap(),
                prefix: 24,
            }],
            up: true,
        }
    }

    /// The plan's cases: a WireGuard port passes, and a port reachable only
    /// on wg0 does not count, whether a rule, a `%wg0` bind or the address
    /// limits it. Docker's bridges count as private too.
    #[test]
    fn wireguard_and_docker_bridges_are_private() {
        let mut facts = host("debian-13", &[]);
        facts.ipv6 = false;
        facts.ssh.listening = vec![22];
        facts.interfaces = vec![
            interface("eth0", None, "203.0.113.5"),
            interface("wg0", Some("wireguard"), "10.8.0.1"),
            interface("docker0", Some("bridge"), "172.17.0.1"),
        ];
        facts.bridges = vec![crate::facts::Bridge {
            name: "docker0".to_owned(),
            docker: true,
        }];
        facts.wireguard.listen_ports = [("wg0".to_owned(), 51820)].into();
        facts.listeners = vec![
            listening(Proto::Tcp, "0.0.0.0", 22, "sshd"),
            listening(Proto::Udp, "0.0.0.0", 51820, ""),
            listening(Proto::Tcp, "0.0.0.0", 5432, "postgres"),
            listening(Proto::Tcp, "0.0.0.0%wg0", 9100, "node_exporter"),
            listening(Proto::Tcp, "10.8.0.1", 8080, "grafana"),
            listening(Proto::Tcp, "172.17.0.1", 3000, "api"),
        ];
        facts.listeners[1].processes.clear();
        let only = |interfaces: &'static [&'static str]| ("tcp", 5432, interfaces);
        let firewall = |scoped: &[(&str, u16, &[&str])]| {
            Some(Firewall {
                input_chains: vec![deny_but(&[("tcp", 22), ("udp", 51820)], scoped)],
                ..Firewall::default()
            })
        };
        facts.firewall = firewall(&[only(&["wg0", "docker0"])]);
        let finding = exposed(&facts);
        assert_eq!(finding.outcome, Outcome::Pass);
        assert_eq!(
            finding.note.as_deref(),
            Some("open to the internet: tcp/22 (sshd), udp/51820")
        );
        // A wildcard is not resolved to interfaces.
        facts.firewall = firewall(&[only(&["wg*"])]);
        assert!(matches!(exposed(&facts).outcome, Outcome::Fail { .. }));

        // Without the facts, wg0 and its port are unknown, so both count.
        facts.firewall = firewall(&[only(&["wg0"])]);
        facts.interfaces.clear();
        facts.wireguard.listen_ports.clear();
        assert_eq!(
            exposed(&facts).outcome,
            Outcome::Fail {
                found: "ports other than SSH, web, DHCP and WireGuard are open: \
                        tcp/5432 (postgres) on wg0, udp/51820"
                    .to_owned()
            }
        );
    }

    /// The ruleset firewall.inbound loads, on a stock Debian 13 VM.
    #[test]
    fn exposed_listeners_on_the_vps_ready_table() {
        let json = std::fs::read(crate::facts::fixtures::testdata("nft/vps-ready-table.json"));
        let mut facts = host("debian-13", &[]);
        facts.firewall = crate::facts::firewall::parse_json(&json.unwrap());
        facts.ipv6 = true;
        facts.ssh.listening = vec![22];
        facts.listeners = crate::facts::listeners::parse(
            "\
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=59,fd=3))
tcp LISTEN 0 128 [::]:22 [::]:* users:((\"sshd\",pid=59,fd=4))
udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:((\"systemd-resolve\",pid=300,fd=13))
udp UNCONN 0 0 *%eth0:68 *:* users:((\"systemd-network\",pid=280,fd=20))
udp UNCONN 0 0 [fe80::1%eth0]:546 [::]:* users:((\"systemd-network\",pid=280,fd=21))
udp UNCONN 0 0 127.0.0.1:323 0.0.0.0:* users:((\"chronyd\",pid=400,fd=5))
udp UNCONN 0 0 [::1]:323 [::]:* users:((\"chronyd\",pid=400,fd=6))
",
        );
        assert_eq!(facts.listeners.len(), 7);
        let finding = exposed(&facts);
        assert_eq!(finding.outcome, Outcome::Pass);
        assert_eq!(
            finding.note.as_deref(),
            Some("open to the internet: tcp/22 (sshd)")
        );
    }

    #[test]
    fn exposed_listeners_ipv6_legacy_and_unread() {
        let mut facts = host("debian-13", &[]);
        facts.listeners = vec![listening(Proto::Tcp, "::", 5432, "postgres")];
        facts.firewall = Some(Firewall::default());
        // IPv6 counts only when the host has a global IPv6 address.
        facts.ipv6 = false;
        assert_eq!(evaluate(&Check::ExposedListeners, &facts), Outcome::Pass);
        facts.ipv6 = true;
        assert!(matches!(
            evaluate(&Check::ExposedListeners, &facts),
            Outcome::Fail { .. }
        ));

        // iptables-legacy may drop what nft does not, as for FW-001; a nft
        // chain that drops decides.
        facts.firewall = Some(Firewall {
            legacy_filter_v6: true,
            ..Firewall::default()
        });
        assert!(matches!(
            evaluate(&Check::ExposedListeners, &facts),
            Outcome::Unknown { reason } if reason.contains("iptables-legacy")
        ));
        facts.firewall = Some(Firewall {
            input_chains: vec![deny_but(&[], &[])],
            legacy_filter_v6: true,
            ..Firewall::default()
        });
        assert_eq!(evaluate(&Check::ExposedListeners, &facts), Outcome::Pass);

        facts.firewall = None;
        assert!(matches!(
            evaluate(&Check::ExposedListeners, &facts),
            Outcome::Unknown { .. }
        ));
        facts.firewall = Some(Firewall::default());
        facts.listeners.clear();
        facts.notices = vec!["ss not found (iproute2); listening sockets are unknown".to_owned()];
        assert_eq!(
            evaluate(&Check::ExposedListeners, &facts),
            Outcome::Unknown {
                reason: "the listening sockets could not be read: ss not found (iproute2)"
                    .to_owned()
            }
        );
    }

    #[test]
    fn public_families_of_addresses() {
        let interfaces = [
            interface("eth0", None, "203.0.113.5"),
            interface("wg0", Some("wireguard"), "10.8.0.1"),
        ];
        let private = |name: &str| matches!(name, "lo" | "tailscale0" | "wg0");
        for (addr, families) in [
            ("0.0.0.0", (true, false)),
            ("203.0.113.5", (true, false)),
            ("::", (false, true)),
            ("2001:db8::1", (false, true)),
            ("*", (true, true)),
            ("::ffff:192.0.2.1", (true, false)),
            ("0.0.0.0%eth0", (true, false)),
            ("127.0.0.53%lo", (false, false)),
            ("::ffff:127.0.0.1", (false, false)),
            ("::1", (false, false)),
            ("169.254.169.254", (false, false)),
            ("fe80::1%eth0", (false, false)),
            ("192.0.2.1%tailscale0", (false, false)),
            ("10.8.0.1", (false, false)),
            ("::ffff:10.8.0.1", (false, false)),
        ] {
            assert_eq!(
                public_families(addr, &interfaces, private),
                families,
                "{addr}"
            );
        }
    }

    #[test]
    fn evaluates_apparmor() {
        let mut facts = host("debian-13", &[]);
        facts.virtualization.container = Virt::None;
        let mut eval = |apparmor| {
            facts.apparmor = apparmor;
            evaluate(&Check::Apparmor, &facts)
        };
        assert_eq!(eval(Some(true)), Outcome::Pass);
        assert!(matches!(eval(Some(false)), Outcome::Fail { .. }));
        assert!(matches!(eval(None), Outcome::Unknown { .. }));

        facts.os.family = OsFamily::Rhel;
        assert!(matches!(
            evaluate(&Check::Apparmor, &facts),
            Outcome::Skip { .. }
        ));
        // Inside a container AppArmor belongs to the host.
        let facts = host("debian-13", &[]);
        assert!(matches!(
            evaluate(&Check::Apparmor, &facts),
            Outcome::Skip { .. }
        ));
    }

    #[test]
    fn evaluates_wireguard_key_files() {
        use crate::facts::{WireguardDir, WireguardFile};
        let mut facts = host("debian-13", &[]);
        let check = |facts: &Facts| evaluate(&Check::WireguardKeyFiles, facts);
        assert_eq!(
            check(&facts),
            Outcome::Skip {
                reason: "/etc/wireguard does not exist".into()
            }
        );
        facts.wireguard.dir = WireguardDir::Unreadable;
        assert!(matches!(check(&facts), Outcome::Unknown { .. }));
        let file = |name: &str, uid, mode| WireguardFile {
            path: format!("/etc/wireguard/{name}").into(),
            uid,
            mode,
        };
        facts.wireguard.dir = WireguardDir::Read {
            files: vec![file("wg0.key", 0, 0o600), file("wg0.conf", 0, 0o400)],
            wg0_managed: Some(true),
        };
        assert_eq!(check(&facts), Outcome::Pass);
        facts.wireguard.dir = WireguardDir::Read {
            files: vec![
                file("wg0.key", 0, 0o600),
                file("wg1.conf", 0, 0o644),
                file("old.key", 1000, 0o600),
            ],
            wg0_managed: None,
        };
        assert_eq!(
            check(&facts),
            Outcome::Fail {
                found: "readable by others than root: /etc/wireguard/wg1.conf (mode 0644, uid \
                        0), /etc/wireguard/old.key (mode 0600, uid 1000); `chown root:root` and \
                        `chmod 600` them"
                    .into()
            }
        );
    }

    #[test]
    fn report_json_flattens_control_and_outcome() {
        let report = run(catalog().unwrap(), &host("debian-12", &[]));
        let json = serde_json::to_value(&report.findings[1]).unwrap();
        assert_eq!(json["id"], "SSH-002");
        assert_eq!(json["status"], "fail");
        assert_eq!(json["found"], "yes");
        assert_eq!(json["check"]["kind"], "sshd_effective");

        let skipped = report
            .findings
            .iter()
            .find(|f| f.control.id == "KRN-001")
            .unwrap();
        let json = serde_json::to_value(skipped).unwrap();
        assert_eq!(json["status"], "skip");
        assert!(json["reason"].is_string());
        assert!(json.get("found").is_none());
        let sysctl_controls = report
            .findings
            .iter()
            .filter(|f| reads_proc_sys(&f.control.check))
            .count();
        let summary = serde_json::to_value(report.summary).unwrap();
        assert_eq!(summary["skipped"], sysctl_controls + 5);
    }
}
