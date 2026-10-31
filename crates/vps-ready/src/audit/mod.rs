//! Checks the host against the controls catalog.
//!
//! Controls are data, not code: each file in `controls/` lists controls whose
//! [`Check`] comes from a closed vocabulary, so the policy can be reviewed
//! without reading Rust. The files are embedded at build time and a unit test
//! parses every one, so a typo fails CI instead of a user's audit.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::facts::ssh::MatchOverride;
use crate::facts::sysctl::Ipv4Conf;
use crate::facts::{AptUpdates, Facts, Firewall, OsFamily, SSHD_CONFIG};

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
    },
    /// Security updates are installed automatically: `unattended-upgrades`
    /// is installed, apt's `APT::Periodic` settings run it, and systemd
    /// starts apt's daily jobs (timers active and enabled, services not
    /// masked). Debian and Ubuntu only so far, where it is unknown without
    /// systemd; skipped on other distros.
    AutoUpdates,
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
    /// The kernel has AppArmor enabled. Debian and Ubuntu only so far;
    /// skipped elsewhere and inside a container.
    Apparmor,
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
            (Outcome::Fail { found }, Check::Sysctl { key, one_of }) => {
                Some(format!("{key} is {found}, expected {}", or_list(one_of)))
            }
            (
                Outcome::Fail { found },
                Check::SshRateLimited
                | Check::AutoUpdates
                | Check::InboundDefaultDeny
                | Check::PublishedPorts
                | Check::Apparmor
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
            let outcome = evaluate(&control.check, facts);
            let mut manual_fix = None;
            if matches!(outcome, Outcome::Fail { .. })
                && let Some(m) = sshd_match_override(&control.check, facts)
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
                    } else if let Some(found) = sshd_match_override(check, facts) {
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
        Check::Sysctl { key, one_of } => {
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
                None => Outcome::Unknown {
                    reason: format!("{key} not found under /proc/sys"),
                },
            }
        }
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
                "Docker publishes ports the firewall would otherwise block: {}",
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

/// For an [`Check::SshdEffective`] whose `sshd -T` value passes, the first
/// `Match` block line that sets the keyword to another value.
fn sshd_match_override(check: &Check, facts: &Facts) -> Option<MatchOverride> {
    let Check::SshdEffective { key, equals } = check else {
        return None;
    };
    if facts.ssh.effective.as_ref()?.get(key) != Some(equals.as_str()) {
        return None;
    }
    facts.ssh.match_override(key, equals)
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
                Check::Sysctl { key, one_of } => {
                    assert!(sysctl::KEYS.contains(&key.as_str()), "{}: {key}", c.id);
                    assert!(!one_of.is_empty(), "{}", c.id);
                }
                Check::SshRateLimited => assert!(facts.ssh.fail2ban.is_some(), "{}", c.id),
                Check::AutoUpdates => assert!(facts.updates.is_some(), "{}", c.id),
                Check::InboundDefaultDeny | Check::PublishedPorts => {
                    assert!(facts.firewall.is_some(), "{}", c.id);
                }
                Check::Apparmor => assert!(facts.apparmor.is_some(), "{}", c.id),
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
        // Plus MAC-001 (in a container) and FW-002 (no Docker).
        assert_eq!(report.summary.skipped, sysctl_controls + 2);
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
                found: "Docker publishes ports the firewall would otherwise block: \
                        tcp/5432, tcp/9000-9001"
                    .to_owned()
            }
        );
        // A private address may be a cloud server's primary one, so it counts.
        let mut bound = port("ip", 5432, false);
        bound.address = Some("10.8.0.1".to_owned());
        assert_eq!(
            eval(vec![bound], false),
            Outcome::Fail {
                found: "Docker publishes ports the firewall would otherwise block: \
                        tcp/5432 on 10.8.0.1"
                    .to_owned()
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
        assert_eq!(summary["skipped"], sysctl_controls + 2);
    }
}
