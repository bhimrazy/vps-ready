//! Checks the host against the controls catalog.
//!
//! Controls are data, not code: each file in `controls/` lists controls whose
//! [`Check`] comes from a closed vocabulary, so the policy can be reviewed
//! without reading Rust. The files are embedded at build time and a unit test
//! parses every one, so a typo fails CI instead of a user's audit.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::facts::{AptUpdates, Facts, Firewall, OsFamily};

/// The embedded catalog, as `(file name, contents)`.
const CATALOG: [(&str, &str); 5] = [
    ("ssh.toml", include_str!("controls/ssh.toml")),
    ("kernel.toml", include_str!("controls/kernel.toml")),
    ("network.toml", include_str!("controls/network.toml")),
    ("updates.toml", include_str!("controls/updates.toml")),
    ("firewall.toml", include_str!("controls/firewall.toml")),
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
}

/// How much a failed control matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
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
    /// A keyword of the effective sshd config (`sshd -T`) has this value.
    SshdEffective {
        /// Keyword in lowercase, as `sshd -T` prints it.
        key: String,
        /// Expected value.
        equals: String,
    },
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
                Check::AutoUpdates | Check::InboundDefaultDeny | Check::PublishedPorts,
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
        .map(|control| {
            let outcome = evaluate(&control.check, facts);
            match outcome {
                Outcome::Pass => summary.passed += 1,
                Outcome::Fail { .. } => summary.failed += 1,
                Outcome::Unknown { .. } => summary.unknown += 1,
                Outcome::Skip { .. } => summary.skipped += 1,
            }
            Finding { control, outcome }
        })
        .collect();
    Report {
        findings,
        summary,
        notices: facts.notices.clone(),
    }
}

fn evaluate(check: &Check, facts: &Facts) -> Outcome {
    match check {
        Check::SshdEffective { key, equals } => {
            let Some(config) = &facts.ssh.effective else {
                return Outcome::Unknown {
                    reason: "effective SSH config is unknown".to_owned(),
                };
            };
            match config.get(key) {
                Some(found) if found == equals => Outcome::Pass,
                Some(found) => Outcome::Fail {
                    found: found.to_owned(),
                },
                None => Outcome::Unknown {
                    reason: format!("`sshd -T` did not print {key}"),
                },
            }
        }
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
        Check::PublishedPorts => match &facts.firewall {
            Some(firewall) => published_ports(firewall, facts.ipv6, facts.docker),
            None if facts.docker => Outcome::Unknown {
                reason: "the firewall ruleset could not be read".to_owned(),
            },
            None => docker_absent(),
        },
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
    if firewall.input_chains.is_empty() {
        return Outcome::Fail {
            found: "no firewall rules filter incoming traffic".to_owned(),
        };
    }
    let drops = |v6: bool| {
        firewall
            .input_chains
            .iter()
            .any(|c| c.covers(v6) && c.drops_unmatched)
    };
    let open: Vec<&str> = [(false, "IPv4"), (true, "IPv6")]
        .into_iter()
        .filter(|&(v6, _)| (!v6 || ipv6) && !drops(v6))
        .map(|(_, name)| name)
        .collect();
    if open.is_empty() {
        Outcome::Pass
    } else {
        Outcome::Fail {
            found: format!(
                "incoming {} traffic that no rule allows is accepted",
                open.join(" and ")
            ),
        }
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
                Check::AutoUpdates => assert!(facts.updates.is_some(), "{}", c.id),
                Check::InboundDefaultDeny | Check::PublishedPorts => {
                    assert!(facts.firewall.is_some(), "{}", c.id);
                }
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
        assert!(parse("fix = \"x\"", valid).is_err());
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
            .filter(|f| matches!(f.control.check, Check::SshdEffective { .. }))
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

    /// Kernel settings belong to the host, so in a container they are
    /// skipped, and skipping does not fail the audit.
    #[test]
    fn container_skips_kernel_controls_without_failing() {
        let mut facts = host("debian-13", &["sshd-T-dropin-00"]);
        facts.ssh.effective = Some(SshdConfig::parse(
            "permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\n\
             permitemptypasswords no\nx11forwarding no\n",
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
            .filter(|f| matches!(f.control.check, Check::Sysctl { .. }))
            .count();
        assert!(sysctl_controls > 0);
        // And FW-002: the fixture has no Docker.
        assert_eq!(report.summary.skipped, sysctl_controls + 1);
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
        });
        assert!(matches!(
            evaluate(&Check::PublishedPorts, &facts),
            Outcome::Unknown { .. }
        ));

        // No input chain drops by default: FW-001 reports it, not FW-002.
        facts.firewall = Some(Firewall {
            input_chains: vec![],
            published: vec![port("ip", 5432, false)],
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
            .filter(|f| matches!(f.control.check, Check::Sysctl { .. }))
            .count();
        let summary = serde_json::to_value(report.summary).unwrap();
        assert_eq!(summary["skipped"], sysctl_controls + 1);
    }
}
