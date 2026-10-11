//! Checks the host against the controls catalog.
//!
//! Controls are data, not code: each file in `controls/` lists controls whose
//! [`Check`] comes from a closed vocabulary, so the policy can be reviewed
//! without reading Rust. The files are embedded at build time and a unit test
//! parses every one, so a typo fails CI instead of a user's audit.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::facts::Facts;

/// The embedded catalog, as `(file name, contents)`.
const CATALOG: [(&str, &str); 3] = [
    ("ssh.toml", include_str!("controls/ssh.toml")),
    ("kernel.toml", include_str!("controls/kernel.toml")),
    ("network.toml", include_str!("controls/network.toml")),
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
}

/// The result of checking one control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum Outcome {
    /// The host meets the control.
    Pass,
    /// The host does not meet the control.
    Fail {
        /// The value found on the host.
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
    /// Every notice from fact collection. Those about SSH explain unknown
    /// outcomes; the rest concern facts no control uses yet.
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
    }
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
    use crate::facts::{SshdConfig, Virt, sysctl};
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
        let config = facts.ssh.effective.unwrap();
        for c in catalog().unwrap() {
            match &c.check {
                Check::SshdEffective { key, .. } => {
                    assert!(config.get(key).is_some(), "{}: {key}", c.id);
                }
                Check::Sysctl { key, one_of } => {
                    assert!(sysctl::KEYS.contains(&key.as_str()), "{}: {key}", c.id);
                    assert!(!one_of.is_empty(), "{}", c.id);
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
        let report = run(catalog().unwrap(), &facts);
        let sysctl_controls = report
            .findings
            .iter()
            .filter(|f| matches!(f.control.check, Check::Sysctl { .. }))
            .count();
        assert!(sysctl_controls > 0);
        assert_eq!(report.summary.skipped, sysctl_controls);
        assert!(report.all_passed(), "{:?}", report.summary);
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
        assert_eq!(summary["skipped"], sysctl_controls);
    }
}
