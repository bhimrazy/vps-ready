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
const CATALOG: [(&str, &str); 1] = [("ssh.toml", include_str!("controls/ssh.toml"))];

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
    /// A keyword of the effective sshd config (`sshd -T`) has this value.
    SshdEffective {
        /// Keyword in lowercase, as `sshd -T` prints it.
        key: String,
        /// Expected value.
        equals: String,
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
    /// A one-line explanation of a failed or unknown outcome, e.g.
    /// `passwordauthentication is yes, expected no`.
    #[must_use]
    pub fn detail(&self) -> Option<String> {
        match (&self.outcome, &self.control.check) {
            (Outcome::Pass, _) => None,
            (Outcome::Fail { found }, Check::SshdEffective { key, equals }) => {
                Some(format!("{key} is {found}, expected {equals}"))
            }
            (Outcome::Unknown { reason }, _) => Some(reason.clone()),
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
}

/// The result of an audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// One finding per control, in catalog order.
    pub findings: Vec<Finding>,
    /// Counts of outcomes.
    pub summary: Summary,
    /// Notes about facts that could not be determined; they explain unknown
    /// outcomes.
    pub notices: Vec<String>,
}

impl Report {
    /// Whether every control passed. Unknown outcomes do not count as passed.
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
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::facts::SshdConfig;
    use crate::facts::fixtures::{HOSTS, host};

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

    /// A key that `sshd -T` never prints would make a control permanently
    /// unknown, so every key must appear in a real capture.
    #[test]
    fn sshd_keys_exist_in_real_sshd_output() {
        let facts = host("ubuntu-24.04", &[]);
        let config = facts.ssh.effective.unwrap();
        for c in catalog().unwrap() {
            let Check::SshdEffective { key, .. } = &c.check;
            assert!(config.get(key).is_some(), "{}: {key}", c.id);
        }
    }

    #[test]
    fn unknown_kind_and_fields_are_rejected() {
        let parse = |check: &str| {
            toml::from_str::<Control>(&format!(
                "id = \"X-001\"\nseverity = \"low\"\ntitle = \"t\"\nwhy = \"w\"\ncheck = {check}"
            ))
        };
        assert!(parse(r#"{ kind = "sshd_effective", key = "port", equals = "22" }"#).is_ok());
        assert!(parse(r#"{ kind = "sshd_whatever", key = "port", equals = "22" }"#).is_err());
        assert!(parse(r#"{ kind = "sshd_effective", key = "port", equal = "22" }"#).is_err());
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
        assert_eq!(report.summary.unknown, report.findings.len());
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

    #[test]
    fn report_json_flattens_control_and_outcome() {
        let report = run(catalog().unwrap(), &host("debian-12", &[]));
        let json = serde_json::to_value(&report.findings[1]).unwrap();
        assert_eq!(json["id"], "SSH-002");
        assert_eq!(json["status"], "fail");
        assert_eq!(json["found"], "yes");
        assert_eq!(json["check"]["kind"], "sshd_effective");
    }
}
