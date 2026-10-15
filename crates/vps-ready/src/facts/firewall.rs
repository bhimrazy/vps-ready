//! The packet filter, from the live nftables ruleset (`nft -j list ruleset`).
//!
//! ufw, firewalld and the `iptables` command (its nft backend, the default on
//! Debian and Ubuntu) all load their rules into nftables, so the ruleset is
//! the one source that shows what is in effect, whichever tool wrote it.
//! Reading it needs root.

use std::path::Path;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use super::{Probe, probe};
use crate::sys::{Cmd, Fs, Runner};

/// What `vps-ready` knows about the packet filter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Firewall {
    /// Filter chains on the input hook, in ruleset order. Every incoming
    /// packet passes each of them.
    pub input_chains: Vec<InputChain>,
}

/// A base chain that filters incoming packets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InputChain {
    /// `ip` (IPv4), `ip6` or `inet` (both).
    pub family: String,
    /// Table name, e.g. `filter` (ufw) or `firewalld`.
    pub table: String,
    /// Chain name, e.g. `INPUT`.
    pub name: String,
    /// Whether packets no rule accepted are dropped: by a `drop` policy, or
    /// by a last rule that drops or rejects everything, as firewalld does.
    pub drops_unmatched: bool,
}

impl InputChain {
    /// Whether the chain sees IPv4 (`ipv6 == false`) or IPv6 packets.
    #[must_use]
    pub fn covers(&self, ipv6: bool) -> bool {
        self.family == "inet" || self.family == if ipv6 { "ip6" } else { "ip" }
    }
}

pub(super) fn detect(runner: &dyn Runner, notices: &mut Vec<String>) -> Option<Firewall> {
    let cmd = Cmd::new("nft")
        .args(["-j", "list", "ruleset"])
        .timeout(Duration::from_secs(10));
    let out = match probe(runner, &cmd, notices) {
        Probe::Ran(out) => out,
        Probe::Missing => {
            notices.push("nft not found; the firewall is unknown".to_owned());
            return None;
        }
        Probe::Failed => return None,
    };
    if !out.ok() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let reason = stderr
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("no error output");
        let mut notice = format!("`nft list ruleset` failed ({reason}); the firewall is unknown");
        if stderr.contains("Operation not permitted") {
            notice.push_str(". Reading the ruleset needs root");
        }
        notices.push(notice);
        return None;
    }
    let parsed = parse(&out.stdout);
    if parsed.is_none() {
        notices.push("unrecognized `nft -j` output; the firewall is unknown".to_owned());
    }
    parsed
}

/// Parses `nft -j list ruleset`: a list of objects, each holding one table,
/// chain or rule. Rules follow their chain, in order.
fn parse(json: &[u8]) -> Option<Firewall> {
    let root: Value = serde_json::from_slice(json).ok()?;
    let objects = root.get("nftables")?.as_array()?;
    let field = |v: &Value, key: &str| v.get(key).and_then(Value::as_str).map(str::to_owned);
    let mut input_chains = Vec::new();
    for chain in objects.iter().filter_map(|o| o.get("chain")) {
        if field(chain, "hook").as_deref() != Some("input")
            || field(chain, "type").as_deref() != Some("filter")
        {
            continue;
        }
        let (family, table, name) = (
            field(chain, "family")?,
            field(chain, "table")?,
            field(chain, "name")?,
        );
        let rules: Vec<&[Value]> = objects
            .iter()
            .filter_map(|o| o.get("rule"))
            .filter(|r| {
                field(r, "family").as_ref() == Some(&family)
                    && field(r, "table").as_ref() == Some(&table)
                    && field(r, "chain").as_ref() == Some(&name)
            })
            .filter_map(|r| r.get("expr")?.as_array().map(Vec::as_slice))
            .collect();
        // A rule that accepts everything ends the chain for every packet,
        // whatever the policy.
        let accepts_all = rules.iter().any(|r| unconditional(r) == Some("accept"));
        let drops_unmatched = !accepts_all
            && (field(chain, "policy").as_deref() == Some("drop")
                || rules
                    .last()
                    .is_some_and(|r| matches!(unconditional(r), Some("drop" | "reject"))));
        input_chains.push(InputChain {
            family,
            table,
            name,
            drops_unmatched,
        });
    }
    Some(Firewall { input_chains })
}

/// The verdict of a rule that matches every packet, e.g. `counter drop`:
/// only statements that do not match (`counter`, `log`) before the verdict.
fn unconditional(expr: &[Value]) -> Option<&'static str> {
    let (verdict, before) = expr.split_last()?;
    if !before
        .iter()
        .all(|s| s.get("counter").is_some() || s.get("log").is_some())
    {
        return None;
    }
    ["accept", "drop", "reject"]
        .into_iter()
        .find(|v| verdict.get(v).is_some())
}

/// Whether the host has an IPv6 address other than loopback. The last field
/// of each `/proc/net/if_inet6` line is the interface.
pub(super) fn has_ipv6(fs: &dyn Fs) -> bool {
    fs.read(Path::new("/proc/net/if_inet6")).is_ok_and(|bytes| {
        String::from_utf8_lossy(&bytes)
            .lines()
            .filter_map(|line| line.split_whitespace().last())
            .any(|iface| iface != "lo")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::fixtures::testdata;
    use crate::sys::Output;
    use crate::sys::fake::{FakeFs, FakeRunner};

    /// Rulesets captured from real hosts with `nft -j list ruleset`.
    fn ruleset(name: &str) -> Firewall {
        let json = std::fs::read(testdata(&format!("nft/{name}.json"))).unwrap();
        parse(&json).unwrap()
    }

    fn chains(fw: &Firewall) -> Vec<(&str, &str, bool)> {
        fw.input_chains
            .iter()
            .map(|c| (c.family.as_str(), c.name.as_str(), c.drops_unmatched))
            .collect()
    }

    #[test]
    fn reads_real_rulesets() {
        // `ufw enable` on Ubuntu 24.04: iptables-nft chains with a drop policy.
        assert_eq!(
            chains(&ruleset("ufw-enabled")),
            [("ip", "INPUT", true), ("ip6", "INPUT", true)]
        );
        // Installed but not enabled: nothing loaded.
        assert_eq!(chains(&ruleset("ufw-disabled")), []);
        // Debian's /etc/nftables.conf: an empty chain that accepts.
        assert_eq!(
            chains(&ruleset("debian-nftables-conf")),
            [("inet", "input", false)]
        );
        // firewalld's chain accepts by policy but ends with a reject.
        assert_eq!(
            chains(&ruleset("firewalld")),
            [("inet", "filter_INPUT", true)]
        );
    }

    #[test]
    fn verdicts_of_rules() {
        let expr = |json: &str| serde_json::from_str::<Vec<Value>>(json).unwrap();
        let cases = [
            (r#"[{"counter": null}, {"drop": null}]"#, Some("drop")),
            (r#"[{"reject": {"type": "icmpx"}}]"#, Some("reject")),
            (r#"[{"accept": null}]"#, Some("accept")),
            (
                r#"[{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}, {"accept": null}]"#,
                None,
            ),
            (r#"[{"jump": {"target": "x"}}]"#, None),
            ("[]", None),
        ];
        for (json, want) in cases {
            assert_eq!(unconditional(&expr(json)), want, "{json}");
        }
    }

    #[test]
    fn accept_all_rule_opens_a_drop_chain() {
        let json = br#"{"nftables": [
            {"chain": {"family": "inet", "table": "t", "name": "in", "type": "filter", "hook": "input", "policy": "drop"}},
            {"rule": {"family": "inet", "table": "t", "chain": "in", "expr": [{"counter": null}, {"accept": null}]}}
        ]}"#;
        assert_eq!(chains(&parse(json).unwrap()), [("inet", "in", false)]);
    }

    #[test]
    fn needs_root() {
        let runner = FakeRunner::new().on(
            "nft",
            ["-j"],
            Output {
                status: 1,
                stderr: b"Operation not permitted (you must be root)\n".to_vec(),
                ..Output::success("")
            },
        );
        let mut notices = Vec::new();
        assert_eq!(detect(&runner, &mut notices), None);
        assert!(notices[0].ends_with("needs root"), "{notices:?}");
    }

    #[test]
    fn ipv6_ignores_loopback() {
        let lo = "00000000000000000000000000000001 01 80 10 80       lo\n";
        let eth = "20010db8000000000000000000000001 02 40 00 80     eth0\n";
        let fs = |text: &str| FakeFs::new().with_file("/proc/net/if_inet6", text.to_owned());
        assert!(!has_ipv6(&FakeFs::new()));
        assert!(!has_ipv6(&fs(lo)));
        assert!(has_ipv6(&fs(&format!("{lo}{eth}"))));
    }
}
