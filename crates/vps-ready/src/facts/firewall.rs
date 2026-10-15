//! The packet filter, from the live nftables ruleset (`nft -j list ruleset`).
//!
//! ufw, firewalld and the `iptables` command (its nft backend, the default on
//! Debian and Ubuntu) all load their rules into nftables, so the ruleset is
//! the one source that shows what is in effect, whichever tool wrote it.
//! Reading it needs root.
//!
//! A chain is judged by what it does to a packet that matches no rule with
//! a condition. Rules that accept only some traffic (`iifname lo`, a port,
//! `meta nfproto ipv4` in an `inet` chain) are assumed to be narrow.

use std::collections::{HashMap, HashSet};
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
    /// Whether a packet that matches no conditional rule is dropped: by a
    /// rule that drops or rejects everything (as firewalld ends its chain),
    /// or by a `drop` policy, and not first accepted by a rule that accepts
    /// everything, also behind a `jump` or `goto`.
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
        // nft's last line is the error that stopped it, e.g. "netlink:
        // Error: cache initialization failed: Operation not permitted".
        let stderr = String::from_utf8_lossy(&out.stderr);
        let reason = stderr
            .lines()
            .map(str::trim)
            .rfind(|l| !l.is_empty())
            .unwrap_or("no error output");
        let mut notice = format!("`nft list ruleset` failed ({reason}); the firewall is unknown");
        if stderr.contains("Operation not permitted") {
            notice.push_str(". Reading the ruleset needs root (CAP_NET_ADMIN)");
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

/// A chain, as `(family, table, name)`.
type ChainKey = (String, String, String);

/// Parses `nft -j list ruleset`: a list of objects, each holding one table,
/// chain or rule. Rules follow their chain, in order.
fn parse(json: &[u8]) -> Option<Firewall> {
    let root: Value = serde_json::from_slice(json).ok()?;
    let objects = root.get("nftables")?.as_array()?;
    let field = |v: &Value, key: &str| v.get(key).and_then(Value::as_str).map(str::to_owned);
    let key = |v: &Value, chain: &str| -> Option<ChainKey> {
        Some((field(v, "family")?, field(v, "table")?, field(v, chain)?))
    };

    // A dormant table's chains are not attached to their hooks.
    let dormant: HashSet<(String, String)> = objects
        .iter()
        .filter_map(|o| o.get("table"))
        .filter(|t| {
            t.get("flags").is_some_and(|f| match f {
                Value::String(s) => s == "dormant",
                Value::Array(a) => a.iter().any(|f| f == "dormant"),
                _ => false,
            })
        })
        .filter_map(|t| Some((field(t, "family")?, field(t, "name")?)))
        .collect();
    let mut rules: HashMap<ChainKey, Vec<&[Value]>> = HashMap::new();
    for rule in objects.iter().filter_map(|o| o.get("rule")) {
        if let (Some(k), Some(expr)) = (key(rule, "chain"), rule.get("expr")?.as_array()) {
            rules.entry(k).or_default().push(expr);
        }
    }

    let mut input_chains = Vec::new();
    for chain in objects.iter().filter_map(|o| o.get("chain")) {
        if field(chain, "hook").as_deref() != Some("input")
            || field(chain, "type").as_deref() != Some("filter")
        {
            continue;
        }
        let k = key(chain, "name")?;
        if dormant.contains(&(k.0.clone(), k.1.clone())) {
            continue;
        }
        let drops_unmatched = match fate(&rules, &k, &mut HashSet::new()) {
            Fate::Accept => false,
            Fate::Drop => true,
            Fate::Continue => field(chain, "policy").as_deref() == Some("drop"),
        };
        let (family, table, name) = k;
        input_chains.push(InputChain {
            family,
            table,
            name,
            drops_unmatched,
        });
    }
    Some(Firewall { input_chains })
}

/// What a chain does to a packet that no conditional rule matches.
#[derive(Debug, PartialEq, Eq)]
enum Fate {
    Accept,
    Drop,
    /// It reaches the end of the chain, or a `return`: a base chain then
    /// applies its policy, a jump goes back to the calling chain.
    Continue,
}

/// Follows such a packet through `chain`: rules that match only some
/// packets are passed over, and the first unconditional verdict decides.
/// `jump` and `goto` are followed (nft rejects loops; `seen` guards anyway).
fn fate(
    rules: &HashMap<ChainKey, Vec<&[Value]>>,
    chain: &ChainKey,
    seen: &mut HashSet<ChainKey>,
) -> Fate {
    if !seen.insert(chain.clone()) {
        return Fate::Continue;
    }
    for expr in rules.get(chain).into_iter().flatten() {
        let target = |t: &str| (chain.0.clone(), chain.1.clone(), t.to_owned());
        match unconditional(expr) {
            Some(Verdict::Accept) => return Fate::Accept,
            Some(Verdict::Drop) => return Fate::Drop,
            Some(Verdict::Return) => return Fate::Continue,
            Some(Verdict::Jump(t)) => match fate(rules, &target(t), seen) {
                Fate::Continue => {}
                decided => return decided,
            },
            // After a goto, falling off the target ends this chain too.
            Some(Verdict::Goto(t)) => return fate(rules, &target(t), seen),
            None => {}
        }
    }
    Fate::Continue
}

/// The verdict of a rule that matches every packet.
#[derive(Debug, PartialEq, Eq)]
enum Verdict<'a> {
    Accept,
    /// `drop` or `reject`.
    Drop,
    Return,
    Jump(&'a str),
    Goto(&'a str),
}

/// The verdict of `expr` if it matches every packet, e.g. `counter drop`:
/// only statements that do not match (`counter`, `log`) before the verdict.
fn unconditional(expr: &[Value]) -> Option<Verdict<'_>> {
    let (verdict, before) = expr.split_last()?;
    if !before
        .iter()
        .all(|s| s.get("counter").is_some() || s.get("log").is_some())
    {
        return None;
    }
    let target = |kind: &str| verdict.get(kind)?.get("target")?.as_str();
    if verdict.get("accept").is_some() {
        Some(Verdict::Accept)
    } else if verdict.get("drop").is_some() || verdict.get("reject").is_some() {
        Some(Verdict::Drop)
    } else if verdict.get("return").is_some() {
        Some(Verdict::Return)
    } else if let Some(t) = target("jump") {
        Some(Verdict::Jump(t))
    } else if let Some(t) = target("goto") {
        Some(Verdict::Goto(t))
    } else {
        // iptables-nft targets nft cannot print, e.g. `-j REJECT`, appear as
        // {"xt": {"type": "target", "name": "REJECT"}}.
        let xt = verdict.get("xt")?;
        match (xt.get("type")?.as_str()?, xt.get("name")?.as_str()?) {
            ("target", "REJECT" | "DROP") => Some(Verdict::Drop),
            ("target", "ACCEPT") => Some(Verdict::Accept),
            _ => None,
        }
    }
}

/// Whether the host has a global IPv6 address, one reachable beyond its
/// own link. In `/proc/net/if_inet6` the fourth field is the scope: `00` is
/// global, while loopback (`10`) and the link-local address every IPv6
/// interface has (`20`) are not.
pub(super) fn has_ipv6(fs: &dyn Fs) -> bool {
    fs.read(Path::new("/proc/net/if_inet6")).is_ok_and(|bytes| {
        String::from_utf8_lossy(&bytes)
            .lines()
            .any(|line| line.split_whitespace().nth(3) == Some("00"))
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
        // `iptables -A INPUT -j REJECT` after a few accepts, on Debian 13:
        // nft prints the reject as an `xt` target.
        assert_eq!(chains(&ruleset("iptables-reject")), [("ip", "INPUT", true)]);
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
            (
                r#"[{"counter": null}, {"drop": null}]"#,
                Some(Verdict::Drop),
            ),
            (r#"[{"reject": {"type": "icmpx"}}]"#, Some(Verdict::Drop)),
            (r#"[{"accept": null}]"#, Some(Verdict::Accept)),
            (r#"[{"return": null}]"#, Some(Verdict::Return)),
            (r#"[{"jump": {"target": "x"}}]"#, Some(Verdict::Jump("x"))),
            (r#"[{"goto": {"target": "x"}}]"#, Some(Verdict::Goto("x"))),
            // `iptables -A INPUT -j REJECT` as nft prints it.
            (
                r#"[{"counter": null}, {"xt": {"type": "target", "name": "REJECT"}}]"#,
                Some(Verdict::Drop),
            ),
            (r#"[{"xt": {"type": "target", "name": "LOG"}}]"#, None),
            (
                r#"[{"xt": {"type": "match", "name": "limit"}}, {"accept": null}]"#,
                None,
            ),
            (
                r#"[{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}, {"accept": null}]"#,
                None,
            ),
            ("[]", None),
        ];
        for (json, want) in cases {
            assert_eq!(unconditional(&expr(json)), want, "{json}");
        }
    }

    /// An `inet` table `t` with an input chain `in` (policy `policy`) and
    /// `chains`, each `(name, [rule expr JSON])`.
    fn ruleset_of(policy: &str, table_flags: &str, chains: &[(&str, &[&str])]) -> Firewall {
        let mut objects = vec![
            format!(r#"{{"table": {{"family": "inet", "name": "t"{table_flags}}}}}"#),
            format!(
                r#"{{"chain": {{"family": "inet", "table": "t", "name": "in", "type": "filter", "hook": "input", "policy": "{policy}"}}}}"#
            ),
        ];
        for (name, rules) in chains {
            if *name != "in" {
                objects.push(format!(
                    r#"{{"chain": {{"family": "inet", "table": "t", "name": "{name}"}}}}"#
                ));
            }
            for expr in *rules {
                objects.push(format!(
                    r#"{{"rule": {{"family": "inet", "table": "t", "chain": "{name}", "expr": {expr}}}}}"#
                ));
            }
        }
        let json = format!(r#"{{"nftables": [{}]}}"#, objects.join(","));
        parse(json.as_bytes()).unwrap()
    }

    #[test]
    fn follows_the_path_of_an_unmatched_packet() {
        let drops = |policy, chains: &[(&str, &[&str])]| {
            ruleset_of(policy, "", chains).input_chains[0].drops_unmatched
        };
        let accept = r#"[{"counter": null}, {"accept": null}]"#;
        let drop = r#"[{"drop": null}]"#;
        let lo = r#"[{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}, {"accept": null}]"#;
        let goto_open = r#"[{"goto": {"target": "open"}}]"#;
        let jump_open = r#"[{"jump": {"target": "open"}}]"#;
        let jump_empty = r#"[{"jump": {"target": "empty"}}]"#;
        let ret = r#"[{"return": null}]"#;

        assert!(drops("drop", &[("in", &[lo])]));
        assert!(!drops("accept", &[("in", &[lo])]));
        // A rule that accepts everything opens a chain whatever its policy.
        assert!(!drops("drop", &[("in", &[accept])]));
        // The first unconditional verdict decides, last rule or not.
        assert!(drops("accept", &[("in", &[drop, accept])]));
        // ...also behind a jump or goto.
        assert!(!drops("drop", &[("in", &[goto_open]), ("open", &[accept])]));
        assert!(!drops(
            "drop",
            &[("in", &[jump_open]), ("open", &[lo, accept])]
        ));
        assert!(drops("accept", &[("in", &[jump_open]), ("open", &[drop])]));
        // A jump that falls through or returns continues the caller.
        assert!(drops("drop", &[("in", &[jump_empty]), ("empty", &[lo])]));
        assert!(drops(
            "accept",
            &[("in", &[jump_open, drop]), ("open", &[ret, accept])]
        ));
        // A goto that falls through ends the base chain: its policy decides.
        assert!(!drops(
            "accept",
            &[("in", &[goto_open, drop]), ("open", &[lo])]
        ));
    }

    #[test]
    fn dormant_tables_are_ignored() {
        let chains: &[(&str, &[&str])] = &[("in", &[])];
        assert_eq!(ruleset_of("drop", "", chains).input_chains.len(), 1);
        for flags in [r#", "flags": "dormant""#, r#", "flags": ["dormant"]"#] {
            assert_eq!(ruleset_of("drop", flags, chains).input_chains, []);
        }
    }

    #[test]
    fn unrecognized_output_is_none() {
        for json in ["", "{}", r#"{"nftables": {}}"#, "[1, 2]"] {
            assert_eq!(parse(json.as_bytes()), None, "{json:?}");
        }
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
        assert!(
            notices[0].ends_with("needs root (CAP_NET_ADMIN)"),
            "{notices:?}"
        );
    }

    #[test]
    fn ipv6_needs_a_global_address() {
        let lo = "00000000000000000000000000000001 01 80 10 80       lo\n";
        let link = "fe80000000000000021122fffe334455 02 40 20 80     eth0\n";
        let global = "20010db8000000000000000000000001 02 40 00 80     eth0\n";
        let fs = |text: &str| FakeFs::new().with_file("/proc/net/if_inet6", text.to_owned());
        assert!(!has_ipv6(&FakeFs::new()));
        assert!(!has_ipv6(&fs(&format!("{lo}{link}"))));
        assert!(has_ipv6(&fs(&format!("{lo}{link}{global}"))));
    }
}
