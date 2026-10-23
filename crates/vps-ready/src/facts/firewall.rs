//! The packet filter, from the live nftables ruleset (`nft -j list ruleset`).
//!
//! ufw, firewalld and the `iptables` command (its nft backend, the default on
//! Debian and Ubuntu) all load their rules into nftables, so the ruleset is
//! the one source that shows what is in effect, whichever tool wrote it.
//! Reading it needs root.
//!
//! A chain is judged by what it does to a packet that matches no rule with
//! a condition. Rules that accept only some traffic (`iifname lo`, a port,
//! `meta nfproto ipv4` in an `inet` chain) are assumed to be narrow. Rules
//! that `return` only some traffic are not: ufw returns every packet for a
//! local address before the `drop` that ends `ufw-not-local`.
//!
//! Both guesses can be wrong. An accept for a whole interface (firewalld's
//! `iifname eth0 goto filter_IN_trusted`) is taken as narrow, so the chain
//! may pass while that interface is open. A narrow return (`iifname lo
//! return` before a `drop`) is taken as wide, so under an `accept` policy
//! the chain fails though it drops everything else.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
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
    /// Container ports Docker publishes beyond loopback and link-local
    /// addresses. Their traffic is forwarded to the container, so input
    /// chains do not see it.
    pub published: Vec<PublishedPort>,
}

/// A port Docker forwards to a container, from a DNAT rule in its `nat`
/// table (iptables backend) or `docker-bridges` table (nftables backend).
/// Ports published only on a loopback or link-local address are left out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublishedPort {
    /// `ip` (IPv4) or `ip6`.
    pub family: String,
    /// `tcp`, `udp` or `sctp`.
    pub proto: String,
    /// Port on the host.
    pub port: u16,
    /// The host address it is bound to (`-p 10.8.0.1:5432:5432`); `None`
    /// for all addresses. A private address can still be reachable, e.g.
    /// a cloud server's primary address behind its provider's NAT.
    pub address: Option<String>,
    /// Whether the user's own rules may filter it: a rule in `DOCKER-USER`
    /// (iptables backend), or a forward chain outside Docker's tables
    /// (nftables backend; a forwarded packet passes every forward chain).
    pub filtered: bool,
}

/// A protocol and port range, e.g. `tcp/443` or `udp/60000-61000`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ports {
    /// `tcp`, `udp` or `sctp`.
    pub proto: String,
    /// First port.
    pub first: u16,
    /// Last port, equal to `first` for a single port.
    pub last: u16,
}

impl Ports {
    fn contains(&self, proto: &str, port: u16) -> bool {
        self.proto == proto && (self.first..=self.last).contains(&port)
    }
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
    /// Ports it accepts from any source on any interface: rules that match
    /// only ports, protocol or connection state (`ufw allow 443/tcp`), in
    /// this chain or one it reaches through such rules.
    pub open_ports: Vec<Ports>,
    /// Ports it accepts that way only on some input interfaces (`ufw allow
    /// in on wg0 to any port 5432`). Whether that is the public interface
    /// is not known, so they may be open.
    pub interface_ports: Vec<Ports>,
    /// Protocols with such a rule whose ports nft does not show (iptables
    /// `multiport`, as ufw writes `allow 80,443/tcp`): any of their ports
    /// may be open.
    pub unread_ports: Vec<String>,
}

impl InputChain {
    /// Whether the chain sees IPv4 (`ipv6 == false`) or IPv6 packets.
    #[must_use]
    pub fn covers(&self, ipv6: bool) -> bool {
        self.family == "inet" || self.family == if ipv6 { "ip6" } else { "ip" }
    }

    /// Whether the chain drops packets to `port`: it drops by default and
    /// does not open the port. `None` when it may open it on some interface
    /// only, or by a rule whose ports nft does not show.
    #[must_use]
    pub fn blocks(&self, proto: &str, port: u16) -> Option<bool> {
        if !self.drops_unmatched || self.open_ports.iter().any(|p| p.contains(proto, port)) {
            Some(false)
        } else if self.unread_ports.iter().any(|p| p == proto)
            || self.interface_ports.iter().any(|p| p.contains(proto, port))
        {
            None
        } else {
            Some(true)
        }
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

    let mut memo = HashMap::new();
    let mut input_chains = Vec::new();
    // Families of the forward filter chains outside Docker's nftables table.
    let mut user_forward = Vec::new();
    for chain in objects.iter().filter_map(|o| o.get("chain")) {
        if field(chain, "type").as_deref() != Some("filter") {
            continue;
        }
        let k = key(chain, "name")?;
        if dormant.contains(&(k.0.clone(), k.1.clone())) {
            continue;
        }
        match field(chain, "hook").as_deref() {
            Some("input") => {}
            Some("forward") if k.1 != DOCKER_NFT_TABLE => {
                user_forward.push(k.0);
                continue;
            }
            _ => continue,
        }
        let fate = fate(&rules, &k, &mut memo);
        let drops_unmatched =
            !fate.accept && (!fate.cont || field(chain, "policy").as_deref() == Some("drop"));
        let mut open = OpenPorts::default();
        collect_open_ports(&rules, &k, false, &mut HashSet::new(), &mut memo, &mut open);
        let (family, table, name) = k;
        input_chains.push(InputChain {
            family,
            table,
            name,
            drops_unmatched,
            open_ports: open.any,
            interface_ports: open.by_interface,
            unread_ports: open.unread,
        });
    }
    let published = published(&rules, &user_forward);
    Some(Firewall {
        input_chains,
        published,
    })
}

/// The table of Docker's nftables firewall backend.
const DOCKER_NFT_TABLE: &str = "docker-bridges";

/// Ports Docker publishes beyond loopback and link-local, from the DNAT
/// rules in its `nat` chain `DOCKER` (iptables backend) or
/// `nat-prerouting-and-output` (nftables backend). `user_forward` lists
/// the families of the forward filter chains outside Docker's tables.
/// Swarm's ingress (`DOCKER-INGRESS`) is not read.
fn published(
    rules: &HashMap<ChainKey, Vec<&[Value]>>,
    user_forward: &[String],
) -> Vec<PublishedPort> {
    let mut out: Vec<PublishedPort> = Vec::new();
    for family in ["ip", "ip6"] {
        let chain =
            |table: &str, name: &str| (family.to_owned(), table.to_owned(), name.to_owned());
        // Older Docker versions put an unconditional `return` in DOCKER-USER.
        let docker_user = rules
            .get(&chain("filter", "DOCKER-USER"))
            .into_iter()
            .flatten()
            .any(|expr| !(matches_all(expr) && verdict(expr) == Some(Verdict::Return)));
        let nft_user = user_forward.iter().any(|f| f == family || f == "inet");
        let nat = [
            (chain("nat", "DOCKER"), docker_user),
            (
                chain(DOCKER_NFT_TABLE, "nat-prerouting-and-output"),
                nft_user,
            ),
        ];
        for (key, filtered) in nat {
            for expr in rules.get(&key).into_iter().flatten() {
                let dnat = expr.iter().any(|s| {
                    s.get("dnat").is_some()
                        || s.get("xt").is_some_and(|xt| {
                            xt.get("type").and_then(Value::as_str) == Some("target")
                                && xt.get("name").and_then(Value::as_str) == Some("DNAT")
                        })
                });
                let address = expr.iter().find_map(daddr);
                if !dnat || address.as_ref().is_some_and(|&(_, local)| local) {
                    continue;
                }
                let address = address.map(|(a, _)| a);
                for ports in expr
                    .iter()
                    .filter_map(|s| s.get("match"))
                    .filter_map(dports)
                {
                    for p in ports {
                        for port in p.first..=p.last {
                            let found = PublishedPort {
                                family: family.to_owned(),
                                proto: p.proto.clone(),
                                port,
                                address: address.clone(),
                                filtered,
                            };
                            if !out.contains(&found) {
                                out.push(found);
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// The destination address `stmt` requires (`ip daddr 10.8.0.1`), and
/// whether it is loopback or link-local, which the internet cannot reach.
fn daddr(stmt: &Value) -> Option<(String, bool)> {
    let m = stmt.get("match")?;
    if m.get("op")?.as_str()? != "=="
        || m.get("left")?.get("payload")?.get("field")?.as_str()? != "daddr"
    {
        return None;
    }
    let right = m.get("right")?;
    let addr = right
        .as_str()
        .or_else(|| right.get("prefix")?.get("addr")?.as_str())?;
    let local = match addr.parse::<IpAddr>().ok()? {
        IpAddr::V4(a) => a.is_loopback() || a.is_link_local(),
        IpAddr::V6(a) => a.is_loopback() || a.is_unicast_link_local(),
    };
    Some((addr.to_owned(), local))
}

/// The ports of a `tcp dport 443` match, also a set or range of ports.
/// `th dport` (any transport header) matches TCP and UDP.
fn dports(m: &Value) -> Option<Vec<Ports>> {
    if m.get("op").and_then(Value::as_str) != Some("==") {
        return None;
    }
    let payload = m.get("left")?.get("payload")?;
    if payload.get("field")?.as_str()? != "dport" {
        return None;
    }
    let protos: &[&str] = match payload.get("protocol")?.as_str()? {
        "th" => &["tcp", "udp"],
        p @ ("tcp" | "udp" | "sctp") => &[p],
        _ => return None,
    };
    let range = |v: &Value| -> Option<(u16, u16)> {
        if let Some(n) = v.as_u64() {
            let n = u16::try_from(n).ok()?;
            return Some((n, n));
        }
        let r = v.get("range")?.as_array()?;
        Some((
            u16::try_from(r.first()?.as_u64()?).ok()?,
            u16::try_from(r.get(1)?.as_u64()?).ok()?,
        ))
    };
    let right = m.get("right")?;
    let ranges: Vec<(u16, u16)> = match right.get("set").and_then(Value::as_array) {
        Some(set) => set.iter().map(range).collect::<Option<_>>()?,
        None => vec![range(right)?],
    };
    Some(
        protos
            .iter()
            .flat_map(|proto| {
                ranges.iter().map(|&(first, last)| Ports {
                    proto: (*proto).to_owned(),
                    first,
                    last,
                })
            })
            .collect(),
    )
}

/// What input chains accept from any source; see [`InputChain`].
#[derive(Default)]
struct OpenPorts {
    any: Vec<Ports>,
    by_interface: Vec<Ports>,
    unread: Vec<String>,
}

/// Adds what `chain` opens to any source. A `jump` or `goto` is followed
/// only if its rule is narrow too; if that rule also matches ports, they
/// are open when the target accepts everything (as `ufw limit` does).
/// `scoped` is set below a jump that matched an input interface.
fn collect_open_ports(
    rules: &HashMap<ChainKey, Vec<&[Value]>>,
    chain: &ChainKey,
    scoped: bool,
    seen: &mut HashSet<(ChainKey, bool)>,
    memo: &mut HashMap<ChainKey, Option<Fate>>,
    out: &mut OpenPorts,
) {
    // Per scope: firewalld jumps to a zone with `iifname`, then without.
    if !seen.insert((chain.clone(), scoped)) {
        return;
    }
    for expr in rules.get(chain).into_iter().flatten() {
        let (Some(v), Some((_, before))) = (verdict(expr), expr.split_last()) else {
            continue;
        };
        let Some(rule) = narrow(before) else {
            continue;
        };
        let scoped = scoped || rule.interface;
        let opens = match v {
            Verdict::Accept => true,
            Verdict::Jump(t) | Verdict::Goto(t) => {
                let target = (chain.0.clone(), chain.1.clone(), t.to_owned());
                if rule.ports.is_empty() && rule.unread.is_empty() {
                    collect_open_ports(rules, &target, scoped, seen, memo, out);
                    false
                } else {
                    fate(rules, &target, memo) == Fate::ACCEPT
                }
            }
            _ => false,
        };
        if opens {
            if scoped {
                &mut out.by_interface
            } else {
                &mut out.any
            }
            .extend(rule.ports);
            out.unread.extend(rule.unread);
        }
    }
}

/// A rule whose matches all still admit any source.
struct Narrow {
    /// The ports it matches; empty if it matches no port.
    ports: Vec<Ports>,
    /// Protocols of an iptables `multiport` match (ufw's `allow
    /// 80,443/tcp`), whose ports nft does not show.
    unread: Vec<String>,
    /// Whether it matches an input interface.
    interface: bool,
}

/// The rule given the statements `before` its verdict, if each is a port,
/// protocol, connection state or input interface match, a counter or a
/// log. iptables-nft shows `-m conntrack` and `-m multiport` as `xt`.
fn narrow(before: &[Value]) -> Option<Narrow> {
    let mut ports = Vec::new();
    let mut proto = None;
    let mut multiport = false;
    let mut interface = false;
    for s in before {
        if s.get("counter").is_some() || s.get("log").is_some() {
            continue;
        }
        if let Some(xt) = s.get("xt") {
            if xt.get("type").and_then(Value::as_str) != Some("match") {
                return None;
            }
            match xt.get("name").and_then(Value::as_str) {
                Some("multiport") => multiport = true,
                Some("conntrack") => {}
                _ => return None,
            }
            continue;
        }
        let m = s.get("match")?;
        if let Some(p) = dports(m) {
            ports.extend(p);
            continue;
        }
        let left = m.get("left")?;
        let key = |kind: &str| left.get(kind)?.get("key")?.as_str();
        let field = left
            .get("payload")
            .and_then(|p| p.get("field"))
            .and_then(Value::as_str);
        match (key("meta"), key("ct"), field) {
            // `meta l4proto tcp`, `ip protocol tcp`, `ip6 nexthdr tcp`.
            (Some("l4proto"), ..) | (_, _, Some("protocol" | "nexthdr")) => {
                proto = m.get("right").and_then(Value::as_str);
            }
            (Some("iifname" | "iif"), ..) => interface = true,
            (Some("nfproto"), ..) | (_, Some("state"), _) => {}
            _ => return None,
        }
    }
    let unread = match (multiport, proto) {
        (false, _) => Vec::new(),
        (true, Some(p)) => vec![p.to_owned()],
        (true, None) => ["tcp", "udp", "sctp"].map(str::to_owned).to_vec(),
    };
    Some(Narrow {
        ports,
        unread,
        interface,
    })
}

/// What a chain can do to a packet that no conditional rule matches. More
/// than one is possible when a conditional `return` lets some packets out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Fate {
    accept: bool,
    drop: bool,
    /// It reaches the end of the chain, or a `return`: a base chain then
    /// applies its policy, a jump goes back to the calling chain.
    cont: bool,
}

impl Fate {
    const ACCEPT: Self = Self {
        accept: true,
        drop: false,
        cont: false,
    };
    const DROP: Self = Self {
        accept: false,
        drop: true,
        cont: false,
    };
    const CONTINUE: Self = Self {
        accept: false,
        drop: false,
        cont: true,
    };

    fn or(self, other: Self) -> Self {
        Self {
            accept: self.accept || other.accept,
            drop: self.drop || other.drop,
            cont: self.cont || other.cont,
        }
    }
}

/// Follows such a packet through `chain`: rules that match only some
/// packets are passed over, and the first unconditional verdict decides.
/// `jump` and `goto` are followed. A conditional `return`, or a conditional
/// `goto` to a chain that falls through, may let the packet out early.
/// `memo` holds each chain's fate (`None` while it is being followed; nft
/// rejects loops anyway).
fn fate(
    rules: &HashMap<ChainKey, Vec<&[Value]>>,
    chain: &ChainKey,
    memo: &mut HashMap<ChainKey, Option<Fate>>,
) -> Fate {
    match memo.get(chain) {
        Some(Some(known)) => return *known,
        Some(None) => return Fate::CONTINUE,
        None => {}
    }
    memo.insert(chain.clone(), None);
    let mut out = Fate::default();
    let mut ended = false;
    for expr in rules.get(chain).into_iter().flatten() {
        let target = |t: &str| (chain.0.clone(), chain.1.clone(), t.to_owned());
        let Some(verdict) = verdict(expr) else {
            continue;
        };
        if !matches_all(expr) {
            match verdict {
                Verdict::Return => out.cont = true,
                Verdict::Goto(t) if fate(rules, &target(t), memo).cont => out.cont = true,
                _ => {}
            }
            continue;
        }
        match verdict {
            Verdict::Accept => out = out.or(Fate::ACCEPT),
            Verdict::Drop => out = out.or(Fate::DROP),
            Verdict::Return => out = out.or(Fate::CONTINUE),
            Verdict::Jump(t) => {
                let then = fate(rules, &target(t), memo);
                out = out.or(Fate {
                    cont: false,
                    ..then
                });
                if then.cont {
                    continue;
                }
            }
            // After a goto, falling off the target ends this chain too.
            Verdict::Goto(t) => out = out.or(fate(rules, &target(t), memo)),
        }
        ended = true;
        break;
    }
    if !ended {
        out.cont = true;
    }
    memo.insert(chain.clone(), Some(out));
    out
}

/// The verdict of a rule.
#[derive(Debug, PartialEq, Eq)]
enum Verdict<'a> {
    Accept,
    /// `drop` or `reject`.
    Drop,
    Return,
    Jump(&'a str),
    Goto(&'a str),
}

/// Whether `expr` matches every packet, e.g. `counter drop`: only
/// statements that do not match (`counter`, `log`) before the verdict.
fn matches_all(expr: &[Value]) -> bool {
    expr.split_last().is_some_and(|(_, before)| {
        before
            .iter()
            .all(|s| s.get("counter").is_some() || s.get("log").is_some())
    })
}

/// The verdict that ends `expr`, if it is one that decides for every
/// packet it applies to. `reject with tcp reset` is not: it only rejects
/// TCP, and other packets go on.
fn verdict(expr: &[Value]) -> Option<Verdict<'_>> {
    let verdict = expr.last()?;
    let target = |kind: &str| verdict.get(kind)?.get("target")?.as_str();
    if verdict.get("accept").is_some() {
        Some(Verdict::Accept)
    } else if let Some(reject) = verdict.get("reject") {
        let tcp_only = reject.get("type").and_then(Value::as_str) == Some("tcp reset");
        (!tcp_only).then_some(Verdict::Drop)
    } else if verdict.get("drop").is_some() {
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
        // `ufw default allow incoming`: ufw-not-local returns every packet
        // for a local address before its drop, so the accept policy decides.
        assert_eq!(
            chains(&ruleset("ufw-default-allow")),
            [("ip", "INPUT", false), ("ip6", "INPUT", false)]
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

    /// `(family, port, filtered)` of each published port.
    fn published_ports(fw: &Firewall) -> Vec<(&str, String, bool)> {
        fw.published
            .iter()
            .map(|p| {
                (
                    p.family.as_str(),
                    format!("{}/{}", p.proto, p.port),
                    p.filtered,
                )
            })
            .collect()
    }

    #[test]
    fn reads_docker_published_ports() {
        let tcp8080 = |family, filtered| (family, "tcp/8080".to_owned(), filtered);
        // Docker 29 on Ubuntu 24.04, `-p 8080:80 -p 127.0.0.1:5432:81`:
        // iptables-nft DNAT rules; the loopback port is left out.
        assert_eq!(
            published_ports(&ruleset("docker-published")),
            [tcp8080("ip", false)]
        );
        // The same with an IPv6 network, `[::1]:5433:82` and a UDP range.
        let fw = ruleset("docker-ipv6");
        let v6 = published_ports(&fw);
        for family in ["ip", "ip6"] {
            for port in ["tcp/8080", "udp/9000", "udp/9001"] {
                assert!(
                    v6.contains(&(family, port.to_owned(), false)),
                    "{family} {port}"
                );
            }
        }
        assert_eq!(v6.len(), 6, "{v6:?}");
        // `iptables -I DOCKER-USER -i eth0 ! -s 203.0.113.0/24 -j DROP`.
        assert_eq!(
            published_ports(&ruleset("docker-user-filter")),
            [tcp8080("ip", true)]
        );
        // `"firewall-backend": "nftables"`: native dnat in docker-bridges.
        assert_eq!(
            published_ports(&ruleset("docker-nftables")),
            [tcp8080("ip", false)]
        );
        assert_eq!(ruleset("ufw-enabled").published, []);
    }

    #[test]
    fn reads_open_ports() {
        let open = |name: &str| -> Vec<Vec<String>> {
            ruleset(name)
                .input_chains
                .iter()
                .map(|c| {
                    c.open_ports
                        .iter()
                        .map(|p| format!("{}/{}-{}", p.proto, p.first, p.last))
                        .collect()
                })
                .collect()
        };
        // `ufw allow 22/tcp`; the DHCP and multicast accepts match more
        // than a port, so they do not open one to everyone.
        assert_eq!(open("ufw-enabled"), [["tcp/22-22"], ["tcp/22-22"]]);
        assert_eq!(open("firewalld"), [["tcp/22-22"]]);

        let fw = ruleset("ufw-enabled");
        let ufw = &fw.input_chains[0];
        assert_eq!(ufw.blocks("tcp", 22), Some(false));
        assert_eq!(ufw.blocks("tcp", 5432), Some(true));
        let accepts = ruleset("debian-nftables-conf");
        assert_eq!(accepts.input_chains[0].blocks("tcp", 5432), Some(false));
    }

    #[test]
    fn reads_ufw_with_docker() {
        // Ubuntu 24.04, Docker 29 and ufw: `allow 22/tcp`, `allow 8443,8444/tcp`,
        // `allow 60000:60010/udp`, `limit 2222/tcp`, `allow 53`, `allow in on
        // eth0 to any port 3000`, `allow from 203.0.113.0/24 to any port 5555`.
        let fw = ruleset("ufw-docker");
        let input = &fw.input_chains[0];
        let open: Vec<String> = input
            .open_ports
            .iter()
            .map(|p| format!("{}/{}", p.proto, p.first))
            .collect();
        assert_eq!(open, ["tcp/22", "tcp/2222", "tcp/53", "udp/53"]);
        // `allow in on eth0`: vps-ready does not know eth0 is the public one.
        assert_eq!(input.blocks("tcp", 3000), None);
        // The multiport allows: their ports are not in the JSON.
        assert_eq!(input.unread_ports, ["tcp", "udp"]);
        assert_eq!(input.blocks("tcp", 2222), Some(false));
        assert_eq!(input.blocks("tcp", 5555), None);

        // `-p 127.0.0.1:5432:81` is left out; `-p 172.18.0.1:8081:82` keeps
        // its address.
        let published: Vec<String> = fw
            .published
            .iter()
            .map(|p| format!("{}/{} {:?}", p.proto, p.port, p.address))
            .collect();
        assert!(!published.iter().any(|p| p.starts_with("tcp/5432 ")));
        for port in [
            "tcp/80 None",
            "tcp/5555 None",
            "udp/60005 None",
            r#"tcp/8081 Some("172.18.0.1")"#,
        ] {
            assert!(published.contains(&port.to_owned()), "{port}");
        }
    }

    #[test]
    fn follows_only_narrow_jumps_for_open_ports() {
        let open = |chains: &[(&str, &[&str])]| -> Vec<String> {
            ruleset_of("drop", "", chains).input_chains[0]
                .open_ports
                .iter()
                .map(|p| format!("{}/{}", p.proto, p.first))
                .collect()
        };
        let accept = r#"[{"accept": null}]"#;
        let port_5432 = r#"[{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 5432}}, {"accept": null}]"#;
        // A zone bound to a source, as firewalld's `--add-source`.
        let from_source = r#"[{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "203.0.113.0", "len": 24}}}}, {"jump": {"target": "zone"}}]"#;
        let on_eth0 = r#"[{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "eth0"}}, {"jump": {"target": "zone"}}]"#;
        assert!(open(&[("in", &[from_source]), ("zone", &[port_5432])]).is_empty());
        // firewalld with an interface bound to the zone: the plain jump still
        // opens the port to everyone, whichever jump comes first.
        let plain = r#"[{"jump": {"target": "zone"}}]"#;
        for rules in [[on_eth0, plain], [plain, on_eth0]] {
            let fw = ruleset_of("drop", "", &[("in", &rules), ("zone", &[port_5432])]);
            assert_eq!(fw.input_chains[0].blocks("tcp", 5432), Some(false));
        }
        // An interface-bound zone: open on that interface only.
        let fw = ruleset_of("drop", "", &[("in", &[on_eth0]), ("zone", &[port_5432])]);
        assert_eq!(fw.input_chains[0].blocks("tcp", 5432), None);
        // `ufw limit 2222/tcp`: the port is on the jump, the target accepts.
        let limit = r#"[{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 2222}}, {"jump": {"target": "ok"}}]"#;
        assert_eq!(open(&[("in", &[limit]), ("ok", &[accept])]), ["tcp/2222"]);
    }

    #[test]
    fn bound_addresses() {
        let stmt = |addr: &str| -> Value {
            serde_json::from_str(&format!(
                r#"{{"match": {{"op": "==", "left": {{"payload": {{"protocol": "ip", "field": "daddr"}}}}, "right": "{addr}"}}}}"#
            ))
            .unwrap()
        };
        for addr in ["127.0.0.1", "169.254.1.1", "::1", "fe80::1"] {
            assert_eq!(daddr(&stmt(addr)), Some((addr.to_owned(), true)), "{addr}");
        }
        for addr in ["10.8.0.1", "100.100.1.1", "203.0.113.5", "fd00::1"] {
            assert_eq!(daddr(&stmt(addr)), Some((addr.to_owned(), false)), "{addr}");
        }
    }

    #[test]
    fn interface_and_conntrack_accepts() {
        let chain = |rule: &str| ruleset_of("drop", "", &[("in", &[rule])]).input_chains;
        // `ufw allow in on wg0 to any port 5432`: maybe open, not to all.
        let wg0 = chain(
            r#"[{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wg0"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 5432}}, {"accept": null}]"#,
        );
        assert_eq!(wg0[0].blocks("tcp", 5432), None);
        // `-p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT`.
        let new80 = chain(
            r#"[{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 80}}, {"xt": {"type": "match", "name": "conntrack"}}, {"accept": null}]"#,
        );
        assert_eq!(new80[0].blocks("tcp", 80), Some(false));
    }

    #[test]
    fn port_matches() {
        let ports = |right: &str, proto: &str| {
            let m: Value = serde_json::from_str(&format!(
                r#"{{"op": "==", "left": {{"payload": {{"protocol": "{proto}", "field": "dport"}}}}, "right": {right}}}"#
            ))
            .unwrap();
            dports(&m).map(|ps| {
                ps.iter()
                    .map(|p| format!("{}/{}-{}", p.proto, p.first, p.last))
                    .collect::<Vec<_>>()
            })
        };
        assert_eq!(ports("443", "tcp").unwrap(), ["tcp/443-443"]);
        assert_eq!(
            ports(r#"{"set": [80, {"range": [8000, 8010]}]}"#, "tcp").unwrap(),
            ["tcp/80-80", "tcp/8000-8010"]
        );
        assert_eq!(ports("53", "th").unwrap(), ["tcp/53-53", "udp/53-53"]);
        assert_eq!(ports("53", "icmp"), None);
        assert_eq!(ports("70000", "tcp"), None);
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
            (r#"[{"reject": null}]"#, Some(Verdict::Drop)),
            // UDP goes on.
            (r#"[{"reject": {"type": "tcp reset"}}]"#, None),
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
            let expr = expr(json);
            let got = if matches_all(&expr) {
                verdict(&expr)
            } else {
                None
            };
            assert_eq!(got, want, "{json}");
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
        // A conditional return may let packets past a later drop, as in
        // ufw-not-local: the policy decides for them.
        let local_ret = r#"[{"fib": {"result": "type", "flags": ["daddr"]}}, {"return": null}]"#;
        let jump_local = r#"[{"jump": {"target": "local"}}]"#;
        assert!(!drops(
            "accept",
            &[("in", &[jump_local]), ("local", &[local_ret, drop])]
        ));
        assert!(drops(
            "drop",
            &[("in", &[jump_local]), ("local", &[local_ret, drop])]
        ));
        // So may a conditional goto to a chain that falls through. A chain
        // reached twice is judged the same both times (firewalld's
        // `iifname eth0 goto zone` then `goto zone`).
        let lo_goto = |t: &str| {
            format!(
                r#"[{{"match": {{"op": "==", "left": {{"meta": {{"key": "iifname"}}}}, "right": "lo"}}}}, {{"goto": {{"target": "{t}"}}}}]"#
            )
        };
        assert!(!drops(
            "accept",
            &[("in", &[&lo_goto("empty"), drop]), ("empty", &[lo])]
        ));
        let goto_drops = r#"[{"goto": {"target": "drops"}}]"#;
        assert!(drops(
            "accept",
            &[
                ("in", &[&lo_goto("drops"), goto_drops]),
                ("drops", &[lo, drop])
            ]
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
