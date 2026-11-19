//! Interfaces, routes, WireGuard and Tailscale, for the VPN modules: the
//! subnet collision check, the `ssh_via` checks and the firewall port.
//!
//! All probes are read-only. `wg show` is limited to `listen-port`: it prints
//! no keys, unlike `wg showconf` and `wg show <if> dump`.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{Probe, probe};
use crate::sys::{Cmd, Fs, Runner};

const WIREGUARD: &str = "wireguard";
const TAILSCALE_IF: &str = "tailscale0";

/// A network interface and its addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Interface {
    /// Interface name.
    pub name: String,
    /// The link type from `ip -d` (`wireguard`, `veth`, `bridge`, ...).
    /// Interfaces without one (physical NICs, `lo`) have `None`.
    pub kind: Option<String>,
    /// Addresses of both families.
    pub addresses: Vec<Address>,
    /// Whether the `UP` flag is set. `operstate` is `UNKNOWN` for WireGuard
    /// and `tun` links, so the flag is the reliable source.
    pub up: bool,
}

impl Interface {
    /// Whether this is a WireGuard interface. The kernel's link type is
    /// reliable where the name is not: `wg0` is only a convention.
    #[must_use]
    pub fn is_wireguard(&self) -> bool {
        self.kind.as_deref() == Some(WIREGUARD)
    }

    /// Whether this is Tailscale's interface, which has a fixed name and a
    /// generic `tun` link type.
    #[must_use]
    pub fn is_tailscale(&self) -> bool {
        self.name == TAILSCALE_IF
    }

    /// Whether this looks like a VPN interface.
    #[must_use]
    pub fn is_vpn(&self) -> bool {
        self.is_wireguard() || self.is_tailscale()
    }
}

/// An address with its prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Address {
    /// The address.
    pub ip: IpAddr,
    /// Prefix length.
    pub prefix: u8,
}

/// A route of either family from `ip -j route show table all`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Route {
    /// `default`, a prefix such as `192.0.2.0/24`, or a bare address.
    pub dst: String,
    /// Outgoing interface.
    pub dev: Option<String>,
    /// Next hop.
    pub gateway: Option<IpAddr>,
    /// `None` for the main table, else its name (`local`, `52`, ...). The
    /// `local` table holds routes for the host's own addresses.
    pub table: Option<String>,
}

/// The interface that holds `ip`, e.g. the one a session's server address is
/// on.
#[must_use]
pub fn interface_with(interfaces: &[Interface], ip: IpAddr) -> Option<&Interface> {
    interfaces
        .iter()
        .find(|i| i.addresses.iter().any(|a| a.ip == ip))
}

/// WireGuard on this host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Wireguard {
    /// Whether the kernel has the module, loaded or loadable. `None` when
    /// neither `/sys/module/wireguard` nor `modprobe` could tell.
    pub module: Option<bool>,
    /// Listen port per interface, from `wg show all listen-port`. Empty
    /// without `wg`, without root, or without interfaces.
    pub listen_ports: BTreeMap<String, u16>,
}

/// Tailscale's state from `tailscale status --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Tailscale {
    /// `NeedsLogin`, `Running`, `Stopped`, ...
    pub backend_state: String,
    /// This node's Tailscale addresses.
    pub ips: Vec<IpAddr>,
    /// When this node's key expires (RFC 3339). `None` when expiry is
    /// disabled for the node, or when the node is not `Running` (no network
    /// map). Treat `None` as disabled only when `backend_state` is `Running`.
    pub key_expiry: Option<String>,
}

#[derive(Deserialize)]
struct RawIf {
    ifname: String,
    linkinfo: Option<RawLinkInfo>,
    #[serde(default)]
    flags: Vec<String>,
    #[serde(default)]
    addr_info: Vec<RawAddr>,
}

#[derive(Deserialize)]
struct RawLinkInfo {
    info_kind: Option<String>,
}

#[derive(Deserialize)]
struct RawAddr {
    local: IpAddr,
    prefixlen: u8,
}

#[derive(Deserialize)]
struct RawRoute {
    dst: String,
    dev: Option<String>,
    gateway: Option<IpAddr>,
    table: Option<String>,
}

#[derive(Deserialize)]
struct RawTailscale {
    #[serde(rename = "BackendState")]
    backend_state: String,
    #[serde(rename = "Self")]
    this: Option<RawSelf>,
}

#[derive(Deserialize)]
struct RawSelf {
    #[serde(rename = "TailscaleIPs")]
    ips: Option<Vec<IpAddr>>,
    #[serde(rename = "KeyExpiry")]
    key_expiry: Option<String>,
}

/// `ip -j -d addr`: `-d` adds `linkinfo.info_kind`, the kernel's link type,
/// so one call gives both the addresses and the WireGuard type.
pub(crate) fn interfaces(runner: &dyn Runner, notices: &mut Vec<String>) -> Vec<Interface> {
    let raw: Vec<RawIf> = ip_json(runner, &["-j", "-d", "addr"], "interfaces", notices);
    raw.into_iter()
        .map(|i| Interface {
            name: i.ifname,
            kind: i.linkinfo.and_then(|l| l.info_kind),
            up: i.flags.iter().any(|f| f == "UP"),
            addresses: i
                .addr_info
                .into_iter()
                .map(|a| Address {
                    ip: a.local,
                    prefix: a.prefixlen,
                })
                .collect(),
        })
        .collect()
}

/// `ip -j route show table all`, which lists both families.
pub(super) fn routes(runner: &dyn Runner, notices: &mut Vec<String>) -> Vec<Route> {
    let args = ["-j", "route", "show", "table", "all"];
    let raw: Vec<RawRoute> = ip_json(runner, &args, "routes", notices);
    raw.into_iter()
        .map(|r| Route {
            dst: r.dst,
            dev: r.dev,
            gateway: r.gateway,
            table: r.table,
        })
        .collect()
}

fn ip_json<T: for<'de> Deserialize<'de>>(
    runner: &dyn Runner,
    args: &[&str],
    what: &str,
    notices: &mut Vec<String>,
) -> Vec<T> {
    let cmd = Cmd::new("ip").args(args.iter().copied());
    match probe(runner, &cmd, notices) {
        Probe::Ran(out) if out.ok() => serde_json::from_slice(&out.stdout).unwrap_or_else(|err| {
            notices.push(format!("parsing `ip` output: {err}; {what} are unknown"));
            Vec::new()
        }),
        Probe::Ran(out) => {
            notices.push(format!(
                "`ip` exited with {}; {what} are unknown",
                out.status
            ));
            Vec::new()
        }
        Probe::Missing => {
            let note = "ip not found; interfaces and routes are unknown".to_owned();
            if !notices.contains(&note) {
                notices.push(note);
            }
            Vec::new()
        }
        Probe::Failed => Vec::new(),
    }
}

pub(super) fn wireguard(fs: &dyn Fs, runner: &dyn Runner, notices: &mut Vec<String>) -> Wireguard {
    let module = if fs.exists(Path::new("/sys/module/wireguard")) {
        Some(true)
    } else {
        // `--dry-run` resolves the module and its dependencies without
        // loading anything.
        let cmd = Cmd::new("modprobe").args(["--dry-run", WIREGUARD]);
        match probe(runner, &cmd, notices) {
            Probe::Ran(out) => Some(out.ok()),
            Probe::Missing | Probe::Failed => None,
        }
    };
    let cmd = Cmd::new("wg")
        .args(["show", "all", "listen-port"])
        .timeout(Duration::from_secs(10));
    let listen_ports = match probe(runner, &cmd, notices) {
        Probe::Ran(out) if out.ok() => parse_listen_ports(&String::from_utf8_lossy(&out.stdout)),
        Probe::Ran(out) => {
            notices.push(format!(
                "`wg show` exited with {}; WireGuard ports are unknown (it needs root)",
                out.status
            ));
            BTreeMap::new()
        }
        Probe::Missing | Probe::Failed => BTreeMap::new(),
    };
    Wireguard {
        module,
        listen_ports,
    }
}

/// `<interface>\t<port>` lines.
fn parse_listen_ports(text: &str) -> BTreeMap<String, u16> {
    text.lines()
        .filter_map(|line| {
            let (name, port) = line.split_once(char::is_whitespace)?;
            // A down interface has no port and prints 0.
            let port: u16 = port.trim().parse().ok().filter(|p| *p != 0)?;
            Some((name.to_owned(), port))
        })
        .collect()
}

/// `None` without `tailscale`, or when its daemon does not answer.
pub(super) fn tailscale(runner: &dyn Runner, notices: &mut Vec<String>) -> Option<Tailscale> {
    let out = match probe(runner, &tailscale_status(), notices) {
        Probe::Ran(out) if out.ok() => out,
        Probe::Ran(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let why = stderr
                .lines()
                .next()
                .map_or_else(|| format!("exited with {}", out.status), str::to_owned);
            notices.push(format!(
                "`tailscale status` failed ({why}); Tailscale's state is unknown"
            ));
            return None;
        }
        Probe::Missing | Probe::Failed => return None,
    };
    parse_tailscale(&out.stdout)
        .inspect_err(|err| {
            notices.push(format!(
                "parsing `tailscale status`: {err}; Tailscale's state is unknown"
            ));
        })
        .ok()
}

/// `tailscale status --json`; `--peers=false` keeps the output small on a
/// big tailnet, and `Self` stays.
pub(crate) fn tailscale_status() -> Cmd {
    Cmd::new("tailscale")
        .args(["status", "--json", "--peers=false"])
        .timeout(Duration::from_secs(10))
}

pub(crate) fn parse_tailscale(json: &[u8]) -> Result<Tailscale, serde_json::Error> {
    let raw: RawTailscale = serde_json::from_slice(json)?;
    let this = raw.this;
    Ok(Tailscale {
        backend_state: raw.backend_state,
        ips: this
            .as_ref()
            .and_then(|s| s.ips.clone())
            .unwrap_or_default(),
        key_expiry: this.and_then(|s| s.key_expiry),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::fixtures::testdata;
    use crate::sys::Output;
    use crate::sys::fake::{FakeFs, FakeRunner};

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(testdata(&format!("network/{name}"))).unwrap()
    }

    fn failed(stderr: &str) -> Output {
        Output {
            status: 1,
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn interfaces_and_routes() {
        let runner = FakeRunner::new()
            .on(
                "ip",
                ["-j", "-d", "addr"],
                Output::success(fixture("ip-addr.json")),
            )
            .on(
                "ip",
                ["-j", "route"],
                Output::success(fixture("ip-route.json")),
            );
        let mut notices = Vec::new();
        let ifs = interfaces(&runner, &mut notices);
        let routes = routes(&runner, &mut notices);
        assert!(notices.is_empty(), "{notices:?}");
        insta::assert_yaml_snapshot!("interfaces-and-routes", (&ifs, &routes));

        let by = |n: &str| ifs.iter().find(|i| i.name == n).unwrap();
        assert!(by("wg0").is_wireguard() && by("wg0").is_vpn());
        assert!(by("tailscale0").is_tailscale() && !by("tailscale0").is_wireguard());
        assert!(!by("eth0").is_vpn());
        assert!(by("wg0").up && !by("wg1").up);
        assert_eq!(
            interface_with(&ifs, "10.77.0.1".parse().unwrap()).map(|i| i.name.as_str()),
            Some("wg0")
        );
        assert!(interface_with(&ifs, "203.0.113.99".parse().unwrap()).is_none());
    }

    #[test]
    fn missing_or_failing_ip_is_unknown() {
        let mut notices = Vec::new();
        assert!(interfaces(&FakeRunner::new(), &mut notices).is_empty());
        let bad = FakeRunner::new().on("ip", ["-j"], Output::success("not json"));
        assert!(routes(&bad, &mut notices).is_empty());
        let exit = FakeRunner::new().on("ip", ["-j"], failed("boom"));
        assert!(routes(&exit, &mut notices).is_empty());
        assert_eq!(notices.len(), 3, "{notices:?}");
        assert!(notices[0].starts_with("ip not found"));
    }

    #[test]
    fn wireguard_module_and_ports() {
        let runner = FakeRunner::new()
            .on(
                "wg",
                ["show"],
                Output::success("wg0\t51820\nwg1\t51821\nwg2\t0\n"),
            )
            .on("modprobe", ["--dry-run"], Output::success(""));
        let mut notices = Vec::new();
        let wg = wireguard(&FakeFs::new(), &runner, &mut notices);
        assert_eq!(wg.module, Some(true));
        assert_eq!(wg.listen_ports.get("wg1"), Some(&51821));
        assert!(!wg.listen_ports.contains_key("wg2"));
        assert!(notices.is_empty());

        // Built in or loaded: modprobe is not asked.
        let fs = FakeFs::new().with_file("/sys/module/wireguard/version", "1\n");
        let wg = wireguard(&fs, &FakeRunner::new(), &mut notices);
        assert_eq!(wg.module, Some(true));
        assert!(wg.listen_ports.is_empty());

        // A container without the module, and no wg: no notice.
        let runner = FakeRunner::new().on("modprobe", ["--dry-run"], failed("not found"));
        let wg = wireguard(&FakeFs::new(), &runner, &mut notices);
        assert_eq!(wg.module, Some(false));
        assert!(notices.is_empty());

        let wg = wireguard(&FakeFs::new(), &FakeRunner::new(), &mut notices);
        assert_eq!(wg.module, None);

        // wg without root.
        let runner = FakeRunner::new().on("wg", ["show"], failed("Operation not permitted"));
        wireguard(&FakeFs::new(), &runner, &mut notices);
        assert_eq!(notices.len(), 1, "{notices:?}");
    }

    #[test]
    fn tailscale_states() {
        for state in ["needs-login", "running", "stopped", "no-expiry"] {
            let ts = parse_tailscale(&fixture(&format!("tailscale-{state}.json"))).unwrap();
            insta::assert_yaml_snapshot!(format!("tailscale-{state}"), ts);
        }
    }

    #[test]
    fn tailscale_probe() {
        let mut notices = Vec::new();
        assert_eq!(tailscale(&FakeRunner::new(), &mut notices), None);
        assert!(notices.is_empty());
        let down = FakeRunner::new().on(
            "tailscale",
            ["status", "--json"],
            failed("failed to connect to local tailscaled"),
        );
        assert_eq!(tailscale(&down, &mut notices), None);
        assert_eq!(
            notices,
            [
                "`tailscale status` failed (failed to connect to local tailscaled); Tailscale's state is unknown"
            ]
        );
        let up = FakeRunner::new().on(
            "tailscale",
            ["status", "--json"],
            Output::success(fixture("tailscale-running.json")),
        );
        let ts = tailscale(&up, &mut notices).unwrap();
        assert_eq!(ts.backend_state, "Running");
    }
}
