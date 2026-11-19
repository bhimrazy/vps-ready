//! The `net.wireguard` module: a WireGuard interface, `wg0`, for admin
//! access to this host only, with a private key generated on the host.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use super::deploy_proxy::is_label;
use super::firewall_inbound;
use super::{
    Applicability, Module, ModuleError, ModuleSteps, ParamDoc, PlanCx, parse_params, refuse,
};
use crate::engine::Reload;
use crate::facts::network::{
    WG0_CONF, WG0_HEADER, WIREGUARD_DIR, interface_with, private_key_line,
};
use crate::facts::{Facts, Init, OsFamily, WireguardDir};
use crate::resource::wireguard::{WG_TIMEOUT, runtime, wg};
use crate::resource::{
    Directory, File, Package, Resource, Service, SyncPeer, WireguardKey, WireguardSync, is_key,
};
use crate::sys::{Cmd, FileKind, FileOwner, Sys, SysError};

/// The interface; a second one is not supported.
pub const INTERFACE: &str = "wg0";
/// The unit that brings it up.
pub const UNIT: &str = "wg-quick@wg0.service";
/// The private key, which `PostUp` loads.
pub const KEY: &str = "/etc/wireguard/wg0.key";
/// `wg`, `wg-quick` and `wg-quick@.service`; the kernel has the module.
pub const PACKAGE: &str = "wireguard-tools";

const DROP_IN_DIR: &str = "/etc/systemd/system/wg-quick@wg0.service.d";
const DROP_IN: &str = "/etc/systemd/system/wg-quick@wg0.service.d/10-vps-ready.conf";

/// The unit's `ExecReload` runs `wg syncconf` with `wg-quick strip`, which
/// on a file without `PrivateKey` clears the key `PostUp` loaded (checked
/// on Debian 13's wireguard-tools 1.0.20210914), cutting every tunnel.
const DROP_IN_TEXT: &str = "\
# Written by vps-ready (net.wireguard). `vps-ready rollback --last` removes it.
# The unit's reload runs `wg syncconf`, which clears the private key that
# PostUp loaded, since wg0.conf holds none. vps-ready changes a running wg0
# with `wg set`; with ExecReload= empty, `systemctl reload` fails instead.
[Service]
ExecReload=
";

/// `# endpoint = <host>` in `wg0.conf`, for `wireguard-config`.
const ENDPOINT_LINE: &str = "# endpoint = ";

/// Mixed into the machine ID for the derived subnet, so it shares nothing
/// with other uses of that ID.
const SUBNET_LABEL: &[u8] = b"vps-ready net.wireguard subnet\n";

const MACHINE_ID: &str = "/etc/machine-id";

const fn default_port() -> u16 {
    51820
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    #[serde(default = "default_port")]
    port: u16,
    /// Empty: derived from the machine ID.
    #[serde(default)]
    address: String,
    /// Only for the client config.
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    peers: Vec<Peer>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Peer {
    name: String,
    public_key: String,
    /// Wide, so that an out-of-range value gets this module's message.
    host: i64,
}

impl Peer {
    /// Its tunnel address in `subnet`; `host` is checked to be 2 to 254.
    fn host_in(&self, subnet: Subnet) -> Ipv4Addr {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        subnet.peer(self.host as u8)
    }
}

impl Params {
    /// The checks that need no host.
    fn check(&self) -> Result<(), ModuleError> {
        if self.port == 0 {
            return refuse("port 0 is not a port; the default is 51820");
        }
        let subnet = if self.address.is_empty() {
            None
        } else {
            Some(Subnet::parse(&self.address)?)
        };
        if !self.endpoint.is_empty() && !is_endpoint(&self.endpoint) {
            return refuse(&format!(
                "endpoint {:?} is not an IP address or a host name, e.g. 203.0.113.10",
                self.endpoint
            ));
        }
        let (mut names, mut keys, mut hosts) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        for peer in &self.peers {
            let name = &peer.name;
            if !is_name(name) {
                return refuse(&format!(
                    "peer name {name:?} is not 1 to 32 lowercase letters, digits and `-`"
                ));
            }
            if !is_key(&peer.public_key) {
                return refuse(&format!(
                    "peer {name}: public_key is not a WireGuard key (44 characters of base64 \
                     for 32 bytes, as `wg pubkey` prints it)"
                ));
            }
            if !(2..=254).contains(&peer.host) {
                return refuse(&format!(
                    "peer {name}: host {} is outside 2 to 254 (the server is .1)",
                    peer.host
                ));
            }
            if !names.insert(name.as_str()) {
                return refuse(&format!("two peers are named {name}"));
            }
            if !keys.insert(peer.public_key.as_str()) {
                return refuse(&format!("peer {name} has the public key of another peer"));
            }
            if !hosts.insert(peer.host) {
                return refuse(&format!("peer {name} has the host of another peer"));
            }
            if let Some(subnet) = subnet
                && peer.host_in(subnet) == subnet.server
            {
                return refuse(&format!(
                    "peer {name}: host {} is this server's own tunnel address, {}",
                    peer.host, subnet.server
                ));
            }
        }
        Ok(())
    }
}

fn is_name(name: &str) -> bool {
    name.len() <= 32 && is_label(name)
}

/// An IP address or a host name.
fn is_endpoint(text: &str) -> bool {
    text.parse::<IpAddr>().is_ok()
        || (text.len() <= 253 && text.split('.').all(|l| is_label(&l.to_ascii_lowercase())))
}

/// The tunnel's IPv4 subnet and the server's address in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Subnet {
    /// The server's address.
    pub(crate) server: Ipv4Addr,
    /// Prefix length, 8 to 24, so that hosts 2 to 254 fit.
    pub(crate) prefix: u8,
}

impl Subnet {
    fn parse(text: &str) -> Result<Self, ModuleError> {
        let bad = || {
            ModuleError::Refused(format!(
                "address {text:?} is not an IPv4 address with a prefix of 8 to 24, e.g. \
                 10.86.12.1/24 (IPv4 only inside the tunnel)"
            ))
        };
        let (ip, prefix) = text.split_once('/').ok_or_else(bad)?;
        let server: Ipv4Addr = ip.parse().map_err(|_| bad())?;
        let prefix: u8 = prefix.parse().map_err(|_| bad())?;
        if !(8..=24).contains(&prefix) {
            return Err(bad());
        }
        let subnet = Self { server, prefix };
        let host = u32::from(server) & !subnet.mask();
        if host == 0 || host == !subnet.mask() {
            return refuse(&format!(
                "address {text}: the server needs a host address, not the subnet's first or \
                 last"
            ));
        }
        Ok(subnet)
    }

    /// A `/24` in 10.0.0.0/8 from two bytes of a SHA-256 of the machine ID,
    /// with the server at `.1`: stable for this host, different on another.
    fn derived(machine_id: &str) -> Self {
        let mut input = SUBNET_LABEL.to_vec();
        input.extend_from_slice(machine_id.trim().as_bytes());
        let hash = sha256(&input);
        Self {
            server: Ipv4Addr::new(10, hash[0], hash[1], 1),
            prefix: 24,
        }
    }

    fn mask(self) -> u32 {
        u32::MAX << (32 - self.prefix)
    }

    fn network(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.server) & self.mask())
    }

    /// The address of `host` in the subnet: the network with `host` in its
    /// last byte.
    pub(crate) fn peer(self, host: u8) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network()) | u32::from(host))
    }

    fn overlaps(self, net: Ipv4Addr, prefix: u8) -> bool {
        let shorter = prefix.min(self.prefix);
        let mask = if shorter == 0 {
            0
        } else {
            u32::MAX << (32 - shorter)
        };
        u32::from(net) & mask == u32::from(self.server) & mask
    }
}

impl std::fmt::Display for Subnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network(), self.prefix)
    }
}

/// A WireGuard interface for admin access to this host: its own tunnel
/// address only, no forwarding, no routes. Debian family with systemd and
/// a kernel with WireGuard.
#[derive(Debug, Clone, Copy)]
pub struct NetWireguard;

impl Module for NetWireguard {
    fn id(&self) -> &'static str {
        "net.wireguard"
    }

    fn title(&self) -> &'static str {
        "Run a WireGuard interface, for a private path to SSH"
    }

    fn why(&self) -> &'static str {
        "A server reachable only through a private network has no SSH port for \
         the internet to scan or brute force. WireGuard gives this host a tunnel \
         address that only your devices' keys can reach, with no outside service; \
         firewall.inbound can then close public SSH. WireGuard does not answer \
         packets without a valid handshake, so its port reveals nothing."
    }

    fn params_doc(&self) -> &'static [ParamDoc] {
        &[
            ParamDoc {
                name: "port",
                default: "51820",
                help: "The UDP port WireGuard listens on; firewall.inbound accepts it.",
            },
            ParamDoc {
                name: "address",
                default: "\"\"",
                help: "This server's tunnel address and subnet, e.g. \"10.86.12.1/24\" (IPv4, a prefix of 8 to 24). Empty: a /24 in 10.0.0.0/8 derived from /etc/machine-id, so each server gets its own. Changing it on a running wg0 is refused.",
            },
            ParamDoc {
                name: "endpoint",
                default: "\"\"",
                help: "The address or host name clients connect to, only for the printed client config. Empty: guessed from this host's public address.",
            },
            ParamDoc {
                name: "peers",
                default: "[]",
                help: "Your devices: { name = \"laptop\", public_key = \"<from wg pubkey>\", host = 2 }. `host` (2 to 254) is the last part of the peer's tunnel address. Public keys only: a device's private key stays on it.",
            },
        ]
    }

    fn applicable(&self, facts: &Facts) -> Applicability {
        let wg0_up = facts.interfaces.iter().any(|i| i.name == INTERFACE);
        let reason = if facts.os.family != OsFamily::Debian {
            "WireGuard is set up only on Debian and Ubuntu so far".to_owned()
        } else if facts.init != Init::Systemd {
            "it needs systemd, to run wg-quick@wg0".to_owned()
        } else if facts.wireguard.module == Some(false) {
            "the kernel has no WireGuard module (a container, or a kernel built without it)"
                .to_owned()
        } else if facts.wireguard.module.is_none() {
            "whether the kernel has WireGuard is unknown: /sys/module/wireguard is missing and \
             modprobe could not tell"
                .to_owned()
        } else {
            match &facts.wireguard.dir {
                WireguardDir::Unreadable => {
                    format!("{WIREGUARD_DIR} can be read only by root; run it with sudo")
                }
                WireguardDir::Read {
                    wg0_managed: Some(false),
                    ..
                } => format!(
                    "{WG0_CONF} was not written by vps-ready, so this WireGuard setup is left \
                     alone (`ssh_via = \"wg0\"` works with it)"
                ),
                WireguardDir::Read {
                    wg0_managed: Some(true),
                    ..
                } => return Applicability::Applicable,
                _ if wg0_up => "a wg0 interface exists that vps-ready did not set up, so it \
                                is left alone (`ssh_via = \"wg0\"` works with it)"
                    .to_owned(),
                _ => return Applicability::Applicable,
            }
        };
        Applicability::NotApplicable { reason }
    }

    fn notes(&self, _facts: &Facts) -> Vec<String> {
        vec![
            "for admin access to this host only: peers reach its tunnel address and nothing \
             else, with no forwarding, routes or NAT"
                .to_owned(),
        ]
    }

    fn check_params(&self, params: &toml::Table) -> Result<(), ModuleError> {
        parse_params::<Params>(params)?.check()
    }

    fn plan(&self, cx: &PlanCx, sys: Sys) -> Result<ModuleSteps, ModuleError> {
        let params: Params = cx.params()?;
        params.check()?;
        let facts = cx.facts;
        let mut notes = Vec::new();
        let subnet = subnet(&params, sys)?;
        if params.address.is_empty() {
            notes.push(format!(
                "the tunnel subnet {subnet} is derived from {MACHINE_ID}, with this server at \
                 {}; set `address` to choose another",
                subnet.server
            ));
        }
        collisions(facts, subnet)?;
        notes.extend(gateway_note(facts, subnet));
        if let Some(p) = params
            .peers
            .iter()
            .find(|p| p.host_in(subnet) == subnet.server)
        {
            return refuse(&format!(
                "peer {}: host {} is this server's own tunnel address, {}",
                p.name, p.host, subnet.server
            ));
        }
        // A file someone gave a PrivateKey since is not diffed or copied.
        if has_private_key(sys)? {
            return refuse(&format!(
                "{WG0_CONF} has a PrivateKey line, which vps-ready never writes: remove it (the \
                 key belongs in {KEY}, which PostUp loads) and apply again"
            ));
        }
        if let Some(wg0) = facts.interfaces.iter().find(|i| i.name == INTERFACE) {
            let want = IpAddr::V4(subnet.server);
            let same = wg0
                .addresses
                .iter()
                .any(|a| a.ip == want && a.prefix == subnet.prefix);
            if !wg0.addresses.is_empty() && !same {
                let now: Vec<String> = wg0
                    .addresses
                    .iter()
                    .map(|a| format!("{}/{}", a.ip, a.prefix))
                    .collect();
                return refuse(&format!(
                    "wg0 is up with {}, and the address {}/{} takes a restart, which vps-ready \
                     does not do: bring wg0 down with `sudo systemctl stop wg-quick@wg0` and \
                     apply again, from public SSH or the console",
                    now.join(", "),
                    subnet.server,
                    subnet.prefix
                ));
            }
        }
        let peers = sync_peers(&params, subnet);
        own_peer(facts, &peers, params.port, sys)?;
        notes.extend(runtime_note(facts, sys)?);
        let key = WireguardKey { path: KEY.into() };
        if let Some(own) = server_public_key(sys)?
            && let Some(p) = params.peers.iter().find(|p| p.public_key == own)
        {
            return refuse(&format!("peer {} has this server's own public key", p.name));
        }
        if params.peers.is_empty() {
            notes.push(
                "no peers: wg0 comes up, but nothing can connect until `peers` lists a device"
                    .to_owned(),
            );
        }
        let resources = vec![
            Resource::Package(Package {
                names: vec![PACKAGE.to_owned()],
            }),
            Resource::Directory(Directory {
                path: WIREGUARD_DIR.into(),
                owner: root(0o700),
            }),
            Resource::WireguardKey(key.clone()),
            Resource::File(File {
                path: WG0_CONF.into(),
                content: render(&params, subnet).into_bytes(),
                owner: root(0o600),
                validate: None,
                describe: None,
            }),
            Resource::Directory(Directory {
                path: DROP_IN_DIR.into(),
                owner: root(0o755),
            }),
            Resource::File(File {
                path: DROP_IN.into(),
                content: DROP_IN_TEXT.as_bytes().to_vec(),
                owner: root(0o644),
                validate: None,
                describe: None,
            }),
            Resource::Service(Service {
                unit: UNIT.to_owned(),
                enabled: true,
                active: true,
            }),
            Resource::WireguardSync(WireguardSync {
                interface: INTERFACE.to_owned(),
                port: params.port,
                peers,
            }),
        ];
        if Resource::WireguardKey(key).diff(sys)?.is_some() {
            notes.push(format!(
                "rollback keeps the generated key {KEY}, so client configs made meanwhile keep \
                 working; `sudo rm {KEY}` and apply again to make a new one"
            ));
        }
        notes.push(firewall_note(facts, params.port, sys)?);
        notes.push(
            "after apply, `sudo vps-ready wireguard-config [PEER]` prints each peer's client \
             config"
                .to_owned(),
        );
        // With the loaded ruleset limiting SSH to wg0, a change here can
        // close SSH, so it needs the timer and a confirm through it.
        let deadman = firewall_inbound::ssh_via(cx.planned, sys)?.as_deref() == Some(INTERFACE);
        Ok(ModuleSteps {
            resources,
            reloads: vec![Reload::DaemonReload],
            notes,
            deadman,
        })
    }

    /// `wg0.conf` parses, the running `wg0` has the key's public key (so
    /// `PostUp` loaded it), and its port and peers are the file's.
    fn verify(&self, cx: &PlanCx, sys: Sys) -> Result<(), String> {
        let params: Params = cx.params().map_err(|e| e.to_string())?;
        let subnet = subnet(&params, sys).map_err(|e| e.to_string())?;
        let strip = Cmd::new("wg-quick")
            .args(["strip", INTERFACE])
            .timeout(WG_TIMEOUT);
        let out = sys
            .runner
            .run(&strip)
            .map_err(|e| format!("`wg-quick strip wg0`: {e}"))?;
        if !out.ok() {
            return Err(format!(
                "`wg-quick strip wg0` exited with status {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let own = server_public_key(sys)
            .map_err(|e| e.to_string())?
            .ok_or("the private key is missing")?;
        let out = sys
            .runner
            .run(&wg(["show", INTERFACE, "public-key"]))
            .map_err(|e| format!("`wg show wg0 public-key`: {e}"))?;
        let running = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if !out.ok() || running != own {
            return Err(format!(
                "wg0 does not have the key in {KEY} (`wg show wg0 public-key` says {running:?}); \
                 its PostUp did not load it"
            ));
        }
        let sync = Resource::WireguardSync(WireguardSync {
            interface: INTERFACE.to_owned(),
            port: params.port,
            peers: sync_peers(&params, subnet),
        });
        match sync.diff(sys) {
            Ok(None) => Ok(()),
            Ok(Some(change)) => Err(format!("wg0 differs from wg0.conf: {}", change.summary)),
            Err(e) => Err(e.to_string()),
        }
    }

    fn verify_timeout(&self) -> Duration {
        WG_TIMEOUT * 5
    }
}

const fn root(mode: u32) -> FileOwner {
    FileOwner {
        mode,
        uid: 0,
        gid: 0,
    }
}

/// `address`, else the subnet derived from the machine ID.
fn subnet(params: &Params, sys: Sys) -> Result<Subnet, ModuleError> {
    if !params.address.is_empty() {
        return Subnet::parse(&params.address);
    }
    let id = match sys.fs.read(Path::new(MACHINE_ID)) {
        Ok(id) => String::from_utf8_lossy(&id).into_owned(),
        Err(SysError::NotFound(_)) => String::new(),
        Err(e) => return Err(e.into()),
    };
    // `uninitialized` before first boot, which every image would share.
    let id = id.trim();
    if id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return refuse(&format!(
            "{MACHINE_ID} is missing or not 32 hex digits, so no subnet can be derived for this \
             server: set `address`, e.g. \"10.86.12.1/24\""
        ));
    }
    Ok(Subnet::derived(id))
}

fn sync_peers(params: &Params, subnet: Subnet) -> Vec<SyncPeer> {
    params
        .peers
        .iter()
        .map(|p| SyncPeer {
            name: p.name.clone(),
            public_key: p.public_key.clone(),
            allowed_ip: format!("{}/32", p.host_in(subnet)),
        })
        .collect()
}

/// Refuses a subnet that overlaps an address or route of the host other
/// than `wg0`'s own; no other is tried, so the answer stays predictable.
fn collisions(facts: &Facts, subnet: Subnet) -> Result<(), ModuleError> {
    let fix = "set `address` in [modules.\"net.wireguard\"] to a subnet that is free here";
    for iface in facts.interfaces.iter().filter(|i| i.name != INTERFACE) {
        for a in &iface.addresses {
            if let IpAddr::V4(ip) = a.ip
                && subnet.overlaps(ip, a.prefix)
            {
                return refuse(&format!(
                    "the WireGuard subnet {subnet} overlaps {ip}/{} on {}; {fix}",
                    a.prefix, iface.name
                ));
            }
        }
    }
    for route in &facts.routes {
        if route.dst == "default" || route.dev.as_deref() == Some(INTERFACE) {
            continue;
        }
        let (net, prefix) = route.dst.split_once('/').unwrap_or((&route.dst, "32"));
        let (Ok(net), Ok(prefix)) = (net.parse::<Ipv4Addr>(), prefix.parse::<u8>()) else {
            continue;
        };
        if prefix <= 32 && subnet.overlaps(net, prefix) {
            let dev = route
                .dev
                .as_deref()
                .map_or_else(String::new, |d| format!(" via {d}"));
            return refuse(&format!(
                "the WireGuard subnet {subnet} overlaps the route {}{dev}; {fix}",
                route.dst
            ));
        }
    }
    Ok(())
}

/// A provider network reached through a gateway in 10.0.0.0/8 has no route
/// of its own here, so the collision check cannot see it.
fn gateway_note(facts: &Facts, subnet: Subnet) -> Option<String> {
    let gateway = facts.routes.iter().find_map(|r| match r.gateway {
        Some(IpAddr::V4(gw)) if r.dst == "default" && r.table.is_none() => Some(gw),
        _ => None,
    })?;
    (gateway.octets()[0] == 10).then(|| {
        format!(
            "the default gateway {gateway} is in 10.0.0.0/8: a provider network behind it (a \
             peered VPC) may use {subnet} without a route here; if so, set `address`"
        )
    })
}

/// Refuses removing the peer this session comes through, changing its key
/// or address, or changing the listen port its client connects to: that
/// would cut the session.
fn own_peer(facts: &Facts, peers: &[SyncPeer], port: u16, sys: Sys) -> Result<(), ModuleError> {
    let Some(session) = &facts.session else {
        return Ok(());
    };
    let server = session.server.ip().to_canonical();
    let through = interface_with(&facts.interfaces, server).is_some_and(|i| i.name == INTERFACE);
    if !through {
        return Ok(());
    }
    let client = session.client.ip().to_canonical();
    let Some(now) = runtime(sys, INTERFACE)? else {
        return Ok(());
    };
    let other_path = "Change it from another path (public SSH while it is open, another peer, or \
                      the console)";
    if now.port != port {
        return refuse(&format!(
            "this session comes through wg0, and changing `port` from {} to {port} would cut \
             it until its client's Endpoint changes too. {other_path}",
            now.port
        ));
    }
    let ip = format!("{client}/32");
    let Some((key, _)) = now
        .peers
        .iter()
        .find(|(_, ips)| ips.iter().any(|net| contains(net, client)))
    else {
        return Ok(());
    };
    if peers
        .iter()
        .any(|p| &p.public_key == key && p.allowed_ip == ip)
    {
        return Ok(());
    }
    refuse(&format!(
        "this session comes through wg0 from {client}, the peer with key {key}: removing that \
         peer, or changing its key or `host`, would cut it. Change it from another path (public \
         SSH while it is open, another peer, or the console)"
    ))
}

/// Whether `net`, an allowed IP such as `10.86.12.0/24` or a bare
/// address, holds `ip`.
pub(crate) fn contains(net: &str, ip: IpAddr) -> bool {
    let (addr, prefix) = net.split_once('/').unwrap_or((net, "32"));
    let (Ok(IpAddr::V4(addr)), Ok(prefix), IpAddr::V4(ip)) =
        (addr.parse::<IpAddr>(), prefix.parse::<u8>(), ip)
    else {
        return net.parse::<IpAddr>().ok() == Some(ip);
    };
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32))
    };
    u32::from(addr) & mask == u32::from(ip) & mask
}

/// Whether the `wg0.conf` on disk has a `PrivateKey` line. Only that is
/// looked for; the file is not kept.
fn has_private_key(sys: Sys) -> Result<bool, ModuleError> {
    match sys.fs.read_nofollow(Path::new(WG0_CONF)) {
        Ok((bytes, _)) => Ok(private_key_line(&bytes)),
        Err(SysError::NotFound(_) | SysError::Symlink(_) | SysError::NotRegular { .. }) => {
            Ok(false)
        }
        Err(e) => Err(e.into()),
    }
}

/// What the plan cannot fix but should say: `wg-quick@wg0` active with no
/// `wg0` (the oneshot unit stays active after the interface goes), or a
/// running `wg0` without its key (as `wg syncconf` leaves it).
fn runtime_note(facts: &Facts, sys: Sys) -> Result<Option<String>, ModuleError> {
    let restart = "`sudo systemctl restart wg-quick@wg0` brings it back with the key";
    if facts.interfaces.iter().any(|i| i.name == INTERFACE) {
        let out = match sys.runner.run(&wg(["show", INTERFACE, "public-key"])) {
            Ok(out) => out,
            Err(SysError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let key = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        return Ok((out.ok() && !is_key(&key)).then(|| {
            format!(
                "wg0 runs without a private key (cleared by `wg syncconf` or `wg set` by hand?), \
                 so no peer can connect; {restart}"
            )
        }));
    }
    let cmd = Cmd::new("systemctl")
        .args(["show", "--property=ActiveState"])
        .arg(UNIT);
    let active = sys
        .runner
        .run(&cmd)
        .ok()
        .filter(crate::sys::Output::ok)
        .is_some_and(|o| String::from_utf8_lossy(&o.stdout).contains("ActiveState=active"));
    Ok(active
        .then(|| format!("wg-quick@wg0 is active but wg0 is gone (deleted by hand?); {restart}")))
}

/// The server's public key; `None` without a key or without `wg`.
fn server_public_key(sys: Sys) -> Result<Option<String>, ModuleError> {
    match sys.fs.metadata(Path::new(KEY)) {
        Err(SysError::NotFound(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(meta) if meta.kind != FileKind::File => return Ok(None),
        Ok(_) => {}
    }
    let out = match sys.runner.run(&wg(["pubkey"]).stdin_from(KEY)) {
        Ok(out) => out,
        Err(SysError::NotFound(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let key = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    Ok((out.ok() && is_key(&key)).then_some(key))
}

/// Who opens the port. `firewall.inbound` comes after this module, so only
/// the ruleset on disk is known here.
fn firewall_note(facts: &Facts, port: u16, sys: Sys) -> Result<String, ModuleError> {
    Ok(if facts.firewall_tools.ufw == Some(true) {
        format!("ufw is active: open UDP {port} there (`sudo ufw allow {port}/udp`)")
    } else if facts.firewall_tools.firewalld == Some(true) {
        format!(
            "firewalld is running: open UDP {port} there (`sudo firewall-cmd --permanent \
             --add-port={port}/udp`)"
        )
    } else if firewall_inbound::accepts_udp(sys, port)? {
        format!("firewall.inbound accepts UDP {port} for it")
    } else {
        format!(
            "firewall.inbound accepts UDP {port} once it is applied; another firewall needs the \
             port opened"
        )
    })
}

/// `wg0.conf`: no `PrivateKey`, which `PostUp` loads from its own file; no
/// `MTU`, `SaveConfig`, `Table` or `DNS`.
fn render(params: &Params, subnet: Subnet) -> String {
    let mut text = format!(
        "{WG0_HEADER} `vps-ready rollback --last` restores\n\
         # the previous state; edits here are replaced by the next apply.\n\
         # The private key is in {KEY} and is loaded by PostUp.\n"
    );
    if !params.endpoint.is_empty() {
        let _ = writeln!(text, "{ENDPOINT_LINE}{}", params.endpoint);
    }
    let _ = write!(
        text,
        "[Interface]\nAddress = {}/{}\nListenPort = {}\nPostUp = wg set %i private-key \
         /etc/wireguard/%i.key\n",
        subnet.server, subnet.prefix, params.port
    );
    for peer in sync_peers(params, subnet) {
        let _ = write!(
            text,
            "\n[Peer]\n# {}\nPublicKey = {}\nAllowedIPs = {}\n",
            peer.name, peer.public_key, peer.allowed_ip
        );
    }
    text
}

/// The client configs of the `wg0.conf` on disk, for every peer or `only`,
/// and a note when the endpoint is a placeholder.
///
/// # Errors
///
/// No `wg0.conf` of vps-ready's, no usable key, or no peer `only`.
pub fn clients(
    sys: Sys,
    facts: &Facts,
    only: Option<&str>,
) -> Result<(String, Option<String>), String> {
    let text = match sys.fs.read_nofollow(Path::new(WG0_CONF)) {
        Ok((bytes, _)) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(SysError::NotFound(_)) => {
            return Err(format!(
                "{WG0_CONF} does not exist: apply net.wireguard first"
            ));
        }
        Err(e) => return Err(format!("reading {WG0_CONF}: {e}")),
    };
    let conf =
        parse_conf(&text).ok_or_else(|| format!("{WG0_CONF} was not written by vps-ready"))?;
    let key = server_public_key(sys)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("{KEY} is missing, or `wg pubkey` does not accept it"))?;
    let (endpoint, note) = endpoint(&conf, facts);
    Ok((client_configs(&conf, &key, &endpoint, only)?, note))
}

/// A peer's client config, from `wg0.conf` as [`render`] writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Conf {
    pub(crate) server: Ipv4Addr,
    pub(crate) port: u16,
    pub(crate) endpoint: Option<String>,
    /// Name, public key, allowed IP.
    pub(crate) peers: Vec<(String, String, String)>,
}

/// Parses a `wg0.conf` that [`render`] wrote; `None` for any other.
pub(crate) fn parse_conf(text: &str) -> Option<Conf> {
    if !text.starts_with(WG0_HEADER) || private_key_line(text.as_bytes()) {
        return None;
    }
    let (mut server, mut port, mut endpoint) = (None, None, None);
    let mut peers: Vec<(String, String, String)> = Vec::new();
    for line in text.lines() {
        if let Some(e) = line.strip_prefix(ENDPOINT_LINE) {
            endpoint = Some(e.trim().to_owned());
        } else if line == "[Peer]" {
            peers.push(Default::default());
        } else if let (Some(name), Some(p)) = (line.strip_prefix("# "), peers.last_mut()) {
            p.0 = name.to_owned();
        } else if let Some((k, v)) = line.split_once(" = ") {
            match (k, peers.last_mut()) {
                ("Address", None) => {
                    server = v.split_once('/').and_then(|(ip, _)| ip.parse().ok());
                }
                ("ListenPort", None) => port = v.parse().ok(),
                ("PublicKey", Some(p)) => p.1 = v.to_owned(),
                ("AllowedIPs", Some(p)) => p.2 = v.to_owned(),
                _ => {}
            }
        }
    }
    Some(Conf {
        server: server?,
        port: port?,
        endpoint,
        peers,
    })
}

/// The client config of each peer of `conf`, or of `only`. The private key
/// line is a placeholder: the device made its key and keeps it.
///
/// # Errors
///
/// A peer named `only` that `conf` lacks.
pub(crate) fn client_configs(
    conf: &Conf,
    server_key: &str,
    endpoint: &str,
    only: Option<&str>,
) -> Result<String, String> {
    let peers: Vec<_> = conf
        .peers
        .iter()
        .filter(|(name, ..)| only.is_none_or(|o| o == name))
        .collect();
    if let Some(name) = only
        && peers.is_empty()
    {
        let names: Vec<&str> = conf.peers.iter().map(|(n, ..)| n.as_str()).collect();
        return Err(format!(
            "no peer named {name} in {WG0_CONF}; its peers are: {}",
            if names.is_empty() {
                "none".to_owned()
            } else {
                names.join(", ")
            }
        ));
    }
    let mut out = String::new();
    for (i, (name, _, ip)) in peers.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let _ = write!(
            out,
            "# {name}: the client config, for the WireGuard app or /etc/wireguard/wg0.conf there\n\
             [Interface]\n\
             PrivateKey = <the private key of {name}, which stays on that device>\n\
             Address = {ip}\n\
             \n\
             [Peer]\n\
             PublicKey = {server_key}\n\
             Endpoint = {endpoint}\n\
             AllowedIPs = {}/32\n\
             PersistentKeepalive = 25\n",
            conf.server
        );
    }
    Ok(out)
}

/// Where clients connect: `endpoint` if set, else the session's server
/// address if public, else a public address of the default route's
/// interface, else a placeholder and a note. No network call.
pub(crate) fn endpoint(conf: &Conf, facts: &Facts) -> (String, Option<String>) {
    let port = conf.port;
    let host = |ip: IpAddr| match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    };
    if let Some(e) = &conf.endpoint {
        return match e.parse::<IpAddr>() {
            Ok(ip) => (host(ip), None),
            Err(_) => (format!("{e}:{port}"), None),
        };
    }
    let session = facts
        .session
        .as_ref()
        .map(|s| s.server.ip().to_canonical())
        .filter(|ip| is_public(*ip));
    let routed = || {
        facts
            .routes
            .iter()
            .filter(|r| r.dst == "default" && r.table.is_none())
            .filter_map(|r| r.dev.as_deref())
            .flat_map(|dev| facts.interfaces.iter().filter(move |i| i.name == dev))
            .flat_map(|i| i.addresses.iter().map(|a| a.ip))
            .find(|ip| is_public(*ip))
    };
    match session.or_else(routed) {
        Some(ip) => (host(ip), None),
        None => (
            format!("<this server's public address>:{port}"),
            Some(
                "this host has no public address of its own (a NATed cloud?): put the address \
                 clients reach it on in Endpoint, or set `endpoint`"
                    .to_owned(),
            ),
        ),
    }
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || (a == 100 && (64..128).contains(&b)))
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unicast_link_local()
                || v6.is_unique_local())
        }
    }
}

/// SHA-256 (FIPS 180-4), for the derived subnet only.
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    for block in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_mut(4).zip(h) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// The UDP port of the `wg0` this module manages: from the `wg0.conf` a
/// module before the caller plans, else from the one on disk with
/// [`WG0_HEADER`]; `None` without either. Only `ListenPort` is read.
///
/// # Errors
///
/// Reading the file on disk.
pub(crate) fn managed_port(planned: &[Resource], sys: Sys) -> Result<Option<u16>, ModuleError> {
    let planned = planned.iter().find_map(|r| match r {
        Resource::File(f) if f.path == Path::new(WG0_CONF) => Some(f.content.clone()),
        _ => None,
    });
    let text = match planned {
        Some(text) => text,
        None => match sys.fs.read_nofollow(Path::new(WG0_CONF)) {
            Ok((text, _)) => text,
            Err(SysError::NotFound(_) | SysError::Permission(_)) => return Ok(None),
            Err(SysError::Symlink(_) | SysError::NotRegular { .. }) => return Ok(None),
            Err(e) => return Err(e.into()),
        },
    };
    Ok(parse_conf(&String::from_utf8_lossy(&text)).map(|c| c.port))
}

#[cfg(test)]
mod tests;
