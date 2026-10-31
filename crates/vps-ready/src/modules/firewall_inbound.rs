//! The `firewall.inbound` module: a default-deny input chain in vps-ready's
//! own nftables table, `inet vps_ready`, loaded by its own unit.

use std::collections::BTreeSet;
use std::time::Duration;

use askama::Template;
use serde::Deserialize;

use super::{Applicability, Module, ModuleError, ModuleSteps, ParamDoc, PlanCx, parse_params};
use crate::engine::Reload;
use crate::facts::{Facts, Init, OsFamily, Proto};
use crate::resource::{Directory, File, Package, Resource, Service, Validate};
use crate::sys::{Cmd, FileOwner, Sys};

/// Holds the ruleset. No package owns a directory it would fit in.
pub const DIR: &str = "/etc/vps-ready";
/// The ruleset; [`Reload::FirewallReload`] checks and loads this path.
pub const RULESET: &str = "/etc/vps-ready/firewall.nft";
/// The unit that loads the ruleset at boot and deletes the table on stop.
pub const UNIT_FILE: &str = "/etc/systemd/system/vps-ready-firewall.service";
const UNIT: &str = "vps-ready-firewall.service";

/// Not `nftables.service`: `/etc/nftables.conf` starts with `flush ruleset`,
/// which would also remove Docker's and fail2ban's tables. Ordered after it,
/// so a boot that loads that file loads this table after its flush. The
/// boot hook of the dead-man switch is ordered after this unit.
const UNIT_TEXT: &str = "\
# Written by vps-ready (firewall.inbound). `vps-ready rollback --last`
# restores the previous state; edits here are replaced by the next apply.
[Unit]
Description=vps-ready: inbound firewall (nftables table inet vps_ready)
DefaultDependencies=no
Wants=network-pre.target
After=nftables.service
Before=network-pre.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/vps-ready/firewall.nft
ExecReload=/usr/sbin/nft -f /etc/vps-ready/firewall.nft
ExecStop=-/usr/sbin/nft delete table inet vps_ready

[Install]
WantedBy=sysinit.target
";

/// Kill timeout of `nft -j list table` in [`Module::verify`].
const NFT_TIMEOUT: Duration = Duration::from_secs(10);

/// The module's params.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    /// Ports to accept from anywhere, e.g. `443/udp`. The current SSH ports
    /// are accepted whatever this says.
    #[serde(default)]
    allow: Vec<Allow>,
}

/// A port in `allow`: `<port>/tcp` or `<port>/udp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct Allow {
    pub(crate) port: u16,
    pub(crate) proto: Proto,
}

impl TryFrom<String> for Allow {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        let bad = || format!("{s:?} is not `<port>/tcp` or `<port>/udp`");
        let (port, proto) = s.split_once('/').ok_or_else(bad)?;
        let proto = match proto {
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            _ => return Err(bad()),
        };
        match port.parse() {
            Ok(port) if port > 0 => Ok(Self { port, proto }),
            _ => Err(bad()),
        }
    }
}

/// The ruleset, as `templates/firewall.nft` renders it.
#[derive(Debug, Clone, PartialEq, Eq, Template)]
#[template(path = "firewall.nft", escape = "none")]
struct Ruleset {
    /// Never empty: it holds the SSH ports.
    tcp: Vec<u16>,
    udp: Vec<u16>,
    /// Accept everything from Docker's bridges.
    docker: bool,
    /// Interfaces named `br-*` that are not Docker's, which that leaves out.
    not_docker: Vec<String>,
}

impl Ruleset {
    fn new(facts: &Facts, params: &Params) -> Self {
        let mut tcp = ssh_ports(facts);
        let mut udp = BTreeSet::new();
        for allow in &params.allow {
            match allow.proto {
                Proto::Tcp => tcp.insert(allow.port),
                Proto::Udp => udp.insert(allow.port),
            };
        }
        Self {
            tcp: tcp.into_iter().collect(),
            udp: udp.into_iter().collect(),
            docker: facts.docker,
            not_docker: not_docker(facts),
        }
    }
}

/// The interfaces named `br-*` that Docker did not name. The ruleset keeps
/// `br-*` so that Docker networks created later are covered too.
fn not_docker(facts: &Facts) -> Vec<String> {
    facts
        .bridges
        .iter()
        .filter(|b| !b.docker)
        .map(|b| b.name.clone())
        .collect()
}

/// Every port SSH may be reached on now: [`crate::facts::Ssh::ports`], the
/// applying session's and every port an sshd process listens on.
pub(crate) fn ssh_ports(facts: &Facts) -> BTreeSet<u16> {
    let mut ports: BTreeSet<u16> = facts.ssh.ports().into_iter().collect();
    ports.extend(facts.session.as_ref().map(|s| s.server.port()));
    // Not every listener named sshd: any user can name a process so.
    ports.extend(&facts.ssh.listening);
    ports
}

/// Drops incoming traffic that no rule accepts, in its own nftables table.
/// Debian family with systemd only. It can lock the admin out, so it needs
/// the dead-man switch, which restores its files even if they changed.
#[derive(Debug, Clone, Copy)]
pub struct FirewallInbound;

/// Root's, with `mode`.
const fn root(mode: u32) -> FileOwner {
    FileOwner {
        mode,
        uid: 0,
        gid: 0,
    }
}

impl Module for FirewallInbound {
    fn id(&self) -> &'static str {
        "firewall.inbound"
    }

    fn title(&self) -> &'static str {
        "Drop incoming traffic that no rule allows"
    }

    fn why(&self) -> &'static str {
        "Without a firewall, any service listening on all addresses, such as a \
         database left at its defaults, is reachable from the internet. This one \
         accepts SSH, the ports the profile allows and replies to the server's own \
         connections, and drops the rest."
    }

    fn params_doc(&self) -> &'static [ParamDoc] {
        &[ParamDoc {
            name: "allow",
            default: "[]",
            help: "Ports to accept from anywhere, e.g. [\"443/tcp\", \"443/udp\"]; the SSH ports are always accepted.",
        }]
    }

    fn needs_deadman(&self) -> bool {
        true
    }

    fn force_restore(&self) -> bool {
        true
    }

    fn applicable(&self, facts: &Facts) -> Applicability {
        let tools = &facts.firewall_tools;
        let firewall = facts.firewall.as_ref();
        let reason = if facts.os.family != OsFamily::Debian {
            "the firewall is set up only on Debian and Ubuntu so far"
        } else if facts.init != Init::Systemd {
            "it needs systemd, for its unit and the dead-man switch"
        } else if tools.ufw == Some(true) {
            "ufw is enabled; vps-ready leaves the firewall to it"
        } else if tools.firewalld == Some(true) {
            "firewalld is running or enabled; vps-ready leaves the firewall to it"
        } else if tools.firewalld.is_none() {
            "whether firewalld is running is unknown (`systemctl show` failed)"
        } else if tools.legacy_filter {
            "the filter table of iptables-legacy is loaded, and vps-ready cannot read its rules"
        } else if tools.nft && firewall.is_none() {
            "`nft list ruleset` failed, so the ruleset cannot be read or changed here \
             (an unprivileged container?)"
        } else if !tools.nft && facts.updates.is_none() {
            "nft is not installed, and apt was not found to install it"
        } else if ssh_ports(facts).is_empty() {
            "the SSH port is unknown: no SSH session, sshd listener, `sshd -T` or \
             ssh.socket shows it"
        } else {
            return Applicability::Applicable;
        };
        Applicability::NotApplicable {
            reason: reason.to_owned(),
        }
    }

    fn notes(&self, facts: &Facts) -> Vec<String> {
        let ports = ssh_ports(facts)
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let mut notes = vec![format!(
            "always accepts TCP {ports}, the current SSH ports (this session's, root's sshd \
             listeners and `Port`), whatever `allow` says"
        )];
        if facts.docker {
            notes.push(
                "Docker is installed: input from docker0 and br-* is accepted, so \
                 containers can reach services on the host; a compromised container \
                 can reach all of them, as with no firewall"
                    .to_owned(),
            );
            let others = not_docker(facts);
            if !others.is_empty() {
                notes.push(format!(
                    "filtered like any other interface, since Docker did not name them: {}",
                    others.join(", ")
                ));
            }
        }
        let firewall = facts.firewall.as_ref();
        notes.extend(forwarded_note(facts));
        let others: Vec<String> = firewall
            .into_iter()
            .flat_map(|f| &f.input_chains)
            .filter(|c| c.drops_unmatched && !(c.family == "inet" && c.table == "vps_ready"))
            .map(|c| format!("{} {} {}", c.family, c.table, c.name))
            .collect();
        if !others.is_empty() {
            notes.push(format!(
                "other chains also filter incoming traffic, and a packet must pass each \
                 of them: {}",
                others.join(", ")
            ));
        }
        if facts.firewall_tools.ufw.is_some() {
            notes.push(
                "`ufw status` does not show these rules; `nft list table inet vps_ready` does"
                    .to_owned(),
            );
        }
        if facts.firewall_tools.nftables_service == Some(true) {
            notes.push(format!(
                "nftables.service is enabled: restarting it flushes the whole ruleset and \
                 removes this table until `systemctl restart {UNIT}`"
            ));
        }
        if !facts.firewall_tools.nft {
            notes.push("if this installs nftables, rollback leaves it installed".to_owned());
        }
        notes
    }

    fn check_params(&self, params: &toml::Table) -> Result<(), ModuleError> {
        parse_params::<Params>(params).map(|_| ())
    }

    /// The ruleset is checked with `nft -c` before it is written; the unit
    /// loads it when it starts.
    fn plan(&self, cx: &PlanCx, _: Sys) -> Result<ModuleSteps, ModuleError> {
        let params: Params = cx.params()?;
        let model = Ruleset::new(cx.facts, &params);
        let ruleset = model.render()?;
        let mut resources = Vec::new();
        if !cx.facts.firewall_tools.nft {
            resources.push(Resource::Package(Package {
                name: "nftables".to_owned(),
            }));
        }
        resources.extend([
            Resource::Directory(Directory {
                path: DIR.into(),
                owner: root(0o755),
            }),
            Resource::File(File {
                path: RULESET.into(),
                content: format!("{ruleset}\n").into_bytes(),
                owner: root(0o644),
                validate: Some(Validate::new("nft", ["-c", "-f", Validate::PATH])),
            }),
            Resource::File(File {
                path: UNIT_FILE.into(),
                content: UNIT_TEXT.as_bytes().to_vec(),
                owner: root(0o644),
                validate: None,
            }),
            Resource::Service(Service {
                unit: UNIT.to_owned(),
                enabled: true,
                active: true,
            }),
        ]);
        // The unit file may change while the unit is active, then the ruleset.
        Ok(ModuleSteps {
            resources,
            reloads: vec![Reload::DaemonReload, Reload::FirewallReload],
            notes: proxied_note(cx.facts, &model).into_iter().collect(),
        })
    }

    /// Reads the loaded table back: it must drop by default and accept every
    /// port the ruleset accepts.
    fn verify(&self, cx: &PlanCx, sys: Sys) -> Result<(), String> {
        let params: Params = cx.params().map_err(|e| e.to_string())?;
        let want = Ruleset::new(cx.facts, &params);
        let cmd = Cmd::new("nft")
            .args(["-j", "list", "table", "inet", "vps_ready"])
            .timeout(NFT_TIMEOUT);
        let out = sys
            .runner
            .run(&cmd)
            .map_err(|e| format!("`nft -j list table inet vps_ready`: {e}"))?;
        if !out.ok() {
            return Err(format!(
                "`nft -j list table inet vps_ready` exited with status {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        check_loaded(&out.stdout, &want)
    }

    fn verify_timeout(&self) -> Duration {
        NFT_TIMEOUT
    }
}

/// The ports Docker publishes for `family` (`ip` or `ip6`), as `5432/tcp`.
fn published(facts: &Facts, family: &str) -> BTreeSet<(u16, String)> {
    facts
        .firewall
        .iter()
        .flat_map(|f| &f.published)
        .filter(|p| p.family == family)
        .map(|p| (p.port, p.proto.clone()))
        .collect()
}

fn show(ports: &BTreeSet<(u16, String)>, quoted: bool) -> String {
    ports
        .iter()
        .map(|(port, proto)| match quoted {
            true => format!("\"{port}/{proto}\""),
            false => format!("{port}/{proto}"),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Over IPv4 the ports Docker publishes are DNATed and forwarded, so this
/// input chain does not see them (FW-002).
fn forwarded_note(facts: &Facts) -> Option<String> {
    let all: BTreeSet<_> = published(facts, "ip")
        .union(&published(facts, "ip6"))
        .cloned()
        .collect();
    (!all.is_empty()).then(|| {
        format!(
            "Docker publishes {}: traffic it forwards to containers does not pass this \
             firewall (FW-002); publish on 127.0.0.1 or filter it in DOCKER-USER",
            show(&all, false)
        )
    })
}

/// Over IPv6 without Docker's ip6tables (the default before Docker 27), a
/// port published only for IPv4 is served by docker-proxy on the host: the
/// connection passes the input chain and is dropped unless `allow` lists
/// the port. Those not in `ruleset` yet.
fn proxied_note(facts: &Facts, ruleset: &Ruleset) -> Option<String> {
    let accepted = |(port, proto): &(u16, String)| match proto.as_str() {
        "tcp" => ruleset.tcp.contains(port),
        "udp" => ruleset.udp.contains(port),
        _ => false,
    };
    let proxied: BTreeSet<_> = published(facts, "ip")
        .difference(&published(facts, "ip6"))
        .filter(|p| !accepted(p))
        .cloned()
        .collect();
    (facts.ipv6 && !proxied.is_empty()).then(|| {
        format!(
            "over IPv6, Docker's ip6tables is off (the default before Docker 27), so \
             connections to {} reach docker-proxy on the host and this firewall drops \
             them; to keep them, add them to `allow`: [{}]",
            show(&proxied, false),
            show(&proxied, true)
        )
    })
}

/// Whether `json`, the loaded table, has an input chain that drops by
/// default and accepts each port of `want`.
fn check_loaded(json: &[u8], want: &Ruleset) -> Result<(), String> {
    let firewall = crate::facts::firewall::parse_json(json)
        .ok_or("unrecognized `nft -j list table` output")?;
    let chain = firewall
        .input_chains
        .iter()
        .find(|c| c.family == "inet" && c.table == "vps_ready")
        .ok_or("the table has no input chain")?;
    if !chain.drops_unmatched {
        return Err("its input chain does not drop by default".to_owned());
    }
    let closed: Vec<String> = [(Proto::Tcp, &want.tcp), (Proto::Udp, &want.udp)]
        .into_iter()
        .flat_map(|(proto, ports)| ports.iter().map(move |p| (proto, *p)))
        .filter(|(proto, port)| chain.blocks(&proto.to_string(), *port) != Some(false))
        .map(|(proto, port)| format!("{proto}/{port}"))
        .collect();
    if closed.is_empty() {
        Ok(())
    } else {
        Err(format!("it does not accept {}", closed.join(", ")))
    }
}

#[cfg(test)]
mod tests;
