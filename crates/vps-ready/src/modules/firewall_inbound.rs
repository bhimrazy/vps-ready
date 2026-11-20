//! The `firewall.inbound` module: a default-deny input chain in vps-ready's
//! own nftables table, `inet vps_ready`, loaded by its own unit.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use askama::Template;
use serde::Deserialize;

use super::{
    Applicability, DOCKER_PACKAGE, Module, ModuleError, ModuleSteps, ParamDoc, PlanCx,
    net_wireguard, parse_params, refuse,
};
use crate::config::STAGED_VIA;
use crate::engine::Reload;
use crate::facts::{Facts, Init, OsFamily, Proto};
use crate::resource::{Directory, File, Package, Resource, Service, Validate};
use crate::sys::{Cmd, FileOwner, Sys, SysError};

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
    /// Accept SSH only on this interface, e.g. `tailscale0`.
    #[serde(default)]
    ssh_via: Via,
}

/// `ssh_via`: an interface name, or `""` for none. A name is what the
/// kernel allows (at most 15 bytes), narrowed to letters, digits, `_`, `-`
/// and `.` so that it is safe in a quoted nft string. The profile turns
/// `"vpn"` into [`STAGED_VIA`] and a name: `staged`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
struct Via {
    name: Option<String>,
    /// Step 1 of 2 (SSH stays public) until a session comes through it.
    staged: bool,
}

impl TryFrom<String> for Via {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        let (name, staged) = match s.strip_prefix(STAGED_VIA) {
            Some(name) => (name, true),
            None => (s.as_str(), false),
        };
        if name.is_empty() {
            return Ok(Self::default());
        }
        let ok = name.len() <= 15
            && name != "."
            && name != ".."
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c));
        if ok {
            Ok(Self {
                name: Some(name.to_owned()),
                staged,
            })
        } else {
            Err(format!(
                "{s:?} is not an interface name (up to 15 letters, digits, `_`, `-` or `.`)"
            ))
        }
    }
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
    /// The SSH ports; never empty.
    ssh: Vec<u16>,
    /// The only interface that SSH is accepted on, if limited.
    ssh_via: Option<String>,
    /// Accepted on any interface: `allow`, and [`Self::ssh`] unless
    /// [`Self::ssh_via`] limits them.
    tcp: Vec<u16>,
    udp: Vec<u16>,
    /// WireGuard listen ports not in [`Self::udp`]: the managed `wg0`'s, and
    /// the `ssh_via` interface's when that is WireGuard.
    wireguard: Vec<u16>,
    /// Accept everything from Docker's bridges.
    docker: bool,
    /// Interfaces named `br-*` that are not Docker's, which that leaves out.
    not_docker: Vec<String>,
}

impl Ruleset {
    fn new(facts: &Facts, params: &Params) -> Self {
        let ssh = ssh_ports(facts);
        let ssh_via = params.ssh_via.name.clone();
        let mut tcp = match ssh_via {
            Some(_) => BTreeSet::new(),
            None => ssh.clone(),
        };
        let mut udp = BTreeSet::new();
        for allow in &params.allow {
            match allow.proto {
                // Left out with a note (`left_out`).
                Proto::Tcp if ssh_via.is_some() && ssh.contains(&allow.port) => false,
                Proto::Tcp => tcp.insert(allow.port),
                Proto::Udp => udp.insert(allow.port),
            };
        }
        Self {
            ssh: ssh.into_iter().collect(),
            ssh_via,
            tcp: tcp.into_iter().collect(),
            udp: udp.into_iter().collect(),
            wireguard: Vec::new(),
            docker: facts.docker,
            not_docker: not_docker(facts),
        }
    }

    /// [`Ruleset::new`], also for a Docker that `cx` plans, with the
    /// WireGuard ports SSH may depend on: the managed `wg0`'s, and that of
    /// `wg_via`, the `ssh_via` interface before step 1 cleared it, when it
    /// is WireGuard.
    fn planned(
        cx: &PlanCx,
        params: &Params,
        wg_via: Option<&str>,
        sys: Sys,
    ) -> Result<Self, ModuleError> {
        let mut ruleset = Self::new(cx.facts, params);
        ruleset.docker |= docker_planned(cx);
        let mut ports = BTreeSet::new();
        let managed = net_wireguard::managed_port(cx.planned, sys)?;
        ports.extend(managed);
        if let Some(via) = wg_via
            && runtime_port_counts(cx.facts, via, managed)
        {
            match cx.facts.wireguard.listen_ports.get(via) {
                Some(port) => {
                    ports.insert(*port);
                }
                // Unknown now (`wg show` failed): keep what the loaded
                // ruleset accepts, so a re-apply does not drop it.
                None => ports.extend(loaded_wireguard_ports(cx.planned, sys)?),
            }
        }
        ruleset.wireguard = ports
            .into_iter()
            .filter(|p| !ruleset.udp.contains(p))
            .collect();
        Ok(ruleset)
    }
}

/// Whether the running listen port of `via` is the one to accept: it is a
/// WireGuard interface other than the managed `wg0`, whose port is the
/// file's, which this apply sets.
fn runtime_port_counts(facts: &Facts, via: &str, managed: Option<u16>) -> bool {
    let wireguard = facts
        .interfaces
        .iter()
        .any(|i| i.name == via && i.is_wireguard());
    wireguard && !(via == net_wireguard::INTERFACE && managed.is_some())
}

/// Refuses `ssh_via` on a WireGuard interface whose listen port is unknown
/// (`wg show` needs root and wireguard-tools) and that `allow` opens no UDP
/// port for: the firewall would drop its packets and with them SSH. A note
/// instead when the rule does not change, or `allow` has UDP ports.
fn unknown_port(
    cx: &PlanCx,
    model: &Ruleset,
    via: &str,
    same: bool,
    sys: Sys,
) -> Result<Option<String>, ModuleError> {
    let managed = net_wireguard::managed_port(cx.planned, sys)?;
    if !runtime_port_counts(cx.facts, via, managed)
        || cx.facts.wireguard.listen_ports.contains_key(via)
    {
        return Ok(None);
    }
    let unread = format!(
        "{via} is a WireGuard interface whose listen port vps-ready cannot read (`wg show all \
         listen-port` failed)"
    );
    if !model.wireguard.is_empty() {
        let kept: Vec<String> = model.wireguard.iter().map(u16::to_string).collect();
        return Ok(Some(format!(
            "{unread}; the WireGuard UDP ports the loaded ruleset accepts stay accepted: {}",
            kept.join(", ")
        )));
    }
    let why = format!("{unread}, so this firewall accepts it only if `allow` lists it");
    if model.udp.is_empty() && model.ssh_via.is_some() && !same {
        return refuse(&format!(
            "{why}: add it, e.g. allow = [\"51820/udp\"], or SSH through {via} stops"
        ));
    }
    let listed: Vec<String> = model.udp.iter().map(|p| format!("{p}/udp")).collect();
    Ok(Some(if listed.is_empty() {
        format!("{why}: add its port, e.g. allow = [\"51820/udp\"]")
    } else {
        format!(
            "{why}: make sure its port is among those `allow` lists ({})",
            listed.join(", ")
        )
    }))
}

/// The ports of the WireGuard line of the ruleset in `planned`, else the
/// one on disk, as `templates/firewall.nft` renders it.
fn loaded_wireguard_ports(planned: &[Resource], sys: Sys) -> Result<Vec<u16>, ModuleError> {
    let Some(text) = ruleset_text(planned, sys)? else {
        return Ok(Vec::new());
    };
    Ok(wireguard_ports_of(&text))
}

/// The ports of the `udp dport { ... } accept` line after the WireGuard
/// comment of `templates/firewall.nft`.
fn wireguard_ports_of(ruleset: &str) -> Vec<u16> {
    let mut lines = ruleset.lines().map(str::trim);
    while let Some(line) = lines.next() {
        if !line.starts_with(WIREGUARD_COMMENT) {
            continue;
        }
        return lines
            .find_map(|l| l.strip_prefix("udp dport {")?.strip_suffix("} accept"))
            .into_iter()
            .flat_map(|ports| ports.split(','))
            .filter_map(|p| p.trim().parse().ok())
            .collect();
    }
    Vec::new()
}

/// The comment above the WireGuard line in `templates/firewall.nft`.
const WIREGUARD_COMMENT: &str = "# WireGuard, which SSH may depend on.";

/// Whether the ruleset on disk accepts UDP `port` from anywhere.
///
/// # Errors
///
/// Reading the ruleset on disk.
pub(crate) fn accepts_udp(sys: Sys, port: u16) -> Result<bool, ModuleError> {
    let Some(text) = ruleset_text(&[], sys)? else {
        return Ok(false);
    };
    Ok(text.lines().any(|l| {
        l.trim()
            .strip_prefix("udp dport {")
            .and_then(|r| r.strip_suffix("} accept"))
            .is_some_and(|ports| ports.split(',').any(|p| p.trim().parse() == Ok(port)))
    }))
}

/// The WireGuard interfaces whose ports this ruleset does not accept, which
/// the admin opens through `allow` if they are needed.
fn wireguard_note(facts: &Facts, ruleset: &Ruleset) -> Option<String> {
    let closed: Vec<String> = facts
        .wireguard
        .listen_ports
        .iter()
        .filter(|(_, port)| !ruleset.udp.contains(port) && !ruleset.wireguard.contains(port))
        .map(|(name, port)| format!("{name} on UDP {port}"))
        .collect();
    (!closed.is_empty()).then(|| {
        format!(
            "WireGuard listens on ports this firewall drops: {}; to keep one reachable, add it to \
             `allow`, e.g. \"<port>/udp\"",
            closed.join(", ")
        )
    })
}

/// Whether a module before this one, `deploy.docker`, installs Docker in
/// the same plan. Its bridges do not exist yet, and rules for them are
/// valid all the same, so one apply is enough.
fn docker_planned(cx: &PlanCx) -> bool {
    cx.planned
        .iter()
        .any(|r| matches!(r, Resource::Package(p) if p.names.iter().any(|n| n == DOCKER_PACKAGE)))
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

/// Why a module that needs [`ssh_ports`] does not apply when it is empty.
pub(crate) const SSH_PORT_UNKNOWN: &str =
    "the SSH port is unknown: no SSH session, sshd listener, `sshd -T` or ssh.socket shows it";

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
        &[
            ParamDoc {
                name: "allow",
                default: "[]",
                help: "Ports to accept from anywhere, e.g. [\"443/tcp\", \"443/udp\"]; the SSH ports are always accepted, only on `ssh_via` when it is set.",
            },
            ParamDoc {
                name: "ssh_via",
                default: "\"\"",
                help: "Accept SSH only on this interface, e.g. \"tailscale0\" or \"wg0\", from a session through it; \"vpn\" for the profile's VPN module's interface, which keeps SSH public until applied from a session through it (the private profile), so an interface named vpn cannot be used; empty for any.",
            },
        ]
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
            SSH_PORT_UNKNOWN
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
        let mut notes = vec![
            format!(
                "always accepts TCP {ports}, the current SSH ports (this session's, root's sshd \
                 listeners and `Port`), whatever `allow` says"
            ),
            "drops incoming IPv4 TCP that carries IP options, also to containers, to blunt \
             CVE-2026-98432 until the kernel is updated and rebooted; TCP labeled with \
             CIPSO (NetLabel) stops working"
                .to_owned(),
        ];
        if facts.docker {
            notes.extend(docker_notes(facts, "Docker is installed"));
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
        notes.extend(crate::audit::tailscale_expiry(facts));
        notes
    }

    fn check_params(&self, params: &toml::Table) -> Result<(), ModuleError> {
        parse_params::<Params>(params).map(|_| ())
    }

    /// The ruleset is checked with `nft -c` before it is written; the unit
    /// loads it when it starts.
    fn plan(&self, cx: &PlanCx, sys: Sys) -> Result<ModuleSteps, ModuleError> {
        let mut params: Params = cx.params()?;
        let wg_via = params.ssh_via.name.clone();
        let mut notes: Vec<String> = stage(cx, &mut params, sys, false)?.into_iter().collect();
        let model = Ruleset::planned(cx, &params, wg_via.as_deref(), sys)?;
        let ruleset = model.render()?;
        notes.extend(wireguard_note(cx.facts, &model));
        if !cx.facts.docker && docker_planned(cx) {
            notes.extend(docker_notes(cx.facts, "deploy.docker installs Docker"));
        }
        notes.extend(proxied_note(cx.facts, &model));
        if let Some(via) = &model.ssh_via {
            notes.extend(left_out(&params, &model, via));
            // The same interface and ports: the SSH rule does not change.
            let on_disk = ruleset_text(cx.planned, sys)?.and_then(|t| ssh_rule_of(&t));
            let same = on_disk.is_some() && on_disk == ssh_rule_of(&ruleset);
            let checked = via::check(cx.facts, via, same, sys)?;
            notes.extend(unknown_port(cx, &model, via, same, sys)?);
            notes.extend(checked);
        } else if let Some(via) = &wg_via {
            notes.extend(unknown_port(cx, &model, via, true, sys)?);
        }
        let mut resources = Vec::new();
        if !cx.facts.firewall_tools.nft {
            resources.push(Resource::Package(Package {
                names: vec!["nftables".to_owned()],
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
                describe: None,
            }),
            Resource::File(File {
                path: UNIT_FILE.into(),
                content: UNIT_TEXT.as_bytes().to_vec(),
                owner: root(0o644),
                validate: None,
                describe: None,
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
            notes,
            deadman: false,
        })
    }

    /// Reads the loaded table back: it must drop by default and accept every
    /// port the ruleset accepts.
    fn verify(&self, cx: &PlanCx, sys: Sys) -> Result<(), String> {
        let mut params: Params = cx.params().map_err(|e| e.to_string())?;
        let wg_via = params.ssh_via.name.clone();
        stage(cx, &mut params, sys, true).map_err(|e| e.to_string())?;
        let want =
            Ruleset::planned(cx, &params, wg_via.as_deref(), sys).map_err(|e| e.to_string())?;
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

/// Step 1 of a staged `ssh_via` (the private profile's `"vpn"`): while
/// this is not a session through the interface and the loaded ruleset does
/// not limit SSH to it yet, drops it from `params`, so SSH stays public,
/// and returns the note. Otherwise `params` stays, and the checks of an
/// explicit `ssh_via` apply. Refused while the loaded ruleset limits SSH to
/// another interface: dropping it would reopen SSH publicly (`verifying`
/// words that for `verify`, which changes nothing).
fn stage(
    cx: &PlanCx,
    params: &mut Params,
    sys: Sys,
    verifying: bool,
) -> Result<Option<String>, ModuleError> {
    let Via {
        name: Some(via),
        staged: true,
    } = &params.ssh_via
    else {
        return Ok(None);
    };
    if via::through(cx.facts, via) {
        return Ok(None);
    }
    match ssh_via(cx.planned, sys)? {
        Some(loaded) if loaded == *via => return Ok(None),
        Some(loaded) if verifying => {
            return refuse(&format!(
                "SSH is limited to {loaded}, but the profile's `ssh_via` is {via}, which this \
                 session does not come through, so the ruleset to check cannot be known: verify \
                 from a login through {via}, or set `ssh_via = \"{loaded}\"`"
            ));
        }
        Some(loaded) => {
            return refuse(&format!(
                "SSH is already limited to {loaded}, and step 1 would reopen it publicly: keep \
                 `ssh_via = \"{loaded}\"` while {via} comes up, then apply this from a login \
                 through {via}; or set `ssh_via = \"\"` to reopen it on purpose"
            ));
        }
        None => {}
    }
    let note = via::step_one(cx.facts, via);
    params.ssh_via = Via::default();
    Ok(Some(note))
}

/// What accepting input from Docker's bridges means, after `why`, e.g.
/// `Docker is installed`.
fn docker_notes(facts: &Facts, why: &str) -> Vec<String> {
    let mut notes = vec![format!(
        "{why}: input from docker0 and br-* is accepted, so containers can reach \
         services on the host; a compromised container can reach all of them, as with \
         no firewall"
    )];
    let others = not_docker(facts);
    if !others.is_empty() {
        notes.push(format!(
            "filtered like any other interface, since Docker did not name them: {}",
            others.join(", ")
        ));
    }
    notes
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

/// The TCP ports this module accepts from anywhere: by the ruleset that a
/// module before the caller plans, else by the one on disk from an earlier
/// apply; `None` when there is neither.
///
/// # Errors
///
/// Reading the ruleset on disk.
pub(crate) fn accepted_tcp(cx: &PlanCx, sys: Sys) -> Result<Option<BTreeSet<u16>>, ModuleError> {
    Ok(ruleset_text(cx.planned, sys)?.map(|text| tcp_ports(&text)))
}

/// The UDP ports of [`accepted_tcp`]'s ruleset, which includes WireGuard's.
///
/// # Errors
///
/// Reading the ruleset on disk.
pub(crate) fn accepted_udp(cx: &PlanCx, sys: Sys) -> Result<Option<BTreeSet<u16>>, ModuleError> {
    Ok(ruleset_text(cx.planned, sys)?.map(|text| {
        text.lines()
            .filter_map(|l| {
                l.trim()
                    .strip_prefix("udp dport {")?
                    .strip_suffix("} accept")
            })
            .flat_map(|ports| ports.split(','))
            .filter_map(|p| p.trim().parse().ok())
            .collect()
    }))
}

/// The interface SSH is limited to (`ssh_via`) by the ruleset in `planned`,
/// else by the one on disk, which the unit loads; `None` when neither
/// limits it.
///
/// # Errors
///
/// Reading the ruleset on disk.
pub(crate) fn ssh_via(planned: &[Resource], sys: Sys) -> Result<Option<String>, ModuleError> {
    Ok(ruleset_text(planned, sys)?.and_then(|text| via_of(&text)))
}

/// The ruleset in `planned`, else the one on disk; `None` without either.
fn ruleset_text(planned: &[Resource], sys: Sys) -> Result<Option<String>, ModuleError> {
    let planned = planned.iter().find_map(|r| match r {
        Resource::File(f) if f.path == Path::new(RULESET) => Some(f.content.clone()),
        _ => None,
    });
    let text = match planned {
        Some(text) => text,
        None => match sys.fs.read(Path::new(RULESET)) {
            Ok(text) => text,
            Err(SysError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        },
    };
    Ok(Some(String::from_utf8_lossy(&text).into_owned()))
}

/// The interface of the `iifname "<if>" tcp dport { ... } accept` line
/// that `templates/firewall.nft` renders for `ssh_via`.
pub(crate) fn via_of(ruleset: &str) -> Option<String> {
    let rule = ssh_rule_of(ruleset)?;
    let (name, _) = rule.strip_prefix("iifname \"")?.split_once('"')?;
    Some(name.to_owned())
}

/// That line, trimmed.
fn ssh_rule_of(ruleset: &str) -> Option<String> {
    ruleset.lines().map(str::trim).find_map(|l| {
        let (_, rest) = l.strip_prefix("iifname \"")?.split_once('"')?;
        let rest = rest.trim_start();
        (rest.starts_with("tcp dport {") && rest.ends_with("} accept")).then(|| l.to_owned())
    })
}

/// The note for SSH ports in `allow`, which `ssh_via` leaves out of the
/// ports open to any interface. Not a refusal, so that a profile extending
/// `minimal` or `web` (both allow `22/tcp`) need not restate `allow`.
fn left_out(params: &Params, model: &Ruleset, via: &str) -> Option<String> {
    let ports: Vec<String> = params
        .allow
        .iter()
        .filter(|a| a.proto == Proto::Tcp && model.ssh.contains(&a.port))
        .map(|a| format!("{}/tcp", a.port))
        .collect();
    let is = if ports.len() == 1 { "is" } else { "are" };
    (!ports.is_empty()).then(|| {
        format!(
            "{} in `allow` {is} left out: `ssh_via` limits SSH to {via}",
            ports.join(", ")
        )
    })
}

/// The ports of the `tcp dport { ... } accept` line that
/// `templates/firewall.nft` renders.
fn tcp_ports(ruleset: &str) -> BTreeSet<u16> {
    ruleset
        .lines()
        .filter_map(|l| {
            l.trim()
                .strip_prefix("tcp dport {")?
                .strip_suffix("} accept")
        })
        .flat_map(|ports| ports.split(','))
        .filter_map(|p| p.trim().parse().ok())
        .collect()
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
    let closed: Vec<String> = [
        (Proto::Tcp, &want.tcp),
        (Proto::Udp, &want.udp),
        (Proto::Udp, &want.wireguard),
    ]
    .into_iter()
    .flat_map(|(proto, ports)| ports.iter().map(move |p| (proto, *p)))
    .filter(|(proto, port)| chain.blocks(&proto.to_string(), *port) != Some(false))
    .map(|(proto, port)| format!("{proto}/{port}"))
    .collect();
    if !closed.is_empty() {
        return Err(format!("it does not accept {}", closed.join(", ")));
    }
    let Some(via) = &want.ssh_via else {
        return Ok(());
    };
    // Public SSH is closed only if nothing but the `ssh_via` rule accepts
    // the SSH ports. A rule that accepts all ports on one interface
    // (`iifname "x" accept`) is not seen: the parser takes it as narrow.
    let only_via = |p: &crate::facts::InterfacePorts| p.interfaces == [via.as_str()];
    let mut wrong = Vec::new();
    for &port in &want.ssh {
        let via_rules: Vec<_> = chain
            .interface_ports
            .iter()
            .filter(|p| p.ports.contains("tcp", port))
            .collect();
        if chain.open_ports.iter().any(|p| p.contains("tcp", port))
            || chain.unread_ports.iter().any(|p| p == "tcp")
            || via_rules.iter().any(|p| !only_via(p))
        {
            wrong.push(format!(
                "it accepts tcp/{port} on interfaces other than {via}"
            ));
        } else if via_rules.is_empty() {
            wrong.push(format!("it does not accept tcp/{port} on {via}"));
        }
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(wrong.join("; "))
    }
}

#[cfg(test)]
mod tests;
mod via;

pub(crate) use via::{
    address, console, is_tailscale, is_tailscale_in, private_via, through, uncounted_via,
};
