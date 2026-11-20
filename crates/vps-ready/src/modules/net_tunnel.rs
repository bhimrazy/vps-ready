//! The `net.tunnel` module: Cloudflare Tunnel's connector, `cloudflared`,
//! from Cloudflare's repository, running as vps-ready's own sandboxed unit
//! with the tunnel's token from a root-only file.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use askama::Template;
use serde::Deserialize;

use super::{
    Applicability, Module, ModuleError, ModuleSteps, ParamDoc, PlanCx, parse_params, refuse,
};
use crate::engine::Reload;
/// The connector's unit, which `Reload::CloudflaredRestart` restarts.
pub const UNIT: &str = "vps-ready-cloudflared.service";
use crate::facts::{Facts, Init, OsFamily, Proto, parse_units, prop};
use crate::resource::{
    AptSource, Directory, File, Package, Resource, Service, Validate, apt_source, architecture,
    check_key_file,
};
use crate::sys::{Cmd, FileOwner, Output, Sys, SysError};

/// cloudflared's package, from Cloudflare's repository.
pub const PACKAGE: &str = "cloudflared";

/// The binary the units run and the path unit watches.
const BINARY: &str = "/usr/bin/cloudflared";

const DIR: &str = "/etc/vps-ready";
const UNIT_FILE: &str = "/etc/systemd/system/vps-ready-cloudflared.service";
/// Restarts the connector after an upgrade replaced [`BINARY`].
const RESTART_UNIT: &str = "vps-ready-cloudflared-restart.service";
const RESTART_UNIT_FILE: &str = "/etc/systemd/system/vps-ready-cloudflared-restart.service";
const PATH_UNIT: &str = "vps-ready-cloudflared-restart.path";
const PATH_UNIT_FILE: &str = "/etc/systemd/system/vps-ready-cloudflared-restart.path";

/// The connector's config file. Without `--config`, cloudflared would read
/// a `config.yml` it finds in `/etc/cloudflared` instead.
const CONFIG: &str = "/etc/vps-ready/cloudflared.yml";
/// Not empty on purpose: an empty config logs an error at every start.
const CONFIG_TEXT: &str = "\
# Written by vps-ready (net.tunnel). `vps-ready rollback --last` restores
# the previous state; edits here are replaced by the next apply.
# vps-ready-cloudflared.service reads it, and no other config file.
no-autoupdate: true
";

const RESTART_SCRIPT: &str = "/etc/vps-ready/cloudflared-restart.sh";
const RESTART_SCRIPT_TEXT: &str = include_str!("../../templates/cloudflared-restart.sh");

const RESTART_UNIT_TEXT: &str = "\
# Written by vps-ready (net.tunnel). `vps-ready rollback --last` restores
# the previous state; edits here are replaced by the next apply.
[Unit]
Description=Restart the Cloudflare Tunnel connector on a new cloudflared (vps-ready net.tunnel)

[Service]
Type=oneshot
TimeoutStartSec=10min
ExecStart=/bin/sh /etc/vps-ready/cloudflared-restart.sh
";

const PATH_UNIT_TEXT: &str = "\
# Written by vps-ready (net.tunnel). `vps-ready rollback --last` restores
# the previous state; edits here are replaced by the next apply.
[Unit]
Description=Watch cloudflared for upgrades (vps-ready net.tunnel)

[Path]
PathChanged=/usr/bin/cloudflared
Unit=vps-ready-cloudflared-restart.service

[Install]
WantedBy=multi-user.target
";

/// Adds Cloudflare's repository to unattended-upgrades' origins. Its
/// `Release` file says `Codename: any`, so `${distro_codename}` would never
/// match.
const ORIGINS: &str = "/etc/apt/apt.conf.d/52vps-ready-cloudflared";

const ORIGINS_CONTENT: &str = "\
// Written by vps-ready (net.tunnel). `vps-ready rollback --last` removes it.
Unattended-Upgrade::Origins-Pattern { \"origin=cloudflared,codename=any\"; };
";

/// The metrics server, fixed so verify can find it.
pub const METRICS_PORT: u16 = 20241;
const METRICS: &str = "127.0.0.1:20241";

/// `--token-file` needs it.
const MIN_VERSION: (u32, u32, u32) = (2025, 4, 0);

/// Kill timeout of each command verify runs.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);

/// The only provider in this version.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Provider {
    #[default]
    Cloudflare,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    /// Parsed so that another value is an error; nothing reads it yet.
    #[serde(default, rename = "provider")]
    _provider: Provider,
    /// Empty: install only; the plan says how to add a token.
    #[serde(default)]
    token_file: String,
    #[serde(default = "yes")]
    auto_update: bool,
}

const fn yes() -> bool {
    true
}

impl Params {
    /// `token_file` goes into the unit's `LoadCredential=` line as it is.
    fn check(&self) -> Result<(), ModuleError> {
        let path = &self.token_file;
        let plain = path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c));
        if !path.is_empty() && (!path.starts_with('/') || !plain) {
            return refuse(&format!(
                "token_file {path:?} is not an absolute path of letters, digits, `.`, `_`, `-` \
                 and `/`, which the connector unit takes as it is"
            ));
        }
        Ok(())
    }
}

/// The connector unit, as `templates/cloudflared.service` renders it.
#[derive(Debug, Template)]
#[template(path = "cloudflared.service", escape = "none")]
struct ConnectorUnit<'a> {
    token_file: &'a str,
    /// `--edge-ip-version auto`, on a host with no IPv4 default route.
    edge_auto: bool,
    /// The resolvers in `/etc/resolv.conf`, allowed besides loopback.
    resolvers: Vec<IpAddr>,
}

/// Runs a Cloudflare Tunnel connector for a remotely-managed tunnel, so a
/// web app is reachable with no inbound port. Debian family with systemd.
#[derive(Debug, Clone, Copy)]
pub struct NetTunnel;

impl Module for NetTunnel {
    fn id(&self) -> &'static str {
        "net.tunnel"
    }

    fn title(&self) -> &'static str {
        "Run a Cloudflare Tunnel connector, for a website with no public port"
    }

    fn why(&self) -> &'static str {
        "A web server on ports 80 and 443 is open to every scanner on the internet. \
         A Cloudflare Tunnel connector opens outbound connections to Cloudflare's edge \
         and receives visitors through them, so the host needs no inbound port at all; \
         firewall.inbound can then leave 80 and 443 closed."
    }

    fn params_doc(&self) -> &'static [ParamDoc] {
        &[
            ParamDoc {
                name: "provider",
                default: "\"cloudflare\"",
                help: "The tunnel provider; \"cloudflare\" is the only one.",
            },
            ParamDoc {
                name: "token_file",
                default: "\"\"",
                help: "A file holding the token of a tunnel created in the Cloudflare dashboard, owned by root with mode 0600, not a symlink, in directories only root can write to. The connector's unit copies it at each start (`LoadCredential=`); vps-ready never reads it. After replacing it, run `sudo systemctl restart vps-ready-cloudflared`. Empty: cloudflared is installed, and no connector runs.",
            },
            ParamDoc {
                name: "auto_update",
                default: "true",
                help: "Let unattended-upgrades (updates.auto) install cloudflared's updates; a path unit then restarts the connector on the new binary, which drops visitors' connections for a moment.",
            },
        ]
    }

    fn applicable(&self, facts: &Facts) -> Applicability {
        let other = other_units(facts);
        let reason = if facts.os.family != OsFamily::Debian {
            "the tunnel is set up only on Debian and Ubuntu so far".to_owned()
        } else if facts.init != Init::Systemd {
            "it needs systemd, to run the connector".to_owned()
        } else if !other.is_empty() {
            format!(
                "a cloudflared unit that vps-ready did not write exists ({}), so this tunnel \
                 setup is left alone",
                other.join(", ")
            )
        } else {
            return Applicability::Applicable;
        };
        Applicability::NotApplicable { reason }
    }

    fn notes(&self, _facts: &Facts) -> Vec<String> {
        vec![
            "no port is opened: the connector connects out to Cloudflare's edge on port 7844 \
             (TCP and UDP), and firewall.inbound's established,related rule covers the replies"
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
        let mut resources = Vec::new();
        let mut notes = Vec::new();
        let mut reloads = Vec::new();

        if let Some(version) = &facts.cloudflared.version {
            match parse_triple(version) {
                Some(v) if v < MIN_VERSION => {
                    return refuse(&format!(
                        "cloudflared {version} is installed, and the connector needs 2025.4.0 or \
                         later for `--token-file`: upgrade it (`sudo apt-get install cloudflared`) \
                         or remove the pinned or hand-installed binary, then apply again"
                    ));
                }
                Some(_) => {}
                None => notes.push(format!(
                    "cloudflared says its version is {version:?}, which is not a release number; \
                     the connector needs 2025.4.0 or later"
                )),
            }
        }

        let source = AptSource::cloudflared();
        // Cloudflare's install docs write their own `cloudflared.list`; a
        // second source with another `Signed-By` breaks `apt-get update`.
        if source.configured_elsewhere(sys)? {
            notes.push(
                "another apt source already names pkg.cloudflare.com/cloudflared, so vps-ready \
                 adds none; cloudflared updates from that one"
                    .to_owned(),
            );
        } else {
            resources.extend(apt_source(&source, &architecture(sys)?));
        }
        if params.auto_update {
            resources.push(Resource::File(File {
                path: ORIGINS.into(),
                content: ORIGINS_CONTENT.into(),
                owner: root(0o644),
                validate: Some(Validate::new("apt-config", ["-c", Validate::PATH, "dump"])),
                describe: None,
            }));
        }
        resources.push(Resource::Package(Package {
            names: vec![PACKAGE.to_owned()],
        }));

        if params.token_file.is_empty() {
            notes.push(
                "no token_file, so no connector runs: create a tunnel in the Cloudflare \
                 dashboard, save its token to a root-only file, set `token_file` and apply again"
                    .to_owned(),
            );
            return Ok(ModuleSteps {
                resources,
                reloads,
                notes,
                deadman: false,
            });
        }

        let path = Path::new(&params.token_file);
        if let Err(why) = check_key_file(sys, path) {
            return refuse(&format!(
                "token_file {}: {why}; it must be a regular file owned by root with mode 0600, \
                 in directories only root can write to",
                path.display()
            ));
        }
        let ours_active = facts.cloudflared.active.iter().any(|u| u == UNIT);
        if !ours_active && metrics_port_taken(facts) {
            return refuse(&format!(
                "something already listens on {METRICS}, the connector's metrics address, which \
                 vps-ready keeps fixed so verify can find it: stop it, or move it to another \
                 port, and apply again"
            ));
        }

        let resolvers = resolvers(sys)?;
        let edge_auto = !facts.routes.is_empty() && !has_ipv4_default(facts);
        if edge_auto {
            notes.push(
                "this host has no IPv4 default route, so the connector reaches Cloudflare's edge \
                 over IPv6 too (`--edge-ip-version auto`)"
                    .to_owned(),
            );
        }
        let unit = ConnectorUnit {
            token_file: &params.token_file,
            edge_auto,
            resolvers: resolvers.clone(),
        }
        .render()?;
        let connector = vec![
            Resource::Directory(Directory {
                path: DIR.into(),
                owner: root(0o755),
            }),
            file(CONFIG, CONFIG_TEXT.into(), None),
            file(
                RESTART_SCRIPT,
                RESTART_SCRIPT_TEXT.into(),
                Some(Validate::new("sh", ["-n", Validate::PATH])),
            ),
            file(UNIT_FILE, format!("{unit}\n"), None),
            file(RESTART_UNIT_FILE, RESTART_UNIT_TEXT.into(), None),
            file(PATH_UNIT_FILE, PATH_UNIT_TEXT.into(), None),
        ];
        // A running connector reads its unit and config only at start.
        let mut changed = false;
        for r in &connector[1..4] {
            changed |= r.diff(sys)?.is_some();
        }
        resources.extend(connector);
        resources.push(Resource::Service(Service {
            unit: UNIT.to_owned(),
            enabled: true,
            active: true,
        }));
        resources.push(Resource::Service(Service {
            unit: PATH_UNIT.to_owned(),
            enabled: true,
            active: true,
        }));
        reloads.push(Reload::DaemonReload);
        if ours_active && changed {
            reloads.push(Reload::CloudflaredRestart);
        }

        notes.extend(resolver_notes(&resolvers));
        notes.extend(filter_note(facts, sys, ours_active));
        if !facts.cloudflared.configs.is_empty() {
            let configs: Vec<String> = facts
                .cloudflared
                .configs
                .iter()
                .map(|p| p.display().to_string())
                .collect();
            notes.push(format!(
                "{} is left alone: the connector reads only {CONFIG}",
                configs.join(" and ")
            ));
        }
        notes.push(format!(
            "the connector's start waits for its first connection to Cloudflare; if the start \
             fails, the tunnel did not connect: check the token in {} and that outbound port \
             7844 is open, then apply again",
            path.display()
        ));
        notes.push(format!(
            "any local user can read the connector's metrics on {METRICS} (connection counts, \
             the tunnel's ID, the cloudflared version), but not the token"
        ));
        notes.push(
            "in the Cloudflare dashboard, give this tunnel a published route for each site, \
             e.g. app.example.com -> http://127.0.0.1:80. With deploy.proxy, Caddy answers on \
             127.0.0.1:80. Without it, point the route at your app's loopback address instead. \
             Only loopback targets work: the connector cannot reach Docker bridges or private \
             networks, so such a route answers 502"
                .to_owned(),
        );
        notes.push(
            "anyone who controls this Cloudflare account can route the internet to any address \
             this host reaches on loopback, including SSH. Turn on two-factor login for the \
             account, and add no routes to ssh:// or other local services"
                .to_owned(),
        );
        if !ours_active {
            notes.push(format!(
                "rollback stops and removes the connector and its units, and keeps the \
                 cloudflared package and {}; the tunnel then shows as down in the dashboard, \
                 where deleting it is up to you",
                path.display()
            ));
        }
        Ok(ModuleSteps {
            resources,
            reloads,
            notes,
            deadman: false,
        })
    }

    /// With a token: the connector is active, has a connection to the
    /// edge (`cloudflared tunnel ready`), and runs the installed binary.
    fn verify(&self, cx: &PlanCx, sys: Sys) -> Result<(), String> {
        let params: Params = cx.params().map_err(|e| e.to_string())?;
        if params.token_file.is_empty() {
            return Ok(());
        }
        let show = Cmd::new("systemctl")
            .args(["show", "--property=ActiveState,MainPID"])
            .arg(UNIT)
            .timeout(VERIFY_TIMEOUT);
        let out = run(sys, &show)?;
        let units = parse_units(&String::from_utf8_lossy(&out.stdout));
        let props = units.first().cloned().unwrap_or_default();
        let pid = prop(&props, "MainPID");
        if prop(&props, "ActiveState") != "active" || pid.is_empty() || pid == "0" {
            return Err(format!("{UNIT} is not active"));
        }
        let ready = Cmd::new("cloudflared")
            .args(["tunnel", "--metrics", METRICS, "ready"])
            .timeout(VERIFY_TIMEOUT);
        let out = run(sys, &ready)?;
        if !out.ok() {
            return Err(format!(
                "the tunnel has no connection to Cloudflare's edge (`cloudflared tunnel ready` \
                 exited with status {}): check the token in {} and that outbound port 7844 is \
                 open, then apply again",
                out.status, params.token_file
            ));
        }
        if !runs_installed_binary(sys, pid)? {
            return Err(format!(
                "cloudflared runs an old binary: {BINARY} was replaced since the connector \
                 started; `sudo systemctl restart {UNIT}` starts the new one"
            ));
        }
        Ok(())
    }

    fn verify_timeout(&self) -> Duration {
        VERIFY_TIMEOUT * 3
    }
}

const fn root(mode: u32) -> FileOwner {
    FileOwner {
        mode,
        uid: 0,
        gid: 0,
    }
}

fn file(path: &str, content: String, validate: Option<Validate>) -> Resource {
    Resource::File(File {
        path: path.into(),
        content: content.into_bytes(),
        owner: root(0o644),
        validate,
        describe: None,
    })
}

fn run(sys: Sys, cmd: &Cmd) -> Result<Output, String> {
    sys.runner
        .run(cmd)
        .map_err(|e| format!("`{} {}`: {e}", cmd.program, cmd.args.join(" ")))
}

/// cloudflared units other than vps-ready's own.
fn other_units(facts: &Facts) -> Vec<String> {
    facts
        .cloudflared
        .units
        .iter()
        .filter(|u| ![UNIT, RESTART_UNIT, PATH_UNIT].contains(&u.as_str()))
        .cloned()
        .collect()
}

/// `2026.11.1` as numbers.
fn parse_triple(version: &str) -> Option<(u32, u32, u32)> {
    let mut parts = version.split('.').map(str::parse::<u32>);
    let triple = (
        parts.next()?.ok()?,
        parts.next()?.ok()?,
        parts.next()?.ok()?,
    );
    parts.next().is_none().then_some(triple)
}

/// Whether a TCP listener holds the metrics port on loopback or on every
/// address.
fn metrics_port_taken(facts: &Facts) -> bool {
    facts.listeners.iter().any(|l| {
        l.proto == Proto::Tcp
            && l.port == METRICS_PORT
            && matches!(l.addr.as_str(), "127.0.0.1" | "0.0.0.0" | "*" | "::")
    })
}

/// A main-table default route that is not over IPv6; an unknown one
/// counts as IPv4.
fn has_ipv4_default(facts: &Facts) -> bool {
    facts.routes.iter().any(|r| {
        r.dst == "default" && r.table.is_none() && !matches!(r.gateway, Some(IpAddr::V6(_)))
    })
}

/// The non-loopback nameservers in `/etc/resolv.conf`, in order, without
/// an IPv6 zone ID, which `IPAddressAllow=` does not accept.
fn resolvers(sys: Sys) -> Result<Vec<IpAddr>, ModuleError> {
    let text = match sys.fs.read(Path::new("/etc/resolv.conf")) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(SysError::NotFound(_)) => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    Ok(parse_resolvers(&text))
}

fn parse_resolvers(text: &str) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("nameserver") {
            continue;
        }
        let Some(addr) = words.next() else { continue };
        let addr = addr.split_once('%').map_or(addr, |(a, _)| a);
        if let Ok(ip) = addr.parse::<IpAddr>()
            && !ip.is_loopback()
            && !out.contains(&ip)
        {
            out.push(ip);
        }
    }
    out
}

/// Whether `ip` is in a range the unit's `IPAddressDeny=` lists.
fn denied(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_link_local()
                || v4.is_multicast()
                || v4.is_private()
                || (a == 100 && (64..128).contains(&b))
                || v4 == std::net::Ipv4Addr::new(168, 63, 129, 16)
        }
        IpAddr::V6(v6) => v6.is_unicast_link_local() || v6.is_unique_local() || v6.is_multicast(),
    }
}

fn resolver_notes(resolvers: &[IpAddr]) -> Option<String> {
    let inside: Vec<String> = resolvers
        .iter()
        .filter(|ip| denied(**ip))
        .map(ToString::to_string)
        .collect();
    (!inside.is_empty()).then(|| {
        format!(
            "the resolver {} in /etc/resolv.conf is in a range the connector may not reach \
             otherwise, so it stays reachable through it (on Google Cloud the resolver is the \
             metadata address, on Azure 168.63.129.16). When the resolvers change, apply again",
            inside.join(", ")
        )
    })
}

/// systemd enforces the unit's address filter with cgroup BPF, and without
/// it only logs a warning.
fn filter_note(facts: &Facts, sys: Sys, ours_active: bool) -> Option<String> {
    let off = "the connector's address filter (`IPAddressDeny=`) is not in effect on this host";
    if ours_active {
        let cmd = Cmd::new("journalctl")
            .args(["-b", "-u", UNIT, "--no-pager", "-o", "cat"])
            .args(["-g", "does not support BPF/cgroup firewalling"])
            .timeout(VERIFY_TIMEOUT);
        let said = sys
            .runner
            .run(&cmd)
            .ok()
            .is_some_and(|o| !String::from_utf8_lossy(&o.stdout).trim().is_empty());
        if said {
            return Some(format!("{off}: systemd says it does not support it"));
        }
    }
    if facts.virtualization.in_container() {
        Some(format!(
            "{off} if the container does not support cgroup BPF"
        ))
    } else if !sys
        .fs
        .exists(Path::new("/sys/fs/cgroup/cgroup.controllers"))
    {
        Some(format!("{off} without the unified cgroup hierarchy"))
    } else {
        None
    }
}

/// Whether `/proc/<pid>/exe` is the file at [`BINARY`], by device and inode.
fn runs_installed_binary(sys: Sys, pid: &str) -> Result<bool, String> {
    if !pid.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{UNIT} has MainPID {pid:?}"));
    }
    let exe = format!("/proc/{pid}/exe");
    let stat = Cmd::new("stat")
        .args(["-L", "-c", "%d:%i", exe.as_str(), BINARY])
        .timeout(VERIFY_TIMEOUT);
    let out = run(sys, &stat)?;
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = text.lines().collect();
    match (out.ok(), lines.as_slice()) {
        (true, [running, file]) => Ok(running == file),
        _ => Err(format!(
            "`stat` could not compare {exe} with {BINARY}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )),
    }
}

#[cfg(test)]
mod tests;
