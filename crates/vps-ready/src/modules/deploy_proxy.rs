//! The `deploy.proxy` module: Caddy from its repository, and a Caddyfile
//! that proxies each site to its upstream with Caddy's automatic HTTPS.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Deserializer};

use super::firewall_inbound::accepted_tcp;
use super::{
    Applicability, Module, ModuleError, ModuleSteps, ParamDoc, PlanCx, parse_params, refuse,
};
use crate::engine::{CADDYFILE, Reload};
use crate::facts::{Facts, Init, OsFamily};
use crate::resource::{AptSource, Directory, File, Package, Resource, apt_source, architecture};
use crate::sys::{Cmd, FileOwner, Sys, SysError};

/// Caddy's package, from Caddy's repository.
pub const PACKAGE: &str = "caddy";

const CADDY_DIR: &str = "/etc/caddy";

/// Where apt reads its sources.
const SOURCES: &str = "/etc/apt/sources.list.d";

/// The source `apt_source` writes for Caddy.
const CADDY_SOURCES: &str = "/etc/apt/sources.list.d/caddy.sources";

/// Caddy's repository, as any apt source names it.
const CADDY_REPO: &str = "dl.cloudsmith.io/public/caddy/stable";

/// The first line of a Caddyfile this module wrote. A Caddyfile that does
/// not start with it is someone else's, and is never overwritten.
const MARKER: &str = "# Written by vps-ready (deploy.proxy).";

const HEADER: &str = "\
# Written by vps-ready (deploy.proxy). `vps-ready rollback --last`
# restores the previous state; edits here are replaced by the next apply.
";

/// Kill timeout of each DNS lookup at plan time.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// The ports Caddy needs: 80 for the HTTP challenge and redirects, 443 to
/// serve.
const PORTS: [u16; 2] = [80, 443];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    /// Required; empty is refused when planning, so that the documented
    /// default parses.
    #[serde(default, deserialize_with = "distinct")]
    sites: Vec<Site>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Site {
    domain: Domain,
    upstream: Upstream,
}

/// Sites with different domains: Caddy refuses two blocks for one.
fn distinct<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<Site>, D::Error> {
    let sites = Vec::<Site>::deserialize(de)?;
    let mut seen = BTreeSet::new();
    match sites.iter().find(|s| !seen.insert(&s.domain.0)) {
        Some(site) => Err(serde::de::Error::custom(format!(
            "{} is listed twice in `sites`",
            site.domain.0
        ))),
        None => Ok(sites),
    }
}

/// A domain Caddy can get a certificate for: lowercase DNS labels, at
/// least two, and not an IP address. Also keeps the Caddyfile plain.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct Domain(String);

impl TryFrom<String> for Domain {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        let labels: Vec<&str> = s.split('.').collect();
        let numeric = labels
            .last()
            .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
        if s.len() <= 253 && labels.len() >= 2 && labels.iter().all(|l| is_label(l)) && !numeric {
            Ok(Self(s))
        } else {
            Err(format!(
                "{s:?} is not a domain name, e.g. app.example.com: lowercase letters, digits \
                 and `-`, in two or more labels separated by dots, with no wildcard"
            ))
        }
    }
}

/// 1 to 63 lowercase letters, digits and `-`, not at either end.
fn is_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Where Caddy sends a site's requests: `<host>:<port>`, with an IPv4
/// address, an IPv6 address in brackets or a host name.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct Upstream(String);

impl TryFrom<String> for Upstream {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        let bad = || {
            format!(
                "{s:?} is not an upstream: write <host>:<port>, e.g. 127.0.0.1:8080, with no scheme or path"
            )
        };
        let (host, port) = s.rsplit_once(':').ok_or_else(bad)?;
        if !matches!(port.parse::<u16>(), Ok(p) if p > 0) {
            return Err(bad());
        }
        if host == "localhost" || host.ends_with(".localhost") {
            return Err(format!(
                "{s:?}: write 127.0.0.1:{port} instead; localhost may resolve to ::1, and \
                 Docker publishes ports on 127.0.0.1 only"
            ));
        }
        let ok = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            Some(v6) => v6.parse::<Ipv6Addr>().is_ok(),
            None => {
                host.parse::<Ipv4Addr>().is_ok()
                    || (host.len() <= 253 && host.split('.').all(is_label))
            }
        };
        if ok { Ok(Self(s)) } else { Err(bad()) }
    }
}

/// Installs Caddy from its repository and writes a Caddyfile that proxies
/// each site to its upstream. Debian family with systemd only. A Caddyfile
/// it did not write is left alone.
#[derive(Debug, Clone, Copy)]
pub struct DeployProxy;

impl Module for DeployProxy {
    fn id(&self) -> &'static str {
        "deploy.proxy"
    }

    fn title(&self) -> &'static str {
        "Serve sites over HTTPS with Caddy, proxied to their upstreams"
    }

    fn why(&self) -> &'static str {
        "An app published on 127.0.0.1 is safe from the internet but also out of \
         its reach. Caddy in front of it serves it over HTTPS, gets and renews the \
         certificates by itself, and redirects HTTP to HTTPS."
    }

    fn params_doc(&self) -> &'static [ParamDoc] {
        &[ParamDoc {
            name: "sites",
            default: "[]",
            help: "Required: the sites Caddy serves, e.g. [{ domain = \"app.example.com\", upstream = \"127.0.0.1:8080\" }]. Each domain needs a DNS record for this host and ports 80 and 443 open.",
        }]
    }

    fn applicable(&self, facts: &Facts) -> Applicability {
        let reason = if facts.os.family != OsFamily::Debian {
            "Caddy is installed only on Debian and Ubuntu so far"
        } else if facts.init != Init::Systemd {
            "it needs systemd, to reload Caddy"
        } else {
            return Applicability::Applicable;
        };
        Applicability::NotApplicable {
            reason: reason.to_owned(),
        }
    }

    fn check_params(&self, params: &toml::Table) -> Result<(), ModuleError> {
        parse_params::<Params>(params).map(|_| ())
    }

    /// The Caddyfile goes before the package, which keeps it as its config
    /// file (`--force-confold`), so Caddy's first start serves it.
    /// `caddy validate` checks it before Caddy reloads.
    fn plan(&self, cx: &PlanCx, sys: Sys) -> Result<ModuleSteps, ModuleError> {
        let params: Params = cx.params()?;
        if params.sites.is_empty() {
            return refuse(
                "`sites` is empty; set the domains and upstreams Caddy serves for deploy.proxy \
                 in a profile",
            );
        }
        let package = Resource::Package(Package {
            name: PACKAGE.to_owned(),
        });
        let installed = package.diff(sys)?.is_none();
        let current = match sys.fs.read(Path::new(CADDYFILE)) {
            Ok(bytes) => Some(bytes),
            Err(SysError::NotFound(_)) => None,
            Err(e) => return Err(e.into()),
        };
        let ours = current
            .as_ref()
            .is_none_or(|c| c.starts_with(MARKER.as_bytes()));

        let mut resources = Vec::new();
        let mut notes = Vec::new();
        // Planned for an installed Caddy too, where they have no change, so
        // that it keeps a repository to get updates from.
        if !configured_elsewhere(sys)? {
            if installed && !sys.fs.exists(Path::new(CADDY_SOURCES)) {
                notes.push(
                    "caddy is installed without Caddy's repository; this adds it, so apt \
                     updates Caddy from there"
                        .to_owned(),
                );
            }
            resources.extend(apt_source(&AptSource::caddy(), &architecture(sys)?));
        }
        if ours {
            resources.extend([
                Resource::Directory(Directory {
                    path: CADDY_DIR.into(),
                    owner: root(0o755),
                }),
                Resource::File(File {
                    path: CADDYFILE.into(),
                    content: caddyfile(&params.sites).into_bytes(),
                    owner: root(0o644),
                    validate: None,
                }),
            ]);
        } else {
            notes.push(format!(
                "{CADDYFILE} was not written by vps-ready, so it is left alone and `sites` is \
                 not used; move it away and plan again to have vps-ready write it"
            ));
        }
        resources.push(package);
        if !installed {
            notes.push("rollback leaves Caddy installed".to_owned());
        }
        if !ours {
            return Ok(ModuleSteps {
                resources,
                reloads: Vec::new(),
                notes,
            });
        }
        if current.is_none() {
            notes.push("rollback removes the Caddyfile and stops Caddy".to_owned());
        }
        notes.extend(firewall_note(cx, sys)?);
        notes.extend(dns_notes(sys, &params.sites));
        Ok(ModuleSteps {
            resources,
            reloads: vec![Reload::CaddyReload],
            notes,
        })
    }
}

/// Whether an apt source other than [`CADDY_SOURCES`] already names Caddy's
/// repository, e.g. `caddy-stable.list` from Caddy's install docs. A second
/// one with another `Signed-By` makes `apt-get update` fail.
fn configured_elsewhere(sys: Sys) -> Result<bool, ModuleError> {
    let mut files = vec![Path::new("/etc/apt/sources.list").to_path_buf()];
    match sys.fs.read_dir(Path::new(SOURCES)) {
        Ok(paths) => files.extend(paths),
        Err(SysError::NotFound(_)) => {}
        Err(e) => return Err(e.into()),
    }
    for path in files
        .iter()
        .filter(|p| p.as_path() != Path::new(CADDY_SOURCES))
    {
        match sys.fs.read(path) {
            Ok(bytes) if String::from_utf8_lossy(&bytes).contains(CADDY_REPO) => return Ok(true),
            Ok(_) | Err(SysError::NotFound(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(false)
}

/// One block per site, after the header.
fn caddyfile(sites: &[Site]) -> String {
    let mut text = HEADER.to_owned();
    for site in sites {
        let _ = write!(
            text,
            "\n{} {{\n\treverse_proxy {}\n}}\n",
            site.domain.0, site.upstream.0
        );
    }
    text
}

/// The ports Caddy needs that `firewall.inbound`, in this plan or applied
/// earlier, does not accept.
fn firewall_note(cx: &PlanCx, sys: Sys) -> Result<Option<String>, ModuleError> {
    let Some(accepted) = accepted_tcp(cx, sys)? else {
        return Ok(None);
    };
    let closed: Vec<String> = PORTS
        .iter()
        .filter(|p| !accepted.contains(p))
        .map(|p| format!("{p}/tcp"))
        .collect();
    Ok((!closed.is_empty()).then(|| {
        format!(
            "firewall.inbound does not allow {}: Caddy needs port 80 to get certificates \
             and 443 to serve HTTPS; add {} to firewall.inbound's `allow`",
            closed.join(" and "),
            if closed.len() == 1 { "it" } else { "them" },
        )
    }))
}

/// The suffixes of names that Caddy never asks a public CA for, and serves
/// with a certificate from its own CA instead.
const INTERNAL: [&str; 4] = [".localhost", ".local", ".internal", ".home.arpa"];

/// What a resolver lookup says about each domain that does not point here.
/// Notes only: DNS may be changing while the user applies.
fn dns_notes(sys: Sys, sites: &[Site]) -> Vec<String> {
    let (internal, public): (Vec<&str>, Vec<&str>) = sites
        .iter()
        .map(|s| s.domain.0.as_str())
        .partition(|d| INTERNAL.iter().any(|s| d.ends_with(s)));
    let mut notes: Vec<String> = internal
        .iter()
        .map(|domain| {
            format!(
                "{domain} is not a public name, so Caddy serves it with a certificate from its \
                 own CA, which browsers do not trust"
            )
        })
        .collect();
    if public.is_empty() {
        return notes;
    }
    let here = match host_addresses(sys) {
        Ok(here) => here,
        Err(why) => {
            notes.push(format!(
                "this host's addresses are unknown ({why}), so the domains' DNS records were \
                 not checked"
            ));
            return notes;
        }
    };
    for domain in public {
        match lookup(sys, domain) {
            Lookup::Found(found) if found.iter().any(|a| here.contains(a)) => {}
            Lookup::Found(found) => {
                let found: Vec<String> = found.iter().map(IpAddr::to_string).collect();
                notes.push(format!(
                    "{domain} resolves to {}, not to an address of this host, so Caddy cannot \
                     get its certificate until it does (unless the provider forwards that \
                     address here)",
                    found.join(", ")
                ));
            }
            Lookup::NotFound => notes.push(format!(
                "{domain} has no address in DNS (or no resolver answered), so Caddy cannot get \
                 its certificate until it points here"
            )),
            Lookup::Failed(why) => notes.push(format!(
                "the DNS lookup of {domain} failed ({why}), so whether it points here was not \
                 checked"
            )),
        }
    }
    notes
}

enum Lookup {
    Found(BTreeSet<IpAddr>),
    NotFound,
    Failed(String),
}

/// `getent ahosts <domain>`, through the host's resolver, with a short
/// timeout. getent exits 2 for no address and for no answer alike.
fn lookup(sys: Sys, domain: &str) -> Lookup {
    let cmd = Cmd::new("getent")
        .args(["ahosts", domain])
        .timeout(LOOKUP_TIMEOUT);
    match sys.runner.run(&cmd) {
        Ok(out) if out.ok() => {
            let found: BTreeSet<IpAddr> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|l| l.split_whitespace().next()?.parse().ok())
                .collect();
            if found.is_empty() {
                Lookup::NotFound
            } else {
                Lookup::Found(found)
            }
        }
        Ok(out) if out.status == 2 => Lookup::NotFound,
        Ok(out) => Lookup::Failed(format!("`getent` exited with status {}", out.status)),
        Err(e) => Lookup::Failed(e.to_string()),
    }
}

/// The host's own addresses: IPv4 from the local routes in
/// `/proc/net/fib_trie`, IPv6 from `/proc/net/if_inet6`, which a host
/// without IPv6 lacks.
fn host_addresses(sys: Sys) -> Result<BTreeSet<IpAddr>, String> {
    const FIB_TRIE: &str = "/proc/net/fib_trie";
    const IF_INET6: &str = "/proc/net/if_inet6";
    let trie = sys
        .fs
        .read(Path::new(FIB_TRIE))
        .map_err(|e| e.to_string())?;
    let mut here = BTreeSet::new();
    // An address line, `|-- 192.0.2.10`, then its route, `/32 host LOCAL`.
    let mut last = None;
    for line in String::from_utf8_lossy(&trie).lines() {
        let line = line.trim_start();
        if let Some(addr) = line.strip_prefix("|-- ") {
            last = addr.trim().parse::<Ipv4Addr>().ok();
        } else if line.starts_with("/32 host LOCAL")
            && let Some(addr) = last
        {
            here.insert(IpAddr::V4(addr));
        }
    }
    match sys.fs.read(Path::new(IF_INET6)) {
        Ok(text) => here.extend(
            String::from_utf8_lossy(&text)
                .lines()
                .filter_map(|l| u128::from_str_radix(l.split_whitespace().next()?, 16).ok())
                .map(|bits| IpAddr::V6(Ipv6Addr::from(bits))),
        ),
        Err(SysError::NotFound(_)) => {}
        Err(e) => return Err(e.to_string()),
    }
    Ok(here)
}

const fn root(mode: u32) -> FileOwner {
    FileOwner {
        mode,
        uid: 0,
        gid: 0,
    }
}

#[cfg(test)]
mod tests;
