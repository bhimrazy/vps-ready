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
use crate::facts::{Facts, Init, OsFamily, Proto};
use crate::resource::{AptSource, Directory, File, Package, Resource, apt_source, architecture};
use crate::sys::Output;
use crate::sys::{Cmd, FileOwner, Sys, SysError};

/// Caddy's package, from Caddy's repository.
pub const PACKAGE: &str = "caddy";

const CADDY_DIR: &str = "/etc/caddy";

/// The first line of a Caddyfile this module wrote. A Caddyfile that does
/// not start with it, and is not the package's own, is someone else's, and
/// is never overwritten.
const MARKER: &str = "# Written by vps-ready (deploy.proxy).";

const HEADER: &str = "\
# Written by vps-ready (deploy.proxy). `vps-ready rollback --last`
# restores the previous state; edits here are replaced by the next apply.
";

/// Kill timeout of each DNS lookup at plan time.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Kill timeout of `systemctl is-active` in [`Module::verify`].
const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);

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
/// it did not write is left alone, unless it is the package's unmodified
/// default.
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
            names: vec![PACKAGE.to_owned()],
        });
        let installed = package.diff(sys)?.is_none();
        let current = caddyfile_state(sys)?;
        let ours = current != Caddyfile::Other;

        let mut resources = Vec::new();
        let mut notes = Vec::new();
        // Planned for an installed Caddy too, where they have no change, so
        // that it keeps a repository to get updates from.
        let source = AptSource::caddy();
        if !source.configured_elsewhere(sys)? {
            if installed && !sys.fs.exists(&source.path()) {
                notes.push(
                    "caddy is installed without Caddy's repository; this adds it, so apt \
                     updates Caddy from there, and the next `apt upgrade` replaces a distro's \
                     Caddy with Caddy's own build"
                        .to_owned(),
                );
            }
            resources.extend(apt_source(&source, &architecture(sys)?));
        }
        if current == Caddyfile::PackageDefault {
            notes.push(format!(
                "{CADDYFILE} is the package's unmodified default, so it is replaced; rollback \
                 restores it"
            ));
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
                    describe: None,
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
        if current == Caddyfile::Missing {
            let dist = if installed {
                ""
            } else {
                " (with its default Caddyfile as Caddyfile.dpkg-dist)"
            };
            notes.push(format!(
                "rollback removes the Caddyfile, and stops and disables Caddy; the package \
                 stays{dist}"
            ));
        }
        notes.extend(listener_note(cx.facts));
        notes.extend(firewall_note(cx, sys)?);
        notes.extend(dns_notes(sys, &params.sites));
        Ok(ModuleSteps {
            resources,
            reloads: vec![Reload::CaddyReload],
            notes,
        })
    }

    /// With a Caddyfile of its own, Caddy runs: a reload of a stopped Caddy
    /// that fails to start, e.g. on a port in use, is not an error to
    /// systemd's reload, so this catches it, and the apply rolls back.
    fn verify(&self, _cx: &PlanCx, sys: Sys) -> Result<(), String> {
        match sys.fs.read(Path::new(CADDYFILE)) {
            Ok(text) if text.starts_with(MARKER.as_bytes()) => {}
            _ => return Ok(()),
        }
        let cmd = Cmd::new("systemctl")
            .args(["is-active", "caddy.service"])
            .timeout(VERIFY_TIMEOUT);
        let out = sys
            .runner
            .run(&cmd)
            .map_err(|e| format!("`systemctl is-active caddy.service`: {e}"))?;
        if out.ok() {
            return Ok(());
        }
        let state = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        Err(format!(
            "caddy.service is {state}, not active; `journalctl -u caddy.service` says why \
             (another program on port 80 or 443?)"
        ))
    }

    fn verify_timeout(&self) -> Duration {
        VERIFY_TIMEOUT
    }
}

/// What `/etc/caddy/Caddyfile` is now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Caddyfile {
    /// There is none.
    Missing,
    /// This module wrote it.
    Ours,
    /// The package's own, unmodified, by the hash dpkg recorded.
    PackageDefault,
    /// Anything else, e.g. written by hand: left alone.
    Other,
}

/// Reads [`CADDYFILE`] and, without our header, compares its MD5 with the
/// conffile hash dpkg recorded for the package. Read-only.
///
/// # Errors
///
/// Reading the file, or running `dpkg-query` or `md5sum`.
pub(crate) fn caddyfile_state(sys: Sys) -> Result<Caddyfile, ModuleError> {
    match sys.fs.read(Path::new(CADDYFILE)) {
        Ok(text) if text.starts_with(MARKER.as_bytes()) => return Ok(Caddyfile::Ours),
        Ok(_) => {}
        Err(SysError::NotFound(_)) => return Ok(Caddyfile::Missing),
        Err(e) => return Err(e.into()),
    }
    let first = |out: &Output, path: &str| -> Option<String> {
        String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
            let mut words = l.split_whitespace();
            (words.next()? == path).then(|| words.next().map(str::to_owned))?
        })
    };
    let conffiles = sys.runner.run(&Cmd::new("dpkg-query").args([
        "-W",
        "--showformat=${Conffiles}",
        PACKAGE,
    ]))?;
    let recorded = conffiles
        .ok()
        .then(|| first(&conffiles, CADDYFILE))
        .flatten();
    let Some(recorded) = recorded else {
        return Ok(Caddyfile::Other);
    };
    let sum = sys
        .runner
        .run(&Cmd::new("md5sum").args(["--", CADDYFILE]))?;
    // md5sum prints `<hash>  <path>`.
    let actual = sum
        .ok()
        .then(|| {
            String::from_utf8_lossy(&sum.stdout)
                .split_whitespace()
                .next()
                .map(str::to_owned)
        })
        .flatten();
    Ok(if actual.as_deref() == Some(recorded.as_str()) {
        Caddyfile::PackageDefault
    } else {
        Caddyfile::Other
    })
}

/// Another program on port 80 or 443, which Caddy then cannot bind.
fn listener_note(facts: &Facts) -> Option<String> {
    let mut taken: Vec<String> = facts
        .listeners
        .iter()
        .filter(|l| l.proto == Proto::Tcp && PORTS.contains(&l.port))
        .filter(|l| !l.processes.iter().any(|p| p == PACKAGE))
        .map(|l| {
            if l.processes.is_empty() {
                l.port.to_string()
            } else {
                format!("{} ({})", l.port, l.processes.join(", "))
            }
        })
        .collect();
    taken.dedup();
    (!taken.is_empty()).then(|| {
        format!(
            "something else listens on port {}: Caddy cannot start while it does, and the \
             apply then rolls back",
            taken.join(" and ")
        )
    })
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
    for (i, domain) in public.iter().enumerate() {
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
            // A resolver that does not answer one name will not answer the
            // next either: one wait is enough.
            Lookup::TimedOut => {
                let secs = LOOKUP_TIMEOUT.as_secs();
                notes.push(match public.len() - i - 1 {
                    0 => format!(
                        "the resolver did not answer within {secs} s, so whether {domain} points \
                         here was not checked"
                    ),
                    n => format!(
                        "the resolver did not answer within {secs} s, so whether {domain} and {n} \
                         other {} point here was not checked",
                        if n == 1 { "domain" } else { "domains" }
                    ),
                });
                break;
            }
        }
    }
    notes
}

enum Lookup {
    Found(BTreeSet<IpAddr>),
    NotFound,
    TimedOut,
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
        Err(SysError::Timeout { .. }) => Lookup::TimedOut,
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
