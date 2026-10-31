//! `deploy.proxy` on [`FakeFs`], with dpkg, apt, caddy, systemctl and the
//! resolver simulated by [`Host`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Mutex;

use super::*;
use crate::engine::{
    self, ApplyOutcome, Deadman, Engine, EngineError, Plan, Selected, StateDir, Target,
};
use crate::facts::fixtures::host;
use crate::modules::FirewallInbound;
use crate::modules::firewall_inbound::RULESET;
use crate::sys::fake::FakeFs;
use crate::sys::{FileKind, Fs, Output, Runner};

const STATE: &str = "/var/lib/vps-ready";

/// This host's address, in `/proc/net/fib_trie`.
const HERE: &str = "192.0.2.10";

/// The local routes of a host with [`HERE`] on eth0, trimmed.
const FIB_TRIE: &str = "\
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
     +-- 192.0.2.0/24 2 0 2
        |-- 192.0.2.0
           /24 link UNICAST
        |-- 192.0.2.10
           /32 host LOCAL
";

/// Loopback and 2001:db8::10 on eth0.
const IF_INET6: &str = "\
00000000000000000000000000000001 01 80 10 80       lo
20010db8000000000000000000000010 02 40 00 80     eth0
";

/// Packages dpkg reports installed, what `getent ahosts` answers, whether
/// `caddy validate` passes, and every command run.
struct Host {
    installed: Mutex<BTreeSet<String>>,
    /// `Err`: the lookup times out.
    dns: BTreeMap<String, Result<Output, ()>>,
    valid: bool,
    calls: Mutex<Vec<String>>,
}

impl Default for Host {
    fn default() -> Self {
        Self {
            installed: Mutex::default(),
            dns: BTreeMap::new(),
            valid: true,
            calls: Mutex::default(),
        }
    }
}

impl Host {
    /// Every domain answers with `addrs`, as `getent ahosts` prints them.
    fn resolving(domains: &[&str], addrs: &[&str]) -> Self {
        let mut host = Self::default();
        for domain in domains {
            host.dns
                .insert((*domain).to_owned(), Ok(ahosts(domain, addrs)));
        }
        host
    }

    fn with_caddy(self) -> Self {
        self.installed.lock().unwrap().insert(PACKAGE.to_owned());
        self
    }

    fn lines(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

fn ahosts(domain: &str, addrs: &[&str]) -> Output {
    let text: String = addrs
        .iter()
        .flat_map(|a| {
            [
                format!("{a}      STREAM {domain}\n"),
                format!("{a}      DGRAM  \n"),
            ]
        })
        .collect();
    Output::success(text)
}

fn exit(status: i32) -> Output {
    Output {
        status,
        ..Output::default()
    }
}

impl Runner for Host {
    fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
        let line = std::iter::once(cmd.program.as_str())
            .chain(cmd.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ");
        self.calls.lock().unwrap().push(line);
        let args: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        let mut installed = self.installed.lock().unwrap();
        let out = match (cmd.program.as_str(), &args[..]) {
            ("dpkg-query", [.., name]) => Output::success(if installed.contains(*name) {
                "installed"
            } else {
                "not-installed"
            }),
            ("dpkg", ["--print-architecture"]) => Output::success("amd64\n"),
            ("apt-get", [.., "update"]) => Output::success(""),
            ("apt-get", [.., name]) => {
                installed.insert((*name).to_owned());
                Output::success("")
            }
            ("getent", ["ahosts", domain]) => match self.dns.get(*domain) {
                Some(Ok(out)) => out.clone(),
                Some(Err(())) => {
                    return Err(SysError::Timeout {
                        program: cmd.program.clone(),
                        timeout: cmd.timeout,
                    });
                }
                None => exit(2),
            },
            ("caddy", ["validate", ..]) if self.valid => Output::success("Valid configuration"),
            ("caddy", ["validate", ..]) => Output {
                status: 1,
                stderr: b"Error: adapting config using caddyfile: unrecognized directive".to_vec(),
                ..Output::default()
            },
            ("systemctl", ["show", ..]) => {
                Output::success("LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n")
            }
            ("systemctl", _) => Output::success(""),
            ("nft", _) => Output::success(""),
            (other, _) => return Err(SysError::NotFound(other.to_owned())),
        };
        Ok(out)
    }
}

fn root_dir() -> FileOwner {
    root(0o755)
}

/// `/etc`, apt's directories and this host's addresses.
fn fs() -> FakeFs {
    FakeFs::new()
        .with_dir("/etc", root_dir())
        .with_dir("/etc/apt", root_dir())
        .with_dir("/etc/apt/sources.list.d", root_dir())
        .with_file("/proc/net/fib_trie", FIB_TRIE)
        .with_file("/proc/net/if_inet6", IF_INET6)
}

/// [`fs`] with `text` as the Caddyfile.
fn with_caddyfile(text: &str) -> FakeFs {
    let fs = fs().with_dir(CADDY_DIR, root_dir());
    fs.write_atomic(Path::new(CADDYFILE), text.as_bytes(), root(0o644))
        .unwrap();
    fs
}

fn facts() -> Facts {
    host("debian-13", &[])
}

fn params(text: &str) -> toml::Table {
    toml::from_str(text).unwrap()
}

const ONE: &str = r#"sites = [{ domain = "app.example.com", upstream = "127.0.0.1:8080" }]"#;

const SEVERAL: &str = r#"sites = [
  { domain = "app.example.com", upstream = "127.0.0.1:8080" },
  { domain = "api.example.com", upstream = "[::1]:9000" },
  { domain = "www.example.com", upstream = "192.0.2.20:80" },
]"#;

fn steps_with(
    params: &toml::Table,
    planned: &[Resource],
    fs: &FakeFs,
    runner: &Host,
) -> Result<ModuleSteps, ModuleError> {
    let facts = facts();
    DeployProxy.plan(
        &PlanCx {
            facts: &facts,
            params,
            planned,
        },
        Sys { fs, runner },
    )
}

fn steps(params: &toml::Table, fs: &FakeFs, runner: &Host) -> ModuleSteps {
    steps_with(params, &[], fs, runner).unwrap()
}

fn ids(steps: &ModuleSteps) -> Vec<String> {
    steps.resources.iter().map(Resource::id).collect()
}

fn caddyfile_of(steps: &ModuleSteps) -> String {
    steps
        .resources
        .iter()
        .find_map(|r| match r {
            Resource::File(f) if f.path == Path::new(CADDYFILE) => {
                Some(String::from_utf8(f.content.clone()).unwrap())
            }
            _ => None,
        })
        .unwrap()
}

fn check(text: &str) -> Result<(), String> {
    DeployProxy
        .check_params(&params(text))
        .map_err(|e| e.to_string())
}

fn plan<'a>(fs: &FakeFs, runner: &Host, facts: &'a Facts, params: &'a toml::Table) -> Plan<'a> {
    let selected = Selected {
        module: &DeployProxy,
        params,
    };
    engine::plan(&[selected], facts, Sys { fs, runner }).unwrap()
}

fn change_ids(plan: &Plan) -> Vec<String> {
    plan.steps().map(|s| s.change.id.clone()).collect()
}

/// Every path under `/etc`, with a file's content and mode.
fn etc(fs: &FakeFs) -> BTreeMap<PathBuf, Option<(Vec<u8>, u32)>> {
    fn walk(fs: &FakeFs, dir: &Path, out: &mut BTreeMap<PathBuf, Option<(Vec<u8>, u32)>>) {
        for path in fs.read_dir(dir).unwrap() {
            let meta = fs.metadata(&path).unwrap();
            if meta.kind == FileKind::Dir {
                out.insert(path.clone(), None);
                walk(fs, &path, out);
            } else {
                out.insert(path.clone(), Some((fs.read(&path).unwrap(), meta.mode)));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(fs, Path::new("/etc"), &mut out);
    out
}

#[test]
fn applies_on_debian_with_systemd_without_the_dead_man() {
    let mut facts = facts();
    assert_eq!(DeployProxy.applicable(&facts), Applicability::Applicable);
    assert!(!DeployProxy.needs_deadman());
    facts.init = Init::Unknown;
    assert_eq!(
        DeployProxy.applicable(&facts),
        Applicability::NotApplicable {
            reason: "it needs systemd, to reload Caddy".into()
        }
    );
    facts.os.family = OsFamily::Rhel;
    assert_eq!(
        DeployProxy.applicable(&facts),
        Applicability::NotApplicable {
            reason: "Caddy is installed only on Debian and Ubuntu so far".into()
        }
    );
}

/// Caddy's source, the directory, the Caddyfile, then the package, so dpkg
/// keeps the Caddyfile; Caddy reloads after them.
#[test]
fn a_fresh_host_gets_caddy_and_one_site() {
    let (fs, runner) = (fs(), Host::resolving(&["app.example.com"], &[HERE]));
    let steps = steps(&params(ONE), &fs, &runner);
    assert_eq!(
        ids(&steps),
        [
            "directory:/etc/apt/keyrings",
            "file:/etc/apt/keyrings/caddy.asc",
            "file:/etc/apt/sources.list.d/caddy.sources",
            "directory:/etc/caddy",
            "file:/etc/caddy/Caddyfile",
            "package:caddy",
        ]
    );
    assert_eq!(steps.reloads, [Reload::CaddyReload]);
    assert_eq!(
        steps.notes,
        [
            "rollback leaves Caddy installed",
            "rollback removes the Caddyfile and stops Caddy",
        ]
    );
    let Some(Resource::File(source)) = steps.resources.get(2) else {
        panic!("{:?}", steps.resources);
    };
    let source = String::from_utf8(source.content.clone()).unwrap();
    assert!(source.contains("Suites: any-version\n"), "{source}");
    let text = caddyfile_of(&steps);
    assert!(text.starts_with(MARKER), "{text}");
    insta::assert_snapshot!("one-site", text);
}

#[test]
fn one_block_per_site() {
    let (fs, runner) = (fs(), Host::default().with_caddy());
    let steps = steps(&params(SEVERAL), &fs, &runner);
    insta::assert_snapshot!("several-sites", caddyfile_of(&steps));
}

/// Required but defaulted, so the documented default parses; empty is
/// refused when planning.
#[test]
fn refuses_empty_sites() {
    let (fs, runner) = (fs(), Host::default());
    check("sites = []").unwrap();
    for text in ["", "sites = []"] {
        let err = steps_with(&params(text), &[], &fs, &runner).unwrap_err();
        assert_eq!(
            err.to_string(),
            "`sites` is empty; set the domains and upstreams Caddy serves for deploy.proxy \
             in a profile"
        );
    }
}

#[test]
fn refuses_bad_domains() {
    check(ONE).unwrap();
    check(r#"sites = [{ domain = "a-b.c1.example.com", upstream = "app:80" }]"#).unwrap();
    for bad in [
        "example",
        "App.example.com",
        "*.example.com",
        "-app.example.com",
        "app-.example.com",
        "app..example.com",
        "app.example.com.",
        "192.0.2.10",
        "app.example.com:443",
        "https://app.example.com",
        "app.example.com { }",
        "",
    ] {
        let text = format!(r#"sites = [{{ domain = "{bad}", upstream = "127.0.0.1:80" }}]"#);
        let err = check(&text).unwrap_err();
        assert!(err.contains("is not a domain name"), "{bad}: {err}");
    }
    let long = format!("{}.example.com", "a".repeat(64));
    let text = format!(r#"sites = [{{ domain = "{long}", upstream = "127.0.0.1:80" }}]"#);
    assert!(check(&text).is_err());

    let twice = r#"sites = [
      { domain = "app.example.com", upstream = "127.0.0.1:8080" },
      { domain = "app.example.com", upstream = "127.0.0.1:8081" },
    ]"#;
    let err = check(twice).unwrap_err();
    assert!(err.contains("app.example.com is listed twice"), "{err}");

    let typo =
        r#"sites = [{ domain = "app.example.com", upstream = "127.0.0.1:80", tls = "internal" }]"#;
    let err = check(typo).unwrap_err();
    assert!(err.contains("unknown field `tls`"), "{err}");
    let missing = r#"sites = [{ domain = "app.example.com" }]"#;
    let err = check(missing).unwrap_err();
    assert!(err.contains("missing field `upstream`"), "{err}");
}

#[test]
fn refuses_bad_upstreams() {
    for good in [
        "127.0.0.1:8080",
        "[::1]:8080",
        "[2001:db8::5]:443",
        "app.internal:3000",
        "app:80",
    ] {
        let text = format!(r#"sites = [{{ domain = "app.example.com", upstream = "{good}" }}]"#);
        check(&text).unwrap_or_else(|e| panic!("{good}: {e}"));
    }
    for bad in [
        "127.0.0.1",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "http://127.0.0.1:8080",
        "127.0.0.1:8080/app",
        "::1:8080",
        "[::1:8080",
        ":8080",
        "app.example.com { }:80",
        "",
    ] {
        let text = format!(r#"sites = [{{ domain = "app.example.com", upstream = "{bad}" }}]"#);
        let err = check(&text).unwrap_err();
        assert!(err.contains("is not an upstream"), "{bad}: {err}");
    }
    for local in ["localhost:8080", "app.localhost:8080"] {
        let text = format!(r#"sites = [{{ domain = "app.example.com", upstream = "{local}" }}]"#);
        let err = check(&text).unwrap_err();
        assert!(
            err.contains(
                "write 127.0.0.1:8080 instead; localhost may resolve to ::1, and Docker \
                 publishes ports on 127.0.0.1 only"
            ),
            "{err}"
        );
    }
}

/// A Caddyfile without the header is never overwritten: only Caddy is
/// installed, with no reload, and nothing at all once it is.
#[test]
fn leaves_a_hand_written_caddyfile_alone() {
    let fs = with_caddyfile("app.example.com {\n\tfile_server\n}\n");
    let runner = Host::default();
    let steps = steps(&params(ONE), &fs, &runner);
    assert_eq!(
        ids(&steps),
        [
            "directory:/etc/apt/keyrings",
            "file:/etc/apt/keyrings/caddy.asc",
            "file:/etc/apt/sources.list.d/caddy.sources",
            "package:caddy",
        ]
    );
    assert!(steps.reloads.is_empty());
    assert_eq!(
        steps.notes,
        [
            "/etc/caddy/Caddyfile was not written by vps-ready, so it is left alone and \
             `sites` is not used; move it away and plan again to have vps-ready write it",
            "rollback leaves Caddy installed",
        ]
    );
    // No lookups for sites that are not served.
    assert!(!runner.lines().iter().any(|l| l.starts_with("getent")));

    let runner = Host::default().with_caddy();
    let steps = steps_with(&params(ONE), &[], &fs, &runner).unwrap();
    assert!(steps.resources.is_empty(), "{:?}", ids(&steps));
}

/// With Caddy installed, its own Caddyfile is rewritten, with no source.
#[test]
fn rewrites_its_own_caddyfile_when_caddy_is_installed() {
    let fs = with_caddyfile(&format!("{HEADER}\nold.example.com {{\n}}\n"));
    let runner = Host::resolving(&["app.example.com"], &[HERE]).with_caddy();
    let facts = facts();
    let params = params(ONE);
    let first = plan(&fs, &runner, &facts, &params);
    assert_eq!(change_ids(&first), ["file:/etc/caddy/Caddyfile"]);
    assert_eq!(
        first.modules[0].notes,
        ["Caddy is already installed: only the Caddyfile is managed"]
    );
}

/// A domain that resolves elsewhere, or not at all, is a note; so is a
/// lookup that fails, and addresses that cannot be read.
#[test]
fn notes_domains_that_do_not_point_here() {
    let fs = fs();
    let mut runner = Host::default().with_caddy();
    runner.dns = BTreeMap::from([
        (
            "app.example.com".to_owned(),
            Ok(ahosts("app.example.com", &[HERE])),
        ),
        (
            "api.example.com".to_owned(),
            Ok(ahosts("api.example.com", &["198.51.100.7", "2001:db8::7"])),
        ),
        ("www.example.com".to_owned(), Err(())),
    ]);
    let notes = |runner: &Host, fs: &FakeFs, text: &str| {
        steps(&params(text), fs, runner).notes[2..].to_vec()
    };
    let several = notes(&runner, &fs, SEVERAL);
    assert_eq!(
        several,
        [
            "api.example.com resolves to 198.51.100.7, 2001:db8::7, not to an address of this \
             host, so Caddy cannot get its certificate until it does (unless the provider \
             forwards that address here)",
            "the DNS lookup of www.example.com failed (`getent` timed out after 5s), so whether \
             it points here was not checked",
        ]
    );
    // The lookups run with a short timeout.
    assert_eq!(
        runner
            .lines()
            .iter()
            .filter(|l| l.starts_with("getent ahosts"))
            .count(),
        3
    );

    // IPv6 counts too.
    runner.dns.insert(
        "app.example.com".to_owned(),
        Ok(ahosts("app.example.com", &["2001:db8::10"])),
    );
    assert!(notes(&runner, &fs, ONE).is_empty());

    runner.dns.clear();
    assert_eq!(
        notes(&runner, &fs, ONE),
        [
            "app.example.com has no address in DNS (or no resolver answered), so Caddy cannot \
             get its certificate until it points here"
        ]
    );
    runner.dns.insert("app.example.com".to_owned(), Ok(exit(1)));
    assert_eq!(
        notes(&runner, &fs, ONE),
        [
            "the DNS lookup of app.example.com failed (`getent` exited with status 1), so \
             whether it points here was not checked"
        ]
    );

    let fs = FakeFs::new();
    assert_eq!(
        notes(&runner, &fs, ONE),
        [
            "this host's addresses are unknown (not found: /proc/net/fib_trie), so the \
             domains' DNS records were not checked"
        ]
    );
}

/// A name Caddy serves from its own CA is not looked up, and says so.
#[test]
fn internal_names_are_not_looked_up() {
    let (fs, runner) = (FakeFs::new(), Host::default().with_caddy());
    let text = r#"sites = [{ domain = "app.localhost", upstream = "127.0.0.1:8080" },
      { domain = "nas.home.arpa", upstream = "127.0.0.1:5000" }]"#;
    let notes = steps(&params(text), &fs, &runner).notes[2..].to_vec();
    assert_eq!(
        notes,
        [
            "app.localhost is not a public name, so Caddy serves it with a certificate from \
             its own CA, which browsers do not trust",
            "nas.home.arpa is not a public name, so Caddy serves it with a certificate from \
             its own CA, which browsers do not trust",
        ]
    );
    assert!(!runner.lines().iter().any(|l| l.starts_with("getent")));
}

#[test]
fn looks_up_with_a_short_timeout() {
    struct Timeouts(Mutex<Vec<Duration>>);
    impl Runner for Timeouts {
        fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
            self.0.lock().unwrap().push(cmd.timeout);
            Ok(exit(2))
        }
    }
    let fs = fs();
    let runner = Timeouts(Mutex::default());
    let site = Site {
        domain: Domain("app.example.com".into()),
        upstream: Upstream("127.0.0.1:8080".into()),
    };
    dns_notes(
        Sys {
            fs: &fs,
            runner: &runner,
        },
        &[site],
    );
    assert_eq!(*runner.0.lock().unwrap(), [LOOKUP_TIMEOUT]);
    assert!(LOOKUP_TIMEOUT <= Duration::from_secs(5));
}

/// `firewall.inbound` earlier in the plan, or applied before, without port
/// 80 or 443 is a note.
#[test]
fn notes_ports_the_firewall_does_not_allow() {
    let facts = facts();
    let runner = Host::resolving(&["app.example.com"], &[HERE]).with_caddy();
    let firewall = |allow: &str| {
        let params = params(&format!("allow = [{allow}]"));
        let cx = PlanCx {
            facts: &facts,
            params: &params,
            planned: &[],
        };
        FirewallInbound
            .plan(
                &cx,
                Sys {
                    fs: &FakeFs::new(),
                    runner: &runner,
                },
            )
            .unwrap()
            .resources
    };
    let fs = fs();
    let notes = |planned: &[Resource], fs: &FakeFs| {
        steps_with(&params(ONE), planned, fs, &runner)
            .unwrap()
            .notes[2..]
            .to_vec()
    };
    assert_eq!(
        notes(&firewall(""), &fs),
        [
            "firewall.inbound does not allow 80/tcp and 443/tcp: Caddy needs port 80 to get \
             certificates and 443 to serve HTTPS; add them to firewall.inbound's `allow`"
        ]
    );
    assert_eq!(
        notes(&firewall("\"80/tcp\", \"443/udp\""), &fs),
        [
            "firewall.inbound does not allow 443/tcp: Caddy needs port 80 to get certificates \
             and 443 to serve HTTPS; add it to firewall.inbound's `allow`"
        ]
    );
    assert!(notes(&firewall("\"80/tcp\", \"443/tcp\""), &fs).is_empty());
    // No firewall.inbound: nothing to say.
    assert!(notes(&[], &fs).is_empty());

    // Applied earlier, not in this plan.
    let Some(Resource::File(ruleset)) = firewall("")
        .into_iter()
        .find(|r| r.id() == format!("file:{RULESET}"))
    else {
        panic!("no ruleset");
    };
    let fs = fs.with_dir("/etc/vps-ready", root_dir());
    fs.write_atomic(Path::new(RULESET), &ruleset.content, root(0o644))
        .unwrap();
    assert_eq!(notes(&[], &fs).len(), 1);
}

/// In the registry after `firewall.inbound`, whose ruleset it reads, and
/// with it in one plan.
#[test]
fn plans_after_the_firewall_in_one_profile() {
    let ids: Vec<&str> = crate::modules::all().iter().map(|m| m.id()).collect();
    let at = |id| ids.iter().position(|i| *i == id).unwrap();
    assert!(at("firewall.inbound") < at("deploy.proxy"));
    assert!(at("deploy.docker") < at("deploy.proxy"));
    assert!(at("deploy.proxy") < at("deploy.user"));

    let (fs, runner) = (fs(), Host::resolving(&["app.example.com"], &[HERE]));
    let mut facts = facts();
    facts.firewall_tools.nft = true;
    let (proxy, firewall) = (params(ONE), params("allow = [\"443/tcp\"]"));
    let selected = [
        Selected {
            module: &FirewallInbound,
            params: &firewall,
        },
        Selected {
            module: &DeployProxy,
            params: &proxy,
        },
    ];
    let plan = engine::plan(
        &selected,
        &facts,
        Sys {
            fs: &fs,
            runner: &runner,
        },
    )
    .unwrap();
    let notes = &plan.modules[1].notes;
    assert!(
        notes
            .iter()
            .any(|n| n.starts_with("firewall.inbound does not allow 80/tcp:")),
        "{notes:?}"
    );
}

/// Apply installs Caddy after writing the Caddyfile and reloads it; the
/// next plan is empty; rollback removes the source, the key and the
/// Caddyfile, leaves the package and stops Caddy.
#[test]
fn applies_then_plans_nothing_and_rolls_back() {
    let (fs, runner) = (fs(), Host::resolving(&["app.example.com"], &[HERE]));
    let facts = facts();
    let params = params(ONE);
    let before = etc(&fs);
    let first = plan(&fs, &runner, &facts, &params);
    assert_eq!(first.steps().count(), 6);

    let state = StateDir::create(&fs, STATE, 0).unwrap();
    let engine = Engine::lock(
        &state,
        Sys {
            fs: &fs,
            runner: &runner,
        },
    )
    .unwrap();
    let outcome = engine
        .apply(&first, &Deadman::default(), &mut |_| {})
        .unwrap();
    assert!(
        matches!(outcome, ApplyOutcome::Applied { .. }),
        "{outcome:?}"
    );
    let next = plan(&fs, &runner, &facts, &params);
    assert!(change_ids(&next).is_empty(), "{:?}", change_ids(&next));
    let applied = runner.lines();
    let install = applied
        .iter()
        .position(|l| l.ends_with(" caddy") && l.starts_with("apt-get"))
        .unwrap();
    let validate = "caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile";
    let checked = applied.iter().position(|l| l == validate).unwrap();
    assert!(install < checked, "{applied:?}");
    assert!(
        applied[checked..].contains(&"systemctl try-reload-or-restart caddy.service".to_owned())
    );

    engine.rollback(Target::Last, &mut |_| {}).unwrap();
    assert_eq!(etc(&fs), before);
    assert!(runner.installed.lock().unwrap().contains(PACKAGE));
    let rolled_back = &runner.lines()[applied.len()..];
    assert_eq!(rolled_back, ["systemctl stop caddy.service"]);
}

/// Rolling back a change to its own Caddyfile restores the old one and
/// reloads Caddy with it.
#[test]
fn rollback_of_a_rewrite_reloads_the_old_caddyfile() {
    let old = format!("{HEADER}\nold.example.com {{\n\treverse_proxy 127.0.0.1:8000\n}}\n");
    let fs = with_caddyfile(&old);
    let runner = Host::resolving(&["app.example.com"], &[HERE]).with_caddy();
    let facts = facts();
    let params = params(ONE);
    let first = plan(&fs, &runner, &facts, &params);
    let state = StateDir::create(&fs, STATE, 0).unwrap();
    let engine = Engine::lock(
        &state,
        Sys {
            fs: &fs,
            runner: &runner,
        },
    )
    .unwrap();
    engine
        .apply(&first, &Deadman::default(), &mut |_| {})
        .unwrap();
    let applied = runner.lines().len();
    engine.rollback(Target::Last, &mut |_| {}).unwrap();
    assert_eq!(fs.read(Path::new(CADDYFILE)).unwrap(), old.as_bytes());
    assert_eq!(
        runner.lines()[applied..],
        [
            "caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile",
            "systemctl try-reload-or-restart caddy.service",
        ]
    );
}

/// A Caddyfile that `caddy validate` rejects fails the apply, which rolls
/// back.
#[test]
fn a_failed_validate_fails_the_apply() {
    let fs = fs();
    let runner = Host {
        valid: false,
        ..Host::resolving(&["app.example.com"], &[HERE])
    };
    let facts = facts();
    let params = params(ONE);
    let before = etc(&fs);
    let first = plan(&fs, &runner, &facts, &params);
    let state = StateDir::create(&fs, STATE, 0).unwrap();
    let engine = Engine::lock(
        &state,
        Sys {
            fs: &fs,
            runner: &runner,
        },
    )
    .unwrap();
    let outcome = engine
        .apply(&first, &Deadman::default(), &mut |_| {})
        .unwrap();
    assert!(
        matches!(
            &outcome,
            ApplyOutcome::RolledBack {
                cause: EngineError::ReloadCheck {
                    reload: Reload::CaddyReload,
                    ..
                },
                ..
            }
        ),
        "{outcome:?}"
    );
    assert_eq!(etc(&fs), before);
    assert!(
        !runner
            .lines()
            .contains(&"systemctl try-reload-or-restart caddy.service".to_owned())
    );
}
