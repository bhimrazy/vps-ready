//! `firewall.inbound` on [`FakeFs`], with apt, systemd and nft simulated by
//! [`Host`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use proptest::prelude::*;

use super::*;
use crate::engine::{self, ApplyOutcome, Deadman, Engine, Plan, Selected, StateDir, Target};
use crate::facts::fixtures::{host, testdata};
use crate::facts::{FirewallTools, InputChain, Listener, Session, SessionId};
use crate::resource::sysctl::BOOT_ID;
use crate::sys::fake::{FakeFs, FakeRunner};
use crate::sys::{FileKind, Fs, Output, Runner, SysError};

const STATE: &str = "/var/lib/vps-ready";
const BIN: &str = "/usr/local/bin/vps-ready";

/// `nft -j list table inet vps_ready` after loading the ruleset of
/// [`facts`] with no params, on Debian 13.
const LOADED: &str = "nft/vps-ready-table.json";

fn session(server: &str) -> Session {
    Session {
        id: SessionId {
            pid: 902,
            start: 4200,
        },
        client: "192.0.2.10:51234".parse().unwrap(),
        server: server.parse().unwrap(),
        uid: 1000,
        user: Some("admin".into()),
    }
}

/// The captured Debian 13 host, applied from an SSH session on port 22.
fn facts() -> Facts {
    let mut facts = host("debian-13", &[]);
    facts.session = Some(session("198.51.100.5:22"));
    facts
}

fn params(text: &str) -> toml::Table {
    toml::from_str(text).unwrap()
}

fn steps(facts: &Facts, params: &toml::Table) -> Result<ModuleSteps, ModuleError> {
    let (fs, runner) = (FakeFs::new(), FakeRunner::new());
    FirewallInbound.plan(
        &PlanCx {
            facts,
            params,
            planned: &[],
        },
        Sys {
            fs: &fs,
            runner: &runner,
        },
    )
}

fn file<'a>(steps: &'a ModuleSteps, path: &str) -> &'a File {
    steps
        .resources
        .iter()
        .find_map(|r| match r {
            Resource::File(f) if f.path == Path::new(path) => Some(f),
            _ => None,
        })
        .unwrap()
}

fn ruleset_of(steps: &ModuleSteps) -> String {
    String::from_utf8(file(steps, RULESET).content.clone()).unwrap()
}

fn reason(facts: &Facts) -> String {
    match FirewallInbound.applicable(facts) {
        Applicability::NotApplicable { reason } => reason,
        Applicability::Applicable => panic!("applies"),
    }
}

#[test]
fn needs_the_dead_man_and_restores_its_files_regardless() {
    let module = FirewallInbound;
    assert!(module.needs_deadman() && module.force_restore());
    assert_eq!(module.verify_timeout(), Duration::from_secs(10));
}

#[test]
fn leaves_other_firewall_managers_alone() {
    let base = facts();
    assert_eq!(FirewallInbound.applicable(&base), Applicability::Applicable);
    let with = |f: &dyn Fn(&mut Facts)| {
        let mut facts = base.clone();
        f(&mut facts);
        reason(&facts)
    };
    assert_eq!(
        with(&|f| f.firewall_tools.ufw = Some(true)),
        "ufw is enabled; vps-ready leaves the firewall to it"
    );
    assert_eq!(
        with(&|f| f.firewall_tools.firewalld = Some(true)),
        "firewalld is running or enabled; vps-ready leaves the firewall to it"
    );
    assert!(with(&|f| f.firewall_tools.firewalld = None).contains("unknown"));
    assert!(with(&|f| f.firewall_tools.legacy_filter = true).contains("iptables-legacy"));
    // Also when nft is missing, so the ruleset was not read.
    assert!(
        with(&|f| {
            f.firewall = None;
            f.firewall_tools.nft = false;
            f.firewall_tools.legacy_filter = true;
        })
        .contains("iptables-legacy")
    );
    assert!(with(&|f| f.firewall = None).contains("`nft list ruleset` failed"));
    assert_eq!(
        with(&|f| {
            f.firewall = None;
            f.firewall_tools.nft = false;
            f.updates = None;
        }),
        "nft is not installed, and apt was not found to install it"
    );
    assert!(with(&|f| f.init = Init::OpenRc).contains("systemd"));
    assert!(with(&|f| f.os.family = OsFamily::Alpine).contains("Debian"));
    // An installed but disabled ufw is no reason.
    let mut facts = base.clone();
    facts.firewall_tools.ufw = Some(false);
    assert_eq!(
        FirewallInbound.applicable(&facts),
        Applicability::Applicable
    );
}

#[test]
fn refuses_when_no_ssh_port_is_known() {
    let mut facts = facts();
    facts.session = None;
    facts.listeners.clear();
    facts.ssh.listening.clear();
    facts.ssh.socket_ports.clear();
    facts.ssh.effective = None;
    assert!(reason(&facts).starts_with("the SSH port is unknown"));
}

#[test]
fn installs_nftables_only_when_nft_is_missing() {
    let mut facts = facts();
    let ids = |facts: &Facts| -> Vec<String> {
        steps(facts, &toml::Table::new())
            .unwrap()
            .resources
            .iter()
            .map(Resource::id)
            .collect()
    };
    let mut want = vec![
        format!("directory:{DIR}"),
        format!("file:{RULESET}"),
        format!("file:{UNIT_FILE}"),
        format!("service:{UNIT}"),
    ];
    assert_eq!(ids(&facts), want);
    facts.firewall_tools.nft = false;
    want.insert(0, "package:nftables".to_owned());
    assert_eq!(ids(&facts), want);
}

#[test]
fn checks_the_ruleset_then_reloads() {
    let steps = steps(&facts(), &toml::Table::new()).unwrap();
    assert_eq!(
        steps.reloads,
        [Reload::DaemonReload, Reload::FirewallReload]
    );
    assert_eq!(
        file(&steps, RULESET).validate,
        Some(Validate::new("nft", ["-c", "-f", "{}"]))
    );
    // The reload loads the path the module writes.
    assert_eq!(
        Reload::FirewallReload.check().unwrap().args,
        ["-c", "-f", RULESET]
    );
}

#[test]
fn ruleset_snapshots() {
    let mut facts = facts();
    insta::assert_snapshot!(
        "ruleset-minimal",
        ruleset_of(&steps(&facts, &params("allow = [\"22/tcp\"]")).unwrap())
    );
    facts.docker = true;
    let web = params("allow = [\"22/tcp\", \"80/tcp\", \"443/tcp\", \"443/udp\"]");
    insta::assert_snapshot!(
        "ruleset-web-docker",
        ruleset_of(&steps(&facts, &web).unwrap())
    );
    // A bridge Docker did not name is left out of `br-*`.
    facts.bridges = ["docker0", "br-0123456789ab", "br-lan", "br-wan"]
        .iter()
        .map(|name| crate::facts::Bridge {
            name: (*name).to_owned(),
            docker: !name.ends_with("an"),
        })
        .collect();
    insta::assert_snapshot!(
        "ruleset-web-docker-other-bridges",
        ruleset_of(&steps(&facts, &web).unwrap())
    );
    let unit = steps(&facts, &toml::Table::new()).unwrap();
    insta::assert_snapshot!(
        "unit",
        String::from_utf8(file(&unit, UNIT_FILE).content.clone()).unwrap()
    );
}

/// On a host without Docker, `deploy.docker` before it in the same plan
/// installs Docker: the bridges are accepted as if Docker were present.
#[test]
fn accepts_the_bridges_of_a_docker_planned_before_it() {
    let facts = facts();
    assert!(!facts.docker);
    let web = params("allow = [\"22/tcp\", \"80/tcp\", \"443/tcp\", \"443/udp\"]");
    let (fs, runner) = (FakeFs::new(), FakeRunner::new());
    let sys = Sys {
        fs: &fs,
        runner: &runner,
    };
    let plan_after = |planned: &[Resource]| {
        FirewallInbound
            .plan(
                &PlanCx {
                    facts: &facts,
                    params: &web,
                    planned,
                },
                sys,
            )
            .unwrap()
    };
    let docker = [Resource::Package(Package {
        name: DOCKER_PACKAGE.to_owned(),
    })];
    let steps = plan_after(&docker);
    let mut with_docker = facts.clone();
    with_docker.docker = true;
    assert_eq!(
        ruleset_of(&steps),
        ruleset_of(&self::steps(&with_docker, &web).unwrap())
    );
    assert!(ruleset_of(&steps).contains("iifname \"docker0\" accept"));
    assert!(
        steps.notes[0]
            .starts_with("deploy.docker installs Docker: input from docker0 and br-* is accepted"),
        "{:?}",
        steps.notes
    );

    let other = [Resource::Package(Package {
        name: "nftables".to_owned(),
    })];
    let steps = plan_after(&other);
    assert!(!ruleset_of(&steps).contains("docker0"));
    assert!(steps.notes.is_empty(), "{:?}", steps.notes);
}

/// Both modules from a profile, through the engine.
#[test]
fn plans_the_bridges_with_deploy_docker_in_the_profile() {
    let fs = FakeFs::new();
    let runner = FakeRunner::new()
        .on("dpkg-query", ["-W"], Output::success("not-installed"))
        .on("dpkg", ["--print-architecture"], Output::success("amd64\n"))
        .on(
            "systemctl",
            ["show"],
            Output::success("LoadState=not-found\nActiveState=inactive\nUnitFileState=\n"),
        );
    let facts = facts();
    let modules = [
        Selected::new(&crate::modules::DeployDocker),
        Selected::new(&FirewallInbound),
    ];
    let plan = engine::plan(
        &modules,
        &facts,
        Sys {
            fs: &fs,
            runner: &runner,
        },
    )
    .unwrap();
    let ruleset = plan
        .steps()
        .find_map(|s| match &s.resource {
            Resource::File(f) if f.path == Path::new(RULESET) => {
                Some(String::from_utf8(f.content.clone()).unwrap())
            }
            _ => None,
        })
        .unwrap();
    assert!(ruleset.contains("iifname \"br-*\" accept"), "{ruleset}");
}

/// The TCP ports a later module reads back: from the planned ruleset, else
/// from the one on disk, else none.
#[test]
fn accepted_tcp_reads_the_planned_ruleset_then_the_one_on_disk() {
    let facts = facts();
    let web = steps(&facts, &params("allow = [\"80/tcp\", \"443/udp\"]")).unwrap();
    let (fs, runner) = (FakeFs::new(), FakeRunner::new());
    let sys = Sys {
        fs: &fs,
        runner: &runner,
    };
    let accepted = |planned: &[Resource], sys| {
        let empty = toml::Table::new();
        let cx = PlanCx {
            facts: &facts,
            params: &empty,
            planned,
        };
        accepted_tcp(&cx, sys).unwrap()
    };
    let ssh: BTreeSet<u16> = ssh_ports(&facts);
    let mut want = ssh.clone();
    want.insert(80);
    assert_eq!(accepted(&web.resources, sys), Some(want));
    assert_eq!(accepted(&[], sys), None);

    let minimal = steps(&facts, &toml::Table::new()).unwrap();
    let fs = FakeFs::new().with_file(RULESET, ruleset_of(&minimal));
    let sys = Sys {
        fs: &fs,
        runner: &runner,
    };
    assert_eq!(accepted(&[], sys), Some(ssh));
}

#[test]
fn allow_takes_ports_with_a_protocol() {
    for good in ["22/tcp", "443/udp", "65535/tcp"] {
        let table = params(&format!("allow = [\"{good}\"]"));
        assert!(FirewallInbound.check_params(&table).is_ok(), "{good}");
    }
    for bad in [
        "22",
        "0/tcp",
        "65536/tcp",
        "22/sctp",
        "80-90/tcp",
        "ssh/tcp",
    ] {
        let table = params(&format!("allow = [\"{bad}\"]"));
        let err = FirewallInbound.check_params(&table).unwrap_err();
        assert!(
            err.to_string().contains("is not `<port>/tcp`"),
            "{bad}: {err}"
        );
    }
    let typo = params("allowed = [\"22/tcp\"]");
    for err in [
        FirewallInbound.check_params(&typo).unwrap_err(),
        steps(&facts(), &typo).unwrap_err(),
    ] {
        assert!(err.to_string().contains("unknown field `allowed`"), "{err}");
    }
}

fn listener(port: u16, process: &str) -> Listener {
    Listener {
        proto: Proto::Tcp,
        addr: "0.0.0.0".to_owned(),
        port,
        processes: vec![process.to_owned()],
    }
}

/// A listener's process name proves nothing: only the ports that the
/// system's sshd, run by root, listens on count.
#[test]
fn a_listener_named_sshd_is_not_an_ssh_port() {
    let mut facts = facts();
    facts.listeners = vec![listener(2222, "sshd"), listener(2200, "sshd-session")];
    facts.ssh.listening = vec![2022];
    let model = Ruleset::new(&facts, &Params::default());
    assert_eq!(model.tcp, [22, 2022]);
}

/// The ports of the `tcp dport` line of a rendered ruleset.
fn rendered_tcp(text: &str) -> BTreeSet<u16> {
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("tcp dport"))
        .unwrap();
    let set = line.split_once('{').unwrap().1.split_once('}').unwrap().0;
    set.split(',').map(|p| p.trim().parse().unwrap()).collect()
}

proptest! {
    /// Whatever the profile allows, every current SSH port is accepted:
    /// the session's, root's sshd listeners', the socket's and `sshd -T`'s.
    #[test]
    fn always_accepts_the_ssh_ports(
        session_port in 1..=u16::MAX,
        listen in proptest::collection::vec(1..=u16::MAX, 0..3),
        socket in proptest::collection::vec(1..=u16::MAX, 0..3),
        config in proptest::collection::vec(1..=u16::MAX, 0..3),
        other in proptest::collection::vec(1..=u16::MAX, 0..3),
        allow in proptest::collection::vec((1..=u16::MAX, any::<bool>()), 0..4),
    ) {
        let mut facts = facts();
        facts.session = Some(session(&format!("198.51.100.5:{session_port}")));
        facts.ssh.listening = listen.clone();
        facts.listeners = other.iter().map(|p| listener(*p, "postgres")).collect();
        facts.ssh.socket_ports = socket.clone();
        facts.ssh.activation = crate::facts::SshActivation::Socket;
        let sshd_t: String = config.iter().map(|p| format!("port {p}\n")).collect();
        facts.ssh.effective = Some(sshd_config::SshdConfig::parse(&sshd_t));
        let list = allow
            .iter()
            .map(|(p, tcp)| format!("\"{p}/{}\"", if *tcp { "tcp" } else { "udp" }))
            .collect::<Vec<_>>()
            .join(", ");
        let params = params(&format!("allow = [{list}]"));
        let model = Ruleset::new(&facts, &parse_params(&params).unwrap());
        let text = ruleset_of(&steps(&facts, &params).unwrap());

        let mut ssh: BTreeSet<u16> = [session_port].into();
        ssh.extend(listen.iter().chain(&socket).chain(&config));
        let tcp: BTreeSet<u16> = model.tcp.iter().copied().collect();
        prop_assert!(tcp.is_superset(&ssh), "{tcp:?} lacks some of {ssh:?}");
        prop_assert_eq!(rendered_tcp(&text), tcp);
        for (port, is_tcp) in &allow {
            let ports = if *is_tcp { &model.tcp } else { &model.udp };
            prop_assert!(ports.contains(port));
        }
    }
}

#[test]
fn notes_what_it_leaves_alone() {
    let mut facts = facts();
    let notes = FirewallInbound.notes(&facts);
    assert_eq!(
        notes,
        [
            "always accepts TCP 22, the current SSH ports (this session's, root's sshd listeners \
          and `Port`), whatever `allow` says"
        ]
    );
    facts.docker = true;
    facts.firewall_tools = FirewallTools {
        nft: false,
        ufw: Some(false),
        firewalld: Some(false),
        nftables_service: Some(true),
        legacy_filter: false,
    };
    facts.ipv6 = true;
    let fw = facts.firewall.as_mut().unwrap();
    fw.published.push(crate::facts::PublishedPort {
        family: "ip".into(),
        proto: "tcp".into(),
        port: 5432,
        address: None,
        filtered: false,
    });
    // Published over IPv6 too: Docker's ip6tables is on, nothing is proxied.
    fw.published.push(crate::facts::PublishedPort {
        family: "ip6".into(),
        proto: "tcp".into(),
        port: 8080,
        address: None,
        filtered: false,
    });
    fw.published.push(crate::facts::PublishedPort {
        family: "ip".into(),
        proto: "tcp".into(),
        port: 8080,
        address: None,
        filtered: false,
    });
    let chain = |table: &str, name: &str, drops_unmatched| InputChain {
        family: "ip".into(),
        table: table.into(),
        name: name.into(),
        drops_unmatched,
        open_ports: Vec::new(),
        interface_ports: Vec::new(),
        unread_ports: Vec::new(),
    };
    // Docker's accept-policy INPUT is not worth a note; a dropping one is.
    fw.input_chains.push(chain("filter", "INPUT", false));
    fw.input_chains.push(chain("mine", "input", true));
    facts.bridges.push(crate::facts::Bridge {
        name: "br-lan".into(),
        docker: false,
    });
    insta::assert_yaml_snapshot!(FirewallInbound.notes(&facts));
    // Over IPv6 only 5432/tcp is proxied, and only until `allow` has it.
    let plan_notes = |facts: &Facts, allow: &str| {
        steps(facts, &params(&format!("allow = [{allow}]")))
            .unwrap()
            .notes
    };
    assert_eq!(
        plan_notes(&facts, ""),
        [
            "over IPv6, Docker's ip6tables is off (the default before Docker 27), so \
          connections to 5432/tcp reach docker-proxy on the host and this firewall drops \
          them; to keep them, add them to `allow`: [\"5432/tcp\"]"
        ]
    );
    assert!(plan_notes(&facts, "\"5432/tcp\"").is_empty());
    facts.ipv6 = false;
    assert!(plan_notes(&facts, "").is_empty());
}

#[test]
fn verify_reads_back_the_loaded_table() {
    let json = std::fs::read(testdata(LOADED)).unwrap();
    let want = Ruleset::new(&facts(), &Params::default());
    assert_eq!(check_loaded(&json, &want), Ok(()));

    let mut more = want.clone();
    more.tcp.push(2222);
    more.udp.push(443);
    assert_eq!(
        check_loaded(&json, &more),
        Err("it does not accept tcp/2222, udp/443".to_owned())
    );
    assert_eq!(
        check_loaded(br#"{"nftables": []}"#, &want),
        Err("the table has no input chain".to_owned())
    );
    let accepting = String::from_utf8(json)
        .unwrap()
        .replace("\"policy\": \"drop\"", "\"policy\": \"accept\"");
    assert_eq!(
        check_loaded(accepting.as_bytes(), &want),
        Err("its input chain does not drop by default".to_owned())
    );
}

/// What the fix promises is what the audit checks: FW-001 passes on the
/// loaded table.
#[test]
fn fw_001_passes_on_the_loaded_table() {
    let json = std::fs::read(testdata(LOADED)).unwrap();
    let mut facts = facts();
    facts.firewall = crate::facts::firewall::parse_json(&json);
    facts.ipv6 = true;
    let control = crate::audit::catalog()
        .unwrap()
        .into_iter()
        .find(|c| c.id == "FW-001")
        .unwrap();
    assert_eq!(control.fix.as_deref(), Some("firewall.inbound"));
    assert_eq!(
        crate::audit::evaluate(&control.check, &facts),
        crate::audit::Outcome::Pass
    );
}

/// What the simulated host has.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct State {
    installed: bool,
    enabled: bool,
    active: bool,
    /// The ruleset the table was loaded from, if it is loaded.
    loaded: Option<Vec<u8>>,
}

/// apt, systemd, systemd-run and nft over a [`FakeFs`]. Starting or
/// reloading the unit loads the ruleset file; stopping it deletes the
/// table.
struct Host<'a> {
    fs: &'a FakeFs,
    state: Mutex<State>,
}

impl Host<'_> {
    fn state(&self) -> State {
        self.state.lock().unwrap().clone()
    }

    fn load(&self, state: &mut State) {
        state.loaded = Some(self.fs.read(Path::new(RULESET)).unwrap());
    }
}

impl Runner for Host<'_> {
    fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
        let mut state = self.state.lock().unwrap();
        let args: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        let fail = |stderr: &str| Output {
            status: 1,
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        };
        let out = match (cmd.program.as_str(), args.as_slice()) {
            ("dpkg-query", _) if state.installed => Output::success("installed"),
            ("dpkg-query", _) => fail(""),
            ("apt-get", _) => {
                state.installed |= args.contains(&"install");
                Output::success("")
            }
            ("nft", ["-c", "-f", path]) if self.fs.exists(Path::new(path)) => Output::success(""),
            ("nft", ["-c", ..]) => fail("No such file or directory"),
            ("nft", ["-j", "list", "table", "inet", "vps_ready"]) => match &state.loaded {
                Some(_) => Output::success(std::fs::read(testdata(LOADED)).unwrap()),
                None => fail("Error: No such file or directory"),
            },
            ("systemd-run", _) => Output::success(""),
            (p, ["version"]) if p.ends_with("/bin/vps-ready") => {
                Output::success(format!("{}\n", crate::VERSION_INFO))
            }
            ("systemctl", ["show", _, unit]) if *unit == UNIT => {
                let load = if self.fs.exists(Path::new(UNIT_FILE)) {
                    "loaded"
                } else {
                    "not-found"
                };
                let file = if state.enabled { "enabled" } else { "disabled" };
                let active = if state.active { "active" } else { "inactive" };
                Output::success(format!(
                    "LoadState={load}\nActiveState={active}\nUnitFileState={file}\n"
                ))
            }
            ("systemctl", ["enable", unit]) if *unit == UNIT => {
                state.enabled = true;
                Output::success("")
            }
            ("systemctl", ["disable", unit]) if *unit == UNIT => {
                state.enabled = false;
                Output::success("")
            }
            ("systemctl", ["start", unit]) if *unit == UNIT => {
                state.active = true;
                self.load(&mut state);
                Output::success("")
            }
            ("systemctl", ["stop", unit]) if *unit == UNIT => {
                state.active = false;
                state.loaded = None;
                Output::success("")
            }
            ("systemctl", ["try-reload-or-restart", unit]) if *unit == UNIT => {
                if state.active {
                    self.load(&mut state);
                }
                Output::success("")
            }
            // daemon-reload, the boot hook and the dead-man timers.
            ("systemctl", _) => Output::success(""),
            _ => return Err(SysError::NotFound(cmd.program.clone())),
        };
        Ok(out)
    }
}

/// A host that can arm the dead-man switch, with `/etc/systemd/system`.
fn fake_fs() -> FakeFs {
    let fs = FakeFs::new()
        .with_file(BOOT_ID, "a\n")
        .with_file("/proc/uptime", "1000.25 900.00\n")
        .with_file(BIN, "\x7fELF");
    fs.create_dir_all(Path::new("/etc/systemd/system"), 0o755)
        .unwrap();
    fs
}

/// Every path under `/etc`, with a file's content.
fn etc(fs: &dyn Fs) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn walk(fs: &dyn Fs, dir: &Path, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for path in fs.read_dir(dir).unwrap() {
            if fs.metadata(&path).unwrap().kind == FileKind::Dir {
                out.insert(path.clone(), None);
                walk(fs, &path, out);
            } else {
                out.insert(path.clone(), Some(fs.read(&path).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(fs, Path::new("/etc"), &mut out);
    out
}

fn plan<'a>(fs: &dyn Fs, runner: &dyn Runner, facts: &'a Facts) -> Plan<'a> {
    engine::plan(
        &[Selected::new(&FirewallInbound)],
        facts,
        Sys { fs, runner },
    )
    .unwrap()
}

#[test]
fn first_plan_snapshot() {
    let fs = fake_fs();
    let host = Host {
        fs: &fs,
        state: Mutex::default(),
    };
    let mut facts = facts();
    facts.firewall_tools.nft = false;
    insta::assert_yaml_snapshot!(plan(&fs, &host, &facts));
}

/// Apply waits for a confirm with the table loaded; the next plan is
/// empty; rollback stops the unit, which deletes the table, and removes
/// the files and the directory. The package stays.
#[test]
fn apply_is_idempotent_and_rolls_back() {
    for nft in [true, false] {
        let fs = fake_fs();
        let host = Host {
            fs: &fs,
            state: Mutex::new(State {
                installed: nft,
                ..State::default()
            }),
        };
        let sys = Sys {
            fs: &fs,
            runner: &host,
        };
        let mut facts = facts();
        facts.firewall_tools.nft = nft;
        let before = etc(&fs);

        let first = plan(&fs, &host, &facts);
        let state = StateDir::create(&fs, STATE, 0).unwrap();
        let engine = Engine::lock(&state, sys).unwrap();
        let deadman = Deadman {
            binary: BIN.into(),
            ..Deadman::default()
        };
        let outcome = engine.apply(&first, &deadman, &mut |_| {}).unwrap();
        assert!(
            matches!(outcome, ApplyOutcome::Pending { .. }),
            "{nft}: {outcome:?}"
        );
        let applied = host.state();
        assert!(applied.installed && applied.enabled && applied.active);
        assert_eq!(
            applied.loaded.as_deref(),
            Some(fs.read(Path::new(RULESET)).unwrap().as_slice())
        );

        let next = plan(&fs, &host, &facts);
        assert_eq!(next.steps().count(), 0, "{nft}");

        engine.rollback(Target::Last, &mut |_| {}).unwrap();
        let mut after = etc(&fs);
        after.remove(Path::new(engine::deadman::HOOK));
        assert_eq!(after, before, "{nft}");
        assert!(!fs.exists(Path::new(DIR)));
        let restored = host.state();
        assert_eq!(
            restored,
            State {
                installed: true,
                ..State::default()
            }
        );
    }
}
