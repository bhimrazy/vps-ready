//! `net.tunnel` on [`FakeFs`], with dpkg, apt, systemctl and cloudflared
//! simulated by [`Host`].

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use super::*;
use crate::engine::{self, ApplyOutcome, Deadman, Engine, Plan, Selected, StateDir, Target};
use crate::facts::fixtures::host;
use crate::facts::{Listener, Route};
use crate::sys::fake::FakeFs;
use crate::sys::{FileKind, Fs, Runner};

const STATE: &str = "/var/lib/vps-ready";
const TOKEN: &str = "/root/cloudflared-token";
const WITH_TOKEN: &str = "token_file = \"/root/cloudflared-token\"";
/// Written to the token file; it must never show up anywhere else.
const MARKER: &str = "MARKER-TOKEN-placeholder-not-a-real-token";

/// A Debian host where installing `cloudflared` starts nothing, as the
/// package does, and the connector connects unless `connects` is false.
struct Host {
    installed: Mutex<bool>,
    /// Unit name to (enabled, active).
    units: Mutex<BTreeMap<String, (bool, bool)>>,
    connects: bool,
    /// What `stat -L -c %d:%i` prints for the running binary.
    running_inode: &'static str,
    calls: Mutex<Vec<Cmd>>,
}

impl Host {
    fn new() -> Self {
        Self {
            installed: Mutex::new(false),
            units: Mutex::new(BTreeMap::new()),
            connects: true,
            running_inode: "2049:100",
            calls: Mutex::new(Vec::new()),
        }
    }

    fn unit(&self, name: &str) -> (bool, bool) {
        self.units
            .lock()
            .unwrap()
            .get(name)
            .copied()
            .unwrap_or_default()
    }

    /// Every `systemctl` command that changes a unit, without `show`.
    fn systemctl(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.program == "systemctl" && c.args[0] != "show")
            .map(|c| c.args.join(" "))
            .collect()
    }
}

impl Runner for Host {
    fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
        self.calls.lock().unwrap().push(cmd.clone());
        let args: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        let mut installed = self.installed.lock().unwrap();
        let mut units = self.units.lock().unwrap();
        let out = match (cmd.program.as_str(), &args[..]) {
            ("dpkg-query", [.., "cloudflared"]) => Output::success(if *installed {
                "installed"
            } else {
                "not-installed"
            }),
            ("dpkg", ["--print-architecture"]) => Output::success("amd64\n"),
            ("apt-config", _) | ("apt-get", [.., "update"]) | ("sh", ["-n", _]) => {
                Output::success("")
            }
            ("apt-get", [.., "cloudflared"]) => {
                *installed = true;
                Output::success("")
            }
            ("systemctl", ["show", props, unit]) => {
                let (enabled, active) = units.get(*unit).copied().unwrap_or_default();
                if props.contains("MainPID") {
                    Output::success(format!(
                        "ActiveState={}\nMainPID={}\n",
                        if active { "active" } else { "inactive" },
                        if active { "4242" } else { "0" }
                    ))
                } else {
                    Output::success(format!(
                        "LoadState=loaded\nUnitFileState={}\nActiveState={}\n",
                        if enabled { "enabled" } else { "disabled" },
                        if active { "active" } else { "inactive" }
                    ))
                }
            }
            ("systemctl", ["daemon-reload"]) => Output::success(""),
            ("systemctl", [verb, unit]) => {
                let state = units.entry((*unit).to_owned()).or_default();
                match *verb {
                    "enable" => state.0 = true,
                    "disable" => state.0 = false,
                    "start" if *unit == UNIT && !self.connects => {
                        return Ok(Output {
                            status: 1,
                            stdout: Vec::new(),
                            stderr: format!(
                                "Job for {UNIT} failed because a timeout was exceeded.\n"
                            )
                            .into_bytes(),
                        });
                    }
                    "start" => state.1 = true,
                    "stop" => state.1 = false,
                    "try-restart" => {}
                    other => panic!("systemctl {other}"),
                }
                Output::success("")
            }
            ("cloudflared", ["tunnel", "--metrics", METRICS, "ready"]) => {
                if self.connects {
                    Output::success("")
                } else {
                    Output {
                        status: 1,
                        stdout: Vec::new(),
                        stderr: b"not ready\n".to_vec(),
                    }
                }
            }
            ("stat", ["-L", "-c", "%d:%i", _, BINARY]) => {
                Output::success(format!("{}\n2049:100\n", self.running_inode))
            }
            ("journalctl", _) => Output::success(""),
            (other, _) => return Err(SysError::NotFound(other.to_owned())),
        };
        Ok(out)
    }
}

/// `/etc` with apt's and systemd's directories, a resolv.conf, cgroup v2,
/// and a root-only token file holding [`MARKER`].
fn fs() -> FakeFs {
    let fs = FakeFs::new()
        .with_dir("/", root(0o755))
        .with_dir("/etc", root(0o755))
        .with_dir("/etc/apt", root(0o755))
        .with_dir("/etc/apt/apt.conf.d", root(0o755))
        .with_dir("/etc/apt/sources.list.d", root(0o755))
        .with_dir("/etc/systemd", root(0o755))
        .with_dir("/etc/systemd/system", root(0o755))
        .with_dir("/root", root(0o700))
        .with_file("/etc/resolv.conf", "nameserver 192.0.2.53\n")
        .with_file("/sys/fs/cgroup/cgroup.controllers", "cpu memory\n");
    fs.write_atomic(Path::new(TOKEN), MARKER.as_bytes(), root(0o600))
        .unwrap();
    fs
}

/// The captured Debian 13 host, without cloudflared.
fn facts() -> Facts {
    host("debian-13", &[])
}

/// `facts()` after an apply: the connector and the path unit active.
fn applied() -> Facts {
    let mut facts = facts();
    facts.cloudflared.version = Some("2026.11.1".into());
    facts.cloudflared.units = vec![UNIT.into(), RESTART_UNIT.into(), PATH_UNIT.into()];
    facts.cloudflared.active = vec![UNIT.into(), PATH_UNIT.into()];
    facts
}

fn table(params: &str) -> toml::Table {
    toml::from_str(params).unwrap()
}

fn try_steps(
    facts: &Facts,
    fs: &FakeFs,
    runner: &Host,
    params: &str,
) -> Result<ModuleSteps, ModuleError> {
    NetTunnel.plan(
        &PlanCx {
            facts,
            params: &table(params),
            planned: &[],
        },
        Sys { fs, runner },
    )
}

fn steps(facts: &Facts, fs: &FakeFs, runner: &Host, params: &str) -> ModuleSteps {
    try_steps(facts, fs, runner, params).unwrap()
}

fn ids(steps: &ModuleSteps) -> Vec<String> {
    steps.resources.iter().map(Resource::id).collect()
}

fn content(steps: &ModuleSteps, path: &str) -> String {
    steps
        .resources
        .iter()
        .find_map(|r| match r {
            Resource::File(f) if f.path == Path::new(path) => {
                Some(String::from_utf8(f.content.clone()).unwrap())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("no {path} in {:?}", ids(steps)))
}

fn plan<'a>(fs: &FakeFs, runner: &Host, facts: &'a Facts, params: &'a toml::Table) -> Plan<'a> {
    let selected = Selected {
        module: &NetTunnel,
        params,
    };
    engine::plan(&[selected], facts, Sys { fs, runner }).unwrap()
}

fn change_ids(plan: &Plan) -> Vec<String> {
    plan.steps().map(|s| s.change.id.clone()).collect()
}

/// Every file under `/etc`, with its content and mode.
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

const INSTALL: [&str; 5] = [
    "directory:/etc/apt/keyrings",
    "file:/etc/apt/keyrings/cloudflared.asc",
    "file:/etc/apt/sources.list.d/cloudflared.sources",
    "file:/etc/apt/apt.conf.d/52vps-ready-cloudflared",
    "package:cloudflared",
];

const CONNECTOR: [&str; 8] = [
    "directory:/etc/vps-ready",
    "file:/etc/vps-ready/cloudflared.yml",
    "file:/etc/vps-ready/cloudflared-restart.sh",
    "file:/etc/systemd/system/vps-ready-cloudflared.service",
    "file:/etc/systemd/system/vps-ready-cloudflared-restart.service",
    "file:/etc/systemd/system/vps-ready-cloudflared-restart.path",
    "service:vps-ready-cloudflared.service",
    "service:vps-ready-cloudflared-restart.path",
];

#[test]
fn applies_on_debian_with_systemd_without_the_dead_man() {
    let mut facts = facts();
    assert_eq!(NetTunnel.applicable(&facts), Applicability::Applicable);
    assert!(!NetTunnel.needs_deadman());
    // Its own units do not count as a hand-made setup.
    let ours = applied();
    assert_eq!(NetTunnel.applicable(&ours), Applicability::Applicable);
    facts.cloudflared.units = vec!["cloudflared.service".into()];
    assert_eq!(
        NetTunnel.applicable(&facts),
        Applicability::NotApplicable {
            reason: "a cloudflared unit that vps-ready did not write exists \
                     (cloudflared.service), so this tunnel setup is left alone"
                .into()
        }
    );
    facts.init = Init::Unknown;
    assert_eq!(
        NetTunnel.applicable(&facts),
        Applicability::NotApplicable {
            reason: "it needs systemd, to run the connector".into()
        }
    );
}

#[test]
fn plan_on_a_fresh_host_snapshot() {
    let (fs, runner) = (fs(), Host::new());
    let facts = facts();
    let params = table(WITH_TOKEN);
    let plan = plan(&fs, &runner, &facts, &params);
    let want: Vec<&str> = INSTALL.iter().chain(&CONNECTOR).copied().collect();
    assert_eq!(change_ids(&plan), want);
    assert!(!plan.needs_deadman());
    insta::assert_yaml_snapshot!(plan);
}

#[test]
fn the_apt_source_uses_suite_any_and_the_embedded_key() {
    let (fs, runner) = (fs(), Host::new());
    let steps = steps(&facts(), &fs, &runner, "");
    assert!(
        content(&steps, "/etc/apt/sources.list.d/cloudflared.sources")
            .contains("URIs: https://pkg.cloudflare.com/cloudflared\nSuites: any\n")
    );
    assert_eq!(
        content(&steps, "/etc/apt/keyrings/cloudflared.asc"),
        crate::resource::CLOUDFLARE_KEY
    );
    assert_eq!(
        crate::resource::CLOUDFLARE_FINGERPRINT,
        "CC94B39C77AE7342A68B89628A682D308D4E5E73"
    );
}

#[test]
fn origin_file() {
    let (fs, runner) = (fs(), Host::new());
    let on = steps(&facts(), &fs, &runner, "");
    insta::assert_snapshot!(content(&on, ORIGINS), @r#"
    // Written by vps-ready (net.tunnel). `vps-ready rollback --last` removes it.
    Unattended-Upgrade::Origins-Pattern { "origin=cloudflared,codename=any"; };
    "#);
    let off = steps(&facts(), &fs, &runner, "auto_update = false");
    assert!(
        !ids(&off).iter().any(|id| id.contains("52vps")),
        "{:?}",
        ids(&off)
    );
}

#[test]
fn connector_unit_snapshot() {
    let (fs, runner) = (fs(), Host::new());
    let steps = steps(&facts(), &fs, &runner, WITH_TOKEN);
    insta::assert_snapshot!(content(&steps, UNIT_FILE), @r"
    # Written by vps-ready (net.tunnel). `vps-ready rollback --last` restores
    # the previous state; edits here are replaced by the next apply.
    [Unit]
    Description=Cloudflare Tunnel connector (vps-ready net.tunnel)
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=notify
    TimeoutStartSec=30
    LoadCredential=token:/root/cloudflared-token
    ExecStart=/usr/bin/cloudflared tunnel --config /etc/vps-ready/cloudflared.yml --metrics 127.0.0.1:20241 run --token-file ${CREDENTIALS_DIRECTORY}/token
    DynamicUser=yes
    NoNewPrivileges=yes
    ProtectSystem=strict
    ProtectHome=yes
    PrivateTmp=yes
    CapabilityBoundingSet=
    RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
    IPAddressDeny=link-local multicast 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 168.63.129.16 fc00::/7
    IPAddressAllow=localhost 192.0.2.53
    Restart=on-failure
    RestartSec=5s

    [Install]
    WantedBy=multi-user.target
    ");
    insta::assert_snapshot!(content(&steps, PATH_UNIT_FILE), @r"
    # Written by vps-ready (net.tunnel). `vps-ready rollback --last` restores
    # the previous state; edits here are replaced by the next apply.
    [Unit]
    Description=Watch cloudflared for upgrades (vps-ready net.tunnel)

    [Path]
    PathChanged=/usr/bin/cloudflared
    Unit=vps-ready-cloudflared-restart.service

    [Install]
    WantedBy=multi-user.target
    ");
    insta::assert_snapshot!(content(&steps, RESTART_UNIT_FILE), @r"
    # Written by vps-ready (net.tunnel). `vps-ready rollback --last` restores
    # the previous state; edits here are replaced by the next apply.
    [Unit]
    Description=Restart the Cloudflare Tunnel connector on a new cloudflared (vps-ready net.tunnel)

    [Service]
    Type=oneshot
    TimeoutStartSec=10min
    ExecStart=/bin/sh /etc/vps-ready/cloudflared-restart.sh
    ");
    assert_eq!(content(&steps, CONFIG), CONFIG_TEXT);
}

#[test]
fn edge_ip_version_auto_without_an_ipv4_default_route() {
    let (fs, runner) = (fs(), Host::new());
    let mut facts = facts();
    facts.routes = vec![Route {
        dst: "default".into(),
        dev: Some("eth0".into()),
        gateway: Some("2001:db8::1".parse().unwrap()),
        table: None,
    }];
    let steps = steps(&facts, &fs, &runner, WITH_TOKEN);
    assert!(
        content(&steps, UNIT_FILE)
            .contains("--metrics 127.0.0.1:20241 --edge-ip-version auto run --token-file")
    );
    assert!(
        steps
            .notes
            .iter()
            .any(|n| n.contains("no IPv4 default route"))
    );
    // The captured host has one.
    let v4 = self::steps(&self::facts(), &fs, &runner, WITH_TOKEN);
    assert!(!content(&v4, UNIT_FILE).contains("--edge-ip-version"));
}

#[test]
fn resolvers_are_allowed_without_zone_ids() {
    let text = "# Generated\nsearch example.com\nnameserver 127.0.0.53\n\
                nameserver fe80::1%eth0\nnameserver 100.100.100.100\n\
                nameserver 168.63.129.16\nnameserver 192.0.2.53\nnameserver 192.0.2.53\n\
                nameserver not-an-address\n";
    let found: Vec<String> = parse_resolvers(text)
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        found,
        ["fe80::1", "100.100.100.100", "168.63.129.16", "192.0.2.53"]
    );
    let fs = fs().with_file("/etc/resolv.conf", text);
    let steps = steps(&facts(), &fs, &Host::new(), WITH_TOKEN);
    assert!(
        content(&steps, UNIT_FILE).contains(
            "\nIPAddressAllow=localhost fe80::1 100.100.100.100 168.63.129.16 192.0.2.53\n"
        )
    );
    assert!(
        steps.notes.iter().any(|n| n.starts_with(
            "the resolver fe80::1, 100.100.100.100, 168.63.129.16 in /etc/resolv.conf"
        )),
        "{:?}",
        steps.notes
    );
}

#[test]
fn the_token_path_is_only_in_load_credential() {
    let (fs, runner) = (fs(), Host::new());
    let steps = steps(&facts(), &fs, &runner, WITH_TOKEN);
    for r in &steps.resources {
        if let Resource::File(f) = r {
            let text = String::from_utf8_lossy(&f.content);
            let lines: Vec<&str> = text.lines().filter(|l| l.contains(TOKEN)).collect();
            if f.path == Path::new(UNIT_FILE) {
                assert_eq!(lines, [format!("LoadCredential=token:{TOKEN}")]);
            } else {
                assert!(lines.is_empty(), "{}: {lines:?}", f.path.display());
            }
        }
    }
}

/// The token's bytes are never read: they are nowhere in the plan, the
/// journal, the files written or the commands run.
#[test]
fn the_token_never_passes_through_vps_ready() {
    let (fs, runner) = (fs(), Host::new());
    let facts = facts();
    let params = table(WITH_TOKEN);
    let plan = plan(&fs, &runner, &facts, &params);
    assert!(!serde_json::to_string(&plan).unwrap().contains(MARKER));
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
        .apply(&plan, &Deadman::default(), &mut |_| {})
        .unwrap();
    engine.rollback(Target::Last, &mut |_| {}).unwrap();
    for cmd in runner.calls.lock().unwrap().iter() {
        assert!(!format!("{cmd:?}").contains(MARKER), "{cmd:?}");
    }
    fn walk(fs: &FakeFs, dir: &Path) {
        for path in fs.read_dir(dir).unwrap() {
            if fs.metadata(&path).unwrap().kind == FileKind::Dir {
                walk(fs, &path);
            } else if path != Path::new(TOKEN) {
                let bytes = fs.read(&path).unwrap();
                assert!(
                    !String::from_utf8_lossy(&bytes).contains(MARKER),
                    "{}",
                    path.display()
                );
            }
        }
    }
    walk(&fs, Path::new("/"));
}

#[test]
fn refuses_an_unsafe_token_file() {
    let runner = Host::new();
    let fix = "it must be a regular file owned by root with mode 0600, in directories only root \
               can write to";
    for (mode, uid, why) in [
        (
            0o640,
            0,
            "its mode 0640 lets other users read it; `chmod 600` it",
        ),
        (
            0o604,
            0,
            "its mode 0604 lets other users read it; `chmod 600` it",
        ),
        (0o600, 1000, "it is owned by uid 1000, not root"),
    ] {
        let fs = fs();
        fs.write_atomic(Path::new(TOKEN), b"t", FileOwner { mode, uid, gid: 0 })
            .unwrap();
        let err = try_steps(&facts(), &fs, &runner, WITH_TOKEN).unwrap_err();
        assert_eq!(err.to_string(), format!("token_file {TOKEN}: {why}; {fix}"));
    }
    let fs = FakeFs::new()
        .with_dir("/", root(0o755))
        .with_dir("/etc", root(0o755))
        .with_dir("/root", root(0o700))
        .with_symlink(TOKEN, "/root/real-token");
    let err = try_steps(&facts(), &fs, &runner, WITH_TOKEN).unwrap_err();
    assert!(err.to_string().contains("it is a symlink"), "{err}");

    for path in ["relative/token", "/root/my token", "/root/%n", "/root/a\nb"] {
        let params = format!("token_file = {path:?}");
        let err = NetTunnel.check_params(&table(&params)).unwrap_err();
        assert!(
            err.to_string()
                .contains("is not an absolute path of letters"),
            "{path:?}: {err}"
        );
    }
    let err = NetTunnel
        .check_params(&table("provider = \"tailscale\""))
        .unwrap_err();
    assert!(err.to_string().contains("unknown variant"), "{err}");
}

#[test]
fn no_token_file_installs_and_says_how_to_add_one() {
    let (fs, runner) = (fs(), Host::new());
    let steps = steps(&facts(), &fs, &runner, "");
    assert_eq!(ids(&steps), INSTALL);
    assert!(steps.reloads.is_empty());
    assert!(
        steps.notes.contains(
            &"no token_file, so no connector runs: create a tunnel in the Cloudflare dashboard, \
          save its token to a root-only file, set `token_file` and apply again"
                .to_owned()
        )
    );
}

#[test]
fn refuses_an_old_cloudflared() {
    let (fs, runner) = (fs(), Host::new());
    let mut facts = facts();
    facts.cloudflared.version = Some("2025.3.9".into());
    let err = try_steps(&facts, &fs, &runner, "").unwrap_err();
    assert!(
        err.to_string()
            .starts_with("cloudflared 2025.3.9 is installed, and the connector needs 2025.4.0"),
        "{err}"
    );
    facts.cloudflared.version = Some("2025.4.0".into());
    assert!(try_steps(&facts, &fs, &runner, "").is_ok());
    assert_eq!(parse_triple("2026.11.1"), Some((2026, 11, 1)));
    assert_eq!(parse_triple("DEV"), None);
}

#[test]
fn refuses_another_listener_on_the_metrics_port() {
    let (fs, runner) = (fs(), Host::new());
    let mut facts = facts();
    facts.listeners.push(Listener {
        proto: Proto::Tcp,
        addr: "127.0.0.1".into(),
        port: METRICS_PORT,
        processes: vec!["node".into()],
    });
    let err = try_steps(&facts, &fs, &runner, WITH_TOKEN).unwrap_err();
    assert!(
        err.to_string()
            .starts_with("something already listens on 127.0.0.1:20241"),
        "{err}"
    );
    // Its own connector's listener is not a conflict.
    let mut ours = applied();
    ours.listeners = facts.listeners;
    assert!(try_steps(&ours, &fs, &runner, WITH_TOKEN).is_ok());
}

#[test]
fn notes_the_filter_in_a_container_or_without_cgroup_v2() {
    let runner = Host::new();
    let note = "the connector's address filter (`IPAddressDeny=`) is not in effect on this host";
    // The captured host is a container.
    let steps = steps(&facts(), &fs(), &runner, WITH_TOKEN);
    assert!(
        steps.notes.contains(&format!(
            "{note} if the container does not support cgroup BPF"
        )),
        "{:?}",
        steps.notes
    );
    let mut vm = facts();
    vm.virtualization.container = crate::facts::Virt::None;
    let fs = fs();
    fs.remove(Path::new("/sys/fs/cgroup/cgroup.controllers"))
        .unwrap();
    let steps = self::steps(&vm, &fs, &runner, WITH_TOKEN);
    assert!(
        steps
            .notes
            .contains(&format!("{note} without the unified cgroup hierarchy"))
    );
    let steps = self::steps(&vm, &self::fs(), &runner, WITH_TOKEN);
    assert!(
        !steps.notes.iter().any(|n| n.starts_with(note)),
        "{:?}",
        steps.notes
    );
}

#[test]
fn apply_then_plan_is_empty_and_rollback_keeps_the_package() {
    let (fs, runner) = (fs(), Host::new());
    let before = etc(&fs);
    let facts = facts();
    let params = table(WITH_TOKEN);
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
        matches!(outcome, ApplyOutcome::Applied { .. }),
        "{outcome:?}"
    );
    assert_eq!(runner.unit(UNIT), (true, true));
    assert_eq!(runner.unit(PATH_UNIT), (true, true));
    // A first start needs no restart.
    assert!(
        !runner
            .systemctl()
            .iter()
            .any(|c| c.starts_with("try-restart"))
    );

    let after = applied();
    let next = plan(&fs, &runner, &after, &params);
    assert!(change_ids(&next).is_empty(), "{:?}", change_ids(&next));

    engine.rollback(Target::Last, &mut |_| {}).unwrap();
    assert_eq!(etc(&fs), before);
    assert_eq!(runner.unit(UNIT), (false, false));
    assert_eq!(runner.unit(PATH_UNIT), (false, false));
    assert!(*runner.installed.lock().unwrap());
    assert!(fs.exists(Path::new(TOKEN)));
}

/// A connector that does not connect fails its start, and the apply rolls
/// back.
#[test]
fn a_failed_start_rolls_back() {
    let fs = fs();
    let runner = Host {
        connects: false,
        ..Host::new()
    };
    let before = etc(&fs);
    let facts = facts();
    let params = table(WITH_TOKEN);
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
    let result = engine.apply(&first, &Deadman::default(), &mut |_| {});
    let text = match result {
        Ok(outcome) => {
            assert!(
                matches!(outcome, ApplyOutcome::RolledBack { .. }),
                "{outcome:?}"
            );
            format!("{outcome:?}")
        }
        Err(e) => format!("{e:#}"),
    };
    assert!(text.contains(UNIT), "{text}");
    assert_eq!(etc(&fs), before);
    assert_eq!(runner.unit(UNIT), (false, false));
}

/// A changed unit on a running connector restarts it; another change, such
/// as the origin file, does not.
#[test]
fn restarts_a_running_connector_only_for_its_own_files() {
    let (fs, runner) = (fs(), Host::new());
    let facts = facts();
    let params = table(WITH_TOKEN);
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
    let after = applied();

    let off = steps(
        &after,
        &fs,
        &runner,
        &format!("{WITH_TOKEN}\nauto_update = false"),
    );
    assert_eq!(off.reloads, [Reload::DaemonReload]);

    // New resolvers change the unit's `IPAddressAllow=`.
    fs.write_atomic(
        Path::new("/etc/resolv.conf"),
        b"nameserver 198.51.100.53\n",
        root(0o644),
    )
    .unwrap();
    let changed = steps(&after, &fs, &runner, WITH_TOKEN);
    assert_eq!(
        changed.reloads,
        [Reload::DaemonReload, Reload::CloudflaredRestart]
    );
}

#[test]
fn verify_needs_a_connected_connector_on_the_new_binary() {
    let fs = fs();
    let facts = facts();
    let params = table(WITH_TOKEN);
    let cx = PlanCx {
        facts: &facts,
        params: &params,
        planned: &[],
    };
    let active = |runner: &Host| {
        runner
            .units
            .lock()
            .unwrap()
            .insert(UNIT.into(), (true, true));
    };
    let runner = Host::new();
    assert_eq!(
        NetTunnel.verify(
            &cx,
            Sys {
                fs: &fs,
                runner: &runner
            }
        ),
        Err(format!("{UNIT} is not active"))
    );
    active(&runner);
    assert_eq!(
        NetTunnel.verify(
            &cx,
            Sys {
                fs: &fs,
                runner: &runner
            }
        ),
        Ok(())
    );

    let runner = Host {
        connects: false,
        ..Host::new()
    };
    active(&runner);
    let err = NetTunnel
        .verify(
            &cx,
            Sys {
                fs: &fs,
                runner: &runner,
            },
        )
        .unwrap_err();
    assert!(
        err.starts_with("the tunnel has no connection to Cloudflare's edge"),
        "{err}"
    );
    assert!(
        err.contains("check the token in /root/cloudflared-token"),
        "{err}"
    );

    let runner = Host {
        running_inode: "2049:99",
        ..Host::new()
    };
    active(&runner);
    let err = NetTunnel
        .verify(
            &cx,
            Sys {
                fs: &fs,
                runner: &runner,
            },
        )
        .unwrap_err();
    assert!(err.starts_with("cloudflared runs an old binary"), "{err}");

    // Without a token there is no connector to check.
    let empty = table("");
    let cx = PlanCx {
        params: &empty,
        ..cx
    };
    assert_eq!(
        NetTunnel.verify(
            &cx,
            Sys {
                fs: &fs,
                runner: &Host::new()
            }
        ),
        Ok(())
    );
}

#[test]
fn the_restart_script_passes_sh_n() {
    use std::io::Write as _;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(RESTART_SCRIPT_TEXT.as_bytes()).unwrap();
    let status = std::process::Command::new("sh")
        .arg("-n")
        .arg(file.path())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(RESTART_SCRIPT_TEXT.contains("cloudflared runs an old binary"));
}

#[test]
fn the_unit_matches_the_reload() {
    assert_eq!(
        Reload::CloudflaredRestart.command().args,
        ["try-restart", UNIT]
    );
}
