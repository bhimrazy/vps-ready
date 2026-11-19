//! `net.tailscale` on [`FakeFs`], with dpkg, apt, systemctl and tailscale
//! simulated by [`Host`].

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use super::*;
use crate::engine::{
    self, ApplyOutcome, Deadman, Engine, EngineError, Plan, Selected, StateDir, Target, Who,
};
use crate::facts::fixtures::host;
use crate::facts::{Address, Interface, Tailscale};
use crate::modules::firewall_inbound::RULESET;
use crate::resource::sysctl::BOOT_ID;
use crate::sys::fake::FakeFs;
use crate::sys::{FileKind, Fs, Output, Runner, SysError};

const STATE: &str = "/var/lib/vps-ready";
const KEY: &str = "/root/tailscale-auth-key";
const WITH_KEY: &str = "auth_key_file = \"/root/tailscale-auth-key\"";

/// A Debian host where installing `tailscale` enables and starts
/// `tailscaled`, as the package does, and `tailscale up` logs in.
struct Host {
    installed: Mutex<bool>,
    /// `tailscaled.service`: enabled, active.
    unit: Mutex<(bool, bool)>,
    backend: Mutex<String>,
    /// Whether `tailscale up` logged in once; `down` keeps it.
    node_key: Mutex<bool>,
    prefs: &'static str,
    /// What `tailscale down` answers; it fails without changing the state.
    down: Output,
    calls: Mutex<Vec<Cmd>>,
}

impl Host {
    fn new() -> Self {
        Self {
            installed: Mutex::new(false),
            unit: Mutex::new((false, false)),
            backend: Mutex::new("NoState".into()),
            node_key: Mutex::new(false),
            prefs: "{}",
            down: Output::success(""),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Installed and running, in `state`.
    fn with_tailscale(state: &str) -> Self {
        let host = Self::new();
        *host.installed.lock().unwrap() = true;
        *host.unit.lock().unwrap() = (true, true);
        *host.backend.lock().unwrap() = state.into();
        *host.node_key.lock().unwrap() = matches!(state, "Running" | "Stopped");
        host
    }

    /// Every `tailscale` command run, without the program.
    fn tailscale(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| {
                c.program == "tailscale" && !matches!(c.args[0].as_str(), "status" | "debug")
            })
            .map(|c| c.args.join(" "))
            .collect()
    }
}

impl Runner for Host {
    fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
        self.calls.lock().unwrap().push(cmd.clone());
        let args: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        let mut installed = self.installed.lock().unwrap();
        let mut unit = self.unit.lock().unwrap();
        let mut backend = self.backend.lock().unwrap();
        let mut node_key = self.node_key.lock().unwrap();
        let out = match (cmd.program.as_str(), &args[..]) {
            ("dpkg-query", [.., "tailscale"]) => Output::success(if *installed {
                "installed"
            } else {
                "not-installed"
            }),
            ("dpkg", ["--print-architecture"]) => Output::success("amd64\n"),
            ("apt-config", _) | ("apt-get", [.., "update"]) => Output::success(""),
            ("apt-get", [.., "tailscale"]) => {
                *installed = true;
                *unit = (true, true);
                Output::success("")
            }
            ("systemctl", ["show", _, UNIT]) => Output::success(if *installed {
                format!(
                    "LoadState=loaded\nUnitFileState={}\nActiveState={}\n",
                    if unit.0 { "enabled" } else { "disabled" },
                    if unit.1 { "active" } else { "inactive" }
                )
            } else {
                "LoadState=not-found\nUnitFileState=\nActiveState=inactive\n".to_owned()
            }),
            ("systemctl", ["daemon-reload"]) => Output::success(""),
            // The dead-man timer, its boot hook and the binary's copy.
            ("systemd-run", _) => Output::success(""),
            ("systemctl", [.., other]) if other.starts_with("vps-ready-") => Output::success(""),
            (copy, ["version"]) if copy.ends_with("/vps-ready") => {
                Output::success(format!("{}\n", crate::VERSION_INFO))
            }
            ("systemctl", [verb, UNIT]) => {
                match *verb {
                    "enable" => unit.0 = true,
                    "disable" => unit.0 = false,
                    "start" => unit.1 = true,
                    "stop" => unit.1 = false,
                    other => panic!("systemctl {other}"),
                }
                Output::success("")
            }
            ("tailscale", _) if !*installed => {
                return Err(SysError::NotFound("tailscale".into()));
            }
            ("tailscale", ["status", ..]) => {
                let ips = if *backend == "Running" {
                    r#"["100.64.0.7","fd7a:115c:a1e0::7"]"#
                } else {
                    "null"
                };
                Output::success(format!(
                    r#"{{"BackendState":"{backend}","HaveNodeKey":{node_key},"Self":{{"TailscaleIPs":{ips}}}}}"#
                ))
            }
            ("tailscale", ["up", rest @ ..]) => {
                let with_key = rest.iter().any(|a| a.starts_with("--auth-key="));
                assert!(
                    with_key || *node_key,
                    "`tailscale up` without a key or a login"
                );
                *backend = "Running".into();
                *node_key = true;
                Output::success("")
            }
            ("tailscale", ["down"]) => {
                if self.down.ok() {
                    *backend = "Stopped".into();
                }
                self.down.clone()
            }
            ("tailscale", ["debug", "prefs"]) => Output::success(self.prefs),
            (other, _) => return Err(SysError::NotFound(other.to_owned())),
        };
        Ok(out)
    }
}

fn root(mode: u32) -> FileOwner {
    FileOwner {
        mode,
        uid: 0,
        gid: 0,
    }
}

/// `/etc` and apt's directories, and a root-only key file.
fn fs() -> FakeFs {
    let fs = FakeFs::new()
        .with_dir("/", root(0o755))
        .with_dir("/etc", root(0o755))
        .with_dir("/etc/apt", root(0o755))
        .with_dir("/etc/apt/apt.conf.d", root(0o755))
        .with_dir("/etc/apt/sources.list.d", root(0o755))
        .with_dir("/root", root(0o700));
    // Built at run time so no key-shaped literal is in the source.
    let key = format!("tskey-{}", "auth-kSECRET");
    fs.write_atomic(Path::new(KEY), key.as_bytes(), root(0o600))
        .unwrap();
    fs
}

/// The captured Debian 13 host; `tailscale` in `state`, if given, with a
/// node key when `Running` or `Stopped`.
fn facts(state: Option<&str>) -> Facts {
    let mut facts = host("debian-13", &[]);
    facts.tailscale = state.map(|s| Tailscale {
        backend_state: s.into(),
        ips: Vec::new(),
        key_expiry: None,
        have_node_key: matches!(s, "Running" | "Stopped"),
    });
    facts
}

fn engine_on<'a>(fs: &'a FakeFs, runner: &'a Host) -> (StateDir, Sys<'a>) {
    (StateDir::create(fs, STATE, 0).unwrap(), Sys { fs, runner })
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
    NetTailscale.plan(
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

fn plan<'a>(fs: &FakeFs, runner: &Host, facts: &'a Facts, params: &'a toml::Table) -> Plan<'a> {
    let selected = Selected {
        module: &NetTailscale,
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

const FRESH: [&str; 7] = [
    "directory:/etc/apt/keyrings",
    "file:/etc/apt/keyrings/tailscale.asc",
    "file:/etc/apt/sources.list.d/tailscale.sources",
    "file:/etc/apt/apt.conf.d/52vps-ready-tailscale",
    "package:tailscale",
    "service:tailscaled.service",
    "tailscale:up",
];

#[test]
fn applies_on_debian_with_systemd_without_the_dead_man() {
    let mut facts = facts(None);
    assert_eq!(NetTailscale.applicable(&facts), Applicability::Applicable);
    assert!(!NetTailscale.needs_deadman());
    facts.os.codename = None;
    assert_eq!(
        NetTailscale.applicable(&facts),
        Applicability::NotApplicable {
            reason: format!(
                "Tailscale's repository has no packages for {}",
                facts.os.pretty_name
            )
        }
    );
    facts.init = Init::Unknown;
    assert_eq!(
        NetTailscale.applicable(&facts),
        Applicability::NotApplicable {
            reason: "it needs systemd, to run tailscaled".into()
        }
    );
}

#[test]
fn plan_on_a_fresh_host_snapshot() {
    let (fs, runner) = (fs(), Host::new());
    let facts = facts(None);
    let params = table(WITH_KEY);
    let plan = plan(&fs, &runner, &facts, &params);
    assert_eq!(change_ids(&plan), FRESH);
    insta::assert_yaml_snapshot!(plan);
}

#[test]
fn origin_file() {
    let (fs, runner) = (fs(), Host::new());
    let steps = steps(&facts(None), &fs, &runner, "");
    let Some(Resource::File(file)) = steps.resources.iter().find(|r| r.id().contains("52vps"))
    else {
        panic!("{:?}", ids(&steps));
    };
    insta::assert_snapshot!(String::from_utf8(file.content.clone()).unwrap(), @r#"
    // Written by vps-ready (net.tailscale). `vps-ready rollback --last` removes it.
    Unattended-Upgrade::Origins-Pattern { "origin=Tailscale,codename=${distro_codename}"; };
    "#);
    assert_eq!(file.owner, root(0o644));

    let off = self::steps(&facts(None), &fs, &runner, "auto_update = false");
    assert!(
        !ids(&off).iter().any(|id| id.contains("52vps")),
        "{:?}",
        ids(&off)
    );
}

#[test]
fn join_argv_has_the_key_file_and_never_the_key() {
    let (fs, runner) = (fs(), Host::new());
    let params = format!(
        "{WITH_KEY}\nlogin_server = \"https://headscale.example.com\"\nhostname = \"web-1\""
    );
    let steps = steps(&facts(Some("NeedsLogin")), &fs, &runner, &params);
    let Some(Resource::TailscaleUp(up)) = steps.resources.last() else {
        panic!("{:?}", ids(&steps));
    };
    assert_eq!(
        up.command().args,
        [
            "up",
            "--auth-key=file:/root/tailscale-auth-key",
            "--accept-dns=false",
            "--login-server=https://headscale.example.com",
            "--hostname=web-1",
            "--timeout=60s",
        ]
    );
    assert!(
        steps.notes.contains(
            &"delete /root/tailscale-auth-key after the login; a one-off key is spent once used, \
              and later applies use the node's own login"
                .to_owned()
        )
    );
}

/// The key's bytes are never read: they are nowhere in the plan, the
/// journal or the commands run.
#[test]
fn the_key_never_passes_through_vps_ready() {
    let (fs, runner) = (fs(), Host::new());
    let facts = facts(None);
    let params = table(WITH_KEY);
    let plan = plan(&fs, &runner, &facts, &params);
    assert!(!serde_json::to_string(&plan).unwrap().contains("SECRET"));
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
    for cmd in runner.calls.lock().unwrap().iter() {
        assert!(!format!("{cmd:?}").contains("SECRET"), "{cmd:?}");
    }
    fn walk(fs: &FakeFs, dir: &Path) {
        for path in fs.read_dir(dir).unwrap() {
            if fs.metadata(&path).unwrap().kind == FileKind::Dir {
                walk(fs, &path);
            } else if path != Path::new(KEY) {
                let bytes = fs.read(&path).unwrap();
                assert!(
                    !String::from_utf8_lossy(&bytes).contains("SECRET"),
                    "{}",
                    path.display()
                );
            }
        }
    }
    walk(&fs, Path::new("/"));
}

#[test]
fn refuses_an_unsafe_key_file() {
    let runner = Host::new();
    let cases = [
        (
            0o640,
            0,
            "its mode 0640 lets other users read it; `chmod 600` it",
        ),
        (0o600, 1000, "it is owned by uid 1000, not root"),
    ];
    for (mode, uid, why) in cases {
        let fs = fs();
        fs.write_atomic(Path::new(KEY), b"k", FileOwner { mode, uid, gid: 0 })
            .unwrap();
        let err = try_steps(&facts(None), &fs, &runner, WITH_KEY).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "auth_key_file {KEY}: {why}; it must be a regular file owned by root with mode \
                 0600, in directories only root can write to"
            )
        );
    }
    let fs = FakeFs::new()
        .with_dir("/", root(0o755))
        .with_dir("/etc", root(0o755))
        .with_symlink(KEY, "/root/real-key");
    let err = try_steps(&facts(None), &fs, &runner, WITH_KEY).unwrap_err();
    assert!(err.to_string().contains("it is a symlink"), "{err}");

    let fs = self::fs().with_dir("/root", root(0o777));
    let err = try_steps(&facts(None), &fs, &runner, WITH_KEY).unwrap_err();
    assert!(
        err.to_string()
            .contains("/root is writable by group or others (mode 0777)"),
        "{err}"
    );
}

#[test]
fn refuses_bad_params() {
    for (params, why) in [
        (
            "login_server = \"ftp://x\"",
            "login_server \"ftp://x\" is not an http or https URL",
        ),
        ("login_server = \"https://\"", "is not an http or https URL"),
        (
            "login_server = \"https://a b\"",
            "is not an http or https URL",
        ),
        (
            "hostname = \"Web 1\"",
            "hostname \"Web 1\" is not a host name",
        ),
        ("hostname = \"-x\"", "is not a host name"),
    ] {
        let err = NetTailscale.check_params(&table(params)).unwrap_err();
        assert!(err.to_string().contains(why), "{params}: {err}");
    }
    assert!(
        NetTailscale
            .check_params(&table("login_server = \"http://10.0.0.1:8080\""))
            .is_ok()
    );
}

#[test]
fn running_plans_no_login() {
    let fs = fs();
    let runner = Host::with_tailscale("Running");
    let steps = steps(&facts(Some("Running")), &fs, &runner, WITH_KEY);
    assert!(
        !ids(&steps).contains(&"tailscale:up".to_owned()),
        "{:?}",
        ids(&steps)
    );
    assert!(steps.notes.is_empty(), "{:?}", steps.notes);
}

#[test]
fn a_node_logged_in_with_other_settings_gets_a_note() {
    let fs = fs();
    let runner = Host {
        prefs: r#"{"ControlURL":"https://controlplane.tailscale.com","RouteAll":false,
            "ExitNodeID":"nX","CorpDNS":true,"RunSSH":true,"AdvertiseRoutes":null}"#,
        ..Host::with_tailscale("Running")
    };
    let steps = steps(&facts(Some("Running")), &fs, &runner, "");
    assert_eq!(
        steps.notes,
        [
            "this node is logged in already, with --accept-dns on, an exit node, Tailscale SSH \
          on; vps-ready leaves it as it is"
        ]
    );
}

#[test]
fn no_key_and_not_logged_in_installs_and_says_how_to_log_in() {
    let (fs, runner) = (fs(), Host::new());
    let steps = steps(
        &facts(None),
        &fs,
        &runner,
        "login_server = \"https://headscale.example.com\"",
    );
    assert_eq!(ids(&steps), FRESH[..6]);
    assert_eq!(
        steps.notes[0],
        "no auth_key_file: unless this node is logged in already, log in with `sudo tailscale \
         up --accept-dns=false --login-server=https://headscale.example.com` after this apply"
    );
}

#[test]
fn leaves_a_source_configured_elsewhere() {
    let fs = fs().with_file(
        "/etc/apt/sources.list.d/tailscale.list",
        "deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] \
         https://pkgs.tailscale.com/stable/debian trixie main\n",
    );
    let steps = steps(&facts(None), &fs, &Host::new(), "");
    assert_eq!(ids(&steps), FRESH[3..6]);
    assert_eq!(
        steps.notes[0],
        "another apt source already names pkgs.tailscale.com, so vps-ready adds none; \
         Tailscale updates from that one"
    );
}

#[test]
fn apply_then_plan_is_empty_and_rollback_restores_etc() {
    let (fs, runner) = (fs(), Host::new());
    let before = etc(&fs);
    let facts = facts(None);
    let params = table(WITH_KEY);
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

    let logged_in = self::facts(Some("Running"));
    let next = plan(&fs, &runner, &logged_in, &params);
    assert!(change_ids(&next).is_empty(), "{:?}", change_ids(&next));

    engine.rollback(Target::Last, &mut |_| {}).unwrap();
    assert_eq!(etc(&fs), before);
    assert_eq!(
        runner.tailscale(),
        [
            "up --auth-key=file:/root/tailscale-auth-key --accept-dns=false --timeout=60s",
            "down"
        ]
    );
    // The package stays, and so does the daemon the package started.
    assert!(*runner.installed.lock().unwrap());
    assert_eq!(*runner.unit.lock().unwrap(), (true, true));
}

/// tailscaled installed but off: rollback turns it off again, and runs no
/// `tailscale down` for a node that was already running.
#[test]
fn rollback_restores_a_stopped_tailscaled() {
    let fs = fs();
    let runner = Host::with_tailscale("Stopped");
    *runner.unit.lock().unwrap() = (false, false);
    let facts = facts(None);
    let params = table("");
    let first = plan(&fs, &runner, &facts, &params);
    assert!(change_ids(&first).contains(&"service:tailscaled.service".to_owned()));
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
    assert_eq!(*runner.unit.lock().unwrap(), (true, true));
    engine.rollback(Target::Last, &mut |_| {}).unwrap();
    assert_eq!(*runner.unit.lock().unwrap(), (false, false));
    assert!(runner.tailscale().is_empty(), "{:?}", runner.tailscale());
}

#[test]
fn verify_needs_a_running_node_after_a_login() {
    let fs = fs();
    let facts = facts(None);
    let params = table(WITH_KEY);
    let cx = PlanCx {
        facts: &facts,
        params: &params,
        planned: &[],
    };
    let runner = Host::with_tailscale("NeedsLogin");
    assert_eq!(
        NetTailscale.verify(&cx, Sys { fs: &fs, runner: &runner }),
        Err("Tailscale is NeedsLogin, not Running, after `tailscale up`; `tailscale status` says why".into())
    );
    let runner = Host::with_tailscale("Running");
    assert_eq!(
        NetTailscale.verify(
            &cx,
            Sys {
                fs: &fs,
                runner: &runner
            }
        ),
        Ok(())
    );
    // Without a key there is no login to check.
    let empty = table("");
    let cx = PlanCx {
        params: &empty,
        ..cx
    };
    let runner = Host::with_tailscale("NeedsLogin");
    assert_eq!(
        NetTailscale.verify(
            &cx,
            Sys {
                fs: &fs,
                runner: &runner
            }
        ),
        Ok(())
    );
}

#[test]
fn settings_that_differ_and_unreadable_settings_get_a_note() {
    let fs = fs();
    let runner = Host {
        prefs: r#"{"ControlURL":"https://controlplane.tailscale.com","Hostname":"",
            "ExitNodeIP":"100.64.0.9","CorpDNS":false}"#,
        ..Host::with_tailscale("Running")
    };
    let params = "login_server = \"https://headscale.example.com\"\nhostname = \"web-1\"";
    let steps = steps(&facts(Some("Running")), &fs, &runner, params);
    assert_eq!(
        steps.notes,
        ["this node is logged in already, with login server \
             \"https://controlplane.tailscale.com\", not https://headscale.example.com, \
             hostname \"\", not web-1, an exit node; vps-ready leaves it as it is"]
    );

    let runner = Host {
        prefs: "not json",
        ..Host::with_tailscale("Running")
    };
    let steps = self::steps(&facts(Some("Running")), &fs, &runner, "");
    assert_eq!(
        steps.notes,
        [
            "this node is logged in already, and `tailscale debug prefs` did not say with \
             which settings; vps-ready leaves it as it is"
        ]
    );
}

/// The one-off key is spent and its file deleted: a node with a node key
/// comes back up without it, after a rollback's `tailscale down` too.
#[test]
fn apply_rollback_apply_again_with_a_spent_key() {
    let (fs, runner) = (fs(), Host::new());
    let params = table(WITH_KEY);
    let fresh = facts(None);
    let first = plan(&fs, &runner, &fresh, &params);
    let (state, sys) = engine_on(&fs, &runner);
    let engine = Engine::lock(&state, sys).unwrap();
    engine
        .apply(&first, &Deadman::default(), &mut |_| {})
        .unwrap();
    engine.rollback(Target::Last, &mut |_| {}).unwrap();
    fs.remove(Path::new(KEY)).unwrap();

    let stopped = facts(Some("Stopped"));
    let steps = steps(&stopped, &fs, &runner, WITH_KEY);
    let Some(Resource::TailscaleUp(up)) = steps.resources.last() else {
        panic!("{:?}", ids(&steps));
    };
    assert_eq!(up.auth_key_file, None);
    let again = plan(&fs, &runner, &stopped, &params);
    engine
        .apply(&again, &Deadman::default(), &mut |_| {})
        .unwrap();
    assert_eq!(
        runner.tailscale(),
        [
            "up --auth-key=file:/root/tailscale-auth-key --accept-dns=false --timeout=60s",
            "down",
            "up --accept-dns=false --timeout=60s",
        ]
    );

    // An expired node key needs a new auth key.
    let mut expired = facts(Some("NeedsLogin"));
    expired.tailscale.as_mut().unwrap().have_node_key = true;
    let err = try_steps(&expired, &fs, &runner, WITH_KEY).unwrap_err();
    assert!(err.to_string().contains("it does not exist"), "{err}");
}

/// `tailscale down` refuses to cut a session that came in over Tailscale
/// when there is no terminal to ask on; the rollback says what to do, and
/// finishes once the node is down.
#[test]
fn rollback_from_a_session_over_tailscale_says_what_to_do() {
    let fs = fs();
    let runner = Host {
        down: Output {
            status: 1,
            stdout: b"You are connected over Tailscale; this action will disable Tailscale \
                and result in your session disconnecting.\n"
                .to_vec(),
            stderr: b"aborted, no changes made\n".to_vec(),
        },
        ..Host::new()
    };
    let params = table(WITH_KEY);
    let fresh = facts(None);
    let first = plan(&fs, &runner, &fresh, &params);
    let (state, sys) = engine_on(&fs, &runner);
    let engine = Engine::lock(&state, sys).unwrap();
    engine
        .apply(&first, &Deadman::default(), &mut |_| {})
        .unwrap();
    let err = engine.rollback(Target::Last, &mut |_| {}).unwrap_err();
    assert!(
        format!("{err:#}").contains("this session comes through Tailscale"),
        "{err:#}"
    );
    // `sudo tailscale down` by hand, then the rollback again.
    *runner.backend.lock().unwrap() = "Stopped".into();
    engine.rollback(Target::Last, &mut |_| {}).unwrap();
}

/// With both the key file and the param gone, a node with a node key still
/// comes back up, and verify checks it.
#[test]
fn a_node_key_needs_no_auth_key_file_param() {
    let fs = fs();
    let runner = Host::with_tailscale("Stopped");
    let stopped = facts(Some("Stopped"));
    let steps = steps(&stopped, &fs, &runner, "");
    let Some(Resource::TailscaleUp(up)) = steps.resources.last() else {
        panic!("{:?}", ids(&steps));
    };
    assert_eq!(up.auth_key_file, None);

    let empty = table("");
    let cx = PlanCx {
        facts: &stopped,
        params: &empty,
        planned: &[],
    };
    let sys = Sys {
        fs: &fs,
        runner: &runner,
    };
    assert_eq!(
        NetTailscale.verify(&cx, sys),
        Err(
            "Tailscale is Stopped, not Running, after `tailscale up`; `tailscale status` says why"
                .into()
        )
    );
    *runner.backend.lock().unwrap() = "Running".into();
    assert_eq!(NetTailscale.verify(&cx, sys), Ok(()));
}

/// A session can come through `tailscale0` only while the node is
/// `Running`, and then nothing this module plans stops `tailscaled` or
/// brings the node down: the unit is only enabled or started, and the join
/// is planned only for a node that is not `Running`.
#[test]
fn nothing_it_plans_stops_a_running_node() {
    for unit in [(true, true), (false, true)] {
        let fs = fs();
        let runner = Host::with_tailscale("Running");
        *runner.unit.lock().unwrap() = unit;
        let facts = facts(Some("Running"));
        let params = table(WITH_KEY);
        let plan = plan(&fs, &runner, &facts, &params);
        for step in plan.steps() {
            assert_ne!(step.change.id, "tailscale:up");
            assert!(!step.change.summary.contains("stop"), "{step:?}");
        }
    }
}

fn iface(name: &str, ip: &str) -> Interface {
    Interface {
        name: name.into(),
        kind: None,
        addresses: vec![Address {
            ip: ip.parse().unwrap(),
            prefix: 32,
        }],
        up: true,
    }
}

/// Without `ssh_via`, a manual rollback that stops the `tailscaled` it
/// started is refused from a session through Tailscale's interface: by its
/// name, with an IPv4-mapped address, or renamed (`--tun ts1`) and known by
/// the node's address. It runs from a public session, or with none.
#[test]
fn rollback_that_stops_tailscaled_is_refused_over_tailscale() {
    let fs = fs();
    let runner = Host::with_tailscale("Running");
    let interfaces = [
        iface("eth0", "192.0.2.10"),
        iface("tailscale0", "100.64.0.7"),
        iface("ts1", "100.64.0.8"),
    ];
    let ips = ["100.64.0.8".parse().unwrap()];
    let who = |server: &str| Who {
        server: Some(server.parse().unwrap()),
        client: Some("198.51.100.7".parse().unwrap()),
        interfaces: &interfaces,
        tailscale: &ips,
        ..Who::default()
    };
    let empty = table("");
    let (state, sys) = engine_on(&fs, &runner);
    let engine = Engine::lock(&state, sys).unwrap();
    for done in [who("192.0.2.10"), Who::default()] {
        *runner.unit.lock().unwrap() = (false, false);
        let fresh = facts(None);
        let first = plan(&fs, &runner, &fresh, &empty);
        engine
            .apply(&first, &Deadman::default(), &mut |_| {})
            .unwrap();
        for server in ["100.64.0.7", "::ffff:100.64.0.7", "100.64.0.8"] {
            let err = engine
                .rollback_by(Target::Last, &who(server), &mut |_| {})
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    EngineError::CutsTailscale {
                        via: None,
                        pending: false,
                        ..
                    }
                ),
                "{server}: {err:?}"
            );
            assert!(err.to_string().contains("provider's console"), "{err}");
        }
        assert_eq!(*runner.unit.lock().unwrap(), (true, true));
        engine
            .rollback_by(Target::Last, &done, &mut |_| {})
            .unwrap();
        assert_eq!(*runner.unit.lock().unwrap(), (false, false));
    }
}

/// Under a loaded `ssh_via` on Tailscale, a rollback that would stop
/// `tailscaled` or take the node down (`tailscale down`) is refused with
/// no session at all (tmux, the console), pending or not.
#[test]
fn under_ssh_via_on_tailscale_a_rollback_that_cuts_it_is_refused() {
    let empty = table("");
    // Pending: it started tailscaled and brought the node up.
    let fs = armable();
    let runner = Host::with_tailscale("Stopped");
    *runner.unit.lock().unwrap() = (false, false);
    let facts = facts(Some("Stopped"));
    let first = plan(&fs, &runner, &facts, &empty);
    let (state, sys) = engine_on(&fs, &runner);
    let engine = Engine::lock(&state, sys).unwrap();
    let outcome = engine.apply(&first, &armed(), &mut |_| {}).unwrap();
    assert!(
        matches!(outcome, ApplyOutcome::Pending { .. }),
        "{outcome:?}"
    );
    let err = engine
        .rollback_by(Target::Last, &Who::default(), &mut |_| {})
        .unwrap_err();
    assert!(
        matches!(&err, EngineError::CutsTailscale { via: Some(v), pending: true, .. } if v == "tailscale0"),
        "{err:?}"
    );
    assert!(err.to_string().contains("safety timer"), "{err}");
    drop(engine);

    // Applied without the timer: only `tailscale down` would cut it.
    let fs = fs_via("tailscale0");
    let runner = Host::with_tailscale("Stopped");
    let first = plan(&fs, &runner, &facts, &empty);
    assert!(!change_ids(&first).contains(&"service:tailscaled.service".to_owned()));
    let (state, sys) = engine_on(&fs, &runner);
    let engine = Engine::lock(&state, sys).unwrap();
    let off = Deadman {
        off: true,
        ..Deadman::default()
    };
    engine.apply(&first, &off, &mut |_| {}).unwrap();
    let err = engine
        .rollback_by(Target::Last, &Who::default(), &mut |_| {})
        .unwrap_err();
    assert!(
        matches!(
            &err,
            EngineError::CutsTailscale {
                via: Some(_),
                pending: false,
                ..
            }
        ),
        "{err:?}"
    );
    let text = err.to_string();
    assert!(text.contains("remove `ssh_via`"), "{text}");
    assert!(!text.contains("console"), "{text}");
    assert!(runner.tailscale().iter().all(|c| c != "down"));
}

/// `fs()` with a loaded ruleset that limits SSH to `via`.
fn fs_via(via: &str) -> FakeFs {
    let fs = fs().with_dir("/etc/vps-ready", root(0o755));
    let rule = format!("    iifname \"{via}\" tcp dport {{ 22 }} accept\n");
    fs.write_atomic(Path::new(RULESET), rule.as_bytes(), root(0o644))
        .unwrap();
    fs
}

/// Under a loaded ruleset that limits SSH to Tailscale's interface, by name
/// or by its address (`--tun ts1`), a change arms the timer and is
/// force-restored; under another interface, or without `ssh_via`, it is not.
#[test]
fn under_ssh_via_on_tailscale_a_change_arms_the_timer() {
    let runner = Host::with_tailscale("Running");
    let mut facts = facts(Some("Running"));
    let ip = "100.64.0.7".parse().unwrap();
    facts.tailscale.as_mut().unwrap().ips = vec![ip];
    facts.interfaces.push(Interface {
        name: "ts1".into(),
        kind: Some("tun".into()),
        addresses: vec![Address { ip, prefix: 32 }],
        up: true,
    });
    let params = table("");
    for (via, armed) in [
        (Some("tailscale0"), true),
        (Some("ts1"), true),
        (Some("wg0"), false),
        (None, false),
    ] {
        let fs = via.map_or_else(fs, fs_via);
        let plan = plan(&fs, &runner, &facts, &params);
        // The apt source and the origin file.
        assert!(!change_ids(&plan).is_empty());
        assert_eq!(plan.ssh_via.as_deref(), via);
        assert_eq!(plan.needs_deadman(), armed, "{via:?}");
        assert_eq!(plan.modules[0].force_restore(), armed, "{via:?}");
    }
}

/// The armed apply records `ssh_via`, so only a confirm through
/// `tailscale0` keeps the change, and each backup as force-restored.
#[test]
fn under_ssh_via_on_tailscale_the_journal_records_it() {
    let fs = armable();
    let runner = Host::with_tailscale("Running");
    let facts = facts(Some("Running"));
    let params = table("");
    let plan = plan(&fs, &runner, &facts, &params);
    let (state, sys) = engine_on(&fs, &runner);
    let outcome = Engine::lock(&state, sys)
        .unwrap()
        .apply(&plan, &armed(), &mut |_| {})
        .unwrap();
    let ApplyOutcome::Pending { txn, .. } = outcome else {
        panic!("{outcome:?}");
    };
    let journal = fs
        .read(Path::new(&format!("{STATE}/txn/{txn}/journal.jsonl")))
        .unwrap();
    let journal = String::from_utf8(journal).unwrap();
    assert!(journal.contains(r#""ssh_via":"tailscale0""#), "{journal}");
    let backups: Vec<&str> = journal
        .lines()
        .filter(|l| l.contains(r#""event":"backup""#))
        .collect();
    assert!(!backups.is_empty());
    assert!(
        backups
            .iter()
            .all(|l| l.contains(r#""force_restore":true"#)),
        "{journal}"
    );
}

const BIN: &str = "/usr/local/bin/vps-ready";

/// `fs_via("tailscale0")` on a host that can arm the timer.
fn armable() -> FakeFs {
    let fs = fs_via("tailscale0")
        .with_file(BOOT_ID, "a\n")
        .with_file("/proc/uptime", "1000.25 900.00\n")
        .with_dir("/usr", root(0o755))
        .with_dir("/usr/local", root(0o755))
        .with_dir("/usr/local/bin", root(0o755))
        .with_dir("/etc/systemd", root(0o755))
        .with_dir("/etc/systemd/system", root(0o755));
    fs.write_atomic(Path::new(BIN), b"\x7fELF", root(0o755))
        .unwrap();
    fs
}

fn armed() -> Deadman {
    Deadman {
        binary: BIN.into(),
        ..Deadman::default()
    }
}
