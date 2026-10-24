//! `ssh.bruteforce` on [`RealFs`] over a tempdir, with apt, systemd and
//! fail2ban simulated by [`Debian`].

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::*;
use crate::engine::{self, ApplyOutcome, Engine, Plan, Selected, StateDir, Target};
use crate::facts::fixtures::host;
use crate::facts::{Session, SessionId};
use crate::sys::{Cmd, Fs, Output, RealFs, Runner, SysError};

const STATE: &str = "/var/lib/vps-ready";

/// What the simulated host has: installed packages and the unit's state.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct State {
    installed: BTreeSet<String>,
    enabled: bool,
    active: bool,
    /// Restarts of a running fail2ban.
    restarts: u32,
}

/// apt, systemd and `fail2ban-client` on a tempdir. Installing `fail2ban`
/// creates `/etc/fail2ban/jail.d` and, as on Debian 13 and Ubuntu 24.04,
/// enables the unit without starting it.
struct Debian {
    root: PathBuf,
    state: Mutex<State>,
    calls: Mutex<Vec<Cmd>>,
}

impl Debian {
    fn new(root: &Path, state: State) -> Self {
        Self {
            root: root.to_owned(),
            state: Mutex::new(state),
            calls: Mutex::default(),
        }
    }

    fn state(&self) -> State {
        self.state.lock().unwrap().clone()
    }

    fn calls(&self) -> Vec<Cmd> {
        self.calls.lock().unwrap().clone()
    }
}

impl Runner for Debian {
    fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
        self.calls.lock().unwrap().push(cmd.clone());
        let mut state = self.state.lock().unwrap();
        let last = cmd.args.last().map_or("", String::as_str);
        let out = match cmd.program.as_str() {
            "dpkg-query" if state.installed.contains(last) => Output::success("installed"),
            "dpkg-query" => Output {
                status: 1,
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
            "apt-get" => {
                if cmd.args.iter().any(|a| a == "install") {
                    state.installed.insert(last.to_owned());
                    if last == "fail2ban" {
                        std::fs::create_dir_all(self.root.join("etc/fail2ban/jail.d")).unwrap();
                        state.enabled = true;
                    }
                }
                Output::success("")
            }
            "systemctl" => {
                match cmd.args[0].as_str() {
                    "show" => {
                        let load = if state.installed.contains("fail2ban") {
                            "loaded"
                        } else {
                            "not-found"
                        };
                        let file = if state.enabled { "enabled" } else { "disabled" };
                        let active = if state.active { "active" } else { "inactive" };
                        return Ok(Output::success(format!(
                            "LoadState={load}\nActiveState={active}\nUnitFileState={file}\n"
                        )));
                    }
                    "enable" => state.enabled = true,
                    "disable" => state.enabled = false,
                    "start" => state.active = true,
                    "stop" => state.active = false,
                    "try-restart" if state.active => state.restarts += 1,
                    "try-restart" | "daemon-reload" => {}
                    other => panic!("unexpected systemctl {other}"),
                }
                Output::success("")
            }
            "fail2ban-client" => Output::success(""),
            other => return Err(SysError::NotFound(other.to_owned())),
        };
        Ok(out)
    }
}

fn session(client: &str) -> Session {
    Session {
        id: SessionId {
            pid: 902,
            start: 4200,
        },
        client: client.parse().unwrap(),
        server: "198.51.100.5:22".parse().unwrap(),
        uid: 1000,
        user: Some("admin".into()),
    }
}

/// The captured Debian 13 host, applied from an SSH session.
fn facts() -> Facts {
    let mut facts = host("debian-13", &[]);
    facts.session = Some(session("192.0.2.10:51234"));
    facts
}

/// A tempdir with an empty `/etc`.
fn root() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("etc")).unwrap();
    dir
}

fn plan<'a>(
    module: &'a SshBruteforce,
    fs: &dyn Fs,
    runner: &dyn Runner,
    facts: &'a Facts,
) -> Plan<'a> {
    engine::plan(&[Selected::new(module)], facts, Sys { fs, runner }).unwrap()
}

fn change_ids(plan: &Plan) -> Vec<String> {
    plan.steps().map(|s| s.change.id.clone()).collect()
}

/// Path and content of every file under `dir/etc`.
fn etc_files(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(path: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if std::fs::symlink_metadata(&path).unwrap().is_dir() {
                walk(&path, out);
            } else {
                out.insert(path.clone(), std::fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(&dir.join("etc"), &mut out);
    out
}

fn steps(facts: &Facts, params: &toml::Table) -> Result<ModuleSteps, ModuleError> {
    let (fs, runner) = (
        crate::sys::fake::FakeFs::new(),
        crate::sys::fake::FakeRunner::new(),
    );
    SshBruteforce::ROOT.plan(
        &PlanCx { facts, params },
        Sys {
            fs: &fs,
            runner: &runner,
        },
    )
}

fn drop_in_of(steps: &ModuleSteps) -> String {
    steps
        .resources
        .iter()
        .find_map(|r| match r {
            Resource::File(f) => Some(String::from_utf8(f.content.clone()).unwrap()),
            _ => None,
        })
        .unwrap()
}

#[test]
fn applies_only_on_debian_with_systemd_and_apt() {
    let mut facts = facts();
    let module = SshBruteforce::ROOT;
    assert_eq!(module.applicable(&facts), Applicability::Applicable);
    let reason = |facts: &Facts| match module.applicable(facts) {
        Applicability::NotApplicable { reason } => reason,
        Applicability::Applicable => panic!("applies"),
    };
    facts.updates = None;
    assert_eq!(reason(&facts), "apt not found, or `apt-config` failed");
    facts.init = Init::OpenRc;
    assert_eq!(
        reason(&facts),
        "the sshd jail reads the systemd journal, and systemd is not running"
    );
    facts.os.family = OsFamily::Alpine;
    assert_eq!(
        reason(&facts),
        "fail2ban is set up only on Debian and Ubuntu so far"
    );
}

#[test]
fn ignores_the_session_address_only_when_there_is_one() {
    let mut facts = facts();
    let none = toml::Table::new();
    assert!(
        drop_in_of(&steps(&facts, &none).unwrap())
            .ends_with("ignoreip = 127.0.0.1/8 ::1 192.0.2.10\n")
    );
    assert_eq!(
        SshBruteforce::ROOT.notes(&facts)[0],
        "the jail never bans 192.0.2.10, the address of this SSH session"
    );

    facts.session = Some(session("[::ffff:192.0.2.10]:51234"));
    assert!(
        drop_in_of(&steps(&facts, &none).unwrap())
            .ends_with("ignoreip = 127.0.0.1/8 ::1 192.0.2.10\n")
    );
    facts.session = Some(session("[2001:db8::10]:51234"));
    assert!(
        drop_in_of(&steps(&facts, &none).unwrap())
            .ends_with("ignoreip = 127.0.0.1/8 ::1 2001:db8::10\n")
    );

    facts.session = None;
    assert!(drop_in_of(&steps(&facts, &none).unwrap()).ends_with("ignoreip = 127.0.0.1/8 ::1\n"));
    assert_eq!(
        SshBruteforce::ROOT.notes(&facts)[0],
        "no SSH session found, so only localhost is exempt from bans"
    );
}

#[test]
fn takes_no_params() {
    let facts = facts();
    assert!(
        SshBruteforce::ROOT
            .check_params(&toml::Table::new())
            .is_ok()
    );
    let typo: toml::Table = toml::from_str("ignoreip = \"192.0.2.1\"").unwrap();
    for err in [
        SshBruteforce::ROOT.check_params(&typo).unwrap_err(),
        steps(&facts, &typo).unwrap_err(),
    ] {
        assert!(
            err.to_string().contains("unknown field `ignoreip`"),
            "{err}"
        );
    }
}

#[test]
fn restarts_fail2ban_after_its_changes() {
    let steps = steps(&facts(), &toml::Table::new()).unwrap();
    assert_eq!(steps.reloads, [Reload::Fail2banRestart]);
    let Some(Resource::File(file)) = steps.resources.get(3) else {
        panic!("the drop-in follows the packages");
    };
    // `fail2ban-client -t` checks the whole configuration, not one file.
    assert_eq!(file.validate, None);
}

#[test]
fn first_plan_snapshot() {
    let dir = root();
    let fs = RealFs::new(dir.path());
    let debian = Debian::new(dir.path(), State::default());
    let facts = facts();
    let plan = plan(&SshBruteforce::ROOT, &fs, &debian, &facts);
    insta::assert_yaml_snapshot!(plan);
}

/// Apply, then plan again; then roll back. Rollback removes the drop-in,
/// stops a fail2ban that was not running and restarts one that was. The
/// packages stay, and so does the unit's enabled state from their install.
#[test]
fn apply_is_idempotent_and_rolls_back() {
    let running = State {
        installed: ["fail2ban", "python3-systemd", "nftables"]
            .map(str::to_owned)
            .into(),
        enabled: true,
        active: true,
        restarts: 0,
    };
    for start in [State::default(), running] {
        let dir = root();
        if start.installed.contains("fail2ban") {
            std::fs::create_dir_all(dir.path().join("etc/fail2ban/jail.d")).unwrap();
        }
        let fs = RealFs::new(dir.path());
        let meta = std::fs::metadata(dir.path()).unwrap();
        let module = SshBruteforce::owned_by(meta.uid(), meta.gid());
        let debian = Debian::new(dir.path(), start.clone());
        let sys = Sys {
            fs: &fs,
            runner: &debian,
        };
        let facts = facts();
        let before = etc_files(dir.path());

        let first = plan(&module, &fs, &debian, &facts);
        let mut want: Vec<String> = Vec::new();
        if !start.installed.contains("fail2ban") {
            want.extend(PACKAGES.map(|p| format!("package:{p}")));
        }
        want.push(format!("file:{DROP_IN}"));
        if !start.active {
            want.push(format!("service:{UNIT}"));
        }
        assert_eq!(change_ids(&first), want, "{start:?}");

        let state = StateDir::create(&fs, STATE, meta.uid()).unwrap();
        let engine = Engine::lock(&state, sys).unwrap();
        let outcome = engine.apply(&first, &mut |_| {}).unwrap();
        assert!(
            matches!(outcome, ApplyOutcome::Applied { .. }),
            "{start:?}: {outcome:?}"
        );
        let drop_in = String::from_utf8(fs.read(Path::new(DROP_IN)).unwrap()).unwrap();
        insta::assert_snapshot!("drop-in", drop_in);
        let applied = debian.state();
        assert!(applied.enabled && applied.active, "{applied:?}");
        assert_eq!(applied.restarts, 1, "{start:?}");
        // The check runs before the restart.
        let calls = debian.calls();
        let check = calls
            .iter()
            .position(|c| *c == Cmd::new("fail2ban-client").arg("-t"))
            .unwrap();
        let restart = calls
            .iter()
            .position(|c| c.program == "systemctl" && c.args[0] == "try-restart")
            .unwrap();
        assert!(check < restart, "{calls:?}");

        let next = plan(&module, &fs, &debian, &facts);
        assert!(change_ids(&next).is_empty(), "{start:?}");
        assert!(next.modules[0].reloads().is_empty(), "{start:?}");

        engine.rollback(Target::Last, &mut |_| {}).unwrap();
        assert_eq!(etc_files(dir.path()), before, "{start:?}");
        let restored = debian.state();
        assert_eq!(
            (restored.enabled, restored.active),
            (true, start.active),
            "{start:?}"
        );
        assert_eq!(
            restored.restarts,
            if start.active { 2 } else { 1 },
            "{start:?}"
        );
        assert!(
            PACKAGES.iter().all(|p| restored.installed.contains(*p)),
            "{restored:?}"
        );
    }
}
