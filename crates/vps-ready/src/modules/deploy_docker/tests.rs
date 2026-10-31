//! `deploy.docker` on [`FakeFs`], with dpkg, apt, dockerd and systemctl
//! simulated by [`Apt`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Mutex;

use super::*;
use crate::engine::{self, ApplyOutcome, Deadman, Engine, Plan, Selected, StateDir, Target};
use crate::facts::fixtures::host;
use crate::facts::{DockerDaemon, DockerEngine, DockerService};
use crate::sys::fake::FakeFs;
use crate::sys::{Cmd, FileKind, Fs, Output, Runner};

const STATE: &str = "/var/lib/vps-ready";
const VERSION: &str = "5:29.0.1-1~debian.13~trixie";
const PORTS_NOTE: &str = "ports published without an address bind to 127.0.0.1 only, not to \
                          ::1: point a reverse proxy at 127.0.0.1:<port>, not localhost";

/// Packages that dpkg reports installed once `apt-get install` ran, and
/// every command run.
#[derive(Default)]
struct Apt {
    installed: Mutex<BTreeSet<String>>,
    calls: Mutex<Vec<Cmd>>,
}

impl Apt {
    /// With Docker's packages installed.
    fn with_docker() -> Self {
        let apt = Self::default();
        apt.installed
            .lock()
            .unwrap()
            .extend(PACKAGES.iter().map(|p| (*p).to_owned()));
        apt
    }

    /// Every command run, as a shell line.
    fn lines(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|c| {
                std::iter::once(c.program.as_str())
                    .chain(c.args.iter().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect()
    }
}

impl Runner for Apt {
    fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
        self.calls.lock().unwrap().push(cmd.clone());
        let args: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        let mut installed = self.installed.lock().unwrap();
        let out = match (cmd.program.as_str(), &args[..]) {
            ("dpkg-query", [.., name]) => Output::success(if installed.contains(*name) {
                "installed"
            } else {
                "not-installed"
            }),
            ("dpkg", ["--print-architecture"]) => Output::success("arm64\n"),
            ("apt-get", [.., "update"]) => Output::success(""),
            ("apt-get", [.., name]) => {
                installed.insert((*name).to_owned());
                Output::success("")
            }
            ("dockerd", ["--validate", ..]) | ("systemctl", ["try-restart", "docker.service"]) => {
                Output::success("")
            }
            (other, _) => return Err(SysError::NotFound(other.to_owned())),
        };
        Ok(out)
    }
}

fn root_dir() -> FileOwner {
    root(0o755)
}

/// `/etc` and apt's directories.
fn fs() -> FakeFs {
    FakeFs::new()
        .with_dir("/etc", root_dir())
        .with_dir("/etc/apt", root_dir())
        .with_dir("/etc/apt/sources.list.d", root_dir())
}

/// [`fs`] with Docker's repository as this module writes it.
fn docker_fs() -> FakeFs {
    let fs = fs();
    let source = AptSource::docker("debian", "trixie").unwrap();
    for resource in apt_source(&source, "arm64") {
        match resource {
            Resource::Directory(d) => fs.create_dir_all(&d.path, 0o755).unwrap(),
            Resource::File(f) => fs.write_atomic(&f.path, &f.content, f.owner).unwrap(),
            other => panic!("{other:?}"),
        }
    }
    fs
}

/// The captured Debian 13 host, without Docker.
fn facts() -> Facts {
    host("debian-13", &[])
}

fn engine_mut(facts: &mut Facts) -> &mut DockerEngine {
    facts.docker_engine.as_mut().unwrap()
}

const RUNNING: DockerService = DockerService {
    loaded: true,
    active: true,
};

/// [`facts`] with Docker Engine installed from Docker's package, running,
/// and its daemon answering with `daemon`.
fn with_docker(daemon: Option<DockerDaemon>) -> Facts {
    let mut facts = facts();
    facts.docker = true;
    let engine = engine_mut(&mut facts);
    engine.packages = vec![DOCKER_PACKAGE.to_owned()];
    engine.docker_ce_version = Some(VERSION.to_owned());
    engine.service = Some(RUNNING);
    engine.daemon = daemon;
    facts
}

/// [`facts`] with a Docker that is not Docker's package, e.g. installed
/// from the static release with its own unit.
fn with_other_docker() -> Facts {
    let mut facts = facts();
    facts.docker = true;
    let engine = engine_mut(&mut facts);
    engine.service = Some(RUNNING);
    engine.daemon = Some(daemon(true, &[], &[]));
    facts
}

fn daemon(live_restore: bool, running: &[&str], networks: &[&str]) -> DockerDaemon {
    let owned = |names: &[&str]| names.iter().map(|n| (*n).to_owned()).collect();
    DockerDaemon {
        live_restore,
        swarm: false,
        running: owned(running),
        networks: owned(networks),
    }
}

fn try_steps(facts: &Facts, fs: &FakeFs, runner: &Apt) -> Result<ModuleSteps, ModuleError> {
    DeployDocker.plan(
        &PlanCx {
            facts,
            params: &toml::Table::new(),
            planned: &[],
        },
        Sys { fs, runner },
    )
}

fn steps(facts: &Facts, fs: &FakeFs, runner: &Apt) -> ModuleSteps {
    try_steps(facts, fs, runner).unwrap()
}

fn plan<'a>(fs: &FakeFs, runner: &Apt, facts: &'a Facts) -> Plan<'a> {
    engine::plan(&[Selected::new(&DeployDocker)], facts, Sys { fs, runner }).unwrap()
}

fn change_ids(plan: &Plan) -> Vec<String> {
    plan.steps().map(|s| s.change.id.clone()).collect()
}

fn ids(steps: &ModuleSteps) -> Vec<String> {
    steps.resources.iter().map(Resource::id).collect()
}

fn reason(facts: &Facts) -> String {
    match DeployDocker.applicable(facts) {
        Applicability::NotApplicable { reason } => reason,
        Applicability::Applicable => panic!("applicable"),
    }
}

fn daemon_json(fs: &FakeFs) -> String {
    String::from_utf8(fs.read(Path::new(DAEMON_JSON)).unwrap()).unwrap()
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

fn apply_and_roll_back(fs: &FakeFs, runner: &Apt, facts: &Facts, plan: &Plan) {
    let state = StateDir::create(fs, STATE, 0).unwrap();
    let engine = Engine::lock(&state, Sys { fs, runner }).unwrap();
    let outcome = engine
        .apply(plan, &Deadman::default(), &mut |_| {})
        .unwrap();
    assert!(
        matches!(outcome, ApplyOutcome::Applied { .. }),
        "{outcome:?}"
    );
    let next = self::plan(fs, runner, facts);
    assert!(change_ids(&next).is_empty(), "{:?}", change_ids(&next));
    engine.rollback(Target::Last, &mut |_| {}).unwrap();
}

#[test]
fn applies_on_debian_with_systemd_without_the_dead_man() {
    let mut facts = facts();
    assert_eq!(DeployDocker.applicable(&facts), Applicability::Applicable);
    assert!(!DeployDocker.needs_deadman());
    facts.init = Init::Unknown;
    assert_eq!(reason(&facts), "it needs systemd, to restart Docker");
    facts.os.family = OsFamily::Rhel;
    assert_eq!(
        reason(&facts),
        "Docker is installed only on Debian and Ubuntu so far"
    );

    let mut facts = self::facts();
    facts.docker_engine = None;
    assert_eq!(
        reason(&facts),
        "the installed packages are unknown (`dpkg-query` failed)"
    );
}

/// The distro's runtime is left alone, and named.
#[test]
fn not_applicable_with_the_distros_docker() {
    let mut facts = facts();
    engine_mut(&mut facts).packages = vec!["docker.io".into()];
    assert_eq!(
        reason(&facts),
        "docker.io is installed, and vps-ready does not replace a container runtime that \
         may be in use; remove it to use Docker's packages"
    );
    engine_mut(&mut facts).packages =
        vec!["podman-docker".into(), "containerd".into(), "runc".into()];
    assert_eq!(
        reason(&facts),
        "podman-docker, containerd, runc are installed, and vps-ready does not replace a \
         container runtime that may be in use; remove them to use Docker's packages"
    );
}

#[test]
fn not_applicable_with_a_daemon_json_it_cannot_merge() {
    let mut facts = with_docker(None);
    engine_mut(&mut facts).daemon_json = DaemonJson::Unusable {
        reason: "is not valid JSON: trailing comma at line 1 column 16".into(),
    };
    assert_eq!(
        reason(&facts),
        "/etc/docker/daemon.json is not valid JSON: trailing comma at line 1 column 16; fix \
         it, then plan again"
    );
}

#[test]
fn not_applicable_in_a_swarm_on_a_snap_or_an_unknown_release() {
    let mut swarm = daemon(false, &[], &[]);
    swarm.swarm = true;
    assert_eq!(
        reason(&with_docker(Some(swarm))),
        "this node is part of a Docker swarm, and live-restore does not work in swarm mode"
    );

    // A `docker` CLI or socket without docker-ce or a docker.service unit,
    // even with a bare /usr/bin/dockerd.
    let mut facts = facts();
    facts.docker = true;
    assert_eq!(
        reason(&facts),
        "Docker is installed, but neither from Docker's package nor with a docker.service \
         unit (a snap?), so vps-ready leaves it alone"
    );

    let mut facts = self::facts();
    facts.os.codename = None;
    assert_eq!(
        reason(&facts),
        "Docker's repository has no packages for Debian GNU/Linux 13 (trixie)"
    );
    // docker-ce keeps its repository, which needs the release.
    let mut facts = with_docker(None);
    facts.os.codename = None;
    assert!(reason(&facts).starts_with("Docker's repository has no packages"));
    // Another Docker needs no repository.
    let mut facts = with_other_docker();
    facts.os.codename = None;
    assert_eq!(DeployDocker.applicable(&facts), Applicability::Applicable);
}

/// The vendor source, the five packages, then the directory and
/// `daemon.json`, checked by dockerd; Docker restarts after them.
#[test]
fn a_fresh_host_gets_docker_from_its_repository() {
    let (fs, runner) = (fs(), Apt::default());
    let facts = facts();
    let steps = steps(&facts, &fs, &runner);
    assert_eq!(
        ids(&steps),
        [
            "directory:/etc/apt/keyrings",
            "file:/etc/apt/keyrings/docker.asc",
            "file:/etc/apt/sources.list.d/docker.sources",
            "package:docker-ce",
            "package:docker-ce-cli",
            "package:containerd.io",
            "package:docker-buildx-plugin",
            "package:docker-compose-plugin",
            "directory:/etc/docker",
            "file:/etc/docker/daemon.json",
        ]
    );
    assert_eq!(steps.reloads, [Reload::DockerRestart]);
    let Some(Resource::File(file)) = steps.resources.last() else {
        panic!("daemon.json comes last");
    };
    assert_eq!(
        file.validate,
        Some(Validate::new(
            "dockerd",
            ["--validate", "--config-file", "{}"]
        ))
    );
    assert_eq!(file.owner, root(0o644));
    let source = steps.resources.iter().find_map(|r| match r {
        Resource::File(f) if f.path.ends_with("docker.sources") => {
            Some(String::from_utf8(f.content.clone()).unwrap())
        }
        _ => None,
    });
    let source = source.unwrap();
    assert!(source.contains("Suites: trixie\n"), "{source}");
    assert!(source.contains("Architectures: arm64\n"), "{source}");
    assert_eq!(
        steps.notes,
        [
            "Docker sets net.ipv4.ip_forward=1 and a FORWARD policy of drop; a host that \
             routes other traffic (a WireGuard peer, a subnet router) needs its own forward \
             rules",
            "rollback leaves Docker's packages installed, and removes the repository they \
             update from",
            PORTS_NOTE,
        ]
    );
}

/// Ubuntu's codename and repository.
#[test]
fn ubuntu_uses_its_own_repository() {
    let (fs, runner) = (fs(), Apt::default());
    let facts = host("ubuntu-24.04", &[]);
    let steps = steps(&facts, &fs, &runner);
    let Some(Resource::File(source)) = steps.resources.get(2) else {
        panic!("{:?}", steps.resources);
    };
    let source = String::from_utf8(source.content.clone()).unwrap();
    assert!(
        source.contains("URIs: https://download.docker.com/linux/ubuntu\nSuites: noble\n"),
        "{source}"
    );
}

/// Apply installs and restarts Docker; the next plan is empty; rollback
/// removes the source, the key, `daemon.json` and the directories, leaves
/// the packages and restarts Docker again.
#[test]
fn applies_then_plans_nothing_and_rolls_back() {
    let (fs, runner) = (fs(), Apt::default());
    let facts = facts();
    let before = etc(&fs);
    let first = plan(&fs, &runner, &facts);
    assert_eq!(first.steps().count(), 10);
    apply_and_roll_back(&fs, &runner, &facts, &first);

    assert_eq!(etc(&fs), before);
    assert_eq!(runner.installed.lock().unwrap().len(), PACKAGES.len());
    let lines = runner.lines();
    let after = lines
        .iter()
        .find(|l| l.starts_with("dockerd --validate --config-file "))
        .unwrap();
    assert!(after.ends_with(".after"), "{after}");
    let restarts: Vec<&String> = lines
        .iter()
        .filter(|l| *l == "dockerd --validate" || *l == "systemctl try-restart docker.service")
        .collect();
    // Once after apply, once after rollback.
    assert_eq!(restarts.len(), 4, "{lines:?}");
    // The packages are installed before daemon.json is checked.
    let install = lines.iter().rposition(|l| l.contains(" install ")).unwrap();
    let validate = lines.iter().position(|l| l == after).unwrap();
    assert!(install < validate, "{lines:?}");
}

/// docker-ce installed from its repository: the source and the packages
/// are planned and have no change, so only `daemon.json` is written.
#[test]
fn docker_ce_installed_without_daemon_json() {
    let (fs, runner) = (docker_fs(), Apt::with_docker());
    let facts = with_docker(Some(daemon(true, &[], &[])));
    let steps = steps(&facts, &fs, &runner);
    assert_eq!(steps.resources.len(), 10, "{:?}", ids(&steps));
    assert!(steps.resources.contains(&Resource::Package(Package {
        name: DOCKER_PACKAGE.to_owned()
    })));
    assert_eq!(steps.notes, [PORTS_NOTE]);
    let first = plan(&fs, &runner, &facts);
    assert_eq!(
        change_ids(&first),
        ["directory:/etc/docker", "file:/etc/docker/daemon.json"]
    );
    let before = etc(&fs);
    apply_and_roll_back(&fs, &runner, &facts, &first);
    assert_eq!(etc(&fs), before);
    assert!(!runner.lines().iter().any(|l| l.starts_with("apt-get")));
}

/// docker-ce whose repository is gone, e.g. after a rollback of an
/// earlier apply, gets it back so that it keeps getting updates.
#[test]
fn docker_ce_without_its_repository_gets_it_back() {
    let (fs, runner) = (fs(), Apt::with_docker());
    let facts = with_docker(Some(daemon(true, &[], &[])));
    let first = plan(&fs, &runner, &facts);
    assert_eq!(
        change_ids(&first),
        [
            "directory:/etc/apt/keyrings",
            "file:/etc/apt/keyrings/docker.asc",
            "file:/etc/apt/sources.list.d/docker.sources",
            "directory:/etc/docker",
            "file:/etc/docker/daemon.json",
        ]
    );
    assert_eq!(
        first.modules[0].notes[0],
        "docker-ce is installed without Docker's repository, so it gets no updates; this \
         adds the repository"
    );
}

/// A repository set up another way, such as `docker.list` from Docker's
/// older install docs, is not added a second time.
#[test]
fn docker_ce_with_its_repository_in_another_file() {
    let fs = fs().with_file(
        "/etc/apt/sources.list.d/docker.list",
        "deb [arch=arm64 signed-by=/etc/apt/keyrings/docker.gpg] \
         https://download.docker.com/linux/debian trixie stable\n",
    );
    let runner = Apt::with_docker();
    let facts = with_docker(Some(daemon(true, &[], &[])));
    let steps = steps(&facts, &fs, &runner);
    assert_eq!(
        ids(&steps)[..2],
        ["package:docker-ce", "package:docker-ce-cli"]
    );
    assert_eq!(steps.notes, [PORTS_NOTE]);
}

#[test]
fn docker_before_23_is_refused() {
    let (fs, runner) = (docker_fs(), Apt::with_docker());
    let mut facts = with_docker(None);
    engine_mut(&mut facts).docker_ce_version = Some("5:20.10.24~3-0~debian-bullseye".into());
    match try_steps(&facts, &fs, &runner) {
        Err(ModuleError::Refused(reason)) => assert_eq!(
            reason,
            "Docker 20 is installed, and deploy.docker needs Docker 23.0 or later (for \
             `dockerd --validate` and `default-network-opts`); upgrade it first"
        ),
        other => panic!("{other:?}"),
    }
}

/// A Docker not from Docker's package only gets `daemon.json`.
#[test]
fn another_docker_gets_only_daemon_json() {
    let (fs, runner) = (fs(), Apt::default());
    let facts = with_other_docker();
    let steps = steps(&facts, &fs, &runner);
    assert_eq!(
        ids(&steps),
        ["directory:/etc/docker", "file:/etc/docker/daemon.json"]
    );
    assert_eq!(
        steps.notes,
        [
            "Docker is installed, but not from Docker's package: only \
             /etc/docker/daemon.json is managed",
            PORTS_NOTE,
        ]
    );
}

/// Keys it sets are added or changed, every other key and the file's mode
/// stay, and a log driver's options go with it. Rollback restores the file.
#[test]
fn merges_into_an_existing_daemon_json() {
    const EXISTING: &str = r#"{
    "registry-mirrors": ["https://mirror.example.com"],
    "log-driver": "json-file",
    "log-opts": { "labels": "app" },
    "ip": "192.0.2.10",
    "default-network-opts": {
        "bridge": { "com.docker.network.driver.mtu": "1450" }
    },
    "debug": false
}
"#;
    let fs = docker_fs().with_dir("/etc/docker", root_dir());
    fs.write_atomic(Path::new(DAEMON_JSON), EXISTING.as_bytes(), root(0o600))
        .unwrap();
    let runner = Apt::with_docker();
    let facts = with_docker(Some(daemon(true, &[], &[])));
    let first = plan(&fs, &runner, &facts);
    assert_eq!(change_ids(&first), ["file:/etc/docker/daemon.json"]);
    insta::assert_yaml_snapshot!(first);
    assert_eq!(
        first.modules[0].notes[..2],
        [
            "log-driver changes from json-file to local for new containers: a log shipper \
             that reads json-file gets nothing from them, and json-file's log-opts are \
             dropped",
            "ip changes from 192.0.2.10 to 127.0.0.1: ports the default bridge publishes \
             without an address are no longer reachable on 192.0.2.10",
        ]
    );

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
    insta::assert_snapshot!("merged", daemon_json(&fs));
    assert_eq!(fs.metadata(Path::new(DAEMON_JSON)).unwrap().mode, 0o600);
    assert!(change_ids(&plan(&fs, &runner, &facts)).is_empty());
    engine.rollback(Target::Last, &mut |_| {}).unwrap();
    assert_eq!(daemon_json(&fs), EXISTING);
}

/// A file that already has every key is not rewritten for its layout,
/// and the same log driver keeps its other options.
#[test]
fn a_file_with_every_key_is_left_alone() {
    const DONE: &str = r#"{"ip": "127.0.0.1", "live-restore": true, "log-driver": "local",
"log-opts": {"max-file": "3", "max-size": "10m", "compress": "false"},
"no-new-privileges": true, "userland-proxy": false,
"default-network-opts": {"bridge": {"com.docker.network.bridge.host_binding_ipv4": "127.0.0.1"}}}"#;
    let fs = docker_fs()
        .with_dir("/etc/docker", root_dir())
        .with_file(DAEMON_JSON, DONE);
    let runner = Apt::with_docker();
    let facts = with_docker(Some(daemon(false, &["web"], &["app_default"])));
    let next = plan(&fs, &runner, &facts);
    assert!(change_ids(&next).is_empty(), "{:?}", change_ids(&next));
    // Nothing restarts, so nothing to warn about.
    assert!(
        next.modules[0].notes.is_empty(),
        "{:?}",
        next.modules[0].notes
    );
}

/// The restart stops running containers unless live-restore is on, and
/// existing networks keep their binding.
#[test]
fn notes_what_the_restart_does_to_running_containers_and_networks() {
    let (fs, runner) = (docker_fs(), Apt::with_docker());
    let notes = |facts: Facts| steps(&facts, &fs, &runner).notes[1..].to_vec();
    let docker = |daemon| notes(with_docker(daemon));
    assert_eq!(
        docker(Some(daemon(false, &["web", "db"], &[]))),
        [
            "live-restore is off, so restarting Docker stops these running containers, and \
             only those with a restart policy start again: web, db; a rollback restarts \
             Docker, and them, again"
        ]
    );
    assert!(docker(Some(daemon(true, &["web", "db"], &[]))).is_empty());
    assert!(docker(Some(daemon(false, &[], &[]))).is_empty());
    assert_eq!(
        docker(Some(daemon(true, &[], &["app_default", "proxy"]))),
        [
            "these existing networks keep publishing ports on all addresses until they are \
             recreated (`docker compose down`, then `up`): app_default, proxy"
        ]
    );
    assert_eq!(
        docker(None),
        [
            "the Docker daemon did not answer, so its running containers are unknown; with \
             live-restore off, restarting Docker stops them"
        ]
    );
    let mut stopped = with_docker(None);
    engine_mut(&mut stopped).service = Some(DockerService {
        loaded: true,
        active: false,
    });
    assert_eq!(
        notes(stopped),
        ["docker.service is not running; Docker reads the new daemon.json when it starts"]
    );
}

/// `deploy.user` with `docker = true`, and `firewall.inbound`, after it
/// see Docker coming.
#[test]
fn plans_docker_ce_for_the_modules_after_it() {
    let (fs, runner) = (fs(), Apt::default());
    let facts = facts();
    let steps = steps(&facts, &fs, &runner);
    assert!(steps.resources.contains(&Resource::Package(Package {
        name: DOCKER_PACKAGE.to_owned()
    })));
}

#[test]
fn takes_no_params() {
    DeployDocker.check_params(&toml::Table::new()).unwrap();
    let typo: toml::Table = toml::from_str("ip = \"0.0.0.0\"").unwrap();
    let err = DeployDocker.check_params(&typo).unwrap_err();
    assert!(err.to_string().contains("unknown field `ip`"), "{err}");
}
