//! The `deploy.docker` module: Docker Engine from Docker's repository, and a
//! `daemon.json` with safe defaults, merged into an existing one.

use std::path::Path;

use serde_json::{Map, Value, json};

use super::{
    Applicability, DOCKER_PACKAGE, Module, ModuleError, ModuleSteps, NoParams, PlanCx, refuse,
};
use crate::engine::Reload;
use crate::facts::docker::{DAEMON_JSON, parse_daemon_json};
use crate::facts::{DaemonJson, DockerEngine, Facts, Init, OsFamily};
use crate::resource::{AptSource, Directory, File, Package, Resource, Validate};
use crate::resource::{apt_source, architecture, configured_elsewhere};
use crate::sys::{FileOwner, Sys, SysError};

/// Docker Engine's packages, as Docker's install docs list them.
pub const PACKAGES: [&str; 5] = [
    DOCKER_PACKAGE,
    "docker-ce-cli",
    "containerd.io",
    "docker-buildx-plugin",
    "docker-compose-plugin",
];

const DOCKER_DIR: &str = "/etc/docker";

const LOG_DRIVER: &str = "local";

/// The first release with `dockerd --validate` and `default-network-opts`.
const MIN_MAJOR: u32 = 23;

/// The source `apt_source` writes for Docker.
const DOCKER_SOURCES: &str = "/etc/apt/sources.list.d/docker.sources";

/// Docker's repository, as any apt source names it, whatever the
/// distribution in its path.
const DOCKER_REPO: &str = "download.docker.com";

/// The keys this module sets. Ports published without an address bind to
/// 127.0.0.1, on the default bridge (`ip`) and on networks created from now
/// on (`default-network-opts`), so they do not bypass the firewall (FW-002).
fn settings() -> Map<String, Value> {
    let value = json!({
        "log-driver": LOG_DRIVER,
        "log-opts": { "max-size": "10m", "max-file": "3" },
        "live-restore": true,
        "no-new-privileges": true,
        "userland-proxy": false,
        "ip": "127.0.0.1",
        "default-network-opts": {
            "bridge": { "com.docker.network.bridge.host_binding_ipv4": "127.0.0.1" }
        }
    });
    value.as_object().cloned().unwrap_or_default()
}

/// `current` with [`settings`] merged in key by key: objects are merged,
/// other values replaced, and every other key is kept in its place. Log
/// options belong to their driver, so another driver's are dropped.
fn merged(mut current: Map<String, Value>) -> Map<String, Value> {
    if current.get("log-driver").and_then(Value::as_str) != Some(LOG_DRIVER)
        && let Some(opts) = current.get_mut("log-opts")
    {
        *opts = Value::Object(Map::new());
    }
    merge(&mut current, settings());
    current
}

fn merge(into: &mut Map<String, Value>, from: Map<String, Value>) {
    for (key, value) in from {
        if let (Some(Value::Object(have)), Value::Object(want)) = (into.get_mut(&key), &value) {
            merge(have, want.clone());
        } else {
            into.insert(key, value);
        }
    }
}

/// Installs Docker Engine from Docker's repository, and keeps that
/// repository for a `docker-ce` already installed; a Docker installed
/// otherwise only gets `daemon.json`. Sets safe defaults there. Debian
/// family with systemd only. It adds nobody to the docker group.
#[derive(Debug, Clone, Copy)]
pub struct DeployDocker;

impl Module for DeployDocker {
    fn id(&self) -> &'static str {
        "deploy.docker"
    }

    fn title(&self) -> &'static str {
        "Install Docker with logs capped and ports on loopback by default"
    }

    fn why(&self) -> &'static str {
        "A port Docker publishes skips the firewall's input rules, so `-p \
         5432:5432` puts a database on the internet. With 127.0.0.1 as the \
         default address, a reverse proxy on the host reaches the container and \
         nobody else does. Capped logs cannot fill the disk, and live-restore \
         keeps containers running while Docker restarts. no-new-privileges keeps \
         processes in new containers from gaining privileges, so setuid programs \
         such as su and sudo stop working inside them."
    }

    fn applicable(&self, facts: &Facts) -> Applicability {
        let reason = if facts.os.family != OsFamily::Debian {
            "Docker is installed only on Debian and Ubuntu so far".to_owned()
        } else if facts.init != Init::Systemd {
            "it needs systemd, to restart Docker".to_owned()
        } else if let Some(reason) = docker_reason(facts) {
            reason
        } else {
            return Applicability::Applicable;
        };
        Applicability::NotApplicable { reason }
    }

    /// `dockerd --validate` checks `daemon.json` before it is written.
    fn plan(&self, cx: &PlanCx, sys: Sys) -> Result<ModuleSteps, ModuleError> {
        let NoParams {} = cx.params()?;
        let facts = cx.facts;
        let mut resources = Vec::new();
        let mut notes = Vec::new();
        let engine = facts.docker_engine.as_ref();
        let installed = engine.is_some_and(DockerEngine::installed);
        let from_package = engine.is_some_and(DockerEngine::from_package);
        if let Some(major) = engine.and_then(DockerEngine::major)
            && major < MIN_MAJOR
        {
            return refuse(&format!(
                "Docker {major} is installed, and deploy.docker needs Docker {MIN_MAJOR}.0 or \
                 later (for `dockerd --validate` and `default-network-opts`); upgrade it first"
            ));
        }
        if installed && !from_package {
            notes.push(
                "Docker is installed, but not from Docker's package: only \
                 /etc/docker/daemon.json is managed"
                    .to_owned(),
            );
        } else {
            // Planned for an installed docker-ce too, where they have no
            // change, so that it keeps a repository to get updates from.
            if !(from_package && configured_elsewhere(sys, "docker", DOCKER_REPO)?) {
                let Some(source) = docker_source(facts) else {
                    return refuse("Docker's repository has no packages for this release");
                };
                if from_package && !sys.fs.exists(Path::new(DOCKER_SOURCES)) {
                    notes.push(
                        "docker-ce is installed without Docker's repository, so it gets no \
                         updates; this adds the repository"
                            .to_owned(),
                    );
                }
                resources.extend(apt_source(&source, &architecture(sys)?));
            }
            resources.extend(PACKAGES.iter().map(|name| {
                Resource::Package(Package {
                    name: (*name).to_owned(),
                })
            }));
            if !from_package {
                notes.push(
                    "Docker sets net.ipv4.ip_forward=1 and a FORWARD policy of drop; a host \
                     that routes other traffic (a WireGuard peer, a subnet router) needs its \
                     own forward rules"
                        .to_owned(),
                );
                notes.push(
                    "rollback leaves Docker's packages installed, and removes the repository \
                     they update from"
                        .to_owned(),
                );
            }
        }

        let (current, owner) = match sys.fs.read(Path::new(DAEMON_JSON)) {
            Ok(bytes) => {
                let meta = sys.fs.metadata(Path::new(DAEMON_JSON))?;
                let owner = FileOwner {
                    mode: meta.mode,
                    uid: meta.uid,
                    gid: meta.gid,
                };
                (Some(bytes), owner)
            }
            Err(SysError::NotFound(_)) => (None, root(0o644)),
            Err(e) => return Err(e.into()),
        };
        let content = match &current {
            Some(bytes) => {
                let have = match parse_daemon_json(bytes) {
                    Ok(have) => have,
                    Err(why) => return refuse(&format!("{DAEMON_JSON} {why}")),
                };
                let want = merged(have.clone());
                // Rewritten only when a value changes, not for its layout.
                if want == have {
                    bytes.clone()
                } else {
                    notes.extend(changed_notes(&have));
                    render(want, indent(bytes))?
                }
            }
            None => render(settings(), b"  ")?,
        };
        if current.as_ref() != Some(&content) {
            notes.extend(restart_notes(facts, installed));
        }

        resources.extend([
            Resource::Directory(Directory {
                path: DOCKER_DIR.into(),
                owner: root(0o755),
            }),
            Resource::File(File {
                path: DAEMON_JSON.into(),
                content,
                owner,
                validate: Some(Validate::new(
                    "dockerd",
                    ["--validate", "--config-file", Validate::PATH],
                )),
            }),
        ]);
        Ok(ModuleSteps {
            resources,
            reloads: vec![Reload::DockerRestart],
            notes,
        })
    }
}

/// Why the Docker part of the host rules the module out, if it does.
fn docker_reason(facts: &Facts) -> Option<String> {
    let Some(engine) = &facts.docker_engine else {
        return Some("the installed packages are unknown (`dpkg-query` failed)".to_owned());
    };
    let conflicts: Vec<&str> = engine
        .packages
        .iter()
        .map(String::as_str)
        .filter(|p| *p != DOCKER_PACKAGE)
        .collect();
    if !conflicts.is_empty() {
        return Some(format!(
            "{} {} installed, and vps-ready does not replace a container runtime that may \
             be in use; remove {} to use Docker's packages",
            conflicts.join(", "),
            if conflicts.len() == 1 { "is" } else { "are" },
            if conflicts.len() == 1 { "it" } else { "them" },
        ));
    }
    if let DaemonJson::Unusable { reason } = &engine.daemon_json {
        return Some(format!("{DAEMON_JSON} {reason}; fix it, then plan again"));
    }
    if engine.daemon.as_ref().is_some_and(|d| d.swarm) {
        return Some(
            "this node is part of a Docker swarm, and live-restore does not work in swarm \
             mode"
                .to_owned(),
        );
    }
    if facts.docker && !engine.installed() {
        return Some(
            "Docker is installed, but neither from Docker's package nor with a \
             docker.service unit (a snap?), so vps-ready leaves it alone"
                .to_owned(),
        );
    }
    // Docker's own package keeps its repository too.
    let needs_repo = !engine.installed() || engine.from_package();
    if needs_repo && docker_source(facts).is_none() {
        return Some(format!(
            "Docker's repository has no packages for {}",
            facts.os.pretty_name
        ));
    }
    None
}

/// What changing a value of the existing `daemon.json` means, beyond the
/// diff.
fn changed_notes(have: &Map<String, Value>) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(driver) = have.get("log-driver").and_then(Value::as_str)
        && driver != LOG_DRIVER
    {
        notes.push(format!(
            "log-driver changes from {driver} to {LOG_DRIVER} for new containers: a log \
             shipper that reads {driver} gets nothing from them, and {driver}'s log-opts \
             are dropped"
        ));
    }
    if let Some(ip) = have.get("ip").and_then(Value::as_str)
        && ip != "127.0.0.1"
    {
        notes.push(format!(
            "ip changes from {ip} to 127.0.0.1: ports the default bridge publishes without \
             an address are no longer reachable on {ip}"
        ));
    }
    notes
}

fn docker_source(facts: &Facts) -> Option<AptSource> {
    AptSource::docker(&facts.os.id, facts.os.codename.as_deref()?)
}

/// What restarting Docker with the new `daemon.json` does to what runs now.
fn restart_notes(facts: &Facts, installed: bool) -> Vec<String> {
    let mut notes = vec![
        "ports published without an address bind to 127.0.0.1 only, not to ::1: point a \
         reverse proxy at 127.0.0.1:<port>, not localhost"
            .to_owned(),
    ];
    if !installed {
        return notes;
    }
    let engine = facts.docker_engine.as_ref();
    if engine
        .and_then(|e| e.service)
        .is_some_and(|s| s.loaded && !s.active)
    {
        notes.push(
            "docker.service is not running; Docker reads the new daemon.json when it starts"
                .to_owned(),
        );
        return notes;
    }
    let Some(daemon) = engine.and_then(|e| e.daemon.as_ref()) else {
        notes.push(
            "the Docker daemon did not answer, so its running containers are unknown; with \
             live-restore off, restarting Docker stops them"
                .to_owned(),
        );
        return notes;
    };
    if !daemon.live_restore && !daemon.running.is_empty() {
        notes.push(format!(
            "live-restore is off, so restarting Docker stops these running containers, and \
             only those with a restart policy start again: {}; a rollback restarts Docker, \
             and them, again",
            daemon.running.join(", ")
        ));
    }
    if !daemon.networks.is_empty() {
        notes.push(format!(
            "these existing networks keep publishing ports on all addresses until they are \
             recreated (`docker compose down`, then `up`): {}",
            daemon.networks.join(", ")
        ));
    }
    notes
}

/// One level of indent in `json`: the leading spaces or tabs of its first
/// indented line, else two spaces. Keeping it keeps the diff small.
fn indent(json: &[u8]) -> &[u8] {
    json.split(|&b| b == b'\n')
        .map(|line| {
            let n = line
                .iter()
                .take_while(|&&b| b == b' ' || b == b'\t')
                .count();
            &line[..n]
        })
        .find(|lead| !lead.is_empty())
        .unwrap_or(b"  ")
}

/// Pretty-printed with `indent`, and a final newline.
fn render(map: Map<String, Value>, indent: &[u8]) -> Result<Vec<u8>, ModuleError> {
    use serde::Serialize as _;

    let mut bytes = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(indent);
    let mut ser = serde_json::Serializer::with_formatter(&mut bytes, formatter);
    Value::Object(map)
        .serialize(&mut ser)
        .map_err(|e| ModuleError::Refused(format!("rendering {DAEMON_JSON}: {e}")))?;
    bytes.push(b'\n');
    Ok(bytes)
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
