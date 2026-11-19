//! The `net.tailscale` module: Tailscale from its repository, `tailscaled`
//! running, and a tailnet login from an auth key file.

use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use super::deploy_proxy::is_label;
use super::{
    Applicability, Module, ModuleError, ModuleSteps, ParamDoc, PlanCx, parse_params, refuse,
};
use crate::facts::network::{parse_tailscale, tailscale_status};
use crate::facts::{Facts, Init, OsFamily};
use crate::resource::{AptSource, File, Package, Resource, Service, TailscaleUp, Validate};
use crate::resource::{apt_source, architecture, check_key_file};
use crate::sys::{Cmd, FileOwner, Sys};

/// Tailscale's package, from Tailscale's repository.
pub const PACKAGE: &str = "tailscale";

const UNIT: &str = "tailscaled.service";

/// Adds Tailscale's repository to unattended-upgrades' origins. The list
/// adds to the one in `52vps-ready` and `50unattended-upgrades`.
const ORIGINS: &str = "/etc/apt/apt.conf.d/52vps-ready-tailscale";

const ORIGINS_CONTENT: &str = "\
// Written by vps-ready (net.tailscale). `vps-ready rollback --last` removes it.
Unattended-Upgrade::Origins-Pattern { \"origin=Tailscale,codename=${distro_codename}\"; };
";

/// Kill timeout of `tailscale status` and `tailscale debug prefs`.
const STATUS_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    /// Empty: no login; the plan says how to log in by hand.
    #[serde(default)]
    auth_key_file: String,
    #[serde(default)]
    login_server: String,
    #[serde(default)]
    hostname: String,
    #[serde(default = "yes")]
    auto_update: bool,
}

const fn yes() -> bool {
    true
}

impl Params {
    /// Checks the values that go into `tailscale up`'s argv.
    fn check(&self) -> Result<(), ModuleError> {
        let url = &self.login_server;
        let plain =
            |s: &str| !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c.is_control());
        let scheme = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"));
        if !url.is_empty() && !scheme.is_some_and(plain) {
            return refuse(&format!(
                "login_server {url:?} is not an http or https URL, e.g. https://headscale.example.com"
            ));
        }
        if !self.hostname.is_empty() && !is_label(&self.hostname) {
            return refuse(&format!(
                "hostname {:?} is not a host name: 1 to 63 lowercase letters, digits and `-`",
                self.hostname
            ));
        }
        Ok(())
    }
}

/// Installs Tailscale from its repository, keeps `tailscaled` running, and
/// logs in with an auth key that `tailscale up` reads from a root-only file.
/// Debian family with systemd only. Never turns on Tailscale SSH or accepts
/// the tailnet's DNS, and never logs out.
#[derive(Debug, Clone, Copy)]
pub struct NetTailscale;

impl Module for NetTailscale {
    fn id(&self) -> &'static str {
        "net.tailscale"
    }

    fn title(&self) -> &'static str {
        "Join a tailnet with Tailscale, for a private path to SSH"
    }

    fn why(&self) -> &'static str {
        "A server reachable only through a private network has no SSH port for \
         the internet to scan or brute force. Tailscale gives this host an \
         address in your tailnet, so you reach the same sshd over it, with the \
         same keys; firewall.inbound can then close public SSH."
    }

    fn params_doc(&self) -> &'static [ParamDoc] {
        &[
            ParamDoc {
                name: "auth_key_file",
                default: "\"\"",
                help: "A file holding an auth key, owned by root with mode 0600 and not a symlink; `tailscale up` reads it, vps-ready never does. Use a one-off, tagged key that is not ephemeral: a tagged node has key expiry off, and an ephemeral one is removed from the tailnet when it goes idle. Delete the file after the login. Empty: log in by hand with `sudo tailscale up --accept-dns=false`.",
            },
            ParamDoc {
                name: "login_server",
                default: "\"\"",
                help: "The coordination server's URL, e.g. a Headscale server's. Empty: Tailscale's.",
            },
            ParamDoc {
                name: "hostname",
                default: "\"\"",
                help: "This node's name in the tailnet. Empty: the host name.",
            },
            ParamDoc {
                name: "auto_update",
                default: "true",
                help: "Let unattended-upgrades (updates.auto) install Tailscale's updates; each restarts tailscaled, which drops tailnet connections for a moment.",
            },
        ]
    }

    fn applicable(&self, facts: &Facts) -> Applicability {
        let reason = if facts.os.family != OsFamily::Debian {
            "Tailscale is installed only on Debian and Ubuntu so far".to_owned()
        } else if facts.init != Init::Systemd {
            "it needs systemd, to run tailscaled".to_owned()
        } else if tailscale_source(facts).is_none() {
            format!(
                "Tailscale's repository has no packages for {}",
                facts.os.pretty_name
            )
        } else {
            return Applicability::Applicable;
        };
        Applicability::NotApplicable { reason }
    }

    fn notes(&self, _facts: &Facts) -> Vec<String> {
        vec![
            "no port is opened: Tailscale needs none, and firewall.inbound's \
             established,related rule covers its replies; tailscaled's own nftables \
             chains (ts-input) coexist with vps-ready's table"
                .to_owned(),
        ]
    }

    fn check_params(&self, params: &toml::Table) -> Result<(), ModuleError> {
        parse_params::<Params>(params)?.check()
    }

    fn plan(&self, cx: &PlanCx, sys: Sys) -> Result<ModuleSteps, ModuleError> {
        let params: Params = cx.params()?;
        params.check()?;
        let Some(source) = tailscale_source(cx.facts) else {
            return refuse("Tailscale's repository has no packages for this release");
        };
        let mut resources = Vec::new();
        let mut notes = Vec::new();
        // Tailscale's install script writes its own `tailscale.list`; a
        // second source with another `Signed-By` breaks `apt-get update`.
        if !source.configured_elsewhere(sys)? {
            resources.extend(apt_source(&source, &architecture(sys)?));
        }
        if params.auto_update {
            resources.push(Resource::File(File {
                path: ORIGINS.into(),
                content: ORIGINS_CONTENT.into(),
                owner: FileOwner {
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                },
                validate: Some(Validate::new("apt-config", ["-c", Validate::PATH, "dump"])),
                describe: None,
            }));
        }
        let package = Resource::Package(Package {
            names: vec![PACKAGE.to_owned()],
        });
        let installed = package.diff(sys)?.is_none();
        resources.push(package);
        resources.push(Resource::Service(Service {
            unit: UNIT.to_owned(),
            enabled: true,
            active: true,
        }));

        let running = cx
            .facts
            .tailscale
            .as_ref()
            .is_some_and(|t| t.backend_state == "Running");
        let login_server = Some(params.login_server).filter(|s| !s.is_empty());
        let hostname = Some(params.hostname).filter(|s| !s.is_empty());
        if running {
            notes.extend(settings_note(sys));
        } else if params.auth_key_file.is_empty() {
            let mut cmd = "sudo tailscale up --accept-dns=false".to_owned();
            if let Some(url) = &login_server {
                cmd.push_str(&format!(" --login-server={url}"));
            }
            if let Some(name) = &hostname {
                cmd.push_str(&format!(" --hostname={name}"));
            }
            notes.push(format!(
                "no auth_key_file, so this node is not logged in: log in with `{cmd}`, then \
                 apply again"
            ));
        } else {
            let path = Path::new(&params.auth_key_file);
            if let Err(why) = check_key_file(sys, path) {
                return refuse(&format!(
                    "auth_key_file {}: {why}; it must be a regular file owned by root with \
                     mode 0600",
                    path.display()
                ));
            }
            resources.push(Resource::TailscaleUp(TailscaleUp {
                auth_key_file: path.into(),
                login_server,
                hostname,
            }));
            notes.push(format!(
                "delete {} after the login; a one-off key is spent once used",
                path.display()
            ));
        }
        if !installed {
            notes.push(
                "rollback leaves Tailscale installed, with /var/lib/tailscale and the node's \
                 login, and removes the repository it updates from; `sudo tailscale logout` \
                 removes the node from the tailnet"
                    .to_owned(),
            );
        }
        Ok(ModuleSteps {
            resources,
            reloads: Vec::new(),
            notes,
        })
    }

    /// After a login with a key, the node is `Running` with an address.
    fn verify(&self, cx: &PlanCx, sys: Sys) -> Result<(), String> {
        let params: Params = cx.params().map_err(|e| e.to_string())?;
        if params.auth_key_file.is_empty() {
            return Ok(());
        }
        let out = sys
            .runner
            .run(&tailscale_status())
            .map_err(|e| format!("`tailscale status`: {e}"))?;
        let status = parse_tailscale(&out.stdout)
            .map_err(|e| format!("parsing `tailscale status --json`: {e}"))?;
        if status.backend_state != "Running" {
            return Err(format!(
                "Tailscale is {}, not Running, after `tailscale up`; `tailscale status` says why",
                status.backend_state
            ));
        }
        if status.ips.is_empty() {
            return Err("Tailscale is Running but this node has no tailnet address".to_owned());
        }
        Ok(())
    }

    fn verify_timeout(&self) -> Duration {
        STATUS_TIMEOUT
    }
}

fn tailscale_source(facts: &Facts) -> Option<AptSource> {
    AptSource::tailscale(&facts.os.id, facts.os.codename.as_deref()?)
}

/// The prefs a node logged in by hand has that this module would not set,
/// as a note; `None` when it has none, or `tailscale debug prefs` fails.
/// `tailscale up` would need `--reset` to change them, and resetting a
/// working node is not a hardening step.
fn settings_note(sys: Sys) -> Option<String> {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Prefs {
        #[serde(default, rename = "CorpDNS")]
        corp_dns: bool,
        #[serde(default)]
        route_all: bool,
        #[serde(default, rename = "ExitNodeID")]
        exit_node_id: String,
        #[serde(default)]
        advertise_routes: Option<Vec<String>>,
        #[serde(default, rename = "RunSSH")]
        run_ssh: bool,
    }
    let cmd = Cmd::new("tailscale")
        .args(["debug", "prefs"])
        .timeout(STATUS_TIMEOUT);
    let out = sys.runner.run(&cmd).ok().filter(|o| o.ok())?;
    let prefs: Prefs = serde_json::from_slice(&out.stdout).ok()?;
    let mut set = Vec::new();
    if prefs.corp_dns {
        set.push("--accept-dns on");
    }
    if prefs.route_all {
        set.push("--accept-routes on");
    }
    if !prefs.exit_node_id.is_empty() {
        set.push("an exit node");
    }
    if prefs.advertise_routes.is_some_and(|r| !r.is_empty()) {
        set.push("advertised routes");
    }
    if prefs.run_ssh {
        set.push("Tailscale SSH on");
    }
    (!set.is_empty()).then(|| {
        format!(
            "this node is logged in already, with {}; vps-ready leaves it as it is",
            set.join(", ")
        )
    })
}

#[cfg(test)]
mod tests;
