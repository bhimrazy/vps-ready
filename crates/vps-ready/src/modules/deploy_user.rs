//! The `deploy.user` module: a login account for CI deploys, separate from
//! the admin, whose keys are restricted and may be forced to run one command.

use std::path::Path;

use serde::{Deserialize, Deserializer};

use super::user_admin::{group_exists, has_sudo_rules, is_plain_key, refuse};
use super::{Applicability, Module, ModuleError, ModuleSteps, ParamDoc, PlanCx};
use crate::engine::deadman::check_binary;
use crate::facts::{Facts, OsFamily};
use crate::resource::user::lookup;
use crate::resource::{AuthorizedKeys, File, Password, Resource, User, Validate};
use crate::sys::{FileOwner, Sys};

/// The sudoers drop-in. sudo skips files in an include directory whose name
/// has a `.` or ends in `~`, so the name has neither.
pub const SUDOERS: &str = "/etc/sudoers.d/90-vps-ready-deploy";

const SUDOERS_DIR: &str = "/etc/sudoers.d";

/// The GECOS field of the account this module creates, by which a later
/// plan knows the account is its own.
pub(crate) const COMMENT: &str = "vps-ready deploy.user";

/// Installed by `deploy.docker`, which creates the `docker` group.
const DOCKER_PACKAGE: &str = "docker-ce";

const HEADER: &str = "\
# Written by vps-ready (deploy.user). `vps-ready rollback --last`
# restores the previous state; edits here are replaced by the next apply.
";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    #[serde(default = "default_name")]
    name: String,
    /// Required; empty is refused when planning, so that the documented
    /// default parses.
    #[serde(default, deserialize_with = "plain_keys")]
    keys: Vec<String>,
    command: Option<String>,
    #[serde(default)]
    docker: bool,
}

fn default_name() -> String {
    "deploy".to_owned()
}

/// Key lines without options, since this module adds its own.
fn plain_keys<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<String>, D::Error> {
    let keys = Vec::<String>::deserialize(de)?;
    match keys.iter().find(|k| !is_plain_key(k.trim())) {
        Some(key) => Err(serde::de::Error::custom(format!(
            "{key:?} is not a public key line without options; deploy.user adds \
             `restrict` (and `command=`) itself"
        ))),
        None => Ok(keys),
    }
}

/// Creates the deploy account. Debian family only, as `user.admin`; it does
/// not need the dead-man switch, since the admin's login is untouched.
#[derive(Debug, Clone, Copy)]
pub struct DeployUser;

impl Module for DeployUser {
    fn id(&self) -> &'static str {
        "deploy.user"
    }

    fn title(&self) -> &'static str {
        "Set up a deploy account whose SSH keys are restricted"
    }

    fn why(&self) -> &'static str {
        "CI that deploys with the admin's key can do anything the admin can. A \
         separate account whose keys cannot forward ports or open a terminal, \
         and with `command` can run only that program, limits what a leaked CI \
         key gives away."
    }

    fn keys_admins(&self) -> bool {
        false
    }

    fn params_doc(&self) -> &'static [ParamDoc] {
        &[
            ParamDoc {
                name: "name",
                default: "\"deploy\"",
                help: "Login name of the deploy account; not user.admin's, and not an existing account vps-ready did not create.",
            },
            ParamDoc {
                name: "keys",
                default: "[]",
                help: "Required: public keys without options, written with `restrict` (and `command=` when set).",
            },
            ParamDoc {
                name: "command",
                default: "\"\"",
                help: "Absolute path of a root-owned program that the keys can only run, and that the account may run as root with sudo, without arguments. Empty: no forced command and no sudo.",
            },
            ParamDoc {
                name: "docker",
                default: "false",
                help: "Add the account to the docker group, which is root access on this host.",
            },
        ]
    }

    fn applicable(&self, facts: &Facts) -> Applicability {
        if facts.os.family == OsFamily::Debian {
            Applicability::Applicable
        } else {
            Applicability::NotApplicable {
                reason: "the deploy account is set up only on Debian and Ubuntu so far".to_owned(),
            }
        }
    }

    fn check_params(&self, params: &toml::Table) -> Result<(), ModuleError> {
        super::parse_params::<Params>(params).map(|_| ())
    }

    /// `visudo -cf` checks the drop-in before it is written.
    fn plan(&self, cx: &PlanCx, sys: Sys) -> Result<ModuleSteps, ModuleError> {
        let params: Params = cx.params()?;
        let name = params.name.as_str();
        let mut notes = Vec::new();
        if params.keys.is_empty() {
            return refuse(
                "`keys` is empty; set the public keys CI logs in with for deploy.user in a profile",
            );
        }
        check_name(cx, sys, name)?;
        let command = params.command.as_deref().filter(|c| !c.is_empty());

        let mut groups = Vec::new();
        if params.docker {
            let planned = cx
                .planned
                .iter()
                .any(|r| matches!(r, Resource::Package(p) if p.name == DOCKER_PACKAGE));
            if !planned && !group_exists(sys, "docker")? {
                return refuse(
                    "`docker = true`, but there is no docker group; install Docker first",
                );
            }
            groups.push("docker".to_owned());
            notes.push(format!(
                "docker = true: {name} joins the docker group, which is root access: it can \
                 start a container that mounts / and change anything on this host"
            ));
        }

        let usepam_off = cx
            .facts
            .ssh
            .effective
            .as_ref()
            .and_then(|c| c.get("usepam"))
            == Some("no");
        // As `user.admin`: with `UsePAM no`, sshd refuses key logins to a
        // locked account. Neither allows a password login.
        let password = if usepam_off {
            notes.push("UsePAM is off: password set to `*` so key logins work".to_owned());
            Password::Star
        } else {
            Password::Locked
        };

        let options = match command {
            Some(command) => {
                // Also keeps the quotes below and the sudoers line plain:
                // only letters, digits and `/._+-`.
                if let Err(why) = check_binary(sys.fs, Path::new(command)) {
                    return refuse(&format!(
                        "`command` {command} cannot be used: {why}. It must be an absolute \
                         path to a file that root owns and only root can write, since \
                         {name} may run it as root"
                    ));
                }
                if !sys.fs.exists(Path::new(SUDOERS_DIR)) {
                    return refuse(&format!(
                        "sudo is not installed ({SUDOERS_DIR} is missing); install it with \
                         `apt-get install sudo` first, or leave out `command`"
                    ));
                }
                format!("restrict,command=\"{command}\"")
            }
            None => {
                if sys.fs.exists(Path::new(SUDOERS)) {
                    notes.push(format!(
                        "no `command`: {SUDOERS} from an earlier apply stays; roll back \
                         the transaction that wrote it (`vps-ready history`) to remove it"
                    ));
                }
                "restrict".to_owned()
            }
        };
        let keys = params
            .keys
            .iter()
            .map(|k| format!("{options} {}", k.trim()))
            .collect();

        let mut resources = vec![
            Resource::User(User {
                name: name.to_owned(),
                groups,
                password,
                comment: Some(COMMENT.to_owned()),
            }),
            Resource::AuthorizedKeys(AuthorizedKeys {
                user: name.to_owned(),
                keys,
            }),
        ];
        if let Some(command) = command {
            resources.push(Resource::File(File {
                path: SUDOERS.into(),
                content: sudoers(name, command).into_bytes(),
                owner: FileOwner {
                    mode: 0o440,
                    uid: 0,
                    gid: 0,
                },
                validate: Some(Validate::new("visudo", ["-cf", Validate::PATH])),
            }));
        }
        Ok(ModuleSteps {
            resources,
            reloads: Vec::new(),
            notes,
        })
    }

    /// With `command`, the deploy user has sudo rules.
    fn verify(&self, cx: &PlanCx, sys: Sys) -> Result<(), String> {
        let params: Params = cx.params().map_err(|e| e.to_string())?;
        if params.command.as_deref().is_none_or(str::is_empty) {
            return Ok(());
        }
        match has_sudo_rules(sys, &params.name) {
            Ok(true) => Ok(()),
            Ok(false) => Err(format!(
                "`sudo -l -U {0}` lists no rules for {0}",
                params.name
            )),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// The drop-in: `command` as root, with no arguments (`""`).
fn sudoers(name: &str, command: &str) -> String {
    format!("{HEADER}{name} ALL=(root) NOPASSWD: {command} \"\"\n")
}

/// Refuses root, the admin `user.admin` sets up in the same plan, an
/// existing account this module did not create, and a group of that name
/// without a user.
fn check_name(cx: &PlanCx, sys: Sys, name: &str) -> Result<(), ModuleError> {
    if name == "root" {
        return refuse("`name` is root; the deploy user must be another account");
    }
    // `user.admin` is the only module before this one that plans a `User`.
    if cx
        .planned
        .iter()
        .any(|r| matches!(r, Resource::User(u) if u.name == name))
    {
        return refuse(&format!(
            "user.admin in this profile sets up {name} as the admin; give deploy.user \
             another `name`"
        ));
    }
    match lookup(sys, name)? {
        Some(entry) if entry.comment != COMMENT => refuse(&format!(
            "{name} already exists, and deploy.user did not create it, so it does not \
             get restricted keys or the docker group; set `name` to a new account"
        )),
        Some(_) => Ok(()),
        // `useradd --user-group` fails then; joining that group instead
        // could grant what it grants.
        None if group_exists(sys, name)? => refuse(&format!(
            "a group named {name} exists, but no user, so `useradd --user-group` \
             cannot create {name}; set `name` to another user"
        )),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests;
