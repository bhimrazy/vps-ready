//! The `deploy.user` module: a login account for CI deploys, separate from
//! the admin, whose keys are restricted and may be forced to run one command.

use std::path::Path;

use serde::{Deserialize, Deserializer};

use super::user_admin::{
    account, check_not_locked, group_exists, has_sudo_rules, sudoers_user, usepam_off,
};
use super::{
    Applicability, DOCKER_PACKAGE, Module, ModuleError, ModuleSteps, ParamDoc, PlanCx, refuse,
};
use crate::engine::deadman::check_binary;
use crate::facts::{Facts, OsFamily};
use crate::resource::authorized_keys::is_plain_key;
use crate::resource::{AuthorizedKeys, File, Password, Resource, User, Validate};
use crate::sys::{FileOwner, Sys, SysError};

/// The sudoers drop-in. sudo skips files in an include directory whose name
/// has a `.` or ends in `~`, so the name has neither.
pub const SUDOERS: &str = "/etc/sudoers.d/90-vps-ready-deploy";

const SUDOERS_DIR: &str = "/etc/sudoers.d";

/// The GECOS field of the account this module creates, by which a later
/// plan knows the account is its own. Only an exact match counts, on
/// purpose: `chfn` writes all four subfields (`vps-ready deploy.user,,,`),
/// so a user who sets this as their own full name does not match.
pub(crate) const COMMENT: &str = "vps-ready deploy.user";

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

impl Params {
    /// `command`, unless empty.
    fn command(&self) -> Option<&str> {
        self.command.as_deref().filter(|c| !c.is_empty())
    }
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
/// not need the dead-man switch, since the admin's login is untouched. Its
/// keys all have options, so it is never taken for an admin who may
/// confirm (see `keyed_users`).
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
                help: "Required: public keys without options. The account's authorized_keys holds exactly these, written with `restrict` (and `command=` when set).",
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
        let command = params.command();
        let mut notes = Vec::new();
        if params.keys.is_empty() {
            return refuse(
                "`keys` is empty; set the public keys CI logs in with for deploy.user in a profile",
            );
        }
        let existing = check_name(cx, sys, name)?;

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

        // As `user.admin`. Neither password allows a password login.
        let password = if usepam_off(cx.facts) {
            if existing {
                check_not_locked(sys, name)?;
            } else {
                notes.push("UsePAM is off: password set to `*` so key logins work".to_owned());
            }
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
                check_drop_in(sys, name)?;
                notes.push(format!(
                    "{name} may run {command} as root with sudo, without a password"
                ));
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
        // Exact: an earlier line for the same key without `command=` would
        // be the one sshd uses, and a key taken out of the profile must go.
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
                exact: true,
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
        if params.command().is_none() {
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

/// Whether the account exists. Refuses root, a group of that name without
/// a user, the admin `user.admin` sets up in the same plan, and an existing
/// account this module did not create.
fn check_name(cx: &PlanCx, sys: Sys, name: &str) -> Result<bool, ModuleError> {
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
    match account(sys, name, "deploy user")? {
        Some(entry) if entry.comment != COMMENT => refuse(&format!(
            "{name} already exists, and deploy.user did not create it (its GECOS field is \
             not \"{COMMENT}\"), so it does not get restricted keys or the docker group; \
             set `name` to a new account"
        )),
        Some(_) => Ok(true),
        None => Ok(false),
    }
}

/// Refuses to hand the drop-in to another user, which would take the rule
/// from the deploy user it names.
fn check_drop_in(sys: Sys, name: &str) -> Result<(), ModuleError> {
    let current = match sys.fs.read(Path::new(SUDOERS)) {
        Ok(bytes) => bytes,
        Err(SysError::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    match sudoers_user(&current) {
        Some(other) if other != name => refuse(&format!(
            "{SUDOERS} gives sudo to {other}, not {name}; roll back the transaction that \
             wrote it (`vps-ready history`), or remove the file, first"
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests;
