//! The `user.admin` module: a login account other than root, with SSH keys
//! and sudo, which `ssh.server` needs before it turns off root and password
//! logins.

use std::path::Path;

use serde::Deserialize;

use super::{Applicability, Module, ModuleError, ModuleSteps, PlanCx};
use crate::facts::{Facts, Init, OsFamily};
use crate::resource::user::{Entry, lookup};
use crate::resource::{AuthorizedKeys, File, Password, Resource, User, Validate};
use crate::sys::{Cmd, FileOwner, Sys, SysError};

/// The sudoers drop-in. sudo skips files in an include directory whose name
/// has a `.` or ends in `~`, so the name has neither.
pub const SUDOERS: &str = "/etc/sudoers.d/90-vps-ready-admin";

const SUDOERS_DIR: &str = "/etc/sudoers.d";

const SHADOW: &str = "/etc/shadow";

const SHELLS: &str = "/etc/shells";

/// The first uid `adduser` gives a login user on Debian and Ubuntu.
const FIRST_LOGIN_UID: u32 = 1000;

const HEADER: &str = "\
# Written by vps-ready (user.admin). `vps-ready rollback --last`
# restores the previous state; edits here are replaced by the next apply.
";

/// What `sudo -l -U <name>` prints, under `LC_ALL=C`, when it lists rules.
const HAS_RULES: &str = " may run the following commands on ";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    #[serde(default = "default_name")]
    name: String,
    /// Empty: the keys of the user this session logged in as.
    #[serde(default)]
    authorized_keys: Vec<String>,
    #[serde(default)]
    sudo: Sudo,
}

fn default_name() -> String {
    "admin".to_owned()
}

/// How an admin without sudo rules gets them.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Sudo {
    /// A `NOPASSWD: ALL` rule in [`SUDOERS`], as cloud images give their
    /// default user.
    #[default]
    Nopasswd,
    /// The `sudo` group; only for an account that already has a password.
    Password,
}

/// Creates or completes the admin account. Debian family with systemd only:
/// it needs the dead-man switch, since a broken key or sudo rule is found
/// only by the new login that `confirm` asks for.
#[derive(Debug, Clone, Copy)]
pub struct UserAdmin;

impl Module for UserAdmin {
    fn id(&self) -> &'static str {
        "user.admin"
    }

    fn title(&self) -> &'static str {
        "Set up an admin account that logs in with an SSH key and uses sudo"
    }

    fn why(&self) -> &'static str {
        "Root and password logins are what attacks on SSH try first. A named \
         account with a key and sudo is what lets ssh.server turn both off \
         without locking you out."
    }

    fn needs_deadman(&self) -> bool {
        true
    }

    fn applicable(&self, facts: &Facts) -> Applicability {
        let reason = if facts.os.family != OsFamily::Debian {
            "the admin account is set up only on Debian and Ubuntu so far"
        } else if facts.init != Init::Systemd {
            "the dead-man switch needs systemd, and systemd is not running"
        } else {
            return Applicability::Applicable;
        };
        Applicability::NotApplicable {
            reason: reason.to_owned(),
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
        if name == "root" {
            return refuse("`name` is root; the admin must be another account");
        }
        let existing = lookup(sys, name)?;
        if let Some(entry) = &existing {
            check_login_account(sys, name, entry)?;
        }
        if existing.is_none() && group_exists(sys, name)? {
            // `useradd --user-group` fails then; joining that group instead
            // could grant what it grants, e.g. Ubuntu's `%admin ALL=(ALL) ALL`.
            return refuse(&format!(
                "a group named {name} exists, but no user, so `useradd --user-group` \
                 cannot create {name}; set `name` to another user"
            ));
        }
        if !sys.fs.exists(Path::new(SUDOERS_DIR)) {
            return refuse(&format!(
                "sudo is not installed ({SUDOERS_DIR} is missing); \
                 install it with `apt-get install sudo` first"
            ));
        }
        let keys = if params.authorized_keys.is_empty() {
            copied_keys(cx.facts, sys, &mut notes)?
        } else {
            params.authorized_keys.clone()
        };
        let usepam_off = cx
            .facts
            .ssh
            .effective
            .as_ref()
            .and_then(|c| c.get("usepam"))
            == Some("no");
        let password = if usepam_off {
            Password::Star
        } else {
            Password::Locked
        };
        if existing.is_none() && usepam_off {
            notes.push("UsePAM is off: password set to `*` so key logins work".to_owned());
        }
        if existing.is_some()
            && usepam_off
            && shadow_field(sys, name)?.is_some_and(|f| f.starts_with('!'))
        {
            return refuse(&format!(
                "UsePAM is off, and {name}'s password is locked (`!` in {SHADOW}), so sshd \
                 refuses its key logins; set a password or run `usermod -p '*' {name}` first"
            ));
        }

        let sudoers = File {
            path: SUDOERS.into(),
            content: format!("{HEADER}{name} ALL=(ALL:ALL) NOPASSWD: ALL\n").into_bytes(),
            owner: FileOwner {
                mode: 0o440,
                uid: 0,
                gid: 0,
            },
            validate: Some(Validate::new("visudo", ["-cf", Validate::PATH])),
        };
        let mut groups = Vec::new();
        let mut drop_in = None;
        // The drop-in is vps-ready's: once there, it is kept to its content,
        // though its rule is also what `sudo -l` lists. It is not handed to
        // another admin, which would take sudo from the one it names.
        if let Some(current) = read_if_exists(sys, Path::new(SUDOERS))? {
            match sudoers_user(&current) {
                Some(other) if other != name => {
                    return refuse(&format!(
                        "{SUDOERS} gives sudo to {other}, not {name}, and rewriting it would \
                         take that away; roll back the transaction that wrote it \
                         (`vps-ready history`), or remove the file, first"
                    ));
                }
                _ if params.sudo == Sudo::Password => {
                    return refuse(&format!(
                        "{SUDOERS} gives {name} sudo without a password, which \
                         `sudo = \"password\"` would leave in place; roll back the transaction \
                         that wrote it (`vps-ready history`), or remove the file, first"
                    ));
                }
                _ => drop_in = Some(sudoers),
            }
        } else if existing.is_some() && has_sudo_rules(sys, name)? {
            notes.push(format!(
                "{name} already has sudo rules (`sudo -l -U {name}`); they stay as they are, \
                 and no sudoers file is written"
            ));
        } else {
            match params.sudo {
                Sudo::Nopasswd => drop_in = Some(sudoers),
                Sudo::Password if existing.is_none() => {
                    return refuse(&format!(
                        "`sudo = \"password\"` needs an account with a password, and {name} \
                         does not exist yet; create it and set one with `passwd {name}` \
                         first, or use `sudo = \"nopasswd\"`"
                    ));
                }
                Sudo::Password if !has_password(sys, name)? => {
                    return refuse(&format!(
                        "`sudo = \"password\"` needs a password, and {name} has none; \
                         set one with `passwd {name}` first, or use `sudo = \"nopasswd\"`"
                    ));
                }
                Sudo::Password => groups.push("sudo".to_owned()),
            }
        }

        let mut resources = vec![
            Resource::User(User {
                name: name.to_owned(),
                groups,
                password,
            }),
            Resource::AuthorizedKeys(AuthorizedKeys {
                user: name.to_owned(),
                keys,
            }),
        ];
        resources.extend(drop_in.map(Resource::File));
        Ok(ModuleSteps {
            resources,
            reloads: Vec::new(),
            notes,
        })
    }

    /// The admin has sudo rules, by whatever means.
    fn verify(&self, cx: &PlanCx, sys: Sys) -> Result<(), String> {
        let params: Params = cx.params().map_err(|e| e.to_string())?;
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

fn refuse<T>(reason: &str) -> Result<T, ModuleError> {
    Err(ModuleError::Refused(reason.to_owned()))
}

fn read_if_exists(sys: Sys, path: &Path) -> Result<Option<Vec<u8>>, ModuleError> {
    match sys.fs.read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(SysError::NotFound(_)) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// The key lines of the user this SSH session logged in as, else of root,
/// who just logged in with one of them. Lines with options are skipped:
/// Ubuntu and AWS images put `command="echo 'Please login as ...'"` on
/// root's keys, which would make the admin unusable.
fn copied_keys(
    facts: &Facts,
    sys: Sys,
    notes: &mut Vec<String>,
) -> Result<Vec<String>, ModuleError> {
    let source = facts
        .session
        .as_ref()
        .and_then(|s| s.user.as_deref())
        .unwrap_or("root");
    let Some(entry) = lookup(sys, source)? else {
        return refuse(&format!(
            "no `authorized_keys` given, and the login user {source} has no passwd entry \
             to copy keys from"
        ));
    };
    let path = entry.home.join(".ssh/authorized_keys");
    let text = read_if_exists(sys, &path)?.unwrap_or_default();
    let mut keys = Vec::new();
    let mut skipped = 0;
    for line in String::from_utf8_lossy(&text).lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if is_plain_key(line) {
            keys.push(line.to_owned());
        } else {
            skipped += 1;
        }
    }
    let path = path.display();
    let lines = |n: usize| if n == 1 { "line" } else { "lines" };
    if keys.is_empty() {
        let skipped = if skipped > 0 {
            format!(" ({skipped} {} with options skipped)", lines(skipped))
        } else {
            String::new()
        };
        return refuse(&format!(
            "no `authorized_keys` given, and {path} has no key to copy{skipped}; \
             set `authorized_keys` for user.admin in a profile"
        ));
    }
    let n = keys.len();
    let them = if n == 1 { "key" } else { "keys" };
    notes.push(format!(
        "no `authorized_keys` given: copies {n} {them} from {path}"
    ));
    if skipped > 0 {
        notes.push(format!(
            "skipped {skipped} {} of {path} with options (command=, no-pty, ...), \
             which would restrict the admin too",
            lines(skipped)
        ));
    }
    Ok(keys)
}

/// Whether `line` starts with a key type rather than options.
/// Whether `line` starts with a key type rather than options, and has a key
/// after it.
fn is_plain_key(line: &str) -> bool {
    let mut fields = line.split_whitespace();
    fields.next().is_some_and(|kind| {
        ["ssh-", "ecdsa-", "sk-"]
            .iter()
            .any(|p| kind.starts_with(p))
    }) && fields.next().is_some()
}

/// Refuses an existing account that is not a login user: a system account,
/// or one whose shell is not in `/etc/shells`, such as `www-data` or
/// `nobody`, which must not get keys and sudo.
fn check_login_account(sys: Sys, name: &str, entry: &Entry) -> Result<(), ModuleError> {
    let other = "set `name` to a login user or to a new account";
    if entry.uid < FIRST_LOGIN_UID {
        return refuse(&format!(
            "{name} is a system account (uid {}, below {FIRST_LOGIN_UID}); {other}",
            entry.uid
        ));
    }
    // An empty shell field means `/bin/sh`.
    let shell = if entry.shell.is_empty() {
        "/bin/sh"
    } else {
        &entry.shell
    };
    let shells = read_if_exists(sys, Path::new(SHELLS))?.unwrap_or_default();
    let listed = String::from_utf8_lossy(&shells)
        .lines()
        .map(str::trim)
        .any(|l| l == shell);
    if !listed {
        return refuse(&format!(
            "{name}'s shell {shell} is not in {SHELLS}, so it is not a login account; {other}"
        ));
    }
    Ok(())
}

/// The user of the rule in a drop-in vps-ready wrote, if it has one.
fn sudoers_user(content: &[u8]) -> Option<String> {
    String::from_utf8_lossy(content)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .and_then(|l| l.split_whitespace().next())
        .map(str::to_owned)
}

fn group_exists(sys: Sys, name: &str) -> Result<bool, ModuleError> {
    let out = sys.runner.run(&Cmd::new("getent").args(["group", name]))?;
    match out.status {
        0 => Ok(true),
        // The key was not found.
        2 => Ok(false),
        status => refuse(&format!(
            "`getent group {name}` exited with status {status}"
        )),
    }
}

/// Whether `sudo -l -U <name>` lists rules for the existing account `name`.
fn has_sudo_rules(sys: Sys, name: &str) -> Result<bool, ModuleError> {
    let cmd = Cmd::new("sudo")
        .args(["-n", "-l", "-U", name])
        .env("LC_ALL", "C");
    let out = match sys.runner.run(&cmd) {
        Ok(out) => out,
        Err(SysError::NotFound(_)) => {
            return refuse("sudo is not installed; install it with `apt-get install sudo` first");
        }
        Err(e) => return Err(e.into()),
    };
    if !out.ok() {
        return refuse(&format!(
            "`sudo -l -U {name}` exited with status {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout_str()?.contains(HAS_RULES))
}

/// Whether `name` has a password hash in `/etc/shadow`: not empty, and not
/// locked (`!`) or unset (`*`).
fn has_password(sys: Sys, name: &str) -> Result<bool, ModuleError> {
    Ok(shadow_field(sys, name)?
        .is_some_and(|hash| !hash.is_empty() && !hash.starts_with(['!', '*'])))
}

/// The password field of `name` in `/etc/shadow`, if it is listed.
fn shadow_field(sys: Sys, name: &str) -> Result<Option<String>, ModuleError> {
    let shadow = sys.fs.read(Path::new(SHADOW))?;
    Ok(String::from_utf8_lossy(&shadow).lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next() == Some(name)).then(|| fields.next().unwrap_or_default().to_owned())
    }))
}

#[cfg(test)]
mod tests;
