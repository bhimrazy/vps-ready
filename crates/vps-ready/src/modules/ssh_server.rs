//! The `ssh.server` module: one sshd drop-in that turns off root and
//! password logins and the other options `SSH-001` to `SSH-007` check.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use askama::Template;
use sshd_config::{Config, IncludeCheck, SshdConfig};

use super::{Applicability, Module, ModuleError, ModuleSteps, NoParams, PlanCx};
use crate::engine::Reload;
use crate::facts::ssh::FsSource;
use crate::facts::{Facts, Init, OsFamily, SSHD_CONFIG};
use crate::resource::{File, Resource, Validate, keyed_users, user};
use crate::sys::{Cmd, FileOwner, Sys, SysError};

/// The drop-in. sshd reads `sshd_config.d/*.conf` in lexical order and uses
/// the first value it reads, so `00-` wins over cloud-init's
/// `50-cloud-init.conf` and over the rest of `sshd_config`.
pub const DROP_IN: &str = "/etc/ssh/sshd_config.d/00-vps-ready.conf";

/// The keywords of `SSH-001` to `SSH-007`, as `sshd -T` prints them and as
/// written, each set to `no`. Nothing else is ever written: never `Port`,
/// `ListenAddress`, `AllowGroups`, `AuthenticationMethods` or a crypto list.
pub const MANAGED: [(&str, &str); 7] = [
    ("permitrootlogin", "PermitRootLogin"),
    ("passwordauthentication", "PasswordAuthentication"),
    (
        "kbdinteractiveauthentication",
        "KbdInteractiveAuthentication",
    ),
    ("permitemptypasswords", "PermitEmptyPasswords"),
    ("x11forwarding", "X11Forwarding"),
    ("hostbasedauthentication", "HostbasedAuthentication"),
    ("permituserenvironment", "PermitUserEnvironment"),
];

/// The value every managed keyword gets.
const VALUE: &str = "no";

/// Keywords whose `no` can lock out an admin who logs in as root or with a
/// password; keyboard-interactive is a password through PAM.
const LOGIN: [&str; 3] = [
    "permitrootlogin",
    "passwordauthentication",
    "kbdinteractiveauthentication",
];

/// As for the `sshd -T` of the facts.
const SSHD_T_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Template)]
#[template(path = "ssh-server.conf", escape = "none")]
struct DropIn<'a> {
    settings: &'a [Setting],
}

struct Setting {
    keyword: &'static str,
    value: &'static str,
}

/// Writes [`DROP_IN`] and reloads sshd. Debian family with systemd only, and
/// only where `sshd_config` reads the drop-in before anything that could
/// override it. Needs the dead-man switch: a wrong setting locks the admin
/// out of new logins while the open session survives the reload.
#[derive(Debug, Clone, Copy)]
pub struct SshServer;

impl Module for SshServer {
    fn id(&self) -> &'static str {
        "ssh.server"
    }

    fn title(&self) -> &'static str {
        "Turn off root and password logins over SSH"
    }

    fn why(&self) -> &'static str {
        "Root is the account name every scanner tries, and passwords can be guessed \
         or reused from leaks. With keys only, and no root login, a bot needs a \
         private key and a user name. X11 forwarding, host-based logins and user \
         environment files are turned off too: a server has no use for them."
    }

    fn needs_deadman(&self) -> bool {
        true
    }

    fn force_restore(&self) -> bool {
        true
    }

    fn applicable(&self, facts: &Facts) -> Applicability {
        let reason = if facts.os.family != OsFamily::Debian {
            "sshd is set up only on Debian and Ubuntu so far".to_owned()
        } else if facts.init != Init::Systemd {
            "the dead-man switch needs systemd, and systemd is not running".to_owned()
        } else if let Some(effective) = &facts.ssh.effective {
            match &facts.ssh.files {
                Some(files) => match include_problem(files, effective) {
                    Some(reason) => reason,
                    None => return Applicability::Applicable,
                },
                None => format!("{SSHD_CONFIG} could not be read"),
            }
        } else {
            "the effective sshd config is unknown (`sshd -T` failed)".to_owned()
        };
        Applicability::NotApplicable { reason }
    }

    fn notes(&self, facts: &Facts) -> Vec<String> {
        let mut notes = vec![
            "SSH sessions that are open now stay open; the new settings apply to new logins"
                .to_owned(),
            "Port, ListenAddress, AllowGroups, AuthenticationMethods and the crypto settings \
             stay as they are"
                .to_owned(),
        ];
        // A Match block wins over the drop-in for the connections it matches.
        notes.extend(MANAGED.iter().filter_map(|&(key, keyword)| {
            let found = facts.ssh.match_override(key, VALUE)?;
            Some(format!(
                "{keyword} {found} stays as it is: vps-ready does not edit Match blocks"
            ))
        }));
        notes
    }

    /// `sshd -t -f` checks the drop-in on its own before it is written; the
    /// reload's `sshd -t` checks the whole configuration after.
    fn plan(&self, cx: &PlanCx, sys: Sys) -> Result<ModuleSteps, ModuleError> {
        let NoParams {} = cx.params()?;
        let Some(effective) = &cx.facts.ssh.effective else {
            return Ok(ModuleSteps::default());
        };
        let listed = listed(sys)?;
        let settings: Vec<Setting> = MANAGED
            .iter()
            .filter(|(key, _)| listed.contains(*key) || fails(effective, key))
            .map(|&(_, keyword)| Setting {
                keyword,
                value: VALUE,
            })
            .collect();
        if settings.is_empty() {
            return Ok(ModuleSteps::default());
        }
        let turned_off: Vec<&str> = LOGIN
            .iter()
            .copied()
            .filter(|key| fails(effective, key))
            .collect();
        if !turned_off.is_empty() {
            require_admin(cx, sys, &turned_off)?;
        }
        Ok(ModuleSteps {
            resources: vec![Resource::File(File {
                path: DROP_IN.into(),
                content: DropIn {
                    settings: &settings,
                }
                .render()?
                .into_bytes(),
                owner: FileOwner {
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                },
                validate: Some(Validate::new("sshd", ["-t", "-f", Validate::PATH])),
            })],
            reloads: vec![Reload::SshdReload],
            notes: Vec::new(),
        })
    }

    /// `sshd -T -C` for each admin's own connection shows every keyword of
    /// the drop-in at its value, so a `Match` block for an admin or an
    /// earlier file cannot have undone it.
    fn verify(&self, cx: &PlanCx, sys: Sys) -> Result<(), String> {
        let listed = listed(sys).map_err(|e| e.to_string())?;
        if listed.is_empty() {
            return Ok(());
        }
        let addr = cx
            .facts
            .session
            .as_ref()
            .map_or(IpAddr::from([127, 0, 0, 1]), |s| {
                s.client.ip().to_canonical()
            });
        for user in login_users(cx) {
            verify_user(sys, &user, addr, &listed)?;
        }
        Ok(())
    }

    fn verify_timeout(&self) -> Duration {
        SSHD_T_TIMEOUT
    }
}

/// Checks that `sshd -T -C` for `user` connecting from `addr` shows every
/// keyword in `listed` at [`VALUE`].
fn verify_user(sys: Sys, user: &str, addr: IpAddr, listed: &BTreeSet<&str>) -> Result<(), String> {
    let spec = format!("user={user},host={addr},addr={addr}");
    let cmd = Cmd::new("sshd")
        .args(["-T", "-C", &spec])
        .timeout(SSHD_T_TIMEOUT);
    let out = sys
        .runner
        .run(&cmd)
        .map_err(|e| format!("`sshd -T -C {spec}` could not run: {e}"))?;
    if !out.ok() {
        return Err(format!(
            "`sshd -T -C {spec}` exited with status {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let shown = SshdConfig::parse(&String::from_utf8_lossy(&out.stdout));
    for key in listed {
        let value = shown.get(key).unwrap_or("nothing");
        if value != VALUE {
            return Err(format!(
                "`sshd -T -C {spec}` shows {key} {value}, not {VALUE}"
            ));
        }
    }
    Ok(())
}

/// Whether `key` has a value other than `no`. A key `sshd -T` does not show
/// is one this sshd does not know, so it is never written.
fn fails(effective: &SshdConfig, key: &str) -> bool {
    effective.get(key).is_some_and(|v| v != VALUE)
}

/// Why [`DROP_IN`] would not win, if it would not. Only keywords that fail
/// now matter: one set to `no` before the drop-in already agrees with it.
fn include_problem(files: &Config, effective: &SshdConfig) -> Option<String> {
    let failing: Vec<&str> = MANAGED
        .iter()
        .map(|&(key, _)| key)
        .filter(|key| fails(effective, key))
        .collect();
    let at = |file: &Path, line: usize| format!("{}:{line}", file.display());
    match files.include_check(Path::new(DROP_IN), &failing) {
        IncludeCheck::Covered => None,
        IncludeCheck::Missing => Some(format!(
            "{SSHD_CONFIG} does not Include {DROP_IN}, and vps-ready does not edit it"
        )),
        IncludeCheck::AfterMatch { file, line } => Some(format!(
            "the Include that reads {DROP_IN} is inside the Match block at {}, so it \
             would apply to some connections only",
            at(&file, line)
        )),
        IncludeCheck::AfterKeyword {
            keyword,
            file,
            line,
        } => Some(format!(
            "{} sets {} before {DROP_IN} is read, so it wins over the drop-in",
            at(&file, line),
            written(&keyword)
        )),
    }
}

/// `keyword` as it is written, e.g. `PermitRootLogin`.
fn written(key: &str) -> &str {
    MANAGED
        .iter()
        .find(|(k, _)| *k == key)
        .map_or(key, |&(_, w)| w)
}

/// The managed keywords [`DROP_IN`] sets now, lowercase; empty if it does
/// not exist.
fn listed(sys: Sys) -> Result<BTreeSet<&'static str>, ModuleError> {
    let config = match Config::read(&FsSource(sys.fs), Path::new(DROP_IN)) {
        Ok(config) => config,
        Err(sshd_config::Error::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(BTreeSet::new());
        }
        Err(e) => {
            return Err(SysError::Io {
                context: "reading the drop-in".to_owned(),
                source: std::io::Error::other(e.to_string()),
            }
            .into());
        }
    };
    Ok(MANAGED
        .iter()
        .map(|&(key, _)| key)
        .filter(|key| config.directives().iter().any(|d| d.keyword == *key))
        .collect())
}

/// The users who may log in and confirm after apply, as [`Plan::admins`]
/// picks them: those the plan gives keys (`user.admin`), else the non-root
/// user of this SSH session, else root.
///
/// [`Plan::admins`]: crate::engine::Plan::admins
fn login_users(cx: &PlanCx) -> Vec<String> {
    let keyed = keyed_users(cx.planned);
    if !keyed.is_empty() {
        return keyed;
    }
    vec![session_user(cx).unwrap_or("root").to_owned()]
}

/// The user of this SSH session, unless it is root.
fn session_user<'a>(cx: &PlanCx<'a>) -> Option<&'a str> {
    cx.facts
        .session
        .as_ref()
        .filter(|s| s.uid != 0)
        .and_then(|s| s.user.as_deref())
}

/// Whether the plan grants `name` sudo: the `sudo` group, or a rule for it
/// in `/etc/sudoers.d`.
fn planned_sudo(planned: &[Resource], name: &str) -> bool {
    planned.iter().any(|r| match r {
        Resource::User(u) => u.name == name && u.groups.iter().any(|g| g == "sudo"),
        Resource::File(f) => {
            f.path.starts_with("/etc/sudoers.d")
                && String::from_utf8_lossy(&f.content)
                    .lines()
                    .any(|l| l.split_whitespace().next() == Some(name))
        }
        _ => false,
    })
}

/// The lockout invariant: turning off root or password logins needs a
/// user other than root with an SSH key and sudo, to log in as afterwards.
/// That is the admin this plan sets up, or the user of this SSH session
/// (who ran sudo). It only stops an apply that could never be confirmed;
/// the confirm from a new login is the real proof.
fn require_admin(cx: &PlanCx, sys: Sys, turned_off: &[&str]) -> Result<(), ModuleError> {
    let mut why_not = Vec::new();
    // As in `Plan::admins`, a plan that sets up an admin is confirmed by
    // that admin, so the session's user does not count then.
    let keyed = keyed_users(cx.planned);
    for name in &keyed {
        if planned_sudo(cx.planned, name) || has_sudo(sys, name)? {
            return Ok(());
        }
        why_not.push(format!("{name} gets SSH keys from this plan but no sudo"));
    }
    match cx
        .facts
        .session
        .as_ref()
        .map(|s| (s.uid, s.user.as_deref()))
    {
        _ if !keyed.is_empty() => {}
        None => why_not.push("there is no SSH session to take the user from".to_owned()),
        Some((0, _)) => why_not.push("this SSH session is root's".to_owned()),
        Some((uid, None)) => why_not.push(format!("uid {uid} of this SSH session has no name")),
        Some((_, Some(name))) => match (has_keys(cx, sys, name)?, has_sudo(sys, name)?) {
            (true, true) => return Ok(()),
            (false, _) => why_not.push(no_keys(cx, name)),
            (true, false) => why_not.push(format!("{name} has no sudo rights")),
        },
    }
    let mut what: Vec<&str> = turned_off
        .iter()
        .map(|key| {
            if *key == "permitrootlogin" {
                "root login"
            } else {
                "password login"
            }
        })
        .collect();
    what.dedup();
    Err(ModuleError::Refused(format!(
        "refusing to turn off {}: no user other than root has an SSH key and sudo \
         to log in with afterwards ({}). Set one up with the user.admin module, or \
         log in as such a user and run vps-ready with sudo",
        what.join(" and "),
        why_not.join("; ")
    )))
}

/// Why `name` counts as having no key: none in its `authorized_keys`, which
/// is all vps-ready reads, even where sshd also takes keys from a command
/// or certificates from a CA.
fn no_keys(cx: &PlanCx, name: &str) -> String {
    let set = |key: &str| {
        cx.facts
            .ssh
            .effective
            .as_ref()
            .and_then(|e| e.get(key))
            .is_some_and(|v| v != "none")
    };
    let mut other = Vec::new();
    if set("authorizedkeyscommand") {
        other.push("AuthorizedKeysCommand");
    }
    if set("trustedusercakeys") {
        other.push("TrustedUserCAKeys");
    }
    if other.is_empty() {
        format!("{name} has no SSH key in authorized_keys")
    } else {
        format!(
            "{name} has no SSH key in authorized_keys, and vps-ready cannot check the keys \
             sshd also takes through {}",
            other.join(" and ")
        )
    }
}

/// Whether `sudo -l -U` lists commands `name` may run. It exits 0 either way.
fn has_sudo(sys: Sys, name: &str) -> Result<bool, ModuleError> {
    let cmd = Cmd::new("sudo")
        .args(["-n", "-l", "-U", name])
        .env("LC_ALL", "C");
    let out = match sys.runner.run(&cmd) {
        Ok(out) => out,
        Err(SysError::NotFound(_)) => {
            return Err(ModuleError::Refused(
                "sudo is not installed; install it with `apt-get install sudo` first".to_owned(),
            ));
        }
        Err(e) => return Err(e.into()),
    };
    Ok(out.ok() && String::from_utf8_lossy(&out.stdout).contains("may run the following commands"))
}

/// Whether one of `name`'s `AuthorizedKeysFile`s, from `sshd -T`, has a key
/// line.
fn has_keys(cx: &PlanCx, sys: Sys, name: &str) -> Result<bool, ModuleError> {
    let Some(entry) = user::lookup(sys, name)? else {
        return Ok(false);
    };
    let files = cx
        .facts
        .ssh
        .effective
        .as_ref()
        .and_then(|e| e.get("authorizedkeysfile"))
        .unwrap_or(".ssh/authorized_keys");
    for pattern in files.split_whitespace().filter(|p| *p != "none") {
        let path = keys_path(pattern, &entry.home, name);
        match sys.fs.read(&path) {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                if text
                    .lines()
                    .map(str::trim)
                    .any(|l| !l.is_empty() && !l.starts_with('#'))
                {
                    return Ok(true);
                }
            }
            Err(SysError::NotFound(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(false)
}

/// An `AuthorizedKeysFile` entry with `%h`, `%u` and `%%` expanded; a
/// relative one is under the home directory.
fn keys_path(pattern: &str, home: &Path, user: &str) -> PathBuf {
    let mut out = String::new();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('h') => out.push_str(&home.to_string_lossy()),
            Some('u') => out.push_str(user),
            Some(other) => {
                out.push('%');
                if other != '%' {
                    out.push(other);
                }
            }
            None => out.push('%'),
        }
    }
    home.join(out)
}

#[cfg(test)]
mod tests;
