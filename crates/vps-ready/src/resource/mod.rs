//! Resources: the things a fix changes, each able to diff, snapshot, apply
//! and restore itself.
//!
//! The set of kinds is closed, so [`Resource`] is an enum. Restoring needs
//! only the [`Backup`] written to the journal (plus the file copies in the
//! transaction directory), so `rollback` works in a later process without
//! planning again.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::sys::{Cmd, FileKind, FileOwner, Output, Sys, SysError};

pub(crate) mod authorized_keys;
pub(crate) mod directory;
mod file;
mod package;
pub(crate) mod service;
pub(crate) mod sysctl;
pub(crate) mod user;

pub use authorized_keys::AuthorizedKeys;
pub use directory::Directory;
pub use file::{File, Validate};
pub use package::Package;
pub use service::Service;
pub use sysctl::Sysctl;
pub use user::{Password, User};

/// Errors from diffing, snapshotting, applying or restoring a resource.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResourceError {
    /// The target of a [`File`] is a symlink, directory or special file.
    #[error("refusing to manage {path}: not a regular file ({kind:?})")]
    NotRegularFile {
        /// Target path.
        path: PathBuf,
        /// What it is instead.
        kind: FileKind,
    },
    /// The directory that would hold a [`File`] does not exist.
    #[error("refusing to create {0}: its parent directory does not exist")]
    MissingParent(PathBuf),
    /// The [`Validate`] command of a [`File`] rejected its `.after` copy or
    /// could not run; the target was not written.
    #[error("refusing to write {path}: `{program}` {reason}")]
    Invalid {
        /// Target path.
        path: PathBuf,
        /// Validate program.
        program: String,
        /// Exit status and stderr, or why it could not run.
        reason: String,
    },
    /// A path vps-ready would write for a user is unsafe: it or a parent is
    /// a symlink, a directory on it has the wrong owner or mode, or the file
    /// has another owner, more than one link or a setuid, setgid or sticky
    /// bit.
    #[error("refusing to manage {path}: {reason}")]
    Unsafe {
        /// The offending path.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },
    /// A systemd unit that a [`Service`] cannot manage.
    #[error("refusing to manage unit {unit}: {reason}")]
    Unit {
        /// Unit name.
        unit: String,
        /// Why, e.g. that it is masked.
        reason: String,
    },
    /// A user, group or unit name that could pass as an option or is not
    /// a plain name.
    #[error("refusing {kind} name {name:?}: not a plain name")]
    InvalidName {
        /// `user`, `group` or `unit`.
        kind: &'static str,
        /// The name.
        name: String,
    },
    /// An [`AuthorizedKeys`] line that is empty or holds a line break.
    #[error("refusing an authorized_keys line for {user}: {reason}")]
    InvalidKey {
        /// The user.
        user: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A command printed something that does not parse.
    #[error("unexpected output from `{program}`: {output:?}")]
    Unexpected {
        /// Program that was run.
        program: String,
        /// Its standard output.
        output: String,
    },
    /// The user of an [`AuthorizedKeys`] does not exist at apply time.
    #[error("user {0} does not exist")]
    NoSuchUser(String),
    /// A command exited with a non-zero status.
    #[error("`{program}` exited with status {status}: {stderr}")]
    Command {
        /// Program that was run.
        program: String,
        /// Exit code; `-1` if killed by a signal.
        status: i32,
        /// Standard error, trimmed.
        stderr: String,
    },
    /// The system boundary failed.
    #[error(transparent)]
    Sys(#[from] SysError),
}

/// Whether rollback returns a resource to its state before apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Reversibility {
    /// Rollback restores the previous state exactly.
    Reversible,
    /// Rollback leaves part of the change in place.
    Partial,
}

/// One change a resource would make, as the plan shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    /// [`Resource::id`] of the resource.
    pub id: String,
    /// One line, e.g. `kernel.kptr_restrict 0 -> 1`.
    pub summary: String,
    /// Unified diff of a file's content, if the content changes.
    pub diff: Option<String>,
    /// What rollback can undo.
    pub reversibility: Reversibility,
}

/// Something vps-ready changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resource {
    /// A whole file vps-ready owns.
    File(File),
    /// A directory that must exist.
    Directory(Directory),
    /// A kernel parameter under `/proc/sys`.
    Sysctl(Sysctl),
    /// An apt package that must be installed.
    Package(Package),
    /// A systemd unit that must be enabled or disabled, active or not.
    Service(Service),
    /// A login account that must exist, in some groups.
    User(User),
    /// Public key lines that a user's `authorized_keys` must contain.
    AuthorizedKeys(AuthorizedKeys),
}

impl Resource {
    /// A stable identifier, e.g. `file:/etc/sysctl.d/90-vps-ready.conf`,
    /// `directory:/etc/vps-ready`,
    /// `sysctl:kernel.kptr_restrict`, `package:unattended-upgrades`,
    /// `service:fail2ban.service`, `user:admin` or `authorized-keys:admin`.
    #[must_use]
    pub fn id(&self) -> String {
        match self {
            Self::File(f) => format!("file:{}", f.path.display()),
            Self::Directory(d) => format!("directory:{}", d.path.display()),
            Self::Sysctl(s) => format!("sysctl:{}", s.key),
            Self::Package(p) => format!("package:{}", p.name),
            Self::Service(s) => format!("service:{}", s.unit),
            Self::User(u) => format!("user:{}", u.name),
            Self::AuthorizedKeys(k) => format!("authorized-keys:{}", k.user),
        }
    }

    /// What rollback can undo.
    #[must_use]
    pub fn reversibility(&self) -> Reversibility {
        match self {
            Self::File(_)
            | Self::Directory(_)
            | Self::Sysctl(_)
            | Self::Service(_)
            | Self::AuthorizedKeys(_) => Reversibility::Reversible,
            // Rollback leaves an installed package installed, and a removed
            // user's home directory.
            Self::Package(_) | Self::User(_) => Reversibility::Partial,
        }
    }

    /// The longest the commands of [`Resource::snapshot`] and
    /// [`Resource::apply`] may run, in total, by their timeouts.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        match self {
            Self::File(f) if f.validate.is_some() => Cmd::DEFAULT_TIMEOUT,
            Self::File(_) | Self::Directory(_) | Self::Sysctl(_) => Duration::ZERO,
            Self::Package(_) => package::TIMEOUT,
            Self::Service(_) => service::TIMEOUT,
            // `getent`, `id`, then `useradd` or `usermod`.
            Self::User(_) => Cmd::DEFAULT_TIMEOUT * 4,
            // `getent` in snapshot and in apply.
            Self::AuthorizedKeys(_) => Cmd::DEFAULT_TIMEOUT * 2,
        }
    }

    /// The longest the commands of [`Resource::diff`] may run, in total, by
    /// their timeouts.
    #[must_use]
    pub fn diff_timeout(&self) -> Duration {
        match self {
            Self::File(_) | Self::Directory(_) | Self::Sysctl(_) => Duration::ZERO,
            // `dpkg-query`; `systemctl show`; `getent`.
            Self::Package(_) | Self::Service(_) | Self::AuthorizedKeys(_) => Cmd::DEFAULT_TIMEOUT,
            // `getent`, then `id`.
            Self::User(_) => Cmd::DEFAULT_TIMEOUT * 2,
        }
    }

    /// The change [`Resource::apply`] would make; `None` if the system is
    /// already in the desired state. Only reads.
    ///
    /// # Errors
    ///
    /// For a [`File`], [`ResourceError::NotRegularFile`]; for an
    /// [`AuthorizedKeys`], that, [`ResourceError::MissingParent`] or
    /// [`ResourceError::Unsafe`]; [`ResourceError::Command`] if a command
    /// fails; [`ResourceError::Unit`], [`ResourceError::InvalidName`] or
    /// [`ResourceError::InvalidKey`]; any [`SysError`] from reading.
    pub fn diff(&self, sys: Sys) -> Result<Option<Change>, ResourceError> {
        let change = match self {
            Self::File(f) => f.diff(sys)?,
            Self::Directory(d) => d.diff(sys)?,
            Self::Sysctl(s) => s.diff(sys)?,
            Self::Package(p) => p.diff(sys)?,
            Self::Service(s) => s.diff(sys)?,
            Self::User(u) => u.diff(sys)?,
            Self::AuthorizedKeys(k) => k.diff(sys)?,
        };
        Ok(change.map(|(summary, diff)| Change {
            id: self.id(),
            summary,
            diff,
            reversibility: self.reversibility(),
        }))
    }

    /// Records the current state, so that [`restore`] can bring it back.
    ///
    /// For a [`File`] or an [`AuthorizedKeys`], this also writes the desired
    /// bytes to [`after_path`]`(txn_dir, n)` and, if the file exists, its
    /// current bytes to [`before_path`]`(txn_dir, n)`, and makes both
    /// durable; for a [`File`], it then runs its [`Validate`] command, if
    /// any, on the `.after` copy. Once this returns, the caller can journal
    /// the [`Backup`] and apply. `n` must be unique within the transaction;
    /// other kinds ignore `txn_dir` and `n`.
    ///
    /// # Errors
    ///
    /// As for [`Resource::diff`], plus [`ResourceError::MissingParent`] and
    /// [`ResourceError::Invalid`] for a [`File`] and
    /// [`ResourceError::NoSuchUser`] for an [`AuthorizedKeys`].
    pub fn snapshot(&self, sys: Sys, txn_dir: &Path, n: u32) -> Result<Backup, ResourceError> {
        match self {
            Self::File(f) => f.snapshot(sys, txn_dir, n),
            Self::Directory(d) => d.snapshot(sys),
            Self::Sysctl(s) => s.snapshot(sys),
            Self::Package(p) => p.snapshot(sys),
            Self::Service(s) => s.snapshot(sys),
            Self::User(u) => u.snapshot(sys),
            Self::AuthorizedKeys(k) => k.snapshot(sys, txn_dir, n),
        }
    }

    /// Makes the change.
    ///
    /// # Errors
    ///
    /// [`ResourceError::Command`] if a command fails; as for
    /// [`Resource::snapshot`]; any [`SysError`].
    pub fn apply(&self, sys: Sys) -> Result<Applied, ResourceError> {
        match self {
            Self::File(f) => f.apply(sys),
            Self::Directory(d) => d.apply(sys),
            Self::Sysctl(s) => s.apply(sys),
            Self::Package(p) => p.apply(sys),
            Self::Service(s) => s.apply(sys),
            Self::User(u) => return u.apply(sys).map(|uid| Applied { uid }),
            Self::AuthorizedKeys(k) => k.apply(sys),
        }?;
        Ok(Applied::default())
    }
}

/// What [`Resource::apply`] learned that the safety check of a rollback
/// needs, journaled with the `applied` line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Applied {
    /// The uid of the account a [`User`] created, so a rollback does not
    /// remove another account that took its name since.
    pub uid: Option<u32>,
}

/// The state of a resource before apply, as written to the journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Backup {
    /// A file, whose bytes (if it existed) are in [`before_path`]`(txn_dir, n)`
    /// and whose applied bytes are in [`after_path`]`(txn_dir, n)`.
    File {
        /// Target path.
        path: PathBuf,
        /// Number of the file copy in the transaction directory.
        n: u32,
        /// Mode and owner; `None` if the file did not exist.
        original: Option<FileCopy>,
    },
    /// A directory.
    Directory {
        /// Its path.
        path: PathBuf,
        /// Whether apply creates it.
        created: bool,
    },
    /// A kernel parameter.
    Sysctl {
        /// Dotted key, e.g. `kernel.kptr_restrict`.
        key: String,
        /// Value as read, trimmed.
        value: String,
        /// Value that apply writes.
        applied: String,
        /// Boot in which `value` was read; `None` if it could not be read, or in
        /// journals from before 0.2.1.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        boot_id: Option<String>,
    },
    /// An apt package.
    Package {
        /// Package name.
        name: String,
        /// Whether it was installed.
        was_installed: bool,
    },
    /// A systemd unit.
    Service {
        /// Unit name.
        unit: String,
        /// Whether it was enabled.
        was_enabled: bool,
        /// Whether it was active.
        was_active: bool,
        /// Whether apply leaves it enabled.
        enabled: bool,
        /// Whether apply leaves it active.
        active: bool,
    },
    /// A login account.
    User {
        /// User name.
        name: String,
        /// Whether apply creates it.
        created: bool,
        /// Groups apply adds it to: all of its groups if it creates it,
        /// otherwise only those it was not in.
        added_groups: Vec<String>,
    },
    /// A user's `authorized_keys`, whose bytes (if it existed) are in
    /// [`before_path`]`(txn_dir, n)` and whose applied bytes are in
    /// [`after_path`]`(txn_dir, n)`.
    #[serde(rename = "authorized-keys")]
    AuthorizedKeys {
        /// User name.
        user: String,
        /// The file, from the user's home directory at apply time.
        path: PathBuf,
        /// Number of the file copy in the transaction directory.
        n: u32,
        /// Mode and owner; `None` if the file did not exist.
        original: Option<FileCopy>,
        /// Whether apply creates its directory, `~/.ssh`.
        created_dir: bool,
    },
}

/// Mode and owner of a backed-up file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileCopy {
    /// Permission bits.
    pub mode: u32,
    /// Owner user id.
    pub uid: u32,
    /// Owner group id.
    pub gid: u32,
}

impl From<FileOwner> for FileCopy {
    fn from(o: FileOwner) -> Self {
        Self {
            mode: o.mode,
            uid: o.uid,
            gid: o.gid,
        }
    }
}

impl From<FileCopy> for FileOwner {
    fn from(c: FileCopy) -> Self {
        Self {
            mode: c.mode,
            uid: c.uid,
            gid: c.gid,
        }
    }
}

/// The users other than root that `resources` give a non-empty
/// `authorized_keys`, in order, each once.
pub fn keyed_users<'a>(resources: impl IntoIterator<Item = &'a Resource>) -> Vec<String> {
    let mut users: Vec<String> = Vec::new();
    for resource in resources {
        if let Resource::AuthorizedKeys(keys) = resource
            && !keys.keys.is_empty()
            && keys.user != "root"
            && !users.contains(&keys.user)
        {
            users.push(keys.user.clone());
        }
    }
    users
}

/// Where the original bytes of backed-up file `n` are kept: `files/<n>.before`.
#[must_use]
pub fn before_path(txn_dir: &Path, n: u32) -> PathBuf {
    txn_dir.join("files").join(format!("{n}.before"))
}

/// Where the bytes that apply writes for file `n` are kept: `files/<n>.after`.
#[must_use]
pub fn after_path(txn_dir: &Path, n: u32) -> PathBuf {
    txn_dir.join("files").join(format!("{n}.after"))
}

/// Where a dead-man rollback keeps the bytes file `n` had when it was
/// restored anyway: `files/<n>.during`.
#[must_use]
pub fn during_path(txn_dir: &Path, n: u32) -> PathBuf {
    txn_dir.join("files").join(format!("{n}.during"))
}

/// Puts back the state recorded in `backup`, with the file copies of the
/// transaction in `txn_dir`. Restoring a file that did not exist removes
/// it, if it is there; a directory apply created is removed if it is empty. Restoring a package does nothing: removing it could
/// take other packages with it. A created user is removed with `userdel`,
/// which keeps its home directory.
///
/// # Errors
///
/// Any [`SysError`], e.g. if `files/<n>.before` is missing or the target is
/// now a symlink; [`ResourceError::Unsafe`] if a parent of an
/// `authorized_keys` is now a symlink; [`ResourceError::Command`], e.g.
/// when `userdel` refuses a user that still has processes.
pub fn restore(sys: Sys, txn_dir: &Path, backup: &Backup) -> Result<(), ResourceError> {
    match backup {
        Backup::File { path, n, original } => file::restore(sys, txn_dir, path, *n, *original),
        Backup::Directory { path, created } => directory::restore(sys, path, *created),
        Backup::Sysctl { key, value, .. } => sysctl::restore(sys, key, value),
        Backup::Package { .. } => Ok(()),
        Backup::Service { .. } => service::restore(sys, backup),
        Backup::User {
            name,
            created,
            added_groups,
        } => user::restore(sys, name, *created, added_groups),
        Backup::AuthorizedKeys {
            user,
            path,
            n,
            original,
            created_dir,
        } => authorized_keys::restore(sys, txn_dir, user, path, *n, *original, *created_dir),
    }
}

/// Runs `cmd`; a non-zero exit is [`ResourceError::Command`].
fn run(sys: Sys, cmd: &Cmd) -> Result<Output, ResourceError> {
    let out = sys.runner.run(cmd)?;
    if out.ok() {
        Ok(out)
    } else {
        Err(failed(&cmd.program, &out))
    }
}

fn failed(program: &str, out: &Output) -> ResourceError {
    ResourceError::Command {
        program: program.to_owned(),
        status: out.status,
        stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
    }
}

/// Whether `name` is a user or group name as Debian's `adduser` accepts by
/// default, so it cannot pass as an option.
fn plain_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 32
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// A [`Sys`] over `fs` whose runner fails every command, for tests whose
/// resource runs no command.
#[cfg(test)]
fn test_sys(fs: &dyn crate::sys::Fs) -> Sys<'_> {
    struct NoRunner;
    impl crate::sys::Runner for NoRunner {
        fn run(&self, cmd: &crate::sys::Cmd) -> Result<crate::sys::Output, SysError> {
            Err(SysError::NotFound(cmd.program.clone()))
        }
    }
    Sys {
        fs,
        runner: &NoRunner,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyed_users_are_those_given_keys_other_than_root() {
        let keys = |user: &str, keys: &[&str]| {
            Resource::AuthorizedKeys(AuthorizedKeys {
                user: user.into(),
                keys: keys.iter().map(|k| (*k).to_owned()).collect(),
            })
        };
        let resources = [
            Resource::User(User {
                name: "nokeys".into(),
                groups: Vec::new(),
                password: Password::Locked,
            }),
            keys("root", &["ssh-ed25519 AAAA root"]),
            keys("empty", &[]),
            keys("admin", &["ssh-ed25519 AAAA a"]),
            keys("deploy", &["ssh-ed25519 AAAA d"]),
            keys("admin", &["ssh-ed25519 AAAA b"]),
        ];
        assert_eq!(keyed_users(&resources), ["admin", "deploy"]);
        assert!(keyed_users(&[]).is_empty());
    }

    #[test]
    fn backup_json_shape() {
        let cases = [
            (
                Backup::File {
                    path: "/etc/sysctl.d/90-vps-ready.conf".into(),
                    n: 1,
                    original: None,
                },
                r#"{"kind":"file","path":"/etc/sysctl.d/90-vps-ready.conf","n":1,"original":null}"#,
            ),
            (
                Backup::File {
                    path: "/etc/apt/apt.conf.d/52vps-ready".into(),
                    n: 2,
                    original: Some(FileCopy {
                        mode: 0o644,
                        uid: 0,
                        gid: 0,
                    }),
                },
                r#"{"kind":"file","path":"/etc/apt/apt.conf.d/52vps-ready","n":2,"original":{"mode":420,"uid":0,"gid":0}}"#,
            ),
            (
                Backup::Directory {
                    path: "/etc/vps-ready".into(),
                    created: true,
                },
                r#"{"kind":"directory","path":"/etc/vps-ready","created":true}"#,
            ),
            (
                Backup::Sysctl {
                    key: "kernel.kptr_restrict".into(),
                    value: "0".into(),
                    applied: "1".into(),
                    boot_id: None,
                },
                r#"{"kind":"sysctl","key":"kernel.kptr_restrict","value":"0","applied":"1"}"#,
            ),
            (
                Backup::Sysctl {
                    key: "kernel.kptr_restrict".into(),
                    value: "0".into(),
                    applied: "1".into(),
                    boot_id: Some("8f3c".into()),
                },
                r#"{"kind":"sysctl","key":"kernel.kptr_restrict","value":"0","applied":"1","boot_id":"8f3c"}"#,
            ),
            (
                Backup::Package {
                    name: "unattended-upgrades".into(),
                    was_installed: false,
                },
                r#"{"kind":"package","name":"unattended-upgrades","was_installed":false}"#,
            ),
            (
                Backup::Service {
                    unit: "fail2ban.service".into(),
                    was_enabled: false,
                    was_active: false,
                    enabled: true,
                    active: true,
                },
                r#"{"kind":"service","unit":"fail2ban.service","was_enabled":false,"was_active":false,"enabled":true,"active":true}"#,
            ),
            (
                Backup::User {
                    name: "admin".into(),
                    created: true,
                    added_groups: vec!["sudo".into()],
                },
                r#"{"kind":"user","name":"admin","created":true,"added_groups":["sudo"]}"#,
            ),
            (
                Backup::AuthorizedKeys {
                    user: "admin".into(),
                    path: "/home/admin/.ssh/authorized_keys".into(),
                    n: 2,
                    original: None,
                    created_dir: true,
                },
                r#"{"kind":"authorized-keys","user":"admin","path":"/home/admin/.ssh/authorized_keys","n":2,"original":null,"created_dir":true}"#,
            ),
        ];
        for (backup, json) in cases {
            assert_eq!(serde_json::to_string(&backup).unwrap(), json);
            assert_eq!(serde_json::from_str::<Backup>(json).unwrap(), backup);
        }
        // A newer binary may add fields; an older one must still read the line.
        let newer =
            r#"{"kind":"sysctl","key":"fs.suid_dumpable","value":"2","applied":"0","extra":1}"#;
        assert!(serde_json::from_str::<Backup>(newer).is_ok());
    }

    #[test]
    fn m2_journals_still_parse() {
        // As v0.2.1 wrote them.
        let journal = concat!(
            r#"{"at":1792932000,"event":"begin","version":"0.2.1","modules":["kernel.sysctl","updates.auto"]}"#,
            "\n",
            r#"{"at":1792932000,"event":"backup","resource":"file:/etc/sysctl.d/90-vps-ready.conf","backup":{"kind":"file","path":"/etc/sysctl.d/90-vps-ready.conf","n":1,"original":null}}"#,
            "\n",
            r#"{"at":1792932000,"event":"applied","resource":"file:/etc/sysctl.d/90-vps-ready.conf"}"#,
            "\n",
            r#"{"at":1792932001,"event":"backup","resource":"sysctl:kernel.kptr_restrict","backup":{"kind":"sysctl","key":"kernel.kptr_restrict","value":"0","applied":"1","boot_id":"8f3c"}}"#,
            "\n",
            r#"{"at":1792932001,"event":"applied","resource":"sysctl:kernel.kptr_restrict"}"#,
            "\n",
            r#"{"at":1792932002,"event":"backup","resource":"package:unattended-upgrades","backup":{"kind":"package","name":"unattended-upgrades","was_installed":true}}"#,
            "\n",
            r#"{"at":1792932040,"event":"applied","resource":"package:unattended-upgrades"}"#,
            "\n",
            r#"{"at":1792932041,"event":"state","state":"applied"}"#,
            "\n",
        );
        let records =
            crate::engine::journal::parse(Path::new("journal.jsonl"), journal.as_bytes()).unwrap();
        let kinds: Vec<&Backup> = records
            .iter()
            .filter_map(|r| match &r.event {
                crate::engine::Event::Backup { backup, .. } => Some(backup),
                _ => None,
            })
            .collect();
        assert!(matches!(
            kinds[..],
            [
                Backup::File { .. },
                Backup::Sysctl { .. },
                Backup::Package { .. }
            ]
        ));
        assert_eq!(
            crate::engine::journal::replay(&records).unwrap(),
            crate::engine::TxnState::Applied
        );
    }

    #[test]
    fn plain_names() {
        for name in ["admin", "_apt", "deploy-1", "a2"] {
            assert!(plain_name(name), "{name}");
        }
        for name in [
            "", "-r", "--help", "Admin", "1admin", "a b", "a:b", "a/b", "a\n",
        ] {
            assert!(!plain_name(name), "{name:?}");
        }
        assert!(!plain_name(&"a".repeat(33)));
    }

    #[test]
    fn change_json_shape() {
        let change = Change {
            id: "sysctl:kernel.kptr_restrict".into(),
            summary: "kernel.kptr_restrict 0 -> 1".into(),
            diff: None,
            reversibility: Reversibility::Reversible,
        };
        assert_eq!(
            serde_json::to_string(&change).unwrap(),
            r#"{"id":"sysctl:kernel.kptr_restrict","summary":"kernel.kptr_restrict 0 -> 1","diff":null,"reversibility":"reversible"}"#
        );
    }
}
