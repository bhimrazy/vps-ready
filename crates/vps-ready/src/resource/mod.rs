//! Resources: the things a fix changes, each able to diff, snapshot, apply
//! and restore itself.
//!
//! The set of kinds is closed, so [`Resource`] is an enum. Restoring needs
//! only the [`Backup`] written to the journal (plus the file copies in the
//! transaction directory), so `rollback` works in a later process without
//! planning again.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::sys::{FileKind, FileOwner, Sys, SysError};

mod file;
mod sysctl;

pub use file::File;
pub use sysctl::Sysctl;

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
    /// A kernel parameter under `/proc/sys`.
    Sysctl(Sysctl),
}

impl Resource {
    /// A stable identifier, e.g. `file:/etc/sysctl.d/90-vps-ready.conf` or
    /// `sysctl:kernel.kptr_restrict`.
    #[must_use]
    pub fn id(&self) -> String {
        match self {
            Self::File(f) => format!("file:{}", f.path.display()),
            Self::Sysctl(s) => format!("sysctl:{}", s.key),
        }
    }

    /// What rollback can undo.
    #[must_use]
    pub fn reversibility(&self) -> Reversibility {
        match self {
            Self::File(_) | Self::Sysctl(_) => Reversibility::Reversible,
        }
    }

    /// The change [`Resource::apply`] would make; `None` if the system is
    /// already in the desired state. Only reads.
    ///
    /// # Errors
    ///
    /// For a [`File`], [`ResourceError::NotRegularFile`] or
    /// [`ResourceError::MissingParent`]; any [`SysError`] from reading.
    pub fn diff(&self, sys: Sys) -> Result<Option<Change>, ResourceError> {
        let change = match self {
            Self::File(f) => f.diff(sys)?,
            Self::Sysctl(s) => s.diff(sys)?,
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
    /// For a [`File`], this also writes the desired bytes to
    /// [`after_path`]`(txn_dir, n)` and, if the file exists, its current bytes
    /// to [`before_path`]`(txn_dir, n)`, and makes both durable, so the caller
    /// can journal the returned [`Backup`] right away. `n` must be unique
    /// within the transaction; other kinds ignore `txn_dir` and `n`.
    ///
    /// # Errors
    ///
    /// For a [`File`], [`ResourceError::NotRegularFile`]; any [`SysError`].
    pub fn snapshot(&self, sys: Sys, txn_dir: &Path, n: u32) -> Result<Backup, ResourceError> {
        match self {
            Self::File(f) => f.snapshot(sys, txn_dir, n),
            Self::Sysctl(s) => s.snapshot(sys),
        }
    }

    /// Makes the change.
    ///
    /// # Errors
    ///
    /// Any [`SysError`] from writing.
    pub fn apply(&self, sys: Sys) -> Result<(), ResourceError> {
        match self {
            Self::File(f) => f.apply(sys),
            Self::Sysctl(s) => s.apply(sys),
        }
    }
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
    /// A kernel parameter.
    Sysctl {
        /// Dotted key, e.g. `kernel.kptr_restrict`.
        key: String,
        /// Value as read, trimmed.
        value: String,
        /// Value that apply writes.
        applied: String,
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

/// Puts back the state recorded in `backup`, with the file copies of the
/// transaction in `txn_dir`. Restoring a file that did not exist removes
/// it, if it is there.
///
/// # Errors
///
/// Any [`SysError`], e.g. if `files/<n>.before` is missing or the target is
/// now a symlink.
pub fn restore(sys: Sys, txn_dir: &Path, backup: &Backup) -> Result<(), ResourceError> {
    match backup {
        Backup::File { path, n, original } => file::restore(sys, txn_dir, path, *n, *original),
        Backup::Sysctl { key, value, .. } => sysctl::restore(sys, key, value),
    }
}

/// A [`Sys`] over `fs` whose runner fails every command; these resources run none.
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
                Backup::Sysctl {
                    key: "kernel.kptr_restrict".into(),
                    value: "0".into(),
                    applied: "1".into(),
                },
                r#"{"kind":"sysctl","key":"kernel.kptr_restrict","value":"0","applied":"1"}"#,
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
