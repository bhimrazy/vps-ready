//! The [`File`] resource.

use std::path::{Path, PathBuf};

use similar::TextDiff;

use super::{Backup, FileCopy, ResourceError, after_path, before_path};
use crate::sys::{Cmd, FileKind, FileOwner, Sys, SysError};

/// A whole file whose content, mode and owner vps-ready owns, such as a
/// drop-in it created. Only regular files are managed: a symlink or special
/// file at `path` is refused, and so is a missing parent directory.
///
/// Snapshots keep bytes, mode and owner only (no xattrs, ACLs or SELinux
/// labels), which is all a file vps-ready created has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    /// Absolute path.
    pub path: PathBuf,
    /// Desired content.
    pub content: Vec<u8>,
    /// Desired mode and owner.
    pub owner: FileOwner,
    /// Checks the desired content before the target is written.
    pub validate: Option<Validate>,
}

/// A command that must exit 0 on the `.after` copy of a [`File`] before the
/// target is written. Every argument equal to [`Validate::PATH`] is replaced
/// with the path of that copy, e.g. `apt-config -c {} dump`.
///
/// The path is the system path; the command runs on the host, so this
/// matches [`crate::sys::Fs`] only when it is rooted at `/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validate {
    /// Program name or absolute path.
    pub program: String,
    /// Arguments, not including the program.
    pub args: Vec<String>,
}

impl Validate {
    /// Placeholder for the path of the `.after` copy.
    pub const PATH: &str = "{}";

    /// `program` with `args`.
    #[must_use]
    pub fn new<I, S>(program: impl Into<String>, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    /// Runs the command on `copy`. Fails closed: a non-zero exit or a
    /// command that cannot run is [`ResourceError::Invalid`].
    fn check(&self, sys: Sys, target: &Path, copy: &Path) -> Result<(), ResourceError> {
        let invalid = |reason: String| ResourceError::Invalid {
            path: target.to_path_buf(),
            program: self.program.clone(),
            reason,
        };
        let copy = copy
            .to_str()
            .ok_or_else(|| invalid(format!("cannot take non-UTF-8 path {}", copy.display())))?;
        let args = self
            .args
            .iter()
            .map(|a| if a == Self::PATH { copy } else { a.as_str() });
        match sys.runner.run(&Cmd::new(&self.program).args(args)) {
            Ok(out) if out.ok() => Ok(()),
            Ok(out) => Err(invalid(format!(
                "exited with status {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ))),
            Err(e) => Err(invalid(format!("could not run: {e}"))),
        }
    }
}

impl File {
    /// The summary and unified diff of the change, or `None`.
    pub(super) fn diff(&self, sys: Sys) -> Result<Option<(String, Option<String>)>, ResourceError> {
        let Some(owner) = self.current(sys)? else {
            self.require_parent(sys)?;
            let summary = format!("create {} ({})", self.path.display(), fmt_owner(self.owner));
            let diff = (!self.content.is_empty()).then(|| unified(b"", &self.content));
            return Ok(Some((summary, diff)));
        };
        let current = sys.fs.read(&self.path)?;
        if current == self.content && owner == self.owner {
            return Ok(None);
        }
        let owner = if owner == self.owner {
            fmt_owner(self.owner)
        } else {
            format!("{} -> {}", fmt_owner(owner), fmt_owner(self.owner))
        };
        let summary = format!("update {} ({owner})", self.path.display());
        let diff = (current != self.content).then(|| unified(&current, &self.content));
        Ok(Some((summary, diff)))
    }

    /// Records mode and owner, copies the current bytes to `files/<n>.before`,
    /// writes the desired bytes to `files/<n>.after` and validates that copy.
    pub(super) fn snapshot(
        &self,
        sys: Sys,
        txn_dir: &Path,
        n: u32,
    ) -> Result<Backup, ResourceError> {
        let original = self.current(sys)?;
        let before = original.map(|_| sys.fs.read(&self.path)).transpose()?;
        sys.fs.create_dir_all(&txn_dir.join("files"), 0o700)?;
        sys.fs.sync_dir(txn_dir)?;
        // Both copies are 0600; `.before` has the original's owner, `.after` the desired one.
        if let (Some(owner), Some(bytes)) = (original, before) {
            let copy = FileOwner {
                mode: 0o600,
                ..owner
            };
            sys.fs
                .write_atomic(&before_path(txn_dir, n), &bytes, copy)?;
        }
        let copy = FileOwner {
            mode: 0o600,
            ..self.owner
        };
        let after = after_path(txn_dir, n);
        sys.fs.write_atomic(&after, &self.content, copy)?;
        if let Some(validate) = &self.validate {
            validate.check(sys, &self.path, &after)?;
        }
        Ok(Backup::File {
            path: self.path.clone(),
            n,
            original: original.map(FileCopy::from),
        })
    }

    pub(super) fn apply(&self, sys: Sys) -> Result<(), ResourceError> {
        Ok(sys.fs.write_atomic(&self.path, &self.content, self.owner)?)
    }

    /// Mode and owner of the regular file at `path`; `None` if it does not exist.
    fn current(&self, sys: Sys) -> Result<Option<FileOwner>, ResourceError> {
        match sys.fs.metadata(&self.path) {
            Ok(meta) if meta.kind == FileKind::File => Ok(Some(meta.owner())),
            Ok(meta) => Err(ResourceError::NotRegularFile {
                path: self.path.clone(),
                kind: meta.kind,
            }),
            Err(SysError::NotFound(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn require_parent(&self, sys: Sys) -> Result<(), ResourceError> {
        let missing = || ResourceError::MissingParent(self.path.clone());
        let parent = self.path.parent().ok_or_else(missing)?;
        match sys.fs.metadata(parent) {
            Ok(meta) if meta.kind == FileKind::Dir => Ok(()),
            Ok(_) | Err(SysError::NotFound(_)) => Err(missing()),
            Err(e) => Err(e.into()),
        }
    }
}

pub(super) fn restore(
    sys: Sys,
    txn_dir: &Path,
    path: &Path,
    n: u32,
    original: Option<FileCopy>,
) -> Result<(), ResourceError> {
    if let Some(copy) = original {
        let bytes = sys.fs.read(&before_path(txn_dir, n))?;
        sys.fs.write_atomic(path, &bytes, copy.into())?;
        return Ok(());
    }
    match sys.fs.remove(path) {
        Ok(()) => {
            if let Some(dir) = path.parent() {
                sys.fs.sync_dir(dir)?;
            }
            Ok(())
        }
        // Already absent: apply never ran, or an earlier restore removed it.
        Err(SysError::NotFound(_)) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn fmt_owner(o: FileOwner) -> String {
    format!("{:04o} {}:{}", o.mode, o.uid, o.gid)
}

fn unified(old: &[u8], new: &[u8]) -> String {
    let old = String::from_utf8_lossy(old);
    let new = String::from_utf8_lossy(new);
    TextDiff::from_lines(old.as_ref(), new.as_ref())
        .unified_diff()
        .to_string()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt as _;

    use super::super::{Resource, restore, test_sys as sys};
    use super::*;
    use crate::sys::fake::{FakeFs, FakeRunner};
    use crate::sys::{Fs, Output, RealFs};

    const PATH: &str = "/etc/sysctl.d/90-vps-ready.conf";
    const TXN: &str = "/var/lib/vps-ready/txn/20261023T114246Z";

    fn root_owner() -> FileOwner {
        FileOwner {
            mode: 0o644,
            uid: 0,
            gid: 0,
        }
    }

    fn resource(content: &str, owner: FileOwner) -> Resource {
        Resource::File(File {
            path: PATH.into(),
            content: content.into(),
            owner,
            validate: None,
        })
    }

    #[test]
    fn diff_creates_a_missing_file() {
        let fs = FakeFs::new().with_file("/etc/sysctl.d/10-other.conf", "");
        let change = resource("a = 1\nb = 2\n", root_owner())
            .diff(sys(&fs))
            .unwrap()
            .unwrap();
        assert_eq!(change.id, format!("file:{PATH}"));
        assert_eq!(change.summary, format!("create {PATH} (0644 0:0)"));
        assert_eq!(
            change.diff.as_deref(),
            Some("@@ -0,0 +1,2 @@\n+a = 1\n+b = 2\n")
        );
    }

    #[test]
    fn diff_of_an_empty_new_file_has_no_unified_diff() {
        let fs = FakeFs::new().with_file("/etc/sysctl.d/10-other.conf", "");
        let change = resource("", root_owner()).diff(sys(&fs)).unwrap().unwrap();
        assert_eq!(change.summary, format!("create {PATH} (0644 0:0)"));
        assert_eq!(change.diff, None);
    }

    #[test]
    fn restore_fails_without_the_before_copy() {
        let fs = FakeFs::new().with_file(PATH, "new = 1\n");
        let backup = Backup::File {
            path: PATH.into(),
            n: 1,
            original: Some(root_owner().into()),
        };
        let err = restore(sys(&fs), Path::new(TXN), &backup).unwrap_err();
        assert!(
            matches!(err, ResourceError::Sys(SysError::NotFound(_))),
            "{err:?}"
        );
        assert_eq!(fs.read(Path::new(PATH)).unwrap(), b"new = 1\n");
    }

    #[test]
    fn restore_refuses_a_target_that_is_now_a_symlink() {
        let txn = Path::new(TXN);
        let fs = FakeFs::new()
            .with_file(before_path(txn, 1), "old = 1\n")
            .with_file("/etc/shadow", "secret\n")
            .with_symlink(PATH, "/etc/shadow");
        let backup = Backup::File {
            path: PATH.into(),
            n: 1,
            original: Some(root_owner().into()),
        };
        let err = restore(sys(&fs), txn, &backup).unwrap_err();
        assert!(
            matches!(err, ResourceError::Sys(SysError::Symlink(_))),
            "{err:?}"
        );
        assert_eq!(fs.read(Path::new("/etc/shadow")).unwrap(), b"secret\n");
    }

    #[test]
    fn diff_is_none_when_content_and_owner_match() {
        let fs = FakeFs::new().with_file(PATH, "a = 1\n");
        let diff = resource("a = 1\n", root_owner()).diff(sys(&fs)).unwrap();
        assert_eq!(diff, None);
    }

    #[test]
    fn diff_shows_content_and_owner_changes() {
        let fs = FakeFs::new().with_file(PATH, "a = 1\nb = 2\n");
        let change = resource("a = 1\nb = 3\n", root_owner())
            .diff(sys(&fs))
            .unwrap()
            .unwrap();
        assert_eq!(change.summary, format!("update {PATH} (0644 0:0)"));
        assert_eq!(
            change.diff.as_deref(),
            Some("@@ -1,2 +1,2 @@\n a = 1\n-b = 2\n+b = 3\n")
        );

        let mode_only = FileOwner {
            mode: 0o600,
            ..root_owner()
        };
        let change = resource("a = 1\nb = 2\n", mode_only)
            .diff(sys(&fs))
            .unwrap()
            .unwrap();
        assert_eq!(
            change.summary,
            format!("update {PATH} (0644 0:0 -> 0600 0:0)")
        );
        assert_eq!(change.diff, None);
    }

    #[test]
    fn diff_refuses_a_symlink() {
        let fs = FakeFs::new()
            .with_file("/etc/real.conf", "a = 1\n")
            .with_symlink(PATH, "/etc/real.conf");
        let err = resource("a = 1\n", root_owner())
            .diff(sys(&fs))
            .unwrap_err();
        assert!(
            matches!(
                err,
                ResourceError::NotRegularFile {
                    kind: FileKind::Symlink,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn diff_refuses_a_non_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("etc/sysctl.d/90-vps-ready.conf")).unwrap();
        let fs = RealFs::new(dir.path());
        let err = resource("a = 1\n", root_owner())
            .diff(sys(&fs))
            .unwrap_err();
        assert!(
            matches!(
                err,
                ResourceError::NotRegularFile {
                    kind: FileKind::Dir,
                    ..
                }
            ),
            "{err:?}"
        );

        let fifo = dir.path().join("etc/fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let err = Resource::File(File {
            path: "/etc/fifo".into(),
            content: Vec::new(),
            owner: root_owner(),
            validate: None,
        })
        .diff(sys(&fs))
        .unwrap_err();
        assert!(
            matches!(
                err,
                ResourceError::NotRegularFile {
                    kind: FileKind::Other,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn diff_refuses_a_missing_parent() {
        let fs = FakeFs::new().with_file("/etc/hostname", "box\n");
        let err = resource("a = 1\n", root_owner())
            .diff(sys(&fs))
            .unwrap_err();
        assert!(
            matches!(err, ResourceError::MissingParent(ref p) if p == Path::new(PATH)),
            "{err:?}"
        );
    }

    /// snapshot, apply, restore on a tempdir; returns the restored bytes and mode.
    fn round_trip(before: Option<&str>) -> Option<(Vec<u8>, u32)> {
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join(PATH.trim_start_matches('/'));
        std::fs::create_dir_all(host.parent().unwrap()).unwrap();
        std::fs::create_dir_all(dir.path().join(TXN.trim_start_matches('/'))).unwrap();
        if let Some(before) = before {
            std::fs::write(&host, before).unwrap();
            std::fs::set_permissions(&host, std::os::unix::fs::PermissionsExt::from_mode(0o640))
                .unwrap();
        }
        let meta = std::fs::metadata(dir.path()).unwrap();
        let owner = FileOwner {
            mode: 0o644,
            uid: meta.uid(),
            gid: meta.gid(),
        };
        let fs = RealFs::new(dir.path());
        let sys = sys(&fs);
        let txn = Path::new(TXN);
        let file = resource("new = 1\n", owner);

        let backup = file.snapshot(sys, txn, 3).unwrap();
        let original = before.map(|_| FileCopy {
            mode: 0o640,
            uid: owner.uid,
            gid: owner.gid,
        });
        assert_eq!(
            backup,
            Backup::File {
                path: PATH.into(),
                n: 3,
                original,
            }
        );
        let copy = fs.read(&before_path(txn, 3)).ok();
        assert_eq!(copy.as_deref(), before.map(str::as_bytes));
        assert_eq!(fs.read(&after_path(txn, 3)).unwrap(), b"new = 1\n");

        file.apply(sys).unwrap();
        assert_eq!(file.diff(sys).unwrap(), None);

        restore(sys, txn, &backup).unwrap();
        // Restoring twice is harmless, as a resumed rollback may do.
        restore(sys, txn, &backup).unwrap();
        let meta = fs.metadata(Path::new(PATH)).ok()?;
        Some((fs.read(Path::new(PATH)).unwrap(), meta.mode))
    }

    #[test]
    fn round_trip_restores_an_existing_file() {
        assert_eq!(
            round_trip(Some("old = 1\n")),
            Some((b"old = 1\n".to_vec(), 0o640))
        );
    }

    #[test]
    fn round_trip_removes_a_created_file() {
        assert_eq!(round_trip(None), None);
    }

    #[test]
    fn round_trip_on_fake_fs_restores_the_owner() {
        let fs = FakeFs::new().with_file(PATH, "old = 1\n");
        let sys = sys(&fs);
        let txn = Path::new(TXN);
        let file = resource(
            "new = 1\n",
            FileOwner {
                mode: 0o600,
                uid: 1000,
                gid: 1000,
            },
        );
        let backup = file.snapshot(sys, txn, 1).unwrap();
        let copy = fs.metadata(&before_path(txn, 1)).unwrap();
        assert_eq!((copy.mode, copy.uid, copy.gid), (0o600, 0, 0));
        file.apply(sys).unwrap();
        restore(sys, txn, &backup).unwrap();
        let meta = fs.metadata(Path::new(PATH)).unwrap();
        assert_eq!(meta.owner(), root_owner());
        assert_eq!(fs.read(Path::new(PATH)).unwrap(), b"old = 1\n");
    }

    const APT: &str = "/etc/apt/apt.conf.d/52vps-ready";
    const APT_CONTENT: &[u8] = b"APT::Periodic::Enable \"1\";\n";

    fn apt_drop_in() -> Resource {
        Resource::File(File {
            path: APT.into(),
            content: APT_CONTENT.into(),
            owner: root_owner(),
            validate: Some(Validate::new("apt-config", ["-c", Validate::PATH, "dump"])),
        })
    }

    /// Snapshots [`apt_drop_in`] over an existing file with `runner`; returns
    /// the result, the commands run and the bytes of the `.after` copy.
    fn snapshot_validated(
        runner: &FakeRunner,
    ) -> (Result<Backup, ResourceError>, Vec<Cmd>, Vec<u8>) {
        let fs = FakeFs::new().with_file(APT, "old\n");
        let sys = Sys { fs: &fs, runner };
        let result = apt_drop_in().snapshot(sys, Path::new(TXN), 2);
        let after = fs.read(&after_path(Path::new(TXN), 2)).unwrap();
        (result, runner.calls(), after)
    }

    fn expected_validate() -> Vec<Cmd> {
        let after = after_path(Path::new(TXN), 2);
        vec![Cmd::new("apt-config").args(["-c", after.to_str().unwrap(), "dump"])]
    }

    #[test]
    fn validate_runs_on_the_after_copy() {
        let runner = FakeRunner::new().on("apt-config", ["-c"], Output::success(""));
        let (result, calls, after) = snapshot_validated(&runner);
        assert!(
            matches!(result, Ok(Backup::File { n: 2, .. })),
            "{result:?}"
        );
        assert_eq!(calls, expected_validate());
        assert_eq!(after, APT_CONTENT);
    }

    #[test]
    fn validate_failure_is_invalid() {
        let rejected = Output {
            status: 100,
            stdout: Vec::new(),
            stderr: b"E: Syntax error\n".to_vec(),
        };
        let runner = FakeRunner::new().on("apt-config", ["-c"], rejected);
        let (result, calls, after) = snapshot_validated(&runner);
        let err = result.unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "refusing to write {APT}: `apt-config` exited with status 100: E: Syntax error"
            )
        );
        assert_eq!(calls, expected_validate());
        assert_eq!(after, APT_CONTENT);
    }

    #[test]
    fn validate_that_cannot_run_fails_closed() {
        let (result, calls, after) = snapshot_validated(&FakeRunner::new());
        assert!(
            matches!(result, Err(ResourceError::Invalid { ref reason, .. }) if reason.starts_with("could not run")),
            "{result:?}"
        );
        assert_eq!(calls, expected_validate());
        assert_eq!(after, APT_CONTENT);
    }
}
