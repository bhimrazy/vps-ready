//! The [`File`] resource.

use std::path::{Path, PathBuf};

use similar::TextDiff;

use super::{Backup, FileCopy, ResourceError, before_path};
use crate::sys::{FileKind, FileOwner, Sys, SysError};

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
}

impl File {
    /// The summary and unified diff of the change, or `None`.
    pub(super) fn diff(&self, sys: Sys) -> Result<Option<(String, Option<String>)>, ResourceError> {
        let Some(owner) = self.current(sys)? else {
            self.require_parent(sys)?;
            let summary = format!("create {} ({})", self.path.display(), fmt_owner(self.owner));
            return Ok(Some((summary, Some(unified(b"", &self.content)))));
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

    /// Records mode and owner, and copies the bytes to `files/<n>.before`.
    pub(super) fn snapshot(
        &self,
        sys: Sys,
        txn_dir: &Path,
        n: u32,
    ) -> Result<Backup, ResourceError> {
        let original = self.current(sys)?;
        if let Some(owner) = original {
            let bytes = sys.fs.read(&self.path)?;
            let files = txn_dir.join("files");
            sys.fs.create_dir_all(&files, 0o700)?;
            sys.fs.sync_dir(txn_dir)?;
            // 0600: the copy may hold secrets the original's mode protected.
            let copy = FileOwner {
                mode: 0o600,
                ..owner
            };
            sys.fs
                .write_atomic(&before_path(txn_dir, n), &bytes, copy)?;
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
        let is_dir = self
            .path
            .parent()
            .and_then(|p| sys.fs.metadata(p).ok())
            .is_some_and(|m| m.kind == FileKind::Dir);
        if is_dir {
            Ok(())
        } else {
            Err(ResourceError::MissingParent(self.path.clone()))
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
        // Already absent: apply never ran, or an earlier restore removed it.
        Ok(()) | Err(SysError::NotFound(_)) => {}
        Err(e) => return Err(e.into()),
    }
    if let Some(dir) = path.parent() {
        sys.fs.sync_dir(dir)?;
    }
    Ok(())
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
    use crate::sys::fake::FakeFs;
    use crate::sys::{Fs, RealFs};

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
}
