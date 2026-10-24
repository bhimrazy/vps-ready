//! The [`Directory`] resource.

use std::io;
use std::path::{Path, PathBuf};

use super::file::fmt_owner;
use super::{Backup, ResourceError};
use crate::sys::{FileKind, FileOwner, Sys, SysError};

/// A directory that must exist, such as `/etc/vps-ready` for the files of
/// vps-ready that no package's directory fits. A missing one is created
/// with `owner`, and rollback removes it again if it is empty by then; an
/// existing one is left as it is. Anything else at `path`, a symlink
/// included, is refused, and so is a missing parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    /// Absolute path.
    pub path: PathBuf,
    /// Mode and owner, if it is created.
    pub owner: FileOwner,
}

impl Directory {
    pub(super) fn diff(&self, sys: Sys) -> Result<Option<(String, Option<String>)>, ResourceError> {
        Ok((!self.exists(sys)?).then(|| {
            let summary = format!(
                "create directory {} ({})",
                self.path.display(),
                fmt_owner(self.owner)
            );
            (summary, None)
        }))
    }

    pub(super) fn snapshot(&self, sys: Sys) -> Result<Backup, ResourceError> {
        let created = !self.exists(sys)?;
        if created {
            let missing = || ResourceError::MissingParent(self.path.clone());
            let parent = self.path.parent().ok_or_else(missing)?;
            match sys.fs.metadata(parent) {
                Ok(meta) if meta.kind == FileKind::Dir => {}
                Ok(_) | Err(SysError::NotFound(_)) => return Err(missing()),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(Backup::Directory {
            path: self.path.clone(),
            created,
        })
    }

    pub(super) fn apply(&self, sys: Sys) -> Result<(), ResourceError> {
        if !self.exists(sys)? {
            sys.fs.create_dir(&self.path, self.owner)?;
        }
        Ok(())
    }

    fn exists(&self, sys: Sys) -> Result<bool, ResourceError> {
        current(sys, &self.path).map(|kind| kind.is_some())
    }
}

/// `Some(Dir)` for a directory, `None` if nothing is at `path`; anything
/// else is [`ResourceError::Unsafe`].
fn current(sys: Sys, path: &Path) -> Result<Option<FileKind>, ResourceError> {
    match sys.fs.metadata(path) {
        Ok(meta) if meta.kind == FileKind::Dir => Ok(Some(FileKind::Dir)),
        Ok(meta) => Err(ResourceError::Unsafe {
            path: path.to_path_buf(),
            reason: format!("not a directory ({:?})", meta.kind),
        }),
        Err(SysError::NotFound(_)) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Removes the directory if apply created it and it is empty; one that now
/// holds other files stays.
pub(super) fn restore(sys: Sys, path: &Path, created: bool) -> Result<(), ResourceError> {
    if !created {
        return Ok(());
    }
    match sys.fs.remove_dir(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                sys.fs.sync_dir(parent)?;
            }
            Ok(())
        }
        Err(SysError::NotFound(_)) => Ok(()),
        Err(SysError::Io { source, .. }) if source.kind() == io::ErrorKind::DirectoryNotEmpty => {
            tracing::warn!(dir = %path.display(), "left in place: it holds other files");
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// The safety check: a directory or nothing is at its path.
pub(crate) fn unchanged(sys: Sys, backup: &Backup) -> Result<bool, ResourceError> {
    let Backup::Directory { path, .. } = backup else {
        return Ok(false);
    };
    match current(sys, path) {
        Ok(_) => Ok(true),
        Err(ResourceError::Unsafe { .. }) => Ok(false),
        Err(e) => Err(e),
    }
}

/// How to restore `backup` by hand; `None` if apply did not create it.
pub(crate) fn by_hand(backup: &Backup) -> Option<String> {
    match backup {
        Backup::Directory {
            path,
            created: true,
        } => Some(format!("rmdir {}", path.display())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt as _;

    use super::super::{Resource, restore as restore_backup, test_sys as sys};
    use super::*;
    use crate::sys::fake::FakeFs;
    use crate::sys::{Fs, RealFs};

    const PATH: &str = "/etc/vps-ready";
    const TXN: &str = "/var/lib/vps-ready/txn/20261023T114246Z";

    fn dir(uid: u32, gid: u32) -> Resource {
        Resource::Directory(Directory {
            path: PATH.into(),
            owner: FileOwner {
                mode: 0o755,
                uid,
                gid,
            },
        })
    }

    #[test]
    fn creates_a_missing_directory_and_removes_it_on_restore() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("etc")).unwrap();
        let meta = std::fs::metadata(root.path()).unwrap();
        let fs = RealFs::new(root.path());
        let sys = sys(&fs);
        let resource = dir(meta.uid(), meta.gid());

        let change = resource.diff(sys).unwrap().unwrap();
        assert_eq!(change.id, format!("directory:{PATH}"));
        assert_eq!(
            change.summary,
            format!(
                "create directory {PATH} (0755 {}:{})",
                meta.uid(),
                meta.gid()
            )
        );
        let backup = resource.snapshot(sys, Path::new(TXN), 1).unwrap();
        assert_eq!(
            backup,
            Backup::Directory {
                path: PATH.into(),
                created: true
            }
        );
        assert!(!fs.exists(Path::new(PATH)));
        resource.apply(sys).unwrap();
        assert_eq!(resource.diff(sys).unwrap(), None);
        let made = fs.metadata(Path::new(PATH)).unwrap();
        assert_eq!((made.kind, made.mode), (FileKind::Dir, 0o755));
        assert!(unchanged(sys, &backup).unwrap());
        assert_eq!(by_hand(&backup).as_deref(), Some("rmdir /etc/vps-ready"));

        restore_backup(sys, Path::new(TXN), &backup).unwrap();
        assert!(!fs.exists(Path::new(PATH)));
        // Already gone: nothing to do.
        restore_backup(sys, Path::new(TXN), &backup).unwrap();
    }

    #[test]
    fn keeps_an_existing_or_non_empty_directory() {
        let owner = FileOwner {
            mode: 0o700,
            uid: 0,
            gid: 0,
        };
        let fs = FakeFs::new().with_dir(PATH, owner);
        let sys = sys(&fs);
        let resource = dir(0, 0);
        assert_eq!(resource.diff(sys).unwrap(), None);
        let backup = resource.snapshot(sys, Path::new(TXN), 1).unwrap();
        assert_eq!(by_hand(&backup), None);
        restore_backup(sys, Path::new(TXN), &backup).unwrap();
        assert!(fs.exists(Path::new(PATH)));

        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("etc/vps-ready")).unwrap();
        std::fs::write(root.path().join("etc/vps-ready/mine"), "x").unwrap();
        let fs = RealFs::new(root.path());
        let created = Backup::Directory {
            path: PATH.into(),
            created: true,
        };
        restore_backup(super::super::test_sys(&fs), Path::new(TXN), &created).unwrap();
        assert!(fs.exists(Path::new("/etc/vps-ready/mine")));
    }

    #[test]
    fn refuses_a_symlink_or_a_missing_parent() {
        let fs = FakeFs::new()
            .with_dir(
                "/srv",
                FileOwner {
                    mode: 0o755,
                    uid: 0,
                    gid: 0,
                },
            )
            .with_symlink(PATH, "/srv");
        let err = dir(0, 0).diff(sys(&fs)).unwrap_err();
        assert!(matches!(err, ResourceError::Unsafe { .. }), "{err:?}");
        let backup = Backup::Directory {
            path: PATH.into(),
            created: true,
        };
        assert!(!unchanged(sys(&fs), &backup).unwrap());

        let root = tempfile::tempdir().unwrap();
        let fs = RealFs::new(root.path());
        let err = dir(0, 0).snapshot(sys(&fs), Path::new(TXN), 1).unwrap_err();
        assert!(matches!(err, ResourceError::MissingParent(_)), "{err:?}");
    }
}
