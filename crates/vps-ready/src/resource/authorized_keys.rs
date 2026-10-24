//! The [`AuthorizedKeys`] resource.

use std::io;
use std::path::{Path, PathBuf};

use super::file::{fmt_owner, unified};
use super::user::account;
use super::{Backup, FileCopy, ResourceError, after_path, before_path, file};
use crate::sys::{FileKind, FileOwner, Sys, SysError};

/// Public key lines that `~/.ssh/authorized_keys` of `user` must contain.
/// Missing lines are appended; no line is ever removed.
///
/// The path comes from the user's passwd entry when the resource is used,
/// so the user may be created earlier in the same transaction. `~/.ssh`
/// (`0700`) and the file (`0600`) are created owned by the user and their
/// primary group. A symlink anywhere on the path is refused, and so is an
/// existing `~/.ssh` that sshd's `StrictModes` would reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedKeys {
    /// User name.
    pub user: String,
    /// Key lines, e.g. `ssh-ed25519 AAAAC3Nza... me@laptop`.
    pub keys: Vec<String>,
}

/// The file and its directory as they are now.
struct Target {
    path: PathBuf,
    /// Desired mode and owner of the file.
    owner: FileOwner,
    dir_exists: bool,
    /// Bytes, mode and owner; `None` if the file does not exist.
    current: Option<(Vec<u8>, FileOwner)>,
}

impl Target {
    fn bytes(&self) -> &[u8] {
        self.current.as_ref().map_or(&[], |(b, _)| b.as_slice())
    }
}

impl AuthorizedKeys {
    /// The summary and unified diff of the change, or `None`.
    pub(super) fn diff(&self, sys: Sys) -> Result<Option<(String, Option<String>)>, ResourceError> {
        self.check_keys()?;
        let Some(target) = self.target(sys)? else {
            // The user does not exist yet: a `User` earlier in the plan creates it.
            let (content, added) = self.desired(b"");
            return Ok((added > 0).then(|| {
                let user = &self.user;
                let summary = format!("create ~{user}/.ssh/authorized_keys (0600 {user}:{user})");
                (summary, Some(unified(b"", &content)))
            }));
        };
        let (content, added) = self.desired(target.bytes());
        let path = target.path.display();
        Ok(match &target.current {
            None if added == 0 => None,
            None => Some((
                format!("create {path} ({})", fmt_owner(target.owner)),
                Some(unified(b"", &content)),
            )),
            Some((_, owner)) if added == 0 && *owner == target.owner => None,
            Some((bytes, owner)) => {
                let owner = if *owner == target.owner {
                    fmt_owner(target.owner)
                } else {
                    format!("{} -> {}", fmt_owner(*owner), fmt_owner(target.owner))
                };
                let diff = (added > 0).then(|| unified(bytes, &content));
                Some((format!("update {path} ({owner})"), diff))
            }
        })
    }

    /// Records mode and owner, copies the current bytes to `files/<n>.before`
    /// and writes the desired bytes to `files/<n>.after`, as a `File` does.
    pub(super) fn snapshot(
        &self,
        sys: Sys,
        txn_dir: &Path,
        n: u32,
    ) -> Result<Backup, ResourceError> {
        self.check_keys()?;
        let target = self
            .target(sys)?
            .ok_or_else(|| ResourceError::NoSuchUser(self.user.clone()))?;
        let (content, _) = self.desired(target.bytes());
        sys.fs.create_dir_all(&txn_dir.join("files"), 0o700)?;
        sys.fs.sync_dir(txn_dir)?;
        if let Some((bytes, owner)) = &target.current {
            let copy = FileOwner {
                mode: 0o600,
                ..*owner
            };
            sys.fs.write_atomic(&before_path(txn_dir, n), bytes, copy)?;
        }
        sys.fs
            .write_atomic(&after_path(txn_dir, n), &content, target.owner)?;
        Ok(Backup::AuthorizedKeys {
            user: self.user.clone(),
            path: target.path,
            n,
            original: target.current.map(|(_, owner)| FileCopy::from(owner)),
            created_dir: !target.dir_exists,
        })
    }

    pub(super) fn apply(&self, sys: Sys) -> Result<(), ResourceError> {
        self.check_keys()?;
        let target = self
            .target(sys)?
            .ok_or_else(|| ResourceError::NoSuchUser(self.user.clone()))?;
        if !target.dir_exists
            && let Some(dir) = target.path.parent()
        {
            let owner = FileOwner {
                mode: 0o700,
                ..target.owner
            };
            sys.fs.create_dir(dir, owner)?;
        }
        let (content, _) = self.desired(target.bytes());
        Ok(sys.fs.write_atomic(&target.path, &content, target.owner)?)
    }

    fn check_keys(&self) -> Result<(), ResourceError> {
        for key in &self.keys {
            let reason = if key.trim().is_empty() {
                "it is empty"
            } else if key.contains(['\n', '\r', '\0']) {
                "it holds a line break"
            } else {
                continue;
            };
            return Err(ResourceError::InvalidKey {
                user: self.user.clone(),
                reason,
            });
        }
        Ok(())
    }

    /// The file and its directory; `None` if the user does not exist.
    fn target(&self, sys: Sys) -> Result<Option<Target>, ResourceError> {
        let Some(entry) = account(sys, &self.user)? else {
            return Ok(None);
        };
        let dir = entry.home.join(".ssh");
        let path = dir.join("authorized_keys");
        refuse_symlinks(sys, &path)?;
        let unsafe_dir = |reason: String| ResourceError::Unsafe {
            path: dir.clone(),
            reason,
        };
        let dir_exists = match sys.fs.metadata(&dir) {
            Ok(meta) if meta.kind != FileKind::Dir => {
                return Err(unsafe_dir("it is not a directory".to_owned()));
            }
            Ok(meta) if meta.uid != entry.uid => {
                return Err(unsafe_dir(format!(
                    "it is owned by uid {}, not {}",
                    meta.uid, entry.uid
                )));
            }
            // sshd's `StrictModes` would ignore the keys.
            Ok(meta) if meta.mode & 0o022 != 0 => {
                return Err(unsafe_dir(format!(
                    "mode {:04o} lets group or others write to it",
                    meta.mode
                )));
            }
            Ok(_) => true,
            Err(SysError::NotFound(_)) => {
                match sys.fs.metadata(&entry.home) {
                    Ok(meta) if meta.kind == FileKind::Dir => {}
                    Ok(_) | Err(SysError::NotFound(_)) => {
                        return Err(ResourceError::MissingParent(dir));
                    }
                    Err(e) => return Err(e.into()),
                }
                false
            }
            Err(e) => return Err(e.into()),
        };
        let current = match sys.fs.metadata(&path) {
            Ok(meta) if meta.kind == FileKind::File => Some((sys.fs.read(&path)?, meta.owner())),
            Ok(meta) => {
                return Err(ResourceError::NotRegularFile {
                    path,
                    kind: meta.kind,
                });
            }
            Err(SysError::NotFound(_)) => None,
            Err(e) => return Err(e.into()),
        };
        Ok(Some(Target {
            path,
            owner: FileOwner {
                mode: 0o600,
                uid: entry.uid,
                gid: entry.gid,
            },
            dir_exists,
            current,
        }))
    }

    /// `current` with the missing keys appended, and how many there were.
    fn desired(&self, current: &[u8]) -> (Vec<u8>, usize) {
        let mut have: Vec<String> = String::from_utf8_lossy(current)
            .lines()
            .map(identity)
            .collect();
        let mut out = current.to_vec();
        let mut added = 0;
        for key in &self.keys {
            let key = key.trim();
            let id = identity(key);
            if have.contains(&id) {
                continue;
            }
            if !out.is_empty() && !out.ends_with(b"\n") {
                out.push(b'\n');
            }
            out.extend_from_slice(key.as_bytes());
            out.push(b'\n');
            have.push(id);
            added += 1;
        }
        (out, added)
    }
}

/// What makes two lines the same key: type and base64 blob, so a different
/// comment does not count. A line with options is compared whole, since
/// its options restrict the key.
fn identity(line: &str) -> String {
    let line = line.trim();
    let mut fields = line.split_whitespace();
    match (fields.next(), fields.next()) {
        (Some(kind), Some(blob))
            if ["ssh-", "ecdsa-", "sk-"]
                .iter()
                .any(|p| kind.starts_with(p)) =>
        {
            format!("{kind} {blob}")
        }
        _ => line.to_owned(),
    }
}

/// Fails if `path` or any of its parents is a symlink. Parents below the
/// first missing one do not exist either, so they are not checked.
fn refuse_symlinks(sys: Sys, path: &Path) -> Result<(), ResourceError> {
    let mut parts: Vec<&Path> = path.ancestors().collect();
    parts.reverse();
    for part in parts {
        match sys.fs.metadata(part) {
            Ok(meta) if meta.kind == FileKind::Symlink => {
                return Err(ResourceError::Unsafe {
                    path: part.to_path_buf(),
                    reason: "it is a symlink".to_owned(),
                });
            }
            Ok(_) => {}
            Err(SysError::NotFound(_)) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Restores the file as a `File` does, then removes `~/.ssh` if apply
/// created it and it is empty; one that now holds other files stays.
pub(super) fn restore(
    sys: Sys,
    txn_dir: &Path,
    path: &Path,
    n: u32,
    original: Option<FileCopy>,
    created_dir: bool,
) -> Result<(), ResourceError> {
    refuse_symlinks(sys, path)?;
    file::restore(sys, txn_dir, path, n, original)?;
    let Some(dir) = path.parent().filter(|_| created_dir) else {
        return Ok(());
    };
    match sys.fs.remove_dir(dir) {
        Ok(()) => {
            if let Some(home) = dir.parent() {
                sys.fs.sync_dir(home)?;
            }
            Ok(())
        }
        Err(SysError::NotFound(_)) => Ok(()),
        Err(SysError::Io { source, .. }) if source.kind() == io::ErrorKind::DirectoryNotEmpty => {
            tracing::warn!(dir = %dir.display(), "left in place: it holds other files");
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// The safety check: whether the file equals `.after` or `.before` (absent
/// counts as `.before` if it did not exist). A symlink on its path counts
/// as changed.
pub(crate) fn unchanged(sys: Sys, txn_dir: &Path, backup: &Backup) -> Result<bool, ResourceError> {
    let Backup::AuthorizedKeys {
        path, n, original, ..
    } = backup
    else {
        return Ok(false);
    };
    match refuse_symlinks(sys, path) {
        Ok(()) => {}
        Err(ResourceError::Unsafe { .. }) => return Ok(false),
        Err(e) => return Err(e),
    }
    let current = match sys.fs.metadata(path) {
        Ok(meta) if meta.kind == FileKind::File => sys.fs.read(path)?,
        Ok(_) => return Ok(false),
        Err(SysError::NotFound(_)) => return Ok(original.is_none()),
        Err(e) => return Err(e.into()),
    };
    if current == sys.fs.read(&after_path(txn_dir, *n))? {
        return Ok(true);
    }
    Ok(original.is_some() && current == sys.fs.read(&before_path(txn_dir, *n))?)
}

/// How to restore `backup` by hand.
pub(crate) fn by_hand(txn_dir: &Path, backup: &Backup) -> Option<String> {
    let Backup::AuthorizedKeys {
        path,
        n,
        original,
        created_dir,
        ..
    } = backup
    else {
        return None;
    };
    Some(match original {
        Some(copy) => format!(
            "copy {} to {} (mode {:04o}, owner {}:{})",
            before_path(txn_dir, *n).display(),
            path.display(),
            copy.mode,
            copy.uid,
            copy.gid
        ),
        None => match path.parent().filter(|_| *created_dir) {
            Some(dir) => format!("remove {}, then rmdir {}", path.display(), dir.display()),
            None => format!("remove {}", path.display()),
        },
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::super::{Change, Resource, Reversibility, restore};
    use super::*;
    use crate::sys::fake::{FakeFs, FakeRunner};
    use crate::sys::{Cmd, Fs, Output, RealFs};

    const TXN: &str = "/var/lib/vps-ready/txn/20261023T114246Z";
    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtest me@laptop";
    const OTHER: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGother old@desk";

    fn keys(keys: &[&str]) -> Resource {
        Resource::AuthorizedKeys(AuthorizedKeys {
            user: "admin".into(),
            keys: keys.iter().map(|&k| k.to_owned()).collect(),
        })
    }

    /// `getent passwd admin` answering with `uid`, `gid` and `/home/admin`.
    fn runner(uid: u32, gid: u32) -> FakeRunner {
        let entry = format!("admin:x:{uid}:{gid}::/home/admin:/bin/bash\n");
        FakeRunner::new().on("getent", ["passwd", "admin"], Output::success(entry))
    }

    /// A tempdir with `/home/admin` and the uid and gid that own it, which
    /// a non-root test may set.
    fn real_home() -> (tempfile::TempDir, u32, u32) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("home/admin")).unwrap();
        std::fs::create_dir_all(dir.path().join(TXN.trim_start_matches('/'))).unwrap();
        let meta = std::fs::metadata(dir.path()).unwrap();
        (dir, meta.uid(), meta.gid())
    }

    #[test]
    fn diff_before_the_user_exists() {
        let fs = FakeFs::new();
        let runner = FakeRunner::new().on(
            "getent",
            ["passwd"],
            Output {
                status: 2,
                ..Output::default()
            },
        );
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        assert_eq!(
            keys(&[KEY]).diff(sys).unwrap(),
            Some(Change {
                id: "authorized-keys:admin".into(),
                summary: "create ~admin/.ssh/authorized_keys (0600 admin:admin)".into(),
                diff: Some(format!("@@ -0,0 +1 @@\n+{KEY}\n")),
                reversibility: Reversibility::Reversible,
            })
        );
        assert_eq!(keys(&[]).diff(sys).unwrap(), None);
        assert_eq!(
            runner.calls()[0],
            Cmd::new("getent").args(["passwd", "admin"])
        );
        let err = keys(&[KEY]).apply(sys).unwrap_err();
        assert!(matches!(err, ResourceError::NoSuchUser(_)), "{err:?}");
    }

    #[test]
    fn only_missing_keys_are_appended() {
        let restricted = format!("no-pty {KEY}");
        let current = format!("# keys\n{OTHER}\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtest");
        let resource = AuthorizedKeys {
            user: "admin".into(),
            keys: vec![
                KEY.into(),
                OTHER.into(),
                restricted.clone(),
                restricted.clone(),
            ],
        };
        // The same key with no comment is present; one with options is not.
        let (out, added) = resource.desired(current.as_bytes());
        assert_eq!(added, 1);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("{current}\n{restricted}\n")
        );
        let (_, added) = resource.desired(format!("{restricted}\n").as_bytes());
        assert_eq!(added, 2);
    }

    #[test]
    fn bad_key_lines_are_refused() {
        let fs = FakeFs::new();
        let runner = runner(1001, 1001);
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        for line in ["", "  ", "ssh-ed25519 AAAA\nssh-rsa BBBB"] {
            let err = keys(&[line]).diff(sys).unwrap_err();
            assert!(matches!(err, ResourceError::InvalidKey { .. }), "{err:?}");
        }
    }

    /// Diff, snapshot, apply, restore on a tempdir; returns the restored
    /// bytes and mode, if the file is there, and whether `~/.ssh` is.
    fn round_trip(before: Option<(&str, u32)>) -> (Option<(Vec<u8>, u32)>, bool) {
        let (dir, uid, gid) = real_home();
        let ssh = dir.path().join("home/admin/.ssh");
        if let Some((content, mode)) = before {
            std::fs::create_dir(&ssh).unwrap();
            std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
            let file = ssh.join("authorized_keys");
            std::fs::write(&file, content).unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let fs = RealFs::new(dir.path());
        let runner = runner(uid, gid);
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let txn = Path::new(TXN);
        let path = Path::new("/home/admin/.ssh/authorized_keys");
        let resource = keys(&[KEY]);

        assert!(resource.diff(sys).unwrap().is_some());
        let backup = resource.snapshot(sys, txn, 2).unwrap();
        assert_eq!(
            backup,
            Backup::AuthorizedKeys {
                user: "admin".into(),
                path: path.into(),
                n: 2,
                original: before.map(|(_, mode)| FileCopy { mode, uid, gid }),
                created_dir: before.is_none(),
            }
        );
        resource.apply(sys).unwrap();
        assert_eq!(resource.diff(sys).unwrap(), None);
        let file = fs.metadata(path).unwrap();
        let ssh_meta = fs.metadata(Path::new("/home/admin/.ssh")).unwrap();
        assert_eq!((file.mode, file.uid, file.gid), (0o600, uid, gid));
        assert_eq!(
            (ssh_meta.mode, ssh_meta.uid, ssh_meta.gid),
            (0o700, uid, gid)
        );
        assert_eq!(
            fs.read(path).unwrap(),
            fs.read(&after_path(txn, 2)).unwrap()
        );
        assert!(unchanged(sys, txn, &backup).unwrap());

        restore(sys, txn, &backup).unwrap();
        // Restoring twice is harmless, as a resumed rollback may do.
        restore(sys, txn, &backup).unwrap();
        assert!(unchanged(sys, txn, &backup).unwrap());
        let restored = fs
            .metadata(path)
            .ok()
            .map(|meta| (fs.read(path).unwrap(), meta.mode));
        (restored, ssh.exists())
    }

    #[test]
    fn round_trip_creates_and_removes_the_directory() {
        assert_eq!(round_trip(None), (None, false));
    }

    #[test]
    fn round_trip_restores_an_existing_file() {
        let before = format!("{OTHER}\n");
        assert_eq!(
            round_trip(Some((&before, 0o644))),
            (Some((before.into_bytes(), 0o644)), true)
        );
    }

    #[test]
    fn restore_keeps_a_created_directory_that_holds_other_files() {
        let (dir, uid, gid) = real_home();
        let fs = RealFs::new(dir.path());
        let runner = runner(uid, gid);
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let txn = Path::new(TXN);
        let backup = keys(&[KEY]).snapshot(sys, txn, 1).unwrap();
        keys(&[KEY]).apply(sys).unwrap();
        std::fs::write(dir.path().join("home/admin/.ssh/known_hosts"), "x\n").unwrap();
        restore(sys, txn, &backup).unwrap();
        assert!(!dir.path().join("home/admin/.ssh/authorized_keys").exists());
        assert!(dir.path().join("home/admin/.ssh/known_hosts").exists());
    }

    fn unsafe_path(err: ResourceError) -> (PathBuf, String) {
        match err {
            ResourceError::Unsafe { path, reason } => (path, reason),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn symlinked_ssh_dir_or_file_is_refused() {
        let (dir, uid, gid) = real_home();
        let host = dir.path();
        std::fs::create_dir_all(host.join("etc/ssh")).unwrap();
        std::os::unix::fs::symlink("/etc/ssh", host.join("home/admin/.ssh")).unwrap();
        let fs = RealFs::new(host);
        let runner = runner(uid, gid);
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let txn = Path::new(TXN);
        for result in [
            keys(&[KEY]).diff(sys).map(|_| ()),
            keys(&[KEY]).snapshot(sys, txn, 1).map(|_| ()),
            keys(&[KEY]).apply(sys),
        ] {
            let (path, reason) = unsafe_path(result.unwrap_err());
            assert_eq!(path, Path::new("/home/admin/.ssh"));
            assert_eq!(reason, "it is a symlink");
        }
        assert!(!host.join("etc/ssh/authorized_keys").exists());

        std::fs::remove_file(host.join("home/admin/.ssh")).unwrap();
        std::fs::create_dir(host.join("home/admin/.ssh")).unwrap();
        std::fs::set_permissions(
            host.join("home/admin/.ssh"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::write(host.join("etc/shadow"), "secret\n").unwrap();
        std::os::unix::fs::symlink("/etc/shadow", host.join("home/admin/.ssh/authorized_keys"))
            .unwrap();
        let (path, _) = unsafe_path(keys(&[KEY]).apply(sys).unwrap_err());
        assert_eq!(path, Path::new("/home/admin/.ssh/authorized_keys"));
        assert_eq!(std::fs::read(host.join("etc/shadow")).unwrap(), b"secret\n");
    }

    #[test]
    fn symlinked_home_is_refused() {
        let fs = FakeFs::new()
            .with_file("/srv/admin/.profile", "")
            .with_symlink("/home/admin", "/srv/admin");
        let runner = runner(1001, 1001);
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let (path, _) = unsafe_path(keys(&[KEY]).diff(sys).unwrap_err());
        assert_eq!(path, Path::new("/home/admin"));
    }

    #[test]
    fn restore_and_unchanged_refuse_a_path_that_became_a_symlink() {
        let txn = Path::new(TXN);
        let fs = FakeFs::new()
            .with_file(after_path(txn, 1), format!("{KEY}\n"))
            .with_file("/etc/ssh/authorized_keys", format!("{KEY}\n"))
            .with_symlink("/home/admin/.ssh", "/etc/ssh");
        let runner = FakeRunner::new();
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let backup = Backup::AuthorizedKeys {
            user: "admin".into(),
            path: "/home/admin/.ssh/authorized_keys".into(),
            n: 1,
            original: None,
            created_dir: true,
        };
        assert!(!unchanged(sys, txn, &backup).unwrap());
        let err = restore(sys, txn, &backup).unwrap_err();
        assert!(matches!(err, ResourceError::Unsafe { .. }), "{err:?}");
        assert!(fs.exists(Path::new("/etc/ssh/authorized_keys")));
    }

    #[test]
    fn an_ssh_dir_sshd_would_ignore_is_refused() {
        let owner = |mode, uid| FileOwner {
            mode,
            uid,
            gid: 1001,
        };
        let runner = runner(1001, 1001);
        let reason = |fs: &FakeFs| {
            let sys = Sys {
                fs,
                runner: &runner,
            };
            unsafe_path(keys(&[KEY]).diff(sys).unwrap_err()).1
        };
        let home = || FakeFs::new().with_dir("/home/admin", owner(0o750, 1001));
        let fs = home().with_dir("/home/admin/.ssh", owner(0o700, 0));
        assert_eq!(reason(&fs), "it is owned by uid 0, not 1001");
        let fs = home().with_dir("/home/admin/.ssh", owner(0o777, 1001));
        assert_eq!(reason(&fs), "mode 0777 lets group or others write to it");
        let fs = home().with_file("/home/admin/.ssh", "");
        assert_eq!(reason(&fs), "it is not a directory");
    }

    #[test]
    fn a_missing_home_is_refused() {
        let fs = FakeFs::new().with_file("/etc/hostname", "box\n");
        let runner = runner(1001, 1001);
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let err = keys(&[KEY]).diff(sys).unwrap_err();
        assert!(matches!(err, ResourceError::MissingParent(_)), "{err:?}");
    }

    #[test]
    fn diff_corrects_the_owner_and_mode() {
        let fs = FakeFs::new()
            .with_dir(
                "/home/admin/.ssh",
                FileOwner {
                    mode: 0o700,
                    uid: 1001,
                    gid: 1001,
                },
            )
            .with_file("/home/admin/.ssh/authorized_keys", format!("{KEY}\n"));
        let runner = runner(1001, 1001);
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let change = keys(&[KEY]).diff(sys).unwrap().unwrap();
        assert_eq!(
            change.summary,
            "update /home/admin/.ssh/authorized_keys (0644 0:0 -> 0600 1001:1001)"
        );
        assert_eq!(change.diff, None);
    }

    #[test]
    fn unchanged_and_by_hand() {
        let txn = Path::new(TXN);
        let path = "/home/admin/.ssh/authorized_keys";
        let fs = FakeFs::new()
            .with_file(before_path(txn, 1), format!("{OTHER}\n"))
            .with_file(after_path(txn, 1), format!("{OTHER}\n{KEY}\n"))
            .with_file(path, format!("{OTHER}\n{KEY}\nssh-ed25519 AAAAadded\n"));
        let runner = FakeRunner::new();
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let existed = Backup::AuthorizedKeys {
            user: "admin".into(),
            path: path.into(),
            n: 1,
            original: Some(FileCopy {
                mode: 0o600,
                uid: 1001,
                gid: 1001,
            }),
            created_dir: false,
        };
        assert!(!unchanged(sys, txn, &existed).unwrap());
        assert_eq!(
            by_hand(txn, &existed).unwrap(),
            format!(
                "copy {} to {path} (mode 0600, owner 1001:1001)",
                before_path(txn, 1).display()
            )
        );
        fs.remove(Path::new(path)).unwrap();
        assert!(!unchanged(sys, txn, &existed).unwrap());
        let created = Backup::AuthorizedKeys {
            user: "admin".into(),
            path: path.into(),
            n: 1,
            original: None,
            created_dir: true,
        };
        assert!(unchanged(sys, txn, &created).unwrap());
        assert_eq!(
            by_hand(txn, &created).unwrap(),
            format!("remove {path}, then rmdir /home/admin/.ssh")
        );
    }
}
