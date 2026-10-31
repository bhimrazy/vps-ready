//! The [`AuthorizedKeys`] resource.

use std::io;
use std::path::{Path, PathBuf};

use super::file::{fmt_owner, unified};
use super::user::lookup;
use super::{Backup, FileCopy, ResourceError, after_path, before_path, file};
use crate::sys::{FileKind, FileMeta, FileOwner, Sys, SysError};

/// Public key lines that `~/.ssh/authorized_keys` of `user` must contain.
/// Missing lines are appended and no line is removed, unless `exact`.
///
/// The path comes from the user's passwd entry when the resource is used,
/// so the user may be created earlier in the same transaction. `~/.ssh`
/// (`0700`) and the file (`0600`) are created owned by the user and their
/// primary group. A symlink anywhere on the path is refused, and so is an
/// existing `~/.ssh` that sshd's `StrictModes` would reject, or an existing
/// file owned by another user, with more than one link or with a setuid,
/// setgid or sticky bit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedKeys {
    /// User name.
    pub user: String,
    /// Key lines, e.g. `ssh-ed25519 AAAAC3Nza... me@laptop`.
    pub keys: Vec<String>,
    /// The file holds exactly `keys`, in order, and every other line is
    /// removed: for keys whose options must not be bypassed by an earlier
    /// line, and that must go when they are taken out of the profile.
    pub exact: bool,
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
            let (content, changed) = self.desired(b"");
            return Ok(changed.then(|| {
                let user = &self.user;
                let summary = format!("create ~{user}/.ssh/authorized_keys (0600 {user}:{user})");
                (summary, Some(unified(b"", &content)))
            }));
        };
        let (content, changed) = self.desired(target.bytes());
        let path = target.path.display();
        Ok(match &target.current {
            None if !changed => None,
            None => Some((
                format!("create {path} ({})", fmt_owner(target.owner)),
                Some(unified(b"", &content)),
            )),
            Some((_, owner)) if !changed && *owner == target.owner => None,
            Some((bytes, owner)) => {
                let owner = if *owner == target.owner {
                    fmt_owner(target.owner)
                } else {
                    format!("{} -> {}", fmt_owner(*owner), fmt_owner(target.owner))
                };
                let diff = changed.then(|| unified(bytes, &content));
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
        let Some(entry) = lookup(sys, &self.user)? else {
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
            // As sshd's `StrictModes`, which would ignore the keys otherwise.
            Ok(meta) if meta.uid != entry.uid && meta.uid != 0 => {
                return Err(unsafe_dir(format!(
                    "it is owned by uid {}, not {} or root",
                    meta.uid, entry.uid
                )));
            }
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
        // The owner's swap of the file after the checks above cannot make
        // root read another file: the metadata checked is the fd's.
        let current = match sys.fs.read_nofollow(&path) {
            Ok((bytes, meta)) => {
                check_file(&path, &meta, entry.uid)?;
                Some((bytes, meta.owner()))
            }
            Err(SysError::NotFound(_)) => None,
            Err(SysError::NotRegular { kind, .. }) => {
                return Err(ResourceError::NotRegularFile { path, kind });
            }
            Err(SysError::Symlink(_)) => {
                return Err(ResourceError::Unsafe {
                    path,
                    reason: "it is a symlink".to_owned(),
                });
            }
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

    /// The desired bytes, and whether they differ from `current`: with
    /// `exact`, the keys alone; otherwise `current` with the missing keys
    /// appended.
    fn desired(&self, current: &[u8]) -> (Vec<u8>, bool) {
        if self.exact {
            let mut seen = Vec::new();
            let mut out = Vec::new();
            for key in self.keys.iter().map(|k| k.trim()) {
                let id = identity(key);
                if !seen.contains(&id) {
                    out.extend_from_slice(key.as_bytes());
                    out.push(b'\n');
                    seen.push(id);
                }
            }
            let changed = out != current;
            return (out, changed);
        }
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
        (out, added > 0)
    }
}

/// Whether `line` lets its user log in to a normal shell: a key, plain or
/// with options other than `restrict` and `command=`, which limit it to no
/// terminal or one program. `from=`, `expiry-time=` and the like still
/// count, so an admin key limited to some addresses is an admin's.
pub(crate) fn gives_a_shell(line: &str) -> bool {
    let line = line.trim();
    if is_plain_key(line) {
        return true;
    }
    // The options end at the first space outside quotes; a quoted value
    // may hold `\"`.
    let (mut quoted, mut escaped) = (false, false);
    let mut names = Vec::new();
    let mut start = 0;
    let mut end = line.len();
    for (i, c) in line.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                names.push(&line[start..i]);
                start = i + 1;
            }
            ' ' | '\t' if !quoted => {
                end = i;
                break;
            }
            _ => {}
        }
    }
    names.push(&line[start..end]);
    is_plain_key(&line[end..])
        && !names.iter().any(|o| {
            let name = o.split('=').next().unwrap_or_default();
            name.eq_ignore_ascii_case("restrict") || name.eq_ignore_ascii_case("command")
        })
}

/// Whether `line` starts with a key type rather than options, and has a key
/// after it.
pub(crate) fn is_plain_key(line: &str) -> bool {
    let mut fields = line.split_whitespace();
    fields.next().is_some_and(|kind| {
        ["ssh-", "ecdsa-", "sk-"]
            .iter()
            .any(|p| kind.starts_with(p))
    }) && fields.next().is_some()
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

/// Refuses an existing file that root should not copy or rewrite for `uid`.
/// A hard link may be another file's other name, e.g. `/etc/shadow`'s.
fn check_file(path: &Path, meta: &FileMeta, uid: u32) -> Result<(), ResourceError> {
    let reason = if meta.uid != uid && meta.uid != 0 {
        format!("it is owned by uid {}, not {uid} or root", meta.uid)
    } else if meta.nlink > 1 {
        format!("it has {} hard links", meta.nlink)
    } else if meta.mode & 0o7000 != 0 {
        format!("mode {:04o} has a setuid, setgid or sticky bit", meta.mode)
    } else {
        return Ok(());
    };
    Err(ResourceError::Unsafe {
        path: path.to_path_buf(),
        reason,
    })
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
    user: &str,
    path: &Path,
    n: u32,
    original: Option<FileCopy>,
    created_dir: bool,
) -> Result<(), ResourceError> {
    refuse_symlinks(sys, path)?;
    let original = original.map(|copy| restored(sys, user, copy)).transpose()?;
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

/// The mode and owner a restored file gets: never more than `0644`, and
/// root's or else the user's from passwd, whatever the journal records.
fn restored(sys: Sys, user: &str, copy: FileCopy) -> Result<FileCopy, ResourceError> {
    let mode = copy.mode & 0o644;
    if copy.uid == 0 {
        return Ok(FileCopy { mode, ..copy });
    }
    let entry = lookup(sys, user)?.ok_or_else(|| ResourceError::NoSuchUser(user.to_owned()))?;
    Ok(FileCopy {
        mode,
        uid: entry.uid,
        gid: entry.gid,
    })
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
    let current = match sys.fs.read_nofollow(path) {
        Ok((bytes, _)) => bytes,
        Err(SysError::NotFound(_)) => return Ok(original.is_none()),
        Err(SysError::Symlink(_) | SysError::NotRegular { .. }) => return Ok(false),
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
        user,
        path,
        n,
        original,
        created_dir,
    } = backup
    else {
        return None;
    };
    Some(match original {
        Some(copy) => {
            // The owner `restore` sets.
            let owner = if copy.uid == 0 {
                format!("0:{}", copy.gid)
            } else {
                format!("{user} and their primary group")
            };
            format!(
                "copy {} to {} (mode {:04o}, owner {owner})",
                before_path(txn_dir, *n).display(),
                path.display(),
                copy.mode & 0o644,
            )
        }
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
            exact: false,
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
            exact: false,
            keys: vec![
                KEY.into(),
                OTHER.into(),
                restricted.clone(),
                restricted.clone(),
            ],
        };
        // The same key with no comment is present; one with options is not.
        let (out, changed) = resource.desired(current.as_bytes());
        assert!(changed);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("{current}\n{restricted}\n")
        );
        let (out, changed) = resource.desired(format!("{restricted}\n").as_bytes());
        assert!(changed);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("{restricted}\n{KEY}\n{OTHER}\n")
        );
        let (_, changed) = resource.desired(format!("{KEY}\n{OTHER}\n{restricted}\n").as_bytes());
        assert!(!changed);
    }

    #[test]
    fn exact_keys_replace_every_other_line() {
        let restricted = format!("restrict {KEY}");
        let resource = AuthorizedKeys {
            user: "admin".into(),
            keys: vec![restricted.clone(), format!(" {OTHER} ")],
            exact: true,
        };
        let want = format!("{restricted}\n{OTHER}\n");
        // An earlier unrestricted line for the same key goes, and so does
        // a comment.
        let (out, changed) = resource.desired(format!("# keys\n{KEY}\n{OTHER}\n").as_bytes());
        assert!(changed);
        assert_eq!(String::from_utf8(out).unwrap(), want);
        let (_, changed) = resource.desired(want.as_bytes());
        assert!(!changed);
        // A key taken out of the list is removed.
        let one = AuthorizedKeys {
            keys: vec![restricted.clone()],
            ..resource
        };
        let (out, changed) = one.desired(want.as_bytes());
        assert!(changed);
        assert_eq!(String::from_utf8(out).unwrap(), format!("{restricted}\n"));
        // A key given twice, or again with another comment, is written once.
        let twice = AuthorizedKeys {
            keys: vec![
                restricted.clone(),
                OTHER.into(),
                restricted.clone(),
                format!("{} new@desk", OTHER.rsplit_once(' ').unwrap().0),
            ],
            ..one
        };
        let (out, _) = twice.desired(b"");
        assert_eq!(String::from_utf8(out).unwrap(), want);
    }

    #[test]
    fn options_that_keep_a_shell() {
        for line in [
            KEY.to_owned(),
            format!("from=\"203.0.113.0/24\" {KEY}"),
            format!("no-agent-forwarding,expiry-time=\"20991231\" {KEY}"),
            format!("environment=\"A=restrict\" {KEY}"),
        ] {
            assert!(gives_a_shell(&line), "{line}");
        }
        for line in [
            format!("restrict {KEY}"),
            format!("restrict,command=\"/usr/local/bin/deploy-app\" {KEY}"),
            format!("no-pty,Command=\"echo \\\"a, b\\\"\" {KEY}"),
            "from=\"203.0.113.1\"".to_owned(),
            "not a key".to_owned(),
        ] {
            assert!(!gives_a_shell(&line), "{line}");
        }
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
            keys(&[KEY]).apply(sys).map(|_| ()),
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

    /// A tempdir with `/home/admin/.ssh` (`0700`), where `make` creates
    /// `authorized_keys` from its host path.
    fn real_ssh(make: impl FnOnce(&Path)) -> (tempfile::TempDir, RealFs, FakeRunner) {
        let (dir, uid, gid) = real_home();
        let ssh = dir.path().join("home/admin/.ssh");
        std::fs::create_dir(&ssh).unwrap();
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
        make(&ssh.join("authorized_keys"));
        let fs = RealFs::new(dir.path());
        (dir, fs, runner(uid, gid))
    }

    #[test]
    fn a_hard_linked_file_is_refused() {
        let (dir, fs, runner) = real_ssh(|keys| {
            let shadow = keys.ancestors().nth(4).unwrap().join("etc/shadow");
            std::fs::create_dir_all(shadow.parent().unwrap()).unwrap();
            std::fs::write(&shadow, "secret\n").unwrap();
            std::fs::hard_link(&shadow, keys).unwrap();
        });
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let txn = Path::new(TXN);
        for result in [
            keys(&[KEY]).diff(sys).map(|_| ()),
            keys(&[KEY]).snapshot(sys, txn, 1).map(|_| ()),
            keys(&[KEY]).apply(sys).map(|_| ()),
        ] {
            let (path, reason) = unsafe_path(result.unwrap_err());
            assert_eq!(path, Path::new("/home/admin/.ssh/authorized_keys"));
            assert_eq!(reason, "it has 2 hard links");
        }
        assert_eq!(
            std::fs::read(dir.path().join("etc/shadow")).unwrap(),
            b"secret\n"
        );
    }

    #[test]
    fn a_fifo_is_refused_without_waiting() {
        let (_dir, fs, runner) = real_ssh(|keys| {
            let out = std::process::Command::new("mkfifo")
                .arg(keys)
                .output()
                .unwrap();
            assert!(out.status.success(), "{out:?}");
        });
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let err = keys(&[KEY]).diff(sys).unwrap_err();
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
        let backup = Backup::AuthorizedKeys {
            user: "admin".into(),
            path: "/home/admin/.ssh/authorized_keys".into(),
            n: 1,
            original: None,
            created_dir: false,
        };
        assert!(!unchanged(sys, Path::new(TXN), &backup).unwrap());
    }

    #[test]
    fn a_file_of_another_user_or_with_a_setuid_bit_is_refused() {
        let path = Path::new("/home/admin/.ssh/authorized_keys");
        let runner = runner(1001, 1001);
        let reason = |mode, uid| {
            let fs = FakeFs::new().with_dir(
                "/home/admin/.ssh",
                FileOwner {
                    mode: 0o700,
                    uid: 1001,
                    gid: 1001,
                },
            );
            let owner = FileOwner {
                mode,
                uid,
                gid: 1001,
            };
            fs.write_atomic(path, format!("{KEY}\n").as_bytes(), owner)
                .unwrap();
            let sys = Sys {
                fs: &fs,
                runner: &runner,
            };
            unsafe_path(keys(&[KEY]).diff(sys).unwrap_err()).1
        };
        assert_eq!(
            reason(0o600, 1002),
            "it is owned by uid 1002, not 1001 or root"
        );
        assert_eq!(
            reason(0o4600, 1001),
            "mode 4600 has a setuid, setgid or sticky bit"
        );
    }

    /// Reads like `FakeFs`, but its `metadata` of `swapped` answers as for
    /// a regular file of the user's: what a check saw before the user put
    /// a symlink in its place.
    struct Swapped {
        inner: FakeFs,
        swapped: &'static str,
    }

    impl Fs for Swapped {
        fn read(&self, path: &Path) -> Result<Vec<u8>, SysError> {
            self.inner.read(path)
        }
        fn read_nofollow(&self, path: &Path) -> Result<(Vec<u8>, FileMeta), SysError> {
            self.inner.read_nofollow(path)
        }
        fn exists(&self, path: &Path) -> bool {
            self.inner.exists(path)
        }
        fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>, SysError> {
            self.inner.read_dir(path)
        }
        fn read_link(&self, path: &Path) -> Result<PathBuf, SysError> {
            self.inner.read_link(path)
        }
        fn metadata(&self, path: &Path) -> Result<FileMeta, SysError> {
            if path != Path::new(self.swapped) {
                return self.inner.metadata(path);
            }
            Ok(FileMeta {
                kind: FileKind::File,
                len: 0,
                mode: 0o600,
                uid: 1001,
                gid: 1001,
                nlink: 1,
            })
        }
        fn write_atomic(
            &self,
            path: &Path,
            bytes: &[u8],
            owner: FileOwner,
        ) -> Result<(), SysError> {
            self.inner.write_atomic(path, bytes, owner)
        }
        fn write(&self, path: &Path, bytes: &[u8]) -> Result<(), SysError> {
            self.inner.write(path, bytes)
        }
        fn append_sync(&self, path: &Path, bytes: &[u8]) -> Result<(), SysError> {
            self.inner.append_sync(path, bytes)
        }
        fn remove(&self, path: &Path) -> Result<(), SysError> {
            self.inner.remove(path)
        }
        fn create_dir_all(&self, path: &Path, mode: u32) -> Result<(), SysError> {
            self.inner.create_dir_all(path, mode)
        }
        fn create_dir(&self, path: &Path, owner: FileOwner) -> Result<(), SysError> {
            self.inner.create_dir(path, owner)
        }
        fn remove_dir(&self, path: &Path) -> Result<(), SysError> {
            self.inner.remove_dir(path)
        }
        fn sync_dir(&self, path: &Path) -> Result<(), SysError> {
            self.inner.sync_dir(path)
        }
        fn try_lock(&self, path: &Path) -> Result<crate::sys::FsLock, SysError> {
            self.inner.try_lock(path)
        }
    }

    #[test]
    fn a_swap_after_the_checks_cannot_change_what_is_read() {
        let txn = Path::new(TXN);
        let path = "/home/admin/.ssh/authorized_keys";
        let fs = Swapped {
            inner: FakeFs::new()
                .with_dir(
                    "/home/admin/.ssh",
                    FileOwner {
                        mode: 0o700,
                        uid: 1001,
                        gid: 1001,
                    },
                )
                .with_file("/etc/shadow", "secret\n")
                .with_file(after_path(txn, 1), "secret\n")
                .with_symlink(path, "/etc/shadow"),
            swapped: path,
        };
        let runner = runner(1001, 1001);
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let (at, reason) = unsafe_path(keys(&[KEY]).diff(sys).unwrap_err());
        assert_eq!(at, Path::new(path));
        assert_eq!(reason, "it is a symlink");
        let backup = Backup::AuthorizedKeys {
            user: "admin".into(),
            path: path.into(),
            n: 1,
            original: None,
            created_dir: false,
        };
        assert!(!unchanged(sys, txn, &backup).unwrap());
    }

    #[test]
    fn restore_sets_no_special_bits_and_the_passwd_owner() {
        let txn = Path::new(TXN);
        let path = Path::new("/home/admin/.ssh/authorized_keys");
        let fs = FakeFs::new()
            .with_file(before_path(txn, 1), format!("{OTHER}\n"))
            .with_file(path, format!("{OTHER}\n{KEY}\n"));
        let runner = runner(1001, 1001);
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let backup = |mode, uid| Backup::AuthorizedKeys {
            user: "admin".into(),
            path: path.into(),
            n: 1,
            original: Some(FileCopy { mode, uid, gid: 42 }),
            created_dir: false,
        };
        let restored = |b: &Backup| {
            restore(sys, txn, b).unwrap();
            let meta = fs.metadata(path).unwrap();
            (meta.mode, meta.uid, meta.gid)
        };
        assert_eq!(restored(&backup(0o6755, 1002)), (0o644, 1001, 1001));
        assert_eq!(restored(&backup(0o4600, 0)), (0o600, 0, 42));
        assert_eq!(fs.read(path).unwrap(), format!("{OTHER}\n").as_bytes());
        let step = by_hand(txn, &backup(0o6755, 1001)).unwrap();
        assert!(
            step.ends_with("(mode 0644, owner admin and their primary group)"),
            "{step}"
        );
        let step = by_hand(txn, &backup(0o4600, 0)).unwrap();
        assert!(step.ends_with("(mode 0600, owner 0:42)"), "{step}");
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
        let fs = home().with_dir("/home/admin/.ssh", owner(0o700, 1002));
        assert_eq!(reason(&fs), "it is owned by uid 1002, not 1001 or root");
        // sshd accepts a `~/.ssh` owned by root.
        let fs = home().with_dir("/home/admin/.ssh", owner(0o755, 0));
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        assert!(keys(&[KEY]).diff(sys).unwrap().is_some());
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
                "copy {} to {path} (mode 0600, owner admin and their primary group)",
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
