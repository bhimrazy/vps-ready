//! The state directory: its permission check, the lock and the transactions.

use std::path::{Path, PathBuf};

use super::journal::{self, Record};
use super::{EngineError, id};
use crate::sys::{FileKind, Fs, FsLock, SysError};

/// The state directory, after its permission check.
#[derive(Debug, Clone)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    /// Where the state lives on a real host.
    pub const DEFAULT: &str = "/var/lib/vps-ready";

    /// Creates `root` if missing, with mode `0700` for it and any missing
    /// parents, checks it as [`StateDir::open`] does, then creates
    /// `root/txn` (mode `0700`) if missing.
    ///
    /// # Errors
    ///
    /// [`EngineError::UnsafeStateDir`], or [`EngineError::Sys`] if a
    /// directory cannot be created or synced.
    pub fn create(
        fs: &dyn Fs,
        root: impl Into<PathBuf>,
        owner_uid: u32,
    ) -> Result<Self, EngineError> {
        let root = root.into();
        fs.create_dir_all(&root, 0o700)?;
        let dir = Self::open(fs, root, owner_uid)?;
        fs.create_dir_all(&dir.txn_root(), 0o700)?;
        fs.sync_dir(&dir.root)?;
        if let Some(parent) = dir.root.parent() {
            fs.sync_dir(parent)?;
        }
        Ok(dir)
    }

    /// Checks the existing directory `root` without following a symlink. It
    /// must be a directory owned by `owner_uid` (root, except in tests) and
    /// not writable by group or others.
    ///
    /// # Errors
    ///
    /// [`EngineError::UnsafeStateDir`] if the check fails; [`EngineError::Sys`]
    /// if `root` cannot be read.
    pub fn open(
        fs: &dyn Fs,
        root: impl Into<PathBuf>,
        owner_uid: u32,
    ) -> Result<Self, EngineError> {
        let root = root.into();
        let meta = fs.metadata(&root)?;
        let reason = match meta.kind {
            FileKind::Symlink => Some("it is a symlink".to_owned()),
            FileKind::File | FileKind::Other => Some("it is not a directory".to_owned()),
            FileKind::Dir if meta.uid != owner_uid => {
                Some(format!("it is owned by uid {}, not {owner_uid}", meta.uid))
            }
            FileKind::Dir if meta.mode & 0o022 != 0 => Some(format!(
                "it is writable by group or others (mode {:04o})",
                meta.mode
            )),
            FileKind::Dir => None,
        };
        match reason {
            Some(reason) => Err(EngineError::UnsafeStateDir {
                path: root.display().to_string(),
                reason,
            }),
            None => Ok(Self { root }),
        }
    }

    /// The directory itself.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn txn_root(&self) -> PathBuf {
        self.root.join("txn")
    }

    /// Takes `<root>/lock` without waiting. Held until the guard is dropped.
    ///
    /// # Errors
    ///
    /// [`EngineError::Busy`] if another process holds it, or [`EngineError::Sys`].
    pub fn lock(&self, fs: &dyn Fs) -> Result<FsLock, EngineError> {
        fs.try_lock(&self.root.join("lock")).map_err(|e| match e {
            SysError::Locked(_) => EngineError::Busy,
            e => EngineError::Sys(e),
        })
    }

    /// Creates `txn/<id>/`, its `files/` and an empty `journal.jsonl`, and
    /// syncs the journal, the transaction directory and `txn/`. The ID comes
    /// from `at` (Unix seconds), with a suffix if it is taken. Call it under
    /// [`StateDir::lock`].
    ///
    /// # Errors
    ///
    /// [`EngineError::Sys`].
    pub fn create_txn(&self, fs: &dyn Fs, at: u64) -> Result<Txn, EngineError> {
        let base = id::base_id(at);
        let txn_root = self.txn_root();
        let mut n = 1;
        let txn = loop {
            let id = id::nth_id(&base, n);
            let dir = txn_root.join(&id);
            if !fs.exists(&dir) {
                break Txn { id, dir };
            }
            n += 1;
        };
        fs.create_dir_all(&txn.files_dir(), 0o700)?;
        fs.append_sync(&txn.journal_path(), b"")?;
        fs.sync_dir(&txn.dir)?;
        fs.sync_dir(&txn_root)?;
        Ok(txn)
    }

    /// Every transaction, oldest first. Entries of `txn/` that are not a
    /// directory named by an ID are skipped with a warning.
    ///
    /// # Errors
    ///
    /// [`EngineError::Sys`] if `txn/` exists but it or an entry cannot be read.
    pub fn txns(&self, fs: &dyn Fs) -> Result<Vec<Txn>, EngineError> {
        let entries = match fs.read_dir(&self.txn_root()) {
            Ok(entries) => entries,
            Err(SysError::NotFound(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut txns = Vec::new();
        for dir in entries {
            let id = dir.file_name().and_then(|n| n.to_str()).map(str::to_owned);
            match id {
                Some(id)
                    if id::sort_key(&id).is_some() && fs.metadata(&dir)?.kind == FileKind::Dir =>
                {
                    txns.push(Txn { id, dir });
                }
                _ => {
                    tracing::warn!(path = %dir.display(), "skipping an entry that is not a transaction");
                }
            }
        }
        txns.sort_by(|a, b| id::sort_key(&a.id).cmp(&id::sort_key(&b.id)));
        Ok(txns)
    }

    /// The transactions that are [`journal::is_unfinished`], oldest first.
    ///
    /// # Errors
    ///
    /// [`EngineError`] if `txn/` or a journal cannot be read or parsed.
    pub fn unfinished(&self, fs: &dyn Fs) -> Result<Vec<Txn>, EngineError> {
        let mut unfinished = Vec::new();
        for txn in self.txns(fs)? {
            if journal::is_unfinished(&txn.read(fs)?) {
                unfinished.push(txn);
            }
        }
        Ok(unfinished)
    }
}

/// One transaction directory, `txn/<id>/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Txn {
    id: String,
    dir: PathBuf,
}

impl Txn {
    /// The ID, e.g. `20261023T114246Z` or `20261023T114246Z-2`.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// `txn/<id>/`.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// `txn/<id>/journal.jsonl`.
    #[must_use]
    pub fn journal_path(&self) -> PathBuf {
        self.dir.join("journal.jsonl")
    }

    /// `txn/<id>/files/`, for the copies of backed-up files.
    #[must_use]
    pub fn files_dir(&self) -> PathBuf {
        self.dir.join("files")
    }

    /// Appends `record` as one line and returns once it is on disk. Callers
    /// check [`journal::transition`] first; this does not.
    ///
    /// # Errors
    ///
    /// [`EngineError::Encode`] or [`EngineError::Sys`].
    pub fn append(&self, fs: &dyn Fs, record: &Record) -> Result<(), EngineError> {
        let mut line = serde_json::to_vec(record).map_err(EngineError::Encode)?;
        line.push(b'\n');
        fs.append_sync(&self.journal_path(), &line)?;
        Ok(())
    }

    /// Reads the journal, as [`journal::parse`] does. A missing journal has
    /// no records.
    ///
    /// # Errors
    ///
    /// [`EngineError::Sys`] if it cannot be read, [`EngineError::Journal`] if
    /// a line is bad.
    pub fn read(&self, fs: &dyn Fs) -> Result<Vec<Record>, EngineError> {
        let path = self.journal_path();
        match fs.read(&path) {
            Ok(bytes) => journal::parse(&path, &bytes),
            Err(SysError::NotFound(_)) => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    /// Reads the journal before appending to it again: a torn final line is
    /// removed from the file, so the next record starts on a line of its own.
    /// The kept bytes are rewritten as they were, unknown fields included.
    /// Call it under [`StateDir::lock`].
    ///
    /// # Errors
    ///
    /// [`EngineError::Sys`] if it cannot be read or rewritten,
    /// [`EngineError::Journal`] if a line is bad.
    pub fn resume(&self, fs: &dyn Fs) -> Result<Vec<Record>, EngineError> {
        let path = self.journal_path();
        let bytes = fs.read(&path)?;
        let clean = journal::clean_len(&bytes);
        if clean < bytes.len() {
            let owner = fs.metadata(&path)?.owner();
            fs.write_atomic(&path, &bytes[..clean], owner)?;
        }
        journal::parse(&path, &bytes[..clean])
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;
    use crate::engine::journal::{Event, TxnState};
    use crate::sys::RealFs;
    use crate::sys::fake::{FakeFs, Op};

    /// A tempdir as the root of a [`RealFs`], and the uid that owns it.
    fn real() -> (tempfile::TempDir, RealFs, u32) {
        let dir = tempfile::tempdir().unwrap();
        let uid = std::fs::metadata(dir.path()).unwrap().uid();
        let fs = RealFs::new(dir.path());
        (dir, fs, uid)
    }

    fn unsafe_reason(err: EngineError) -> String {
        match err {
            EngineError::UnsafeStateDir { reason, .. } => reason,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn creates_a_private_state_dir() {
        let (dir, fs, uid) = real();
        let state = StateDir::create(&fs, "/var/lib/vps-ready", uid).unwrap();
        assert_eq!(state.root(), Path::new("/var/lib/vps-ready"));
        for path in ["var/lib/vps-ready", "var/lib/vps-ready/txn"] {
            let meta = std::fs::metadata(dir.path().join(path)).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o700, "{path}");
        }
        // A second run accepts what the first created.
        StateDir::create(&fs, "/var/lib/vps-ready", uid).unwrap();
        StateDir::open(&fs, "/var/lib/vps-ready", uid).unwrap();
    }

    #[test]
    fn refuses_an_unsafe_state_dir() {
        let (dir, fs, uid) = real();
        let host = |p: &str| dir.path().join(p.trim_start_matches('/'));

        std::fs::create_dir(host("/real")).unwrap();
        std::os::unix::fs::symlink(host("/real"), host("/link")).unwrap();
        let reason = unsafe_reason(StateDir::open(&fs, "/link", uid).unwrap_err());
        assert_eq!(reason, "it is a symlink");
        // `create` follows the link to make the directory, then refuses it.
        let reason = unsafe_reason(StateDir::create(&fs, "/link", uid).unwrap_err());
        assert_eq!(reason, "it is a symlink");

        std::fs::write(host("/file"), "").unwrap();
        let reason = unsafe_reason(StateDir::open(&fs, "/file", uid).unwrap_err());
        assert_eq!(reason, "it is not a directory");

        let reason = unsafe_reason(StateDir::open(&fs, "/real", uid + 1).unwrap_err());
        assert_eq!(reason, format!("it is owned by uid {uid}, not {}", uid + 1));

        for mode in [0o720, 0o702, 0o777] {
            std::fs::set_permissions(host("/real"), std::fs::Permissions::from_mode(mode)).unwrap();
            let reason = unsafe_reason(StateDir::open(&fs, "/real", uid).unwrap_err());
            assert!(
                reason.starts_with("it is writable by group or others"),
                "{mode:o}"
            );
        }
        // Readable by others is allowed; only writes matter.
        std::fs::set_permissions(host("/real"), std::fs::Permissions::from_mode(0o755)).unwrap();
        StateDir::open(&fs, "/real", uid).unwrap();

        let err = StateDir::open(&fs, "/missing", uid).unwrap_err();
        assert!(
            matches!(err, EngineError::Sys(SysError::NotFound(_))),
            "{err:?}"
        );
    }

    #[test]
    fn a_second_lock_is_busy() {
        let (_dir, fs, uid) = real();
        let state = StateDir::create(&fs, "/state", uid).unwrap();
        let held = state.lock(&fs).unwrap();
        let err = state.lock(&fs).unwrap_err();
        assert_eq!(err.to_string(), "another vps-ready is running");
        drop(held);
        let _held = state.lock(&fs).unwrap();
    }

    #[test]
    fn creates_transactions_with_suffixes() {
        let (dir, fs, uid) = real();
        let state = StateDir::create(&fs, "/state", uid).unwrap();
        let at = 1_792_755_766;
        let ids: Vec<String> = (0..3)
            .map(|_| state.create_txn(&fs, at).unwrap().id().to_owned())
            .collect();
        assert_eq!(
            ids,
            [
                "20261023T114246Z",
                "20261023T114246Z-2",
                "20261023T114246Z-3"
            ]
        );
        let txn = dir.path().join("state/txn/20261023T114246Z-2");
        assert!(txn.join("files").is_dir());
        assert_eq!(std::fs::read(txn.join("journal.jsonl")).unwrap(), b"");
        assert_eq!(
            std::fs::metadata(txn.join("journal.jsonl"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn lists_transactions_in_time_order() {
        let fs = FakeFs::new();
        let state = StateDir::create(&fs, "/state", 0).unwrap();
        let at = 1_792_755_766;
        for _ in 0..10 {
            state.create_txn(&fs, at).unwrap();
        }
        state.create_txn(&fs, at + 1).unwrap();
        state.create_txn(&fs, at - 86_400).unwrap();
        fs.create_dir_all(Path::new("/state/txn/stray"), 0o700)
            .unwrap();

        let ids: Vec<String> = state
            .txns(&fs)
            .unwrap()
            .iter()
            .map(|t| t.id().to_owned())
            .collect();
        let mut expected = vec!["20261022T114246Z".to_owned(), "20261023T114246Z".to_owned()];
        expected.extend((2..=10).map(|n| format!("20261023T114246Z-{n}")));
        expected.push("20261023T114247Z".to_owned());
        assert_eq!(ids, expected);
    }

    #[test]
    fn journal_round_trip_and_unfinished() {
        let fs = FakeFs::new();
        let state = StateDir::create(&fs, "/state", 0).unwrap();
        assert!(state.txns(&fs).unwrap().is_empty());

        let done = state.create_txn(&fs, 1).unwrap();
        let open = state.create_txn(&fs, 2).unwrap();
        let empty = state.create_txn(&fs, 3).unwrap();
        let records = [
            Record {
                at: 1,
                event: Event::Begin {
                    version: "0.2.0".into(),
                    modules: vec!["kernel.sysctl".into()],
                },
            },
            Record {
                at: 1,
                event: Event::Applied {
                    resource: "sysctl:kernel.kptr_restrict".into(),
                },
            },
            Record {
                at: 2,
                event: Event::State {
                    state: TxnState::Applied,
                },
            },
        ];
        for r in &records {
            done.append(&fs, r).unwrap();
        }
        for r in &records[..2] {
            open.append(&fs, r).unwrap();
        }
        assert_eq!(done.read(&fs).unwrap(), records);
        assert_eq!(
            journal::replay(&done.read(&fs).unwrap()).unwrap(),
            TxnState::Applied
        );

        // An empty or missing journal changed nothing.
        fs.remove(&empty.journal_path()).unwrap();
        assert_eq!(empty.read(&fs).unwrap(), vec![]);
        assert_eq!(state.unfinished(&fs).unwrap(), vec![open.clone()]);

        // A torn line after the final `state` record is ignored.
        fs.append_sync(&done.journal_path(), b"{\"at\":3,\"ev")
            .unwrap();
        assert_eq!(done.read(&fs).unwrap(), records);
        assert!(!journal::is_unfinished(&done.read(&fs).unwrap()));
    }

    #[test]
    fn resume_removes_a_torn_line() {
        let fs = FakeFs::new();
        let state = StateDir::create(&fs, "/state", 0).unwrap();
        let txn = state.create_txn(&fs, 0).unwrap();
        let first =
            b"{\"at\":1,\"event\":\"begin\",\"version\":\"0.2.0\",\"modules\":[],\"new\":1}\n";
        fs.append_sync(&txn.journal_path(), first).unwrap();
        fs.append_sync(&txn.journal_path(), b"{\"at\":2,\"ev")
            .unwrap();

        assert_eq!(txn.resume(&fs).unwrap().len(), 1);
        // The kept line is rewritten byte for byte, unknown field included.
        assert_eq!(fs.read(&txn.journal_path()).unwrap(), first);
        assert_eq!(fs.metadata(&txn.journal_path()).unwrap().mode, 0o600);

        let applied = Record {
            at: 3,
            event: Event::Applied {
                resource: "r".into(),
            },
        };
        txn.append(&fs, &applied).unwrap();
        let records = txn.read(&fs).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1], applied);
        // Nothing torn: nothing rewritten.
        assert_eq!(txn.resume(&fs).unwrap(), records);
    }

    #[test]
    fn unreadable_transactions_are_errors_or_skipped() {
        let fs = FakeFs::new();
        let state = StateDir::create(&fs, "/state", 0).unwrap();
        let old = state.create_txn(&fs, 0).unwrap();
        fs.append_sync(
            &old.journal_path(),
            b"not json\n{\"at\":1,\"event\":\"applied\",\"resource\":\"r\"}\n",
        )
        .unwrap();
        let err = state.unfinished(&fs).unwrap_err();
        assert!(
            matches!(err, EngineError::Journal { line: 1, .. }),
            "{err:?}"
        );

        // A regular file named like a transaction is skipped.
        let fs = FakeFs::new().with_file("/state/txn/20261023T114246Z", "x");
        let state = StateDir::create(&fs, "/state", 0).unwrap();
        assert_eq!(state.txns(&fs).unwrap(), vec![]);
    }

    #[test]
    fn a_failed_append_is_an_error() {
        let fs = FakeFs::new().fail(Op::Append, 2);
        let state = StateDir::create(&fs, "/state", 0).unwrap();
        // The first append creates the empty journal.
        let txn = state.create_txn(&fs, 0).unwrap();
        let record = Record {
            at: 0,
            event: Event::Applied {
                resource: "r".into(),
            },
        };
        let err = txn.append(&fs, &record).unwrap_err();
        assert!(
            matches!(err, EngineError::Sys(SysError::Io { .. })),
            "{err:?}"
        );
    }
}
