//! In-memory fakes for [`Runner`] and [`Fs`], for unit and integration tests.
//!
//! Compiled under `cfg(test)` and with the `testing` feature.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::{Cmd, FileKind, FileMeta, FileOwner, Fs, FsLock, Output, Runner, SysError};

/// A scripted [`Runner`]. Each rule matches a program plus a prefix of its
/// arguments; the first matching rule wins. Unmatched commands fail with
/// [`SysError::NotFound`]. Every call is recorded.
#[derive(Debug, Default)]
pub struct FakeRunner {
    rules: Vec<(String, Vec<String>, Output)>,
    calls: Mutex<Vec<Cmd>>,
}

impl FakeRunner {
    /// A runner with no rules.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Answers `program args_prefix...` with `output`.
    #[must_use]
    pub fn on<I, S>(mut self, program: &str, args_prefix: I, output: Output) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let prefix = args_prefix.into_iter().map(Into::into).collect();
        self.rules.push((program.to_owned(), prefix, output));
        self
    }

    /// Loads a host fixture written by `test/capture-host-fixtures.sh`.
    ///
    /// `dir/commands.tsv` lists `name`, exit code and the exact argv, one
    /// command per line, tab-separated; stdout and stderr live in
    /// `dir/cmd/<name>.stdout` and `.stderr` (absent means empty). Several
    /// entries may share an argv: by default the first one answers, and names
    /// listed in `prefer` move to the front, which is how a test selects a
    /// scenario such as `sshd-T-before-login`.
    ///
    /// # Errors
    ///
    /// Any I/O error, or [`io::ErrorKind::InvalidData`] for a malformed line
    /// or a `prefer` name that matches no entry (so a typo cannot silently
    /// replay the default capture).
    pub fn from_fixture(dir: &Path, prefer: &[&str]) -> io::Result<Self> {
        let invalid = |msg: String| io::Error::new(io::ErrorKind::InvalidData, msg);
        let read_optional = |path: PathBuf| match std::fs::read(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            other => other,
        };

        let tsv = std::fs::read_to_string(dir.join("commands.tsv"))?;
        let mut entries = Vec::new();
        for line in tsv.lines().filter(|l| !l.is_empty()) {
            let mut fields = line.split('\t');
            let (Some(name), Some(status), Some(program)) =
                (fields.next(), fields.next(), fields.next())
            else {
                return Err(invalid(format!("malformed fixture line: {line:?}")));
            };
            let status = status
                .parse()
                .map_err(|_| invalid(format!("bad exit code in {line:?}")))?;
            let cmd_dir = dir.join("cmd");
            let output = Output {
                status,
                stdout: read_optional(cmd_dir.join(format!("{name}.stdout")))?,
                stderr: read_optional(cmd_dir.join(format!("{name}.stderr")))?,
            };
            let args = fields.map(str::to_owned).collect();
            entries.push((name, (program.to_owned(), args, output)));
        }
        if let Some(missing) = prefer
            .iter()
            .find(|p| !entries.iter().any(|(name, _)| name == *p))
        {
            return Err(invalid(format!(
                "no fixture named {missing:?} in {}",
                dir.display()
            )));
        }
        // Stable sort: preferred entries first, file order otherwise.
        entries.sort_by_key(|(name, _)| !prefer.contains(name));
        Ok(Self {
            rules: entries.into_iter().map(|(_, rule)| rule).collect(),
            calls: Mutex::default(),
        })
    }

    /// Commands run so far, in order.
    pub fn calls(&self) -> Vec<Cmd> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Runner for FakeRunner {
    fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(cmd.clone());
        self.rules
            .iter()
            .find(|(program, prefix, _)| *program == cmd.program && cmd.args.starts_with(prefix))
            .map(|(_, _, output)| output.clone())
            .ok_or_else(|| SysError::NotFound(cmd.program.clone()))
    }
}

/// A [`FakeFs`] operation that a test can make fail, see [`FakeFs::fail`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Op {
    /// Writing file content: [`Fs::write`] and the temp file of [`Fs::write_atomic`].
    Write,
    /// The rename of [`Fs::write_atomic`].
    Rename,
    /// [`Fs::remove`].
    Remove,
    /// [`Fs::append_sync`].
    Append,
}

#[derive(Debug, Clone)]
enum Node {
    File(Vec<u8>),
    Dir,
    Symlink(PathBuf),
}

#[derive(Debug, Clone)]
struct Entry {
    node: Node,
    mode: u32,
    uid: u32,
    gid: u32,
}

impl Entry {
    fn new(node: Node, mode: u32) -> Self {
        Self {
            node,
            mode,
            uid: 0,
            gid: 0,
        }
    }
}

#[derive(Debug, Default)]
struct State {
    entries: BTreeMap<PathBuf, Entry>,
    /// Calls of each operation so far.
    counts: BTreeMap<Op, usize>,
    /// The call of each operation that fails.
    fail_at: BTreeMap<Op, usize>,
    /// The first call of each operation from which every call fails.
    fail_from: BTreeMap<Op, usize>,
}

impl State {
    /// Directories exist explicitly or implicitly as ancestors of an entry.
    fn is_dir(&self, path: &Path) -> bool {
        path == Path::new("/")
            || self.entries.iter().any(|(p, e)| {
                (p == path && matches!(e.node, Node::Dir)) || (p != path && p.starts_with(path))
            })
    }

    /// Follows symlinks (absolute targets, at most 8 hops) to the final path.
    fn resolve(&self, path: &Path) -> PathBuf {
        let mut path = path.to_path_buf();
        for _ in 0..8 {
            match self.entries.get(&path).map(|e| &e.node) {
                Some(Node::Symlink(target)) => path.clone_from(target),
                _ => break,
            }
        }
        path
    }

    fn file(&self, path: &Path) -> Option<&Vec<u8>> {
        match self.entries.get(path).map(|e| &e.node) {
            Some(Node::File(contents)) => Some(contents),
            _ => None,
        }
    }

    /// Counts a call of `op`, and fails it if it is the one set by [`FakeFs::fail`].
    fn tick(&mut self, op: Op, path: &Path) -> Result<(), SysError> {
        let n = self.counts.entry(op).or_default();
        *n += 1;
        if self.fail_at.get(&op) == Some(n)
            || self.fail_from.get(&op).is_some_and(|from| *n >= *from)
        {
            return Err(SysError::Io {
                context: path.display().to_string(),
                source: io::Error::other(format!("injected failure of {op:?} call {n}")),
            });
        }
        Ok(())
    }

    fn require_parent(&self, path: &Path) -> Result<(), SysError> {
        match path.parent() {
            Some(parent) if self.is_dir(parent) => Ok(()),
            _ => Err(not_found(path)),
        }
    }
}

fn not_found(path: &Path) -> SysError {
    SysError::NotFound(path.display().to_string())
}

fn io_error(path: &Path, kind: io::ErrorKind) -> SysError {
    SysError::Io {
        context: path.display().to_string(),
        source: io::Error::from(kind),
    }
}

/// An in-memory [`Fs`]: a map from absolute path to a file, directory or
/// symlink, each with a mode and owner. Directories also exist implicitly as
/// ancestors of other entries, as `0755 root:root`. Files added with
/// [`FakeFs::with_file`] are `0644 root:root`.
///
/// [`FakeFs::fail`] makes one call of a write operation fail, to test what
/// the caller does after a failure. A failed call changes no entry: the fake
/// models only that case, not a real `append_sync` whose bytes landed before
/// its `sync_all` failed.
#[derive(Debug, Default)]
pub struct FakeFs {
    state: Mutex<State>,
    /// Paths locked by [`Fs::try_lock`], shared with the guards that unlock them.
    locks: Arc<Mutex<BTreeSet<PathBuf>>>,
}

/// Removes its path from [`FakeFs::locks`] when dropped.
struct FakeLock {
    locks: Arc<Mutex<BTreeSet<PathBuf>>>,
    path: PathBuf,
}

impl Drop for FakeLock {
    fn drop(&mut self) {
        self.locks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.path);
    }
}

impl FakeFs {
    /// An empty filesystem.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds (or replaces) a file.
    #[must_use]
    pub fn with_file(self, path: impl Into<PathBuf>, contents: impl Into<Vec<u8>>) -> Self {
        let entry = Entry::new(Node::File(contents.into()), 0o644);
        self.lock().entries.insert(path.into(), entry);
        self
    }

    /// Adds (or replaces) a directory with `owner`.
    #[must_use]
    pub fn with_dir(self, path: impl Into<PathBuf>, owner: FileOwner) -> Self {
        let entry = Entry {
            node: Node::Dir,
            mode: owner.mode,
            uid: owner.uid,
            gid: owner.gid,
        };
        self.lock().entries.insert(path.into(), entry);
        self
    }

    /// Adds (or replaces) a symlink to the absolute path `target`.
    #[must_use]
    pub fn with_symlink(self, path: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        let entry = Entry::new(Node::Symlink(target.into()), 0o777);
        self.lock().entries.insert(path.into(), entry);
        self
    }

    /// Makes the `n`-th call of `op` that reaches the write (counting from 1)
    /// fail with [`SysError::Io`]. Calls rejected before that, e.g. with
    /// [`SysError::NotFound`] or [`SysError::Symlink`], are not counted.
    /// Only that call fails.
    #[must_use]
    pub fn fail(self, op: Op, n: usize) -> Self {
        self.lock().fail_at.insert(op, n);
        self
    }

    /// Like [`FakeFs::fail`], but every call of `op` from the `n`-th on
    /// fails, as on a full disk; with `1`, every call from now on.
    pub fn fail_from(&self, op: Op, n: usize) {
        self.lock().fail_from.insert(op, n);
    }

    /// Makes the next call of `op` fail, as [`FakeFs::fail`] does.
    pub fn fail_next(&self, op: Op) {
        let mut state = self.lock();
        let next = state.counts.get(&op).copied().unwrap_or_default() + 1;
        state.fail_at.insert(op, next);
    }

    /// Ends every [`FakeFs::fail_from`]: the disk has space again.
    pub fn heal(&self) {
        self.lock().fail_from.clear();
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Fs for FakeFs {
    fn read(&self, path: &Path) -> Result<Vec<u8>, SysError> {
        let state = self.lock();
        state
            .file(&state.resolve(path))
            .cloned()
            .ok_or_else(|| not_found(path))
    }

    fn exists(&self, path: &Path) -> bool {
        let state = self.lock();
        let target = state.resolve(path);
        state.file(&target).is_some() || state.is_dir(&target)
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>, SysError> {
        let state = self.lock();
        if !state.is_dir(path) {
            return Err(not_found(path));
        }
        let mut entries: Vec<PathBuf> = state
            .entries
            .keys()
            .filter_map(|f| f.strip_prefix(path).ok()?.components().next())
            .map(|first| path.join(first))
            .collect();
        entries.sort();
        entries.dedup();
        Ok(entries)
    }

    fn metadata(&self, path: &Path) -> Result<FileMeta, SysError> {
        let state = self.lock();
        let Some(entry) = state.entries.get(path) else {
            if state.is_dir(path) {
                return Ok(FileMeta {
                    kind: FileKind::Dir,
                    len: 0,
                    mode: 0o755,
                    uid: 0,
                    gid: 0,
                });
            }
            return Err(not_found(path));
        };
        let (kind, len) = match &entry.node {
            Node::File(contents) => (FileKind::File, contents.len() as u64),
            Node::Dir => (FileKind::Dir, 0),
            Node::Symlink(target) => (FileKind::Symlink, target.as_os_str().len() as u64),
        };
        Ok(FileMeta {
            kind,
            len,
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
        })
    }

    fn write_atomic(&self, path: &Path, bytes: &[u8], owner: FileOwner) -> Result<(), SysError> {
        let mut state = self.lock();
        match state.entries.get(path).map(|e| &e.node) {
            Some(Node::Symlink(_)) => return Err(SysError::Symlink(path.display().to_string())),
            Some(Node::Dir) => return Err(io_error(path, io::ErrorKind::IsADirectory)),
            Some(Node::File(_)) | None => {}
        }
        state.require_parent(path)?;
        state.tick(Op::Write, path)?;
        state.tick(Op::Rename, path)?;
        let entry = Entry {
            node: Node::File(bytes.to_vec()),
            mode: owner.mode,
            uid: owner.uid,
            gid: owner.gid,
        };
        state.entries.insert(path.to_path_buf(), entry);
        Ok(())
    }

    fn write(&self, path: &Path, bytes: &[u8]) -> Result<(), SysError> {
        let mut state = self.lock();
        let target = state.resolve(path);
        if state.file(&target).is_none() {
            return Err(not_found(path));
        }
        state.tick(Op::Write, path)?;
        if let Some(entry) = state.entries.get_mut(&target) {
            entry.node = Node::File(bytes.to_vec());
        }
        Ok(())
    }

    fn append_sync(&self, path: &Path, bytes: &[u8]) -> Result<(), SysError> {
        let mut state = self.lock();
        let target = state.resolve(path);
        if state.entries.contains_key(&target) && state.file(&target).is_none() {
            return Err(io_error(path, io::ErrorKind::IsADirectory));
        }
        state.require_parent(&target)?;
        state.tick(Op::Append, path)?;
        let entry = state
            .entries
            .entry(target)
            .or_insert_with(|| Entry::new(Node::File(Vec::new()), 0o600));
        if let Node::File(contents) = &mut entry.node {
            contents.extend_from_slice(bytes);
        }
        Ok(())
    }

    fn remove(&self, path: &Path) -> Result<(), SysError> {
        let mut state = self.lock();
        match state.entries.get(path).map(|e| &e.node) {
            Some(Node::File(_) | Node::Symlink(_)) => {}
            Some(Node::Dir) => return Err(io_error(path, io::ErrorKind::IsADirectory)),
            None => return Err(not_found(path)),
        }
        state.tick(Op::Remove, path)?;
        state.entries.remove(path);
        // Keep a parent that existed only implicitly through this entry, as a
        // real directory outlives its last entry.
        if let Some(parent) = path.parent().filter(|p| !state.is_dir(p)) {
            let entry = Entry::new(Node::Dir, 0o755);
            state.entries.insert(parent.to_path_buf(), entry);
        }
        Ok(())
    }

    fn create_dir_all(&self, path: &Path, mode: u32) -> Result<(), SysError> {
        let mut state = self.lock();
        // Outermost first, so each created parent gets `mode` too.
        let dirs: Vec<&Path> = path.ancestors().collect();
        for dir in dirs.into_iter().rev() {
            match state.entries.get(dir).map(|e| &e.node) {
                Some(Node::File(_) | Node::Symlink(_)) => {
                    return Err(io_error(path, io::ErrorKind::NotADirectory));
                }
                Some(Node::Dir) => {}
                None if state.is_dir(dir) => {}
                None => {
                    let entry = Entry::new(Node::Dir, mode);
                    state.entries.insert(dir.to_path_buf(), entry);
                }
            }
        }
        Ok(())
    }

    fn create_dir(&self, path: &Path, owner: FileOwner) -> Result<(), SysError> {
        let mut state = self.lock();
        if state.entries.contains_key(path) || state.is_dir(path) {
            return Err(io_error(path, io::ErrorKind::AlreadyExists));
        }
        state.require_parent(path)?;
        let entry = Entry {
            node: Node::Dir,
            mode: owner.mode,
            uid: owner.uid,
            gid: owner.gid,
        };
        state.entries.insert(path.to_path_buf(), entry);
        Ok(())
    }

    fn remove_dir(&self, path: &Path) -> Result<(), SysError> {
        let mut state = self.lock();
        match state.entries.get(path).map(|e| &e.node) {
            Some(Node::Dir) => {}
            Some(_) => return Err(io_error(path, io::ErrorKind::NotADirectory)),
            None if state.is_dir(path) => {}
            None => return Err(not_found(path)),
        }
        if state
            .entries
            .keys()
            .any(|p| p != path && p.starts_with(path))
        {
            return Err(io_error(path, io::ErrorKind::DirectoryNotEmpty));
        }
        state.entries.remove(path);
        if let Some(parent) = path.parent().filter(|p| !state.is_dir(p)) {
            let entry = Entry::new(Node::Dir, 0o755);
            state.entries.insert(parent.to_path_buf(), entry);
        }
        Ok(())
    }

    fn sync_dir(&self, path: &Path) -> Result<(), SysError> {
        if self.lock().is_dir(path) {
            Ok(())
        } else {
            Err(not_found(path))
        }
    }

    fn try_lock(&self, path: &Path) -> Result<FsLock, SysError> {
        let mut state = self.lock();
        match state.entries.get(path).map(|e| &e.node) {
            Some(Node::File(_)) => {}
            Some(_) => return Err(io_error(path, io::ErrorKind::IsADirectory)),
            None => {
                state.require_parent(path)?;
                let entry = Entry::new(Node::File(Vec::new()), 0o600);
                state.entries.insert(path.to_path_buf(), entry);
            }
        }
        let mut locks = self.locks.lock().unwrap_or_else(PoisonError::into_inner);
        if !locks.insert(path.to_path_buf()) {
            return Err(SysError::Locked(path.display().to_string()));
        }
        Ok(FsLock::new(FakeLock {
            locks: Arc::clone(&self.locks),
            path: path.to_path_buf(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_runner_matches_prefix_and_records() {
        let runner = FakeRunner::new().on("sshd", ["-T"], Output::success("port 22\n"));
        let out = runner
            .run(&Cmd::new("sshd").args(["-T", "-C", "user=root"]))
            .unwrap();
        assert_eq!(out.stdout_str().unwrap(), "port 22\n");
        assert!(runner.run(&Cmd::new("sshd").arg("-V")).is_err());
        assert_eq!(runner.calls().len(), 2);
    }

    #[test]
    fn fake_fs_has_implicit_dirs() {
        let fs = FakeFs::new()
            .with_file("/etc/ssh/sshd_config", "Port 22\n")
            .with_file("/etc/hostname", "box\n");
        assert!(fs.exists(Path::new("/etc/ssh")));
        assert_eq!(
            fs.read_dir(Path::new("/etc")).unwrap(),
            vec![PathBuf::from("/etc/hostname"), PathBuf::from("/etc/ssh")]
        );
        assert_eq!(fs.metadata(Path::new("/etc")).unwrap().kind, FileKind::Dir);
        assert!(fs.read(Path::new("/etc/shadow")).is_err());
    }

    #[test]
    fn fake_fs_sets_the_owner() {
        let fs = FakeFs::new().with_file("/etc/a", "old\n");
        let owner = FileOwner {
            mode: 0o640,
            uid: 1000,
            gid: 1001,
        };
        fs.write_atomic(Path::new("/etc/a"), b"new\n", owner)
            .unwrap();
        let meta = fs.metadata(Path::new("/etc/a")).unwrap();
        assert_eq!((meta.mode, meta.uid, meta.gid), (0o640, 1000, 1001));
    }

    #[test]
    fn fake_fs_fails_only_the_nth_call() {
        let path = Path::new("/etc/a");
        let owner = FileOwner {
            mode: 0o600,
            uid: 0,
            gid: 0,
        };
        let fs = FakeFs::new()
            .with_file(path, "old\n")
            .fail(Op::Rename, 2)
            .fail(Op::Write, 4)
            .fail(Op::Append, 1)
            .fail(Op::Remove, 1);

        fs.write_atomic(path, b"one\n", owner).unwrap();
        assert!(fs.write_atomic(path, b"two\n", owner).is_err());
        assert_eq!(fs.read(path).unwrap(), b"one\n");
        assert_eq!(fs.metadata(path).unwrap().mode, 0o600);
        fs.write_atomic(path, b"three\n", owner).unwrap();

        assert!(fs.write(path, b"four\n").is_err());
        assert_eq!(fs.read(path).unwrap(), b"three\n");
        fs.write(path, b"five\n").unwrap();

        let journal = Path::new("/etc/journal");
        assert!(fs.append_sync(journal, b"1\n").is_err());
        assert!(!fs.exists(journal));
        fs.append_sync(journal, b"1\n").unwrap();

        assert!(fs.remove(path).is_err());
        assert_eq!(fs.read(path).unwrap(), b"five\n");
        fs.remove(path).unwrap();
        assert!(!fs.exists(path));
    }
}
