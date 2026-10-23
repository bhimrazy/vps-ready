//! The system boundary: every process spawn and file access goes through the
//! [`Runner`] and [`Fs`] traits.
//!
//! Production code receives `&dyn Runner` / `&dyn Fs` (or both as [`Sys`])
//! and never calls `std::process` or `std::fs` directly, so tests can
//! substitute the fakes in `sys::fake` (available under `cfg(test)` or the
//! `testing` feature).
//!
//! Paths passed to [`Fs`] are always absolute paths *on the inspected system*
//! (for example `/etc/os-release`); [`RealFs`] maps them under its root.

use std::fmt;
use std::fs::{DirBuilder, File, OpenOptions, Permissions, TryLockError};
use std::io::{self, Read, Write as _};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(any(test, feature = "testing"))]
pub mod fake;

/// Errors from the system boundary.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SysError {
    /// A file or program does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// The OS refused access.
    #[error("permission denied: {0}")]
    Permission(String),
    /// A command did not finish within its timeout and was killed.
    #[error("`{program}` timed out after {timeout:?}")]
    Timeout {
        /// Program that was run.
        program: String,
        /// Timeout that elapsed.
        timeout: Duration,
    },
    /// A write was refused because the target is a symlink.
    #[error("refusing to write through a symlink: {0}")]
    Symlink(String),
    /// A lock is held through another open file, usually by another process.
    #[error("{0} is locked by another process")]
    Locked(String),
    /// Data that must be text was not valid UTF-8.
    #[error("{0} is not valid UTF-8")]
    NonUtf8(String),
    /// Any other I/O error.
    #[error("{context}: {source}")]
    Io {
        /// What was being done, e.g. `reading /etc/os-release`.
        context: String,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
}

impl SysError {
    /// Classifies an [`io::Error`], keeping `subject` (a path or program) for the message.
    #[must_use]
    pub fn from_io(subject: impl Into<String>, err: io::Error) -> Self {
        let subject = subject.into();
        match err.kind() {
            io::ErrorKind::NotFound => Self::NotFound(subject),
            io::ErrorKind::PermissionDenied => Self::Permission(subject),
            _ => Self::Io {
                context: subject,
                source: err,
            },
        }
    }
}

/// A command to run. Build with [`Cmd::new`] and the chained setters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    /// Program name (looked up in [`SYSTEM_PATH`]) or absolute path.
    pub program: String,
    /// Arguments, not including the program.
    pub args: Vec<String>,
    /// Extra environment variables, added to the inherited environment.
    pub env: Vec<(String, String)>,
    /// Kill the process if it runs longer than this.
    pub timeout: Duration,
}

impl Cmd {
    /// Default timeout for a command.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

    /// A command with no arguments and the default timeout.
    #[must_use]
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    /// Appends one argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Appends several arguments.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Sets an environment variable for the child.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Overrides the timeout.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// The result of a finished command. A non-zero status is *not* an error at
/// this layer; callers decide what a failure means.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    /// Exit code; `-1` if the process was killed by a signal.
    pub status: i32,
    /// Captured standard output.
    pub stdout: Vec<u8>,
    /// Captured standard error.
    pub stderr: Vec<u8>,
}

impl Output {
    /// A successful (status 0) output with the given stdout.
    #[must_use]
    pub fn success(stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 0,
            stdout: stdout.into(),
            stderr: Vec::new(),
        }
    }

    /// Whether the command exited with status 0.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.status == 0
    }

    /// Stdout as UTF-8.
    ///
    /// # Errors
    ///
    /// [`SysError::NonUtf8`] if stdout is not valid UTF-8.
    pub fn stdout_str(&self) -> Result<&str, SysError> {
        std::str::from_utf8(&self.stdout).map_err(|_| SysError::NonUtf8("command stdout".into()))
    }
}

/// Runs external commands.
pub trait Runner {
    /// Runs `cmd` to completion and captures its output.
    ///
    /// # Errors
    ///
    /// [`SysError::NotFound`] if the program does not exist,
    /// [`SysError::Timeout`] if it exceeded `cmd.timeout`, or another
    /// [`SysError`] if it could not be spawned or waited on.
    fn run(&self, cmd: &Cmd) -> Result<Output, SysError>;
}

/// What kind of filesystem object a path is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// Regular file.
    File,
    /// Directory.
    Dir,
    /// Symbolic link (metadata is not followed).
    Symlink,
    /// Socket, FIFO, device, ...
    Other,
}

/// The subset of file metadata the auditor needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMeta {
    /// Object kind.
    pub kind: FileKind,
    /// Size in bytes.
    pub len: u64,
    /// Permission bits (`st_mode & 0o7777`).
    pub mode: u32,
    /// Owner user id.
    pub uid: u32,
    /// Owner group id.
    pub gid: u32,
}

impl FileMeta {
    /// The mode and owner, in the form [`Fs::write_atomic`] takes.
    #[must_use]
    pub fn owner(&self) -> FileOwner {
        FileOwner {
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
        }
    }
}

/// Mode and owner of a file written by [`Fs::write_atomic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileOwner {
    /// Permission bits (`0o7777` at most).
    pub mode: u32,
    /// Owner user id.
    pub uid: u32,
    /// Owner group id.
    pub gid: u32,
}

/// A lock taken by [`Fs::try_lock`], released when dropped.
#[must_use = "the lock is released when the guard is dropped"]
pub struct FsLock {
    _guard: Box<dyn Send>,
}

impl FsLock {
    /// Wraps `guard`, whose drop releases the lock.
    pub fn new(guard: impl Send + 'static) -> Self {
        Self {
            _guard: Box::new(guard),
        }
    }
}

impl fmt::Debug for FsLock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FsLock")
    }
}

/// Filesystem access.
pub trait Fs {
    /// Reads a whole file.
    ///
    /// # Errors
    ///
    /// [`SysError::NotFound`], [`SysError::Permission`] or [`SysError::Io`].
    fn read(&self, path: &Path) -> Result<Vec<u8>, SysError>;

    /// Whether `path` exists (following symlinks).
    fn exists(&self, path: &Path) -> bool;

    /// Lists the entries of a directory as full paths, sorted.
    ///
    /// # Errors
    ///
    /// [`SysError::NotFound`], [`SysError::Permission`] or [`SysError::Io`].
    fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>, SysError>;

    /// Metadata of `path`, *not* following a final symlink (`lstat`).
    ///
    /// # Errors
    ///
    /// [`SysError::NotFound`], [`SysError::Permission`] or [`SysError::Io`].
    fn metadata(&self, path: &Path) -> Result<FileMeta, SysError>;

    /// Replaces the file at `path` with `bytes`, `owner.mode`, `owner.uid`
    /// and `owner.gid`, so that after a crash it holds either the old or the
    /// new content, never a mix. Returns once the new file and its directory
    /// entry are on disk. An error before the rename leaves the old file
    /// unchanged; if only the final directory sync fails, the new file is in
    /// place but may not survive a crash.
    ///
    /// # Errors
    ///
    /// [`SysError::Symlink`] if `path` is a symlink; [`SysError::NotFound`]
    /// if the parent directory does not exist; [`SysError::Permission`] or
    /// [`SysError::Io`].
    fn write_atomic(&self, path: &Path, bytes: &[u8], owner: FileOwner) -> Result<(), SysError>;

    /// Truncates the existing file at `path` and writes `bytes` in place,
    /// without creating it, syncing it or changing its metadata. Only for
    /// `/proc/sys`, where a file cannot be replaced by a rename.
    ///
    /// # Errors
    ///
    /// [`SysError::NotFound`], [`SysError::Permission`] or [`SysError::Io`].
    fn write(&self, path: &Path, bytes: &[u8]) -> Result<(), SysError>;

    /// Appends `bytes` to `path`, creating it with mode `0600` if missing,
    /// and returns once the data is on disk. A newly created file's directory
    /// entry is not synced: call [`Fs::sync_dir`] on its parent for that.
    ///
    /// # Errors
    ///
    /// [`SysError::NotFound`] if the parent directory does not exist;
    /// [`SysError::Permission`] or [`SysError::Io`].
    fn append_sync(&self, path: &Path, bytes: &[u8]) -> Result<(), SysError>;

    /// Removes the file or symlink at `path` (not a directory). The removal
    /// is durable only after [`Fs::sync_dir`] on the parent.
    ///
    /// # Errors
    ///
    /// [`SysError::NotFound`], [`SysError::Permission`] or [`SysError::Io`].
    fn remove(&self, path: &Path) -> Result<(), SysError>;

    /// Creates `path` and any missing parents with `mode` (minus the umask,
    /// on [`RealFs`]). Existing directories are left as they are.
    ///
    /// # Errors
    ///
    /// [`SysError::Permission`] or [`SysError::Io`].
    fn create_dir_all(&self, path: &Path, mode: u32) -> Result<(), SysError>;

    /// Flushes the directory `path` to disk, which makes the creation,
    /// rename or removal of its entries durable.
    ///
    /// # Errors
    ///
    /// [`SysError::NotFound`], [`SysError::Permission`] or [`SysError::Io`].
    fn sync_dir(&self, path: &Path) -> Result<(), SysError>;

    /// Takes an exclusive lock on `path`, creating the file with mode `0600`
    /// if missing, without waiting. The lock lasts until the returned guard
    /// is dropped or the process exits.
    ///
    /// # Errors
    ///
    /// [`SysError::Locked`] if the lock is already held;
    /// [`SysError::NotFound`] if the parent directory does not exist;
    /// [`SysError::Permission`] or [`SysError::Io`].
    fn try_lock(&self, path: &Path) -> Result<FsLock, SysError>;
}

/// The system boundary in one `Copy` value, so higher layers take one argument.
#[derive(Clone, Copy)]
pub struct Sys<'a> {
    /// Filesystem access.
    pub fs: &'a dyn Fs,
    /// Command execution.
    pub runner: &'a dyn Runner,
}

/// `PATH` for every command, systemd's default. The caller's `PATH` is not
/// used: a non-root user's often lacks `/usr/sbin` (where `sshd` lives), and
/// when running as root it must not decide which binaries run.
pub const SYSTEM_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// [`Runner`] backed by [`std::process::Command`].
///
/// Programs are looked up in [`SYSTEM_PATH`]. Stdin is closed; stdout and
/// stderr are drained on background threads so a chatty child cannot block on
/// a full pipe while we wait for it.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealRunner;

impl RealRunner {
    const POLL: Duration = Duration::from_millis(10);
}

impl Runner for RealRunner {
    fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
        tracing::debug!(program = %cmd.program, args = ?cmd.args, "run");
        let mut child = Command::new(&cmd.program)
            .args(&cmd.args)
            .env("PATH", SYSTEM_PATH)
            .envs(cmd.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SysError::from_io(cmd.program.clone(), e))?;

        let stdout = drain(child.stdout.take());
        let stderr = drain(child.stderr.take());

        let deadline = Instant::now() + cmd.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() >= deadline => {
                    // Best effort: the child may have exited in between.
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(SysError::Timeout {
                        program: cmd.program.clone(),
                        timeout: cmd.timeout,
                    });
                }
                Ok(None) => thread::sleep(Self::POLL),
                Err(e) => return Err(SysError::from_io(cmd.program.clone(), e)),
            }
        };

        Ok(Output {
            status: status.code().unwrap_or(-1),
            stdout: join(stdout, &cmd.program)?,
            stderr: join(stderr, &cmd.program)?,
        })
    }
}

type Drain = Option<thread::JoinHandle<io::Result<Vec<u8>>>>;

fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> Drain {
    pipe.map(|mut pipe| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            pipe.read_to_end(&mut buf).map(|_| buf)
        })
    })
}

fn join(handle: Drain, program: &str) -> Result<Vec<u8>, SysError> {
    let Some(handle) = handle else {
        return Ok(Vec::new());
    };
    match handle.join() {
        Ok(result) => {
            result.map_err(|e| SysError::from_io(format!("reading output of {program}"), e))
        }
        Err(_) => Err(SysError::Io {
            context: format!("reading output of {program}"),
            source: io::Error::other("reader thread panicked"),
        }),
    }
}

/// [`Fs`] backed by [`std::fs`], rooted at a base directory.
///
/// `RealFs::new("/")` reads the live system. Any other root (a chroot, a
/// mounted image, a test fixture tree) is read as if it were `/`. The root is
/// a convenience, not a security boundary: absolute symlinks inside it still
/// resolve against the host.
#[derive(Debug, Clone)]
pub struct RealFs {
    root: PathBuf,
}

impl Default for RealFs {
    fn default() -> Self {
        Self::new("/")
    }
}

impl RealFs {
    /// A filesystem view rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The host path for a path on the inspected system.
    fn host_path(&self, path: &Path) -> PathBuf {
        self.root.join(path.strip_prefix("/").unwrap_or(path))
    }

    /// Writes `bytes` to a new file at `tmp` with `owner`, and syncs it.
    fn write_temp(tmp: &Path, bytes: &[u8], owner: FileOwner) -> io::Result<()> {
        // `create_new` (O_EXCL) never follows a symlink planted at `tmp`, and
        // 0600 keeps the content private until the final mode is set.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(tmp)?;
        file.write_all(bytes)?;
        // Owner before mode: chown can clear the setuid and setgid bits.
        std::os::unix::fs::fchown(&file, Some(owner.uid), Some(owner.gid))?;
        file.set_permissions(Permissions::from_mode(owner.mode))?;
        file.sync_all()
    }
}

/// The temp file `write_atomic` uses for `path`: `.<name>.vps-ready-tmp` in
/// the same directory, because `rename` cannot cross filesystems.
fn temp_path(path: &Path) -> Option<PathBuf> {
    let mut name = std::ffi::OsString::from(".");
    name.push(path.file_name()?);
    name.push(".vps-ready-tmp");
    Some(path.with_file_name(name))
}

impl Fs for RealFs {
    fn read(&self, path: &Path) -> Result<Vec<u8>, SysError> {
        std::fs::read(self.host_path(path))
            .map_err(|e| SysError::from_io(path.display().to_string(), e))
    }

    fn exists(&self, path: &Path) -> bool {
        self.host_path(path).exists()
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>, SysError> {
        let subject = || path.display().to_string();
        let mut entries = Vec::new();
        for entry in
            std::fs::read_dir(self.host_path(path)).map_err(|e| SysError::from_io(subject(), e))?
        {
            let entry = entry.map_err(|e| SysError::from_io(subject(), e))?;
            entries.push(path.join(entry.file_name()));
        }
        entries.sort();
        Ok(entries)
    }

    fn metadata(&self, path: &Path) -> Result<FileMeta, SysError> {
        let meta = std::fs::symlink_metadata(self.host_path(path))
            .map_err(|e| SysError::from_io(path.display().to_string(), e))?;
        let ft = meta.file_type();
        let kind = if ft.is_symlink() {
            FileKind::Symlink
        } else if ft.is_dir() {
            FileKind::Dir
        } else if ft.is_file() {
            FileKind::File
        } else {
            FileKind::Other
        };
        Ok(FileMeta {
            kind,
            len: meta.len(),
            mode: meta.mode() & 0o7777,
            uid: meta.uid(),
            gid: meta.gid(),
        })
    }

    fn write_atomic(&self, path: &Path, bytes: &[u8], owner: FileOwner) -> Result<(), SysError> {
        let subject = || path.display().to_string();
        let host = self.host_path(path);
        match std::fs::symlink_metadata(&host) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(SysError::Symlink(subject())),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(SysError::from_io(subject(), e)),
        }
        let (Some(tmp), Some(dir)) = (temp_path(&host), host.parent()) else {
            return Err(SysError::Io {
                context: subject(),
                source: io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"),
            });
        };
        // A crash during an earlier call can leave the temp file behind.
        match std::fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(SysError::from_io(subject(), e)),
        }
        let written =
            Self::write_temp(&tmp, bytes, owner).and_then(|()| std::fs::rename(&tmp, &host));
        if let Err(e) = written {
            // Best effort: the original is untouched either way.
            let _ = std::fs::remove_file(&tmp);
            return Err(SysError::from_io(subject(), e));
        }
        // The rename is not durable until the directory itself is synced.
        File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| SysError::from_io(subject(), e))
    }

    fn write(&self, path: &Path, bytes: &[u8]) -> Result<(), SysError> {
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(self.host_path(path))
            .and_then(|mut f| f.write_all(bytes))
            .map_err(|e| SysError::from_io(path.display().to_string(), e))
    }

    fn append_sync(&self, path: &Path, bytes: &[u8]) -> Result<(), SysError> {
        OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(self.host_path(path))
            .and_then(|mut f| {
                f.write_all(bytes)?;
                f.sync_all()
            })
            .map_err(|e| SysError::from_io(path.display().to_string(), e))
    }

    fn remove(&self, path: &Path) -> Result<(), SysError> {
        std::fs::remove_file(self.host_path(path))
            .map_err(|e| SysError::from_io(path.display().to_string(), e))
    }

    fn create_dir_all(&self, path: &Path, mode: u32) -> Result<(), SysError> {
        DirBuilder::new()
            .recursive(true)
            .mode(mode)
            .create(self.host_path(path))
            .map_err(|e| SysError::from_io(path.display().to_string(), e))
    }

    fn sync_dir(&self, path: &Path) -> Result<(), SysError> {
        File::open(self.host_path(path))
            .and_then(|d| d.sync_all())
            .map_err(|e| SysError::from_io(path.display().to_string(), e))
    }

    fn try_lock(&self, path: &Path) -> Result<FsLock, SysError> {
        let subject = || path.display().to_string();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.host_path(path))
            .map_err(|e| SysError::from_io(subject(), e))?;
        match file.try_lock() {
            // Closing the file releases the lock.
            Ok(()) => Ok(FsLock::new(file)),
            Err(TryLockError::WouldBlock) => Err(SysError::Locked(subject())),
            Err(TryLockError::Error(e)) => Err(SysError::from_io(subject(), e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_a_command_and_captures_output() {
        let out = RealRunner
            .run(&Cmd::new("sh").args(["-c", "echo hi; echo err >&2; exit 3"]))
            .unwrap();
        assert_eq!(out.status, 3);
        assert!(!out.ok());
        assert_eq!(out.stdout_str().unwrap(), "hi\n");
        assert_eq!(out.stderr, b"err\n");
    }

    #[test]
    fn uses_the_system_path() {
        let out = RealRunner
            .run(&Cmd::new("sh").args(["-c", "echo \"$PATH\""]))
            .unwrap();
        assert_eq!(out.stdout_str().unwrap().trim(), SYSTEM_PATH);
    }

    #[test]
    fn missing_program_is_not_found() {
        let err = RealRunner
            .run(&Cmd::new("definitely-not-a-real-program-vps-ready"))
            .unwrap_err();
        assert!(matches!(err, SysError::NotFound(_)), "{err:?}");
    }

    #[test]
    fn timeout_kills_the_child() {
        let cmd = Cmd::new("sleep")
            .arg("5")
            .timeout(Duration::from_millis(100));
        let err = RealRunner.run(&cmd).unwrap_err();
        assert!(matches!(err, SysError::Timeout { .. }), "{err:?}");
    }

    #[test]
    fn real_fs_is_rooted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("etc")).unwrap();
        std::fs::write(dir.path().join("etc/hostname"), "box\n").unwrap();
        let fs = RealFs::new(dir.path());

        assert_eq!(fs.read(Path::new("/etc/hostname")).unwrap(), b"box\n");
        assert!(fs.exists(Path::new("/etc")));
        assert_eq!(
            fs.read_dir(Path::new("/etc")).unwrap(),
            vec![PathBuf::from("/etc/hostname")]
        );
        let meta = fs.metadata(Path::new("/etc/hostname")).unwrap();
        assert_eq!((meta.kind, meta.len), (FileKind::File, 4));
        assert!(matches!(
            fs.read(Path::new("/nope")),
            Err(SysError::NotFound(_))
        ));
    }

    /// The write behavior shared by [`RealFs`] and [`fake::FakeFs`]. `fs`
    /// has a directory `/etc`, a symlink `/etc/link` to `/etc/real`, which
    /// holds `real\n`, and a file `/etc/only/x`, the only entry of its
    /// directory. `owner` is one the caller may set.
    fn write_contract(fs: &dyn Fs, owner: FileOwner) {
        let path = Path::new("/etc/new.conf");
        let mode = |p: &str| fs.metadata(Path::new(p)).unwrap().mode;

        fs.write_atomic(
            path,
            b"a\n",
            FileOwner {
                mode: 0o640,
                ..owner
            },
        )
        .unwrap();
        assert_eq!(fs.read(path).unwrap(), b"a\n");
        assert_eq!(mode("/etc/new.conf"), 0o640);

        fs.write_atomic(
            path,
            b"b\n",
            FileOwner {
                mode: 0o600,
                ..owner
            },
        )
        .unwrap();
        assert_eq!(fs.read(path).unwrap(), b"b\n");
        assert_eq!(mode("/etc/new.conf"), 0o600);
        let tmp = fs
            .read_dir(Path::new("/etc"))
            .unwrap()
            .into_iter()
            .find(|p| p.to_string_lossy().ends_with(".vps-ready-tmp"));
        assert_eq!(tmp, None);

        let err = fs
            .write_atomic(Path::new("/etc/link"), b"x\n", owner)
            .unwrap_err();
        assert!(matches!(err, SysError::Symlink(_)), "{err:?}");
        assert_eq!(fs.read(Path::new("/etc/real")).unwrap(), b"real\n");
        let link = fs.metadata(Path::new("/etc/link")).unwrap();
        assert_eq!(link.kind, FileKind::Symlink);

        let err = fs
            .write_atomic(Path::new("/nope/x"), b"x\n", owner)
            .unwrap_err();
        assert!(matches!(err, SysError::NotFound(_)), "{err:?}");

        fs.write(path, b"c").unwrap();
        assert_eq!(fs.read(path).unwrap(), b"c");
        assert_eq!(mode("/etc/new.conf"), 0o600);
        let err = fs.write(Path::new("/etc/missing"), b"x").unwrap_err();
        assert!(matches!(err, SysError::NotFound(_)), "{err:?}");
        assert!(!fs.exists(Path::new("/etc/missing")));

        let journal = Path::new("/etc/journal");
        fs.append_sync(journal, b"1\n").unwrap();
        fs.append_sync(journal, b"2\n").unwrap();
        assert_eq!(fs.read(journal).unwrap(), b"1\n2\n");
        assert_eq!(mode("/etc/journal"), 0o600);

        fs.remove(journal).unwrap();
        assert!(!fs.exists(journal));
        assert!(matches!(fs.remove(journal), Err(SysError::NotFound(_))));

        // Removing a directory's last entry keeps the directory.
        fs.remove(Path::new("/etc/only/x")).unwrap();
        fs.sync_dir(Path::new("/etc/only")).unwrap();
        let only = fs.metadata(Path::new("/etc/only")).unwrap();
        assert_eq!(only.kind, FileKind::Dir);

        // Removing a symlink removes only the link.
        fs.remove(Path::new("/etc/link")).unwrap();
        assert!(fs.metadata(Path::new("/etc/link")).is_err());
        assert_eq!(fs.read(Path::new("/etc/real")).unwrap(), b"real\n");

        assert!(fs.create_dir_all(Path::new("/etc/real"), 0o755).is_err());

        let state = Path::new("/var/lib/vps-ready");
        fs.create_dir_all(state, 0o700).unwrap();
        fs.create_dir_all(state, 0o755).unwrap();
        let meta = fs.metadata(state).unwrap();
        assert_eq!((meta.kind, meta.mode), (FileKind::Dir, 0o700));
        fs.sync_dir(state).unwrap();
        assert!(matches!(
            fs.sync_dir(Path::new("/nope")),
            Err(SysError::NotFound(_))
        ));
    }

    /// A tempdir root with `/etc/real`, `/etc/link` and `/etc/only/x`, and an owner that a
    /// non-root user may set: the one the tempdir already has.
    fn real_root() -> (tempfile::TempDir, FileOwner) {
        let dir = tempfile::tempdir().unwrap();
        let etc = dir.path().join("etc");
        std::fs::create_dir(&etc).unwrap();
        std::fs::write(etc.join("real"), "real\n").unwrap();
        std::os::unix::fs::symlink("/etc/real", etc.join("link")).unwrap();
        std::fs::create_dir(etc.join("only")).unwrap();
        std::fs::write(etc.join("only/x"), "x\n").unwrap();
        let meta = std::fs::metadata(&etc).unwrap();
        let owner = FileOwner {
            mode: 0o644,
            uid: meta.uid(),
            gid: meta.gid(),
        };
        (dir, owner)
    }

    #[test]
    fn real_fs_writes() {
        let (dir, owner) = real_root();
        write_contract(&RealFs::new(dir.path()), owner);
    }

    #[test]
    fn fake_fs_writes() {
        let fs = fake::FakeFs::new()
            .with_file("/etc/real", "real\n")
            .with_symlink("/etc/link", "/etc/real")
            .with_file("/etc/only/x", "x\n");
        write_contract(
            &fs,
            FileOwner {
                mode: 0o644,
                uid: 0,
                gid: 0,
            },
        );
    }

    /// The lock behavior shared by [`RealFs`] and [`fake::FakeFs`]. `fs` has
    /// a directory `/etc`.
    fn lock_contract(fs: &dyn Fs) {
        let path = Path::new("/etc/lock");
        let first = fs.try_lock(path).unwrap();
        assert_eq!(fs.metadata(path).unwrap().mode, 0o600);
        let err = fs.try_lock(path).unwrap_err();
        assert!(matches!(err, SysError::Locked(_)), "{err:?}");
        drop(first);
        let _again = fs.try_lock(path).unwrap();
        let err = fs.try_lock(Path::new("/nope/lock")).unwrap_err();
        assert!(matches!(err, SysError::NotFound(_)), "{err:?}");
    }

    #[test]
    fn real_fs_locks() {
        let (dir, _) = real_root();
        lock_contract(&RealFs::new(dir.path()));
    }

    #[test]
    fn fake_fs_locks() {
        lock_contract(&fake::FakeFs::new().with_file("/etc/real", "real\n"));
    }

    #[test]
    fn write_atomic_removes_a_stale_temp_file() {
        let (dir, owner) = real_root();
        let stale = dir.path().join("etc/.new.conf.vps-ready-tmp");
        std::fs::write(&stale, "left by a crash").unwrap();
        let fs = RealFs::new(dir.path());
        fs.write_atomic(Path::new("/etc/new.conf"), b"a\n", owner)
            .unwrap();
        assert!(!stale.exists());
        assert_eq!(fs.read(Path::new("/etc/new.conf")).unwrap(), b"a\n");
    }

    #[test]
    fn failed_write_atomic_leaves_the_target_and_no_temp_file() {
        let (dir, owner) = real_root();
        // A non-empty directory at the target makes the final rename fail,
        // for root too, after the temp file was written and synced.
        let target = dir.path().join("etc/new.conf");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("keep"), "kept\n").unwrap();
        let fs = RealFs::new(dir.path());

        let err = fs.write_atomic(Path::new("/etc/new.conf"), b"a\n", owner);
        assert!(err.is_err(), "{err:?}");
        assert_eq!(std::fs::read(target.join("keep")).unwrap(), b"kept\n");
        assert!(!dir.path().join("etc/.new.conf.vps-ready-tmp").exists());
    }
}
