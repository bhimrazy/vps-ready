//! The system boundary: every process spawn and file read goes through the
//! [`Runner`] and [`Fs`] traits.
//!
//! Production code receives `&dyn Runner` / `&dyn Fs` and never calls
//! `std::process` or `std::fs` directly, so tests can substitute the fakes in
//! `sys::fake` (available under `cfg(test)` or the `testing` feature).
//!
//! Paths passed to [`Fs`] are always absolute paths *on the inspected system*
//! (for example `/etc/os-release`); [`RealFs`] maps them under its root.

use std::io::{self, Read};
use std::os::unix::fs::MetadataExt as _;
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

/// Read-only filesystem access.
///
/// Writes (`write_atomic`, `rename`, `chmod`, ...) are added in M2 together
/// with the engine's snapshot and rollback support.
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
            .run(&Cmd::new("definitely-not-a-real-program-vpsready"))
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
}
