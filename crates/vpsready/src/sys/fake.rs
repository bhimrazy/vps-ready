//! In-memory fakes for [`Runner`] and [`Fs`], for unit and integration tests.
//!
//! Compiled under `cfg(test)` and with the `testing` feature.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use super::{Cmd, FileKind, FileMeta, Fs, Output, Runner, SysError};

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
    /// Any I/O error, or [`io::ErrorKind::InvalidData`] for a malformed line.
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

/// An in-memory [`Fs`]: a map from absolute path to file contents.
/// Directories exist implicitly as ancestors of files.
#[derive(Debug, Clone, Default)]
pub struct FakeFs {
    files: BTreeMap<PathBuf, Vec<u8>>,
}

impl FakeFs {
    /// An empty filesystem.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds (or replaces) a file.
    #[must_use]
    pub fn with_file(mut self, path: impl Into<PathBuf>, contents: impl Into<Vec<u8>>) -> Self {
        self.files.insert(path.into(), contents.into());
        self
    }

    fn is_dir(&self, path: &Path) -> bool {
        self.files.keys().any(|f| f != path && f.starts_with(path))
    }
}

impl Fs for FakeFs {
    fn read(&self, path: &Path) -> Result<Vec<u8>, SysError> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| SysError::NotFound(path.display().to_string()))
    }

    fn exists(&self, path: &Path) -> bool {
        self.files.contains_key(path) || self.is_dir(path)
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>, SysError> {
        if !self.is_dir(path) {
            return Err(SysError::NotFound(path.display().to_string()));
        }
        let mut entries: Vec<PathBuf> = self
            .files
            .keys()
            .filter_map(|f| f.strip_prefix(path).ok()?.components().next())
            .map(|first| path.join(first))
            .collect();
        entries.sort();
        entries.dedup();
        Ok(entries)
    }

    fn metadata(&self, path: &Path) -> Result<FileMeta, SysError> {
        let (kind, len, mode) = match self.files.get(path) {
            Some(contents) => (FileKind::File, contents.len() as u64, 0o644),
            None if self.is_dir(path) => (FileKind::Dir, 0, 0o755),
            None => return Err(SysError::NotFound(path.display().to_string())),
        };
        Ok(FileMeta {
            kind,
            len,
            mode,
            uid: 0,
            gid: 0,
        })
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
}
