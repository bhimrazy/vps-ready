//! Read-only discovery of what the host is.
//!
//! [`collect`] gathers [`Facts`] through the [`Fs`] and [`Runner`] traits.
//! Missing sources are not errors: the fact becomes `Unknown` and a notice is
//! recorded, so `vpsready detect` also works on a developer laptop or in a
//! minimal container.

use std::fmt;
use std::path::Path;

use serde::Serialize;

use crate::sys::{Fs, Runner, SysError};

pub mod os_release;

pub use os_release::{OsFamily, OsRelease};

/// Everything `vpsready` knows about the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Facts {
    /// Operating system identification from `os-release`.
    pub os: OsRelease,
    /// Init system running as PID 1.
    pub init: Init,
    /// Human-readable notes about facts that could not be determined.
    pub notices: Vec<String>,
}

/// The init system running as PID 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Init {
    /// systemd.
    Systemd,
    /// OpenRC (Alpine, Gentoo).
    OpenRc,
    /// Something else, e.g. a shell or `tini` in a container.
    Other(String),
    /// `/proc/1/comm` could not be read.
    Unknown,
}

impl fmt::Display for Init {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Systemd => f.write_str("systemd"),
            Self::OpenRc => f.write_str("openrc"),
            Self::Other(name) => write!(f, "other ({name})"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

/// Errors that stop fact collection. A *missing* source is not an error.
#[derive(Debug, thiserror::Error)]
pub enum FactsError {
    /// A source exists but could not be read (e.g. permission denied).
    #[error("reading {path}")]
    Read {
        /// Path on the inspected system.
        path: String,
        /// Underlying error.
        #[source]
        source: SysError,
    },
}

/// Collects facts about the system behind `fs` and `runner`.
///
/// `runner` is unused in M0; from M1 it runs probes such as `sshd -T`.
///
/// # Errors
///
/// [`FactsError::Read`] if a source exists but cannot be read.
pub fn collect(fs: &dyn Fs, _runner: &dyn Runner) -> Result<Facts, FactsError> {
    let mut notices = Vec::new();
    let os = detect_os(fs, &mut notices)?;
    let init = detect_init(fs, &mut notices)?;
    Ok(Facts { os, init, notices })
}

/// Reads `path`, mapping "not found" to `None`.
fn read_optional(fs: &dyn Fs, path: &str) -> Result<Option<Vec<u8>>, FactsError> {
    match fs.read(Path::new(path)) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(SysError::NotFound(_)) => Ok(None),
        Err(source) => Err(FactsError::Read {
            path: path.to_owned(),
            source,
        }),
    }
}

fn detect_os(fs: &dyn Fs, notices: &mut Vec<String>) -> Result<OsRelease, FactsError> {
    for path in os_release::PATHS {
        if let Some(bytes) = read_optional(fs, path)? {
            return Ok(OsRelease::parse(&String::from_utf8_lossy(&bytes)));
        }
    }
    notices.push(format!(
        "no os-release found ({}); OS is unknown",
        os_release::PATHS.join(", ")
    ));
    Ok(OsRelease::unknown())
}

fn detect_init(fs: &dyn Fs, notices: &mut Vec<String>) -> Result<Init, FactsError> {
    let Some(bytes) = read_optional(fs, "/proc/1/comm")? else {
        notices.push("/proc/1/comm not found; init system is unknown".to_owned());
        return Ok(Init::Unknown);
    };
    let comm = String::from_utf8_lossy(&bytes).trim().to_owned();
    Ok(match comm.as_str() {
        "systemd" => Init::Systemd,
        "openrc-init" => Init::OpenRc,
        // Alpine boots busybox `init`, which then starts OpenRC.
        "init" if fs.exists(Path::new("/sbin/openrc")) => Init::OpenRc,
        "" => Init::Unknown,
        _ => Init::Other(comm),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::RealFs;
    use crate::sys::fake::{FakeFs, FakeRunner};

    const FIXTURES: [&str; 5] = [
        "ubuntu-24.04",
        "debian-13",
        "rocky-9",
        "alpine-3.22",
        "fedora-42",
    ];

    #[test]
    fn fixtures_snapshot() {
        for name in FIXTURES {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("testdata/os-release")
                .join(name);
            let facts = collect(&RealFs::new(root), &FakeRunner::new()).unwrap();
            insta::assert_yaml_snapshot!(name, facts);
        }
    }

    #[test]
    fn empty_system_is_unknown_with_notices() {
        let facts = collect(&FakeFs::new(), &FakeRunner::new()).unwrap();
        assert_eq!(facts.os.family, OsFamily::Unknown);
        assert_eq!(facts.init, Init::Unknown);
        assert_eq!(facts.notices.len(), 2);
    }

    #[test]
    fn falls_back_to_usr_lib() {
        let fs = FakeFs::new().with_file("/usr/lib/os-release", "ID=arch\n");
        let facts = collect(&fs, &FakeRunner::new()).unwrap();
        assert_eq!(facts.os.family, OsFamily::Arch);
    }

    #[test]
    fn detects_init() {
        let cases: [(&[(&str, &str)], Init); 4] = [
            (&[("/proc/1/comm", "systemd\n")], Init::Systemd),
            (
                &[("/proc/1/comm", "init\n"), ("/sbin/openrc", "")],
                Init::OpenRc,
            ),
            (&[("/proc/1/comm", "init\n")], Init::Other("init".into())),
            (&[("/proc/1/comm", "bash\n")], Init::Other("bash".into())),
        ];
        for (files, want) in cases {
            let fs = files
                .iter()
                .fold(FakeFs::new(), |fs, (p, c)| fs.with_file(*p, *c));
            let facts = collect(&fs, &FakeRunner::new()).unwrap();
            assert_eq!(facts.init, want, "{files:?}");
        }
    }
}
