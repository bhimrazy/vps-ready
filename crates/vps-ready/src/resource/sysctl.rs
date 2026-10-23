//! The [`Sysctl`] resource.

use std::path::PathBuf;

use super::{Backup, ResourceError};
use crate::sys::{Sys, SysError};

/// The running value of a kernel parameter, read and written through
/// `/proc/sys/<key with dots as slashes>`. It does not persist across a
/// reboot; a [`super::File`] drop-in does that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sysctl {
    /// Dotted key, e.g. `kernel.kptr_restrict`.
    pub key: String,
    /// Desired value, e.g. `1`.
    pub value: String,
}

impl Sysctl {
    /// The summary of the change, or `None`.
    pub(super) fn diff(&self, sys: Sys) -> Result<Option<(String, Option<String>)>, ResourceError> {
        let current = read(sys, &self.key)?;
        Ok((current != self.value)
            .then(|| (format!("{} {current} -> {}", self.key, self.value), None)))
    }

    pub(super) fn snapshot(&self, sys: Sys) -> Result<Backup, ResourceError> {
        Ok(Backup::Sysctl {
            key: self.key.clone(),
            value: read(sys, &self.key)?,
        })
    }

    pub(super) fn apply(&self, sys: Sys) -> Result<(), ResourceError> {
        restore(sys, &self.key, &self.value)
    }
}

pub(super) fn restore(sys: Sys, key: &str, value: &str) -> Result<(), ResourceError> {
    Ok(sys.fs.write(&proc_path(key), value.as_bytes())?)
}

fn proc_path(key: &str) -> PathBuf {
    PathBuf::from("/proc/sys").join(key.replace('.', "/"))
}

/// The value without surrounding whitespace (the kernel appends a newline).
fn read(sys: Sys, key: &str) -> Result<String, ResourceError> {
    let path = proc_path(key);
    let bytes = sys.fs.read(&path)?;
    let text =
        String::from_utf8(bytes).map_err(|_| SysError::NonUtf8(path.display().to_string()))?;
    Ok(text.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::super::{Change, Resource, Reversibility, restore, test_sys as sys};
    use super::*;
    use crate::sys::Fs as _;
    use crate::sys::fake::FakeFs;

    const PROC: &str = "/proc/sys/kernel/kptr_restrict";

    fn kptr(value: &str) -> Resource {
        Resource::Sysctl(Sysctl {
            key: "kernel.kptr_restrict".into(),
            value: value.into(),
        })
    }

    #[test]
    fn diff_compares_the_running_value() {
        let fs = FakeFs::new().with_file(PROC, "0\n");
        assert_eq!(kptr("0").diff(sys(&fs)).unwrap(), None);
        assert_eq!(
            kptr("1").diff(sys(&fs)).unwrap(),
            Some(Change {
                id: "sysctl:kernel.kptr_restrict".into(),
                summary: "kernel.kptr_restrict 0 -> 1".into(),
                diff: None,
                reversibility: Reversibility::Reversible,
            })
        );
    }

    #[test]
    fn missing_key_is_an_error() {
        let fs = FakeFs::new();
        let err = kptr("1").diff(sys(&fs)).unwrap_err();
        assert!(
            matches!(err, ResourceError::Sys(SysError::NotFound(_))),
            "{err:?}"
        );
    }

    #[test]
    fn round_trip() {
        let fs = FakeFs::new().with_file(PROC, "0\n");
        let sys = sys(&fs);
        let txn = Path::new("/var/lib/vps-ready/txn/20261023T114246Z");
        let resource = kptr("1");

        let backup = resource.snapshot(sys, txn, 1).unwrap();
        assert_eq!(
            backup,
            Backup::Sysctl {
                key: "kernel.kptr_restrict".into(),
                value: "0".into(),
            }
        );
        resource.apply(sys).unwrap();
        assert_eq!(fs.read(Path::new(PROC)).unwrap(), b"1");
        assert_eq!(resource.diff(sys).unwrap(), None);

        restore(sys, txn, &backup).unwrap();
        assert_eq!(fs.read(Path::new(PROC)).unwrap(), b"0");
    }
}
