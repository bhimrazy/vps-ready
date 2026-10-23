//! Kernel settings, read from the files under `/proc/sys`.
//!
//! Only the settings in [`KEYS`] are read, without running a command. Most
//! are readable by anyone, but older kernels restrict a few to root: the
//! `fs.protected_*` files before Linux 5.18, e.g. Ubuntu 22.04's 5.15.
//!
//! The IPv4 settings in [`CONF_KEYS`] are also read for each interface,
//! because the kernel combines `net.ipv4.conf.all` with the interface's own
//! value.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use crate::sys::{Fs, SysError};

/// The settings that are read, by their `sysctl` name. The audit catalog may
/// only use names listed here.
pub const KEYS: [&str; 14] = [
    "fs.protected_fifos",
    "fs.protected_hardlinks",
    "fs.protected_regular",
    "fs.protected_symlinks",
    "fs.suid_dumpable",
    "kernel.dmesg_restrict",
    "kernel.kptr_restrict",
    "kernel.perf_event_paranoid",
    "kernel.randomize_va_space",
    "kernel.unprivileged_bpf_disabled",
    "kernel.yama.ptrace_scope",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.icmp_echo_ignore_broadcasts",
    "net.ipv4.tcp_syncookies",
];

/// The IPv4 settings read from each directory under `/proc/sys/net/ipv4/conf`.
pub const CONF_KEYS: [&str; 4] = [
    "accept_redirects",
    "forwarding",
    "rp_filter",
    "send_redirects",
];

/// The [`CONF_KEYS`] of one directory under `/proc/sys/net/ipv4/conf`, by
/// setting name.
pub type Ipv4Conf = BTreeMap<String, String>;

/// The settings in [`KEYS`] that could be read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Sysctl {
    /// Values by setting name. A setting the kernel does not have, e.g.
    /// `kernel.yama.ptrace_scope` without Yama, is absent.
    pub values: BTreeMap<String, String>,
    /// Settings that exist but are readable only by root on this kernel.
    pub unreadable: Vec<String>,
    /// [`CONF_KEYS`] under `/proc/sys/net/ipv4/conf`, by directory: `all`,
    /// `default` (the values a new interface starts with) and each interface
    /// but `lo`, where only the host's own packets arrive. An interface
    /// removed while it was being read is absent.
    pub ipv4_conf: BTreeMap<String, Ipv4Conf>,
}

impl Sysctl {
    /// The value of one setting, e.g. `get("kernel.kptr_restrict")`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    /// Whether `key` exists but could not be read without root.
    #[must_use]
    pub fn is_unreadable(&self, key: &str) -> bool {
        self.unreadable.iter().any(|k| k == key)
    }
}

pub(crate) fn detect(fs: &dyn Fs, notices: &mut Vec<String>) -> Sysctl {
    if !fs.exists(Path::new("/proc/sys/kernel")) {
        notices.push("/proc/sys not found; kernel settings are unknown".to_owned());
        return Sysctl::default();
    }
    let mut sysctl = Sysctl::default();
    for key in KEYS {
        let path = format!("/proc/sys/{}", key.replace('.', "/"));
        match fs.read(Path::new(&path)) {
            Ok(bytes) => {
                sysctl.values.insert(
                    key.to_owned(),
                    String::from_utf8_lossy(&bytes).trim().to_owned(),
                );
            }
            // The kernel was built without this setting.
            Err(SysError::NotFound(_)) => {}
            Err(SysError::Permission(_)) => sysctl.unreadable.push(key.to_owned()),
            Err(err) => notices.push(format!("reading {path}: {err}")),
        }
    }
    sysctl.ipv4_conf = ipv4_conf(fs, notices);
    // One notice, not one per file: on such kernels it is always a group.
    if !sysctl.unreadable.is_empty() {
        let (noun, verb, them) = if sysctl.unreadable.len() == 1 {
            ("setting", "is", "it")
        } else {
            ("settings", "are", "them")
        };
        notices.push(format!(
            "{} kernel {noun} {verb} readable only by root on this kernel ({}); \
             run with sudo to check {them}",
            sysctl.unreadable.len(),
            sysctl.unreadable.join(", ")
        ));
    }
    sysctl
}

fn ipv4_conf(fs: &dyn Fs, notices: &mut Vec<String>) -> BTreeMap<String, Ipv4Conf> {
    let dir = Path::new("/proc/sys/net/ipv4/conf");
    let entries = match fs.read_dir(dir) {
        Ok(entries) => entries,
        // The kernel was built without IPv4.
        Err(SysError::NotFound(_)) => return BTreeMap::new(),
        Err(err) => {
            notices.push(format!("reading {}: {err}", dir.display()));
            return BTreeMap::new();
        }
    };
    let mut confs = BTreeMap::new();
    'dirs: for entry in entries {
        let Some(name) = entry.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name == "lo" {
            continue;
        }
        let mut conf = Ipv4Conf::new();
        for key in CONF_KEYS {
            let path = entry.join(key);
            match fs.read(&path) {
                Ok(bytes) => {
                    conf.insert(
                        key.to_owned(),
                        String::from_utf8_lossy(&bytes).trim().to_owned(),
                    );
                }
                // The interface was removed after it was listed.
                Err(SysError::NotFound(_)) => continue 'dirs,
                Err(err) => notices.push(format!("reading {}: {err}", path.display())),
            }
        }
        confs.insert(name.to_owned(), conf);
    }
    confs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::fake::FakeFs;

    #[test]
    fn reads_listed_settings() {
        let fs = FakeFs::new()
            .with_file("/proc/sys/kernel/kptr_restrict", "1\n")
            .with_file("/proc/sys/net/ipv4/conf/all/accept_source_route", "0\n");
        let mut notices = Vec::new();
        let sysctl = detect(&fs, &mut notices);
        assert!(notices.is_empty(), "{notices:?}");
        assert_eq!(sysctl.get("kernel.kptr_restrict"), Some("1"));
        assert_eq!(
            sysctl.get("net.ipv4.conf.all.accept_source_route"),
            Some("0")
        );
        assert_eq!(sysctl.get("kernel.dmesg_restrict"), None);
    }

    #[test]
    fn reads_ipv4_conf_per_interface_but_lo() {
        let fs = ["all", "default", "eth0", "lo"]
            .iter()
            .fold(FakeFs::new(), |fs, dir| {
                CONF_KEYS.iter().fold(fs, |fs, key| {
                    fs.with_file(format!("/proc/sys/net/ipv4/conf/{dir}/{key}"), "1\n")
                })
            })
            .with_file("/proc/sys/kernel/kptr_restrict", "1\n")
            // An interface removed between listing and reading.
            .with_file("/proc/sys/net/ipv4/conf/veth0/forwarding", "1\n");
        let mut notices = Vec::new();
        let sysctl = detect(&fs, &mut notices);
        assert!(notices.is_empty(), "{notices:?}");
        assert_eq!(
            sysctl.ipv4_conf.keys().collect::<Vec<_>>(),
            ["all", "default", "eth0"]
        );
        assert_eq!(
            sysctl.ipv4_conf["eth0"]
                .get("rp_filter")
                .map(String::as_str),
            Some("1")
        );
    }

    /// Reads like `FakeFs`, but refuses the paths in `denied`, as a kernel
    /// with root-only files does.
    struct DenyFs<'a> {
        inner: FakeFs,
        denied: &'a [&'a str],
    }

    impl Fs for DenyFs<'_> {
        fn read(&self, path: &Path) -> Result<Vec<u8>, SysError> {
            if self.denied.iter().any(|d| Path::new(d) == path) {
                return Err(SysError::Permission(path.display().to_string()));
            }
            self.inner.read(path)
        }
        fn exists(&self, path: &Path) -> bool {
            self.inner.exists(path)
        }
        fn read_dir(&self, path: &Path) -> Result<Vec<std::path::PathBuf>, SysError> {
            self.inner.read_dir(path)
        }
        fn metadata(&self, path: &Path) -> Result<crate::sys::FileMeta, SysError> {
            self.inner.metadata(path)
        }
        fn write_atomic(
            &self,
            path: &Path,
            bytes: &[u8],
            owner: crate::sys::FileOwner,
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
        fn sync_dir(&self, path: &Path) -> Result<(), SysError> {
            self.inner.sync_dir(path)
        }
        fn try_lock(&self, path: &Path) -> Result<crate::sys::FsLock, SysError> {
            self.inner.try_lock(path)
        }
    }

    #[test]
    fn root_only_settings_are_one_notice() {
        let fs = DenyFs {
            inner: FakeFs::new()
                .with_file("/proc/sys/kernel/kptr_restrict", "1\n")
                .with_file("/proc/sys/fs/protected_symlinks", "1\n")
                .with_file("/proc/sys/fs/protected_hardlinks", "1\n"),
            denied: &[
                "/proc/sys/fs/protected_symlinks",
                "/proc/sys/fs/protected_hardlinks",
            ],
        };
        let mut notices = Vec::new();
        let sysctl = detect(&fs, &mut notices);
        assert_eq!(sysctl.get("kernel.kptr_restrict"), Some("1"));
        assert_eq!(sysctl.get("fs.protected_symlinks"), None);
        assert!(sysctl.is_unreadable("fs.protected_symlinks"));
        assert!(!sysctl.is_unreadable("kernel.dmesg_restrict"));
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert!(notices[0].starts_with("2 kernel settings are readable only by root"));
    }

    #[test]
    fn one_unreadable_setting_is_singular() {
        let fs = DenyFs {
            inner: FakeFs::new()
                .with_file("/proc/sys/kernel/kptr_restrict", "1\n")
                .with_file("/proc/sys/fs/protected_symlinks", "1\n"),
            denied: &["/proc/sys/fs/protected_symlinks"],
        };
        let mut notices = Vec::new();
        detect(&fs, &mut notices);
        assert!(notices[0].starts_with("1 kernel setting is readable only by root"));
        assert!(notices[0].ends_with("run with sudo to check it"));
    }

    #[test]
    fn missing_proc_sys_is_one_notice() {
        let mut notices = Vec::new();
        assert_eq!(detect(&FakeFs::new(), &mut notices), Sysctl::default());
        assert_eq!(notices.len(), 1);
    }
}
