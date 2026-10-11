//! Kernel settings, read from the files under `/proc/sys`.
//!
//! Only the settings in [`KEYS`] are read. Reading a file does not need a
//! command, and none of these files are restricted to root.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use crate::sys::{Fs, SysError};

/// The settings that are read, by their `sysctl` name. The audit catalog may
/// only use names listed here.
pub const KEYS: [&str; 13] = [
    "fs.protected_fifos",
    "fs.protected_hardlinks",
    "fs.protected_regular",
    "fs.protected_symlinks",
    "fs.suid_dumpable",
    "kernel.dmesg_restrict",
    "kernel.kptr_restrict",
    "kernel.randomize_va_space",
    "kernel.unprivileged_bpf_disabled",
    "kernel.yama.ptrace_scope",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.icmp_echo_ignore_broadcasts",
    "net.ipv4.tcp_syncookies",
];

/// Values of the settings in [`KEYS`]. A setting the kernel does not have,
/// e.g. `kernel.yama.ptrace_scope` without Yama, is absent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Sysctl(BTreeMap<String, String>);

impl Sysctl {
    /// The value of one setting, e.g. `get("kernel.kptr_restrict")`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }
}

pub(super) fn detect(fs: &dyn Fs, notices: &mut Vec<String>) -> Sysctl {
    if !fs.exists(Path::new("/proc/sys/kernel")) {
        notices.push("/proc/sys not found; kernel settings are unknown".to_owned());
        return Sysctl::default();
    }
    let mut values = BTreeMap::new();
    for key in KEYS {
        let path = format!("/proc/sys/{}", key.replace('.', "/"));
        match fs.read(Path::new(&path)) {
            Ok(bytes) => {
                values.insert(
                    key.to_owned(),
                    String::from_utf8_lossy(&bytes).trim().to_owned(),
                );
            }
            // The kernel was built without this setting.
            Err(SysError::NotFound(_)) => {}
            Err(err) => notices.push(format!("reading {path}: {err}")),
        }
    }
    Sysctl(values)
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
    fn missing_proc_sys_is_one_notice() {
        let mut notices = Vec::new();
        assert_eq!(detect(&FakeFs::new(), &mut notices), Sysctl::default());
        assert_eq!(notices.len(), 1);
    }
}
