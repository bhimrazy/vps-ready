//! `kernel.sysctl`: the kernel settings of the `KRN-*` and `NET-*` controls
//! marked `fix = "kernel.sysctl"`, set at runtime and kept across reboots by
//! a drop-in in `/etc/sysctl.d`.

use std::path::Path;

use super::{Applicability, Module, ModuleError};
use crate::audit::{self, Check};
use crate::facts::Facts;
use crate::resource::{File, Resource, Sysctl};
use crate::sys::{FileOwner, Sys, SysError};

/// The drop-in. It sorts after the distros' defaults; a `99-*` file or
/// `/etc/sysctl.conf` (read through Debian's `99-sysctl.conf`) can still
/// override it at boot.
pub const DROP_IN: &str = "/etc/sysctl.d/90-vps-ready.conf";

/// The value written for each key, in drop-in order. Each is in its
/// control's `one_of`, and the kernel accepts the old value back at runtime,
/// so rollback can restore it: not `unprivileged_bpf_disabled=1` or
/// `ptrace_scope=3`. `kptr_restrict=2` would hide `/proc/kallsyms` from root
/// too and break `perf` and `bpftrace`.
pub const VALUES: [(&str, &str); 14] = [
    ("kernel.kptr_restrict", "1"),
    ("kernel.dmesg_restrict", "1"),
    ("kernel.unprivileged_bpf_disabled", "2"),
    ("kernel.yama.ptrace_scope", "1"),
    ("kernel.randomize_va_space", "2"),
    ("kernel.perf_event_paranoid", "2"),
    ("fs.protected_symlinks", "1"),
    ("fs.protected_hardlinks", "1"),
    ("fs.protected_fifos", "1"),
    ("fs.protected_regular", "1"),
    ("fs.suid_dumpable", "0"),
    ("net.ipv4.tcp_syncookies", "1"),
    ("net.ipv4.conf.all.accept_source_route", "0"),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
];

const HEADER: &str = "# Written by vps-ready (kernel.sysctl). `vps-ready rollback --last`\n\
                      # restores the previous state; edits here are replaced by the next apply.\n";

/// The `kernel.sysctl` module.
#[derive(Debug, Clone, Copy)]
pub struct KernelSysctl {
    uid: u32,
    gid: u32,
}

impl KernelSysctl {
    /// The drop-in owned by root:root.
    pub const ROOT: Self = Self { uid: 0, gid: 0 };

    /// The drop-in owned by `uid:gid`, for tests that cannot `chown` to root.
    #[cfg(test)]
    fn owned_by(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }
}

impl Module for KernelSysctl {
    fn id(&self) -> &'static str {
        "kernel.sysctl"
    }

    fn title(&self) -> &'static str {
        "Harden kernel settings"
    }

    fn why(&self) -> &'static str {
        "Hides kernel addresses and logs from normal users, restricts BPF, ptrace and \
         perf, protects shared directories such as /tmp, and turns on SYN cookies."
    }

    fn applicable(&self, facts: &Facts) -> Applicability {
        if facts.sysctl.is_some() {
            Applicability::Applicable
        } else {
            Applicability::NotApplicable {
                reason: "kernel settings belong to the host inside a container".to_owned(),
            }
        }
    }

    /// A key goes into the drop-in if its running value fails its control or
    /// the existing drop-in lists it; only failing keys are also set at
    /// runtime. Keeping listed keys makes a second run a no-op, and leaving
    /// out passing ones keeps a distro's stricter value (Ubuntu's
    /// `perf_event_paranoid=4`) at the next boot.
    fn plan(&self, facts: &Facts, sys: Sys) -> Result<Vec<Resource>, ModuleError> {
        let Some(running) = &facts.sysctl else {
            return Ok(Vec::new());
        };
        let listed = listed_keys(sys)?;
        let controls = audit::catalog()?;
        let mut lines = String::new();
        let mut runtime = Vec::new();
        for (key, value) in VALUES {
            let Some(one_of) = controls.iter().find_map(|c| match &c.check {
                Check::Sysctl { key: k, one_of }
                    if k == key && c.fix.as_deref() == Some(self.id()) =>
                {
                    Some(one_of)
                }
                _ => None,
            }) else {
                continue;
            };
            let fails = running
                .get(key)
                .is_some_and(|v| !one_of.iter().any(|o| o == v));
            // A key the kernel lacks is skipped; one only root can read is
            // not set, but stays in the drop-in if listed (see `notes`).
            let exists = running.get(key).is_some() || running.is_unreadable(key);
            if fails {
                runtime.push(Resource::Sysctl(Sysctl {
                    key: key.to_owned(),
                    value: value.to_owned(),
                }));
            }
            if fails || (exists && listed.iter().any(|k| k == key)) {
                lines.push_str(&format!("{key} = {value}\n"));
            }
        }
        if lines.is_empty() {
            return Ok(Vec::new());
        }
        let file = Resource::File(File {
            path: DROP_IN.into(),
            content: format!("{HEADER}{lines}").into_bytes(),
            owner: FileOwner {
                mode: 0o644,
                uid: self.uid,
                gid: self.gid,
            },
            validate: None,
        });
        Ok(std::iter::once(file).chain(runtime).collect())
    }

    fn notes(&self, facts: &Facts) -> Vec<String> {
        let Some(running) = &facts.sysctl else {
            return Vec::new();
        };
        let skipped: Vec<&str> = VALUES
            .iter()
            .map(|(key, _)| *key)
            .filter(|key| running.is_unreadable(key))
            .collect();
        if skipped.is_empty() {
            return Vec::new();
        }
        let (noun, verb, them) = if skipped.len() == 1 {
            ("setting", "is", "it")
        } else {
            ("settings", "are", "them")
        };
        vec![format!(
            "{} kernel {noun} {verb} readable only by root on this kernel ({}), so the plan \
             skips {them}; run with sudo to plan {them}",
            skipped.len(),
            skipped.join(", ")
        )]
    }
}

/// The keys the existing drop-in sets, in `key = value` lines.
fn listed_keys(sys: Sys) -> Result<Vec<String>, ModuleError> {
    let bytes = match sys.fs.read(Path::new(DROP_IN)) {
        Ok(bytes) => bytes,
        Err(SysError::NotFound(_)) => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    Ok(String::from_utf8_lossy(&bytes)
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with(['#', ';']))
        .filter_map(|l| l.split_once('='))
        .map(|(key, _)| key.trim().trim_start_matches('-').replace('/', "."))
        .collect())
}

#[cfg(test)]
mod tests;
