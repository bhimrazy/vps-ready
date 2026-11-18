//! Whether a reboot is pending, on Debian and Ubuntu.
//!
//! Two signals, both read from files. `/run/reboot-required` is written by
//! `update-notifier-common` (Ubuntu) and by the kernel hook of
//! `unattended-upgrades` (Debian). The hook is absent without that package,
//! so the running kernel is also compared with the images in `/boot`. A
//! security update often keeps the same release name and overwrites its
//! image, so the running kernel's own image is also checked for a change
//! after boot.

use std::path::Path;

use serde::Serialize;

use crate::sys::{Fs, SysError};

const FLAG: &str = "/run/reboot-required";

/// Seconds an image may be newer than boot time before it counts as
/// replaced, for clock steps at boot.
const SLACK: i64 = 60;

/// What the host says about a pending reboot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Reboot {
    /// Whether `/run/reboot-required` exists.
    pub flagged: bool,
    /// The running kernel's release, e.g. `6.1.0-43-amd64`. `None` when it
    /// could not be read.
    pub running: Option<String>,
    /// Releases of the kernel images in `/boot` (`vmlinuz-*`), sorted.
    pub installed: Vec<String>,
    /// Whether `/boot/vmlinuz-<running>` was modified after the system
    /// booted. `None` when that could not be told.
    pub image_replaced: Option<bool>,
}

impl Reboot {
    /// The newest installed kernel of the running kernel's flavor (the
    /// `amd64` or `generic` part of its release), when it is newer than the
    /// running one.
    #[must_use]
    pub fn newer_kernel(&self) -> Option<&str> {
        let running = self.running.as_deref()?;
        let (run_ver, flavor) = split_release(running);
        self.installed
            .iter()
            .filter(|r| split_release(r).1 == flavor)
            .max_by(|a, b| compare(split_release(a).0, split_release(b).0))
            .filter(|newest| compare(split_release(newest).0, run_ver).is_gt())
            .map(String::as_str)
    }
}

/// Splits `6.1.0-43-cloud-amd64` into the version (`6.1.0-43`) and the
/// flavor (`cloud-amd64`): after the first `-`, all-digit parts still belong
/// to the version.
fn split_release(release: &str) -> (&str, &str) {
    let mut end = release.find('-').unwrap_or(release.len());
    while let Some(rest) = release.get(end + 1..) {
        let part = rest.split('-').next().unwrap_or("");
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            break;
        }
        end += 1 + part.len();
    }
    (&release[..end], release.get(end + 1..).unwrap_or(""))
}

/// Orders versions the way dpkg does for the characters kernel releases
/// use: runs of digits by value, other runs by text.
fn compare(a: &str, b: &str) -> std::cmp::Ordering {
    fn runs(s: &str) -> Vec<&str> {
        let mut out = Vec::new();
        let mut start = 0;
        let mut prev: Option<bool> = None;
        for (i, c) in s.char_indices() {
            let digit = c.is_ascii_digit();
            if prev.is_some_and(|p| p != digit) {
                out.push(&s[start..i]);
                start = i;
            }
            prev = Some(digit);
        }
        if start < s.len() {
            out.push(&s[start..]);
        }
        out
    }
    let (a, b) = (runs(a), runs(b));
    for (x, y) in a.iter().zip(&b) {
        let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            _ => x.cmp(y),
        };
        if ord.is_ne() {
            return ord;
        }
    }
    a.len().cmp(&b.len())
}

pub(super) fn detect(fs: &dyn Fs, notices: &mut Vec<String>) -> Reboot {
    let running = match fs.read(Path::new("/proc/sys/kernel/osrelease")) {
        Ok(bytes) => Some(String::from_utf8_lossy(&bytes).trim().to_owned()),
        Err(err) => {
            notices.push(format!("reading the running kernel's release: {err}"));
            None
        }
    };
    let installed = match fs.read_dir(Path::new("/boot")) {
        Ok(entries) => entries
            .iter()
            .filter_map(|p| p.file_name()?.to_str()?.strip_prefix("vmlinuz-"))
            .map(str::to_owned)
            .collect(),
        Err(SysError::NotFound(_)) => Vec::new(),
        Err(err) => {
            notices.push(format!("listing /boot: {err}"));
            Vec::new()
        }
    };
    let image_replaced = running.as_deref().and_then(|r| image_replaced(fs, r));
    Reboot {
        flagged: fs.exists(Path::new(FLAG)),
        running,
        installed,
        image_replaced,
    }
}

/// Compares the image's mtime with `btime` in `/proc/stat`.
fn image_replaced(fs: &dyn Fs, running: &str) -> Option<bool> {
    let stat = fs.read(Path::new("/proc/stat")).ok()?;
    let btime: i64 = String::from_utf8_lossy(&stat)
        .lines()
        .find_map(|l| l.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()?;
    let image = fs
        .metadata(Path::new(&format!("/boot/vmlinuz-{running}")))
        .ok()?;
    Some(image.mtime > btime + SLACK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::fake::FakeFs;

    fn reboot(running: &str, installed: &[&str]) -> Reboot {
        Reboot {
            flagged: false,
            running: Some(running.to_owned()),
            installed: installed.iter().map(|s| (*s).to_owned()).collect(),
            image_replaced: None,
        }
    }

    #[test]
    fn splits_releases() {
        assert_eq!(split_release("6.1.0-43-amd64"), ("6.1.0-43", "amd64"));
        assert_eq!(
            split_release("6.1.0-43-cloud-amd64"),
            ("6.1.0-43", "cloud-amd64")
        );
        assert_eq!(
            split_release("6.12.57+deb13-amd64"),
            ("6.12.57+deb13", "amd64")
        );
        assert_eq!(
            split_release("5.15.0-130-generic"),
            ("5.15.0-130", "generic")
        );
        assert_eq!(split_release("6.8.0"), ("6.8.0", ""));
    }

    #[test]
    fn finds_a_newer_kernel() {
        let r = reboot(
            "6.1.0-9-amd64",
            &["6.1.0-9-amd64", "6.1.0-10-amd64", "6.1.0-43-cloud-amd64"],
        );
        // By value, not text (10 > 9); other flavors are ignored.
        assert_eq!(r.newer_kernel(), Some("6.1.0-10-amd64"));
        let r = reboot("6.12.57+deb13-amd64", &["6.12.117+deb13-amd64"]);
        assert_eq!(r.newer_kernel(), Some("6.12.117+deb13-amd64"));
        let r = reboot(
            "5.15.0-130-generic",
            &["5.15.0-130-generic", "5.15.0-9-generic"],
        );
        assert_eq!(r.newer_kernel(), None);
        // The running kernel was removed from /boot.
        let r = reboot("6.1.0-43-amd64", &["6.1.0-40-amd64"]);
        assert_eq!(r.newer_kernel(), None);
        assert_eq!(reboot("6.1.0-43-amd64", &[]).newer_kernel(), None);
    }

    #[test]
    fn reads_the_host() {
        let fs = FakeFs::new()
            .with_file("/proc/sys/kernel/osrelease", "6.1.0-9-amd64\n")
            .with_file("/boot/vmlinuz-6.1.0-9-amd64", "")
            .with_file("/boot/vmlinuz-6.1.0-10-amd64", "")
            .with_file("/boot/initrd.img-6.1.0-10-amd64", "")
            .with_file(FLAG, "");
        let mut notices = Vec::new();
        let r = detect(&fs, &mut notices);
        assert!(notices.is_empty(), "{notices:?}");
        assert!(r.flagged);
        assert_eq!(r.running.as_deref(), Some("6.1.0-9-amd64"));
        assert_eq!(r.installed, ["6.1.0-10-amd64", "6.1.0-9-amd64"]);
    }

    #[test]
    fn no_boot_dir_is_no_kernels() {
        let fs = FakeFs::new().with_file("/proc/sys/kernel/osrelease", "6.8.0\n");
        let mut notices = Vec::new();
        let r = detect(&fs, &mut notices);
        assert!(notices.is_empty(), "{notices:?}");
        assert!(!r.flagged);
        assert!(r.installed.is_empty());
    }

    #[test]
    fn detects_a_replaced_running_image() {
        let host = |mtime| {
            let fs = FakeFs::new()
                .with_file("/proc/sys/kernel/osrelease", "6.1.0-28-amd64\n")
                .with_file("/proc/stat", "cpu 1 2 3\nbtime 1000000\nprocesses 5\n")
                .with_file("/boot/vmlinuz-6.1.0-28-amd64", "")
                .with_mtime("/boot/vmlinuz-6.1.0-28-amd64", mtime);
            detect(&fs, &mut Vec::new()).image_replaced
        };
        assert_eq!(host(900_000), Some(false));
        // Within the slack of boot time.
        assert_eq!(host(1_000_030), Some(false));
        assert_eq!(host(1_000_061), Some(true));

        // No /proc/stat or no image: unknown, not a failure.
        let fs = FakeFs::new().with_file("/proc/sys/kernel/osrelease", "6.1.0-28-amd64\n");
        assert_eq!(detect(&fs, &mut Vec::new()).image_replaced, None);
    }
}
