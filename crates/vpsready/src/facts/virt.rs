//! Virtualization and container detection.
//!
//! On systemd hosts this asks `systemd-detect-virt`, which knows every common
//! hypervisor and container runtime. Without it (OpenRC), only the container
//! marker files that Docker and Podman create are checked.

use std::fmt;
use std::path::Path;

use serde::Serialize;

use super::{Probe, probe};
use crate::sys::{Cmd, Fs, Runner};

/// One kind of virtualization (container or VM), as reported by
/// `systemd-detect-virt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Virt {
    /// Not virtualized in this way.
    None,
    /// Could not be determined.
    Unknown,
    /// The detected technology, e.g. `kvm`, `docker`, `lxc`.
    #[serde(untagged)]
    Detected(String),
}

impl fmt::Display for Virt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::Unknown => f.write_str("unknown"),
            Self::Detected(name) => f.write_str(name),
        }
    }
}

/// Whether the host is a VM, a container, or a container inside a VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Virtualization {
    /// Container runtime, if any.
    pub container: Virt,
    /// Hypervisor, if any.
    pub vm: Virt,
}

impl Virtualization {
    /// Whether we run inside a container. Kernel settings such as sysctl then
    /// belong to the host and must not be changed from here.
    #[must_use]
    pub fn in_container(&self) -> bool {
        matches!(self.container, Virt::Detected(_))
    }
}

pub(super) fn detect(
    fs: &dyn Fs,
    runner: &dyn Runner,
    notices: &mut Vec<String>,
) -> Virtualization {
    let container = match detect_virt(runner, "--container", notices) {
        Probe::Ran(virt) => virt,
        Probe::Missing | Probe::Failed => {
            let marker = [("/.dockerenv", "docker"), ("/run/.containerenv", "podman")]
                .into_iter()
                .find(|(path, _)| fs.exists(Path::new(path)));
            match marker {
                Some((_, name)) => Virt::Detected(name.to_owned()),
                None => Virt::Unknown,
            }
        }
    };
    let vm = match detect_virt(runner, "--vm", notices) {
        Probe::Ran(virt) => virt,
        Probe::Missing => {
            notices.push("systemd-detect-virt not found; virtualization is unknown".to_owned());
            Virt::Unknown
        }
        Probe::Failed => Virt::Unknown,
    };
    Virtualization { container, vm }
}

/// Runs `systemd-detect-virt <flag>`. It prints `none` and exits 1 when
/// nothing is detected, so the exit code is not checked; empty output counts
/// as unknown.
fn detect_virt(runner: &dyn Runner, flag: &str, notices: &mut Vec<String>) -> Probe<Virt> {
    match probe(runner, &Cmd::new("systemd-detect-virt").arg(flag), notices) {
        Probe::Ran(out) => Probe::Ran(match String::from_utf8_lossy(&out.stdout).trim() {
            "" => Virt::Unknown,
            "none" => Virt::None,
            name => Virt::Detected(name.to_owned()),
        }),
        Probe::Missing => Probe::Missing,
        Probe::Failed => Probe::Failed,
    }
}
