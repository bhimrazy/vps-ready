//! `vpsready`: make a fresh Linux VPS ready for production, safely.
//!
//! `vpsready` is a single static binary that runs as root on a freshly
//! provisioned Linux server. It detects the system, audits it against a
//! catalogue of controls, plans hardening changes, and applies them with
//! snapshots and rollback. Changes that can lock you out (SSH, firewall) are
//! guarded by a dead-man switch: they are reverted automatically unless you
//! confirm them from a *new* SSH session.
//!
//! Non-goals: fleet management, a web UI, and self-update.
//!
//! # Crate layout
//!
//! - [`cli`]: argument parsing and command dispatch.
//! - [`sys`]: the only place that touches the host (processes and files),
//!   behind the [`sys::Runner`] and [`sys::Fs`] traits so everything else is
//!   testable with fakes.
//! - [`facts`]: read-only discovery of what the host is (OS, init system, ...).
//!
//! The library exists so that integration tests and future tooling can drive
//! the same code as the binary; it has no stability guarantees before 1.0.

use std::fmt;

use serde::Serialize;

pub mod cli;
pub mod facts;
pub mod sys;

/// Build metadata reported by `vpsready version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct VersionInfo {
    /// Crate version from `Cargo.toml`.
    pub version: &'static str,
    /// Git commit the binary was built from (`VPSREADY_COMMIT` at build time).
    pub commit: Option<&'static str>,
    /// Build date (`VPSREADY_BUILD_DATE` at build time), e.g. `2026-10-11`.
    pub build_date: Option<&'static str>,
    /// Target triple the binary was compiled for.
    pub target: &'static str,
}

/// Version and build metadata of this binary.
pub const VERSION_INFO: VersionInfo = VersionInfo {
    version: env!("CARGO_PKG_VERSION"),
    commit: option_env!("VPSREADY_COMMIT"),
    build_date: option_env!("VPSREADY_BUILD_DATE"),
    target: env!("VPSREADY_TARGET"),
};

impl fmt::Display for VersionInfo {
    /// Formats as `vpsready <version> (<commit> <date>) <target>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "vpsready {} ({} {}) {}",
            self.version,
            self.commit.unwrap_or("unknown"),
            self.build_date.unwrap_or("unknown"),
            self.target
        )
    }
}
