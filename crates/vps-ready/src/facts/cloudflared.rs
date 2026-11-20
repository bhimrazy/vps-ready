//! cloudflared, the Cloudflare Tunnel connector: its version, its systemd
//! units and the config files it would read on its own.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use super::{Probe, probe};
use crate::sys::{Cmd, Fs, Runner};

/// Where cloudflared looks for `config.yml` or `config.yaml` without
/// `--config`; a home directory's are left out, since the connector has none.
pub const CONFIG_DIRS: [&str; 2] = ["/etc/cloudflared", "/usr/local/etc/cloudflared"];

/// cloudflared on this host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Cloudflared {
    /// From `cloudflared --version`, e.g. `2026.11.1`; `None` when it is
    /// not installed or did not say.
    pub version: Option<String>,
    /// Units whose name contains `cloudflared`, with a unit file or loaded,
    /// vps-ready's own included.
    pub units: Vec<String>,
    /// Those of [`Cloudflared::units`] that are active.
    pub active: Vec<String>,
    /// Config files cloudflared would find on its own, in [`CONFIG_DIRS`].
    pub configs: Vec<PathBuf>,
}

impl Cloudflared {
    /// Whether a connector runs: an active cloudflared service other than
    /// one that only restarts another.
    #[must_use]
    pub fn connector_runs(&self) -> bool {
        self.active
            .iter()
            .any(|u| u.ends_with(".service") && !u.ends_with("-restart.service"))
    }
}

pub(super) fn detect(fs: &dyn Fs, runner: &dyn Runner, notices: &mut Vec<String>) -> Cloudflared {
    let version = match probe(runner, &version_cmd(), notices) {
        Probe::Ran(out) if out.ok() => parse_version(&String::from_utf8_lossy(&out.stdout)),
        Probe::Ran(out) => {
            notices.push(format!(
                "`cloudflared --version` exited with {}; its version is unknown",
                out.status
            ));
            None
        }
        Probe::Missing | Probe::Failed => None,
    };
    let list = |args: &[&str], notices: &mut Vec<String>| match probe(
        runner,
        &Cmd::new("systemctl").args(args.iter().copied()),
        notices,
    ) {
        Probe::Ran(out) if out.ok() => first_words(&String::from_utf8_lossy(&out.stdout)),
        _ => Vec::new(),
    };
    let active = list(
        &[
            "list-units",
            "--no-legend",
            "--plain",
            "--full",
            "--state=active",
            "*cloudflared*",
        ],
        notices,
    );
    let mut units = list(
        &["list-unit-files", "--no-legend", "--full", "*cloudflared*"],
        notices,
    );
    units.extend(active.iter().cloned());
    units.sort();
    units.dedup();
    let configs = CONFIG_DIRS
        .iter()
        .flat_map(|dir| ["config.yml", "config.yaml"].map(|f| Path::new(dir).join(f)))
        .filter(|p| fs.exists(p))
        .collect();
    Cloudflared {
        version,
        units,
        active,
        configs,
    }
}

/// `cloudflared --version`.
pub(crate) fn version_cmd() -> Cmd {
    Cmd::new("cloudflared")
        .arg("--version")
        .timeout(Duration::from_secs(10))
}

/// The version in `cloudflared version 2026.11.1 (built ...)`.
pub(crate) fn parse_version(text: &str) -> Option<String> {
    let mut words = text.split_whitespace();
    words.find(|w| *w == "version")?;
    words.next().map(str::to_owned)
}

/// The first word of each line: the unit names of `systemctl list-units`
/// and `list-unit-files` without a legend.
fn first_words(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::Output;
    use crate::sys::fake::{FakeFs, FakeRunner};

    #[test]
    fn parses_the_version() {
        assert_eq!(
            parse_version("cloudflared version 2026.11.1 (built 2026-11-19-1200 UTC)\n"),
            Some("2026.11.1".into())
        );
        assert_eq!(parse_version("cloudflared\n"), None);
    }

    #[test]
    fn finds_units_and_configs() {
        let runner = FakeRunner::new()
            .on(
                "cloudflared",
                ["--version"],
                Output::success("cloudflared version 2025.4.0 (built 2025-04-01)\n"),
            )
            .on(
                "systemctl",
                ["list-units"],
                Output::success("cloudflared.service loaded active running cloudflared\n"),
            )
            .on(
                "systemctl",
                ["list-unit-files"],
                Output::success(
                    "cloudflared.service enabled enabled\n\
                     cloudflared-update.timer disabled enabled\n",
                ),
            );
        let fs = FakeFs::new().with_file("/etc/cloudflared/config.yml", "tunnel: x\n");
        let found = detect(&fs, &runner, &mut Vec::new());
        assert_eq!(
            found,
            Cloudflared {
                version: Some("2025.4.0".into()),
                units: vec![
                    "cloudflared-update.timer".into(),
                    "cloudflared.service".into()
                ],
                active: vec!["cloudflared.service".into()],
                configs: vec!["/etc/cloudflared/config.yml".into()],
            }
        );
        assert!(found.connector_runs());
    }

    #[test]
    fn nothing_without_cloudflared() {
        let found = detect(&FakeFs::new(), &FakeRunner::new(), &mut Vec::new());
        assert_eq!(found, Cloudflared::default());
        assert!(!found.connector_runs());
        let restart = Cloudflared {
            active: vec!["vps-ready-cloudflared-restart.service".into()],
            ..Cloudflared::default()
        };
        assert!(!restart.connector_runs());
    }
}
