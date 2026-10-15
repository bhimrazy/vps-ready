//! Automatic updates through apt, on Debian and Ubuntu.
//!
//! apt's daily jobs run `unattended-upgrade` when the `APT::Periodic`
//! settings ask for it. Under systemd the jobs are started by two timers;
//! without systemd, by cron. The settings are read with `apt-config`, which
//! applies apt's own rules across `apt.conf.d/`, as `sshd -T` does for SSH.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use super::{Init, Probe, Unit, parse_units, probe, prop};
use crate::sys::{Cmd, Fs, Runner};

/// apt's systemd timers: the first refreshes the package lists, the second
/// installs the updates.
const TIMERS: [&str; 2] = ["apt-daily.timer", "apt-daily-upgrade.timer"];

/// The program the `unattended-upgrades` package installs.
const UNATTENDED_UPGRADE: &str = "/usr/bin/unattended-upgrade";

/// How apt updates the host on its own.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AptUpdates {
    /// Whether the `unattended-upgrades` package is installed.
    pub unattended_upgrades: bool,
    /// Effective `APT::Periodic` settings, without the prefix, e.g.
    /// `Unattended-Upgrade` = `1`. A value is an interval in days; `0` or
    /// unset turns the job off.
    pub periodic: BTreeMap<String, String>,
    /// State of each of apt's timers: `active` when it is loaded, running and
    /// enabled at boot, otherwise what is wrong, e.g. `masked`, `disabled` or
    /// `inactive`. Empty without systemd, where cron runs the jobs.
    pub timers: BTreeMap<String, String>,
}

pub(super) fn detect(
    fs: &dyn Fs,
    runner: &dyn Runner,
    init: &Init,
    notices: &mut Vec<String>,
) -> Option<AptUpdates> {
    let periodic = periodic(runner, notices)?;
    let timers = if *init == Init::Systemd {
        timers(runner, notices)?
    } else {
        BTreeMap::new()
    };
    Some(AptUpdates {
        unattended_upgrades: fs.exists(Path::new(UNATTENDED_UPGRADE)),
        periodic,
        timers,
    })
}

fn periodic(runner: &dyn Runner, notices: &mut Vec<String>) -> Option<BTreeMap<String, String>> {
    let cmd = Cmd::new("apt-config").args(["dump", "APT::Periodic"]);
    match probe(runner, &cmd, notices) {
        Probe::Ran(out) if out.ok() => Some(parse_periodic(&String::from_utf8_lossy(&out.stdout))),
        Probe::Ran(out) => {
            notices.push(format!(
                "`apt-config dump` exited with {}; automatic updates are unknown",
                out.status
            ));
            None
        }
        Probe::Missing => {
            notices.push("apt-config not found; automatic updates are unknown".to_owned());
            None
        }
        Probe::Failed => None,
    }
}

/// Parses `apt-config dump APT::Periodic` lines such as
/// `APT::Periodic::Unattended-Upgrade "1";`.
fn parse_periodic(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let (key, value) = line.trim().strip_suffix(';')?.split_once(' ')?;
            let key = key.strip_prefix("APT::Periodic::")?;
            Some((key.to_owned(), value.trim().trim_matches('"').to_owned()))
        })
        .collect()
}

fn timers(runner: &dyn Runner, notices: &mut Vec<String>) -> Option<BTreeMap<String, String>> {
    let cmd = Cmd::new("systemctl")
        .args(["show", "--property=Id,LoadState,ActiveState,UnitFileState"])
        .args(TIMERS);
    match probe(runner, &cmd, notices) {
        Probe::Ran(out) if out.ok() => Some(
            parse_units(&String::from_utf8_lossy(&out.stdout))
                .iter()
                .map(|unit| (prop(unit, "Id").to_owned(), timer_state(unit).to_owned()))
                .collect(),
        ),
        Probe::Ran(out) => {
            notices.push(format!(
                "`systemctl show` exited with {}; apt's timers are unknown",
                out.status
            ));
            None
        }
        Probe::Missing => {
            notices.push("systemctl not found; apt's timers are unknown".to_owned());
            None
        }
        Probe::Failed => None,
    }
}

/// `active`, or the first thing that keeps the timer from firing: a masked
/// timer is `masked`, a stopped one e.g. `inactive`, and one that runs now
/// but will not start after a reboot `disabled`.
fn timer_state(unit: &Unit) -> &str {
    match (
        prop(unit, "LoadState"),
        prop(unit, "ActiveState"),
        prop(unit, "UnitFileState"),
    ) {
        (load, _, _) if load != "loaded" => load,
        (_, active, _) if active != "active" => active,
        (_, _, file) if !file.starts_with("enabled") => file,
        _ => "active",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::Output;
    use crate::sys::fake::{FakeFs, FakeRunner};

    #[test]
    fn parses_periodic_settings() {
        let parsed = parse_periodic(
            "APT::Periodic \"\";\nAPT::Periodic::Enable \"0\";\n\
             APT::Periodic::Unattended-Upgrade \"1\";\n",
        );
        assert_eq!(
            parsed,
            BTreeMap::from([
                ("Enable".to_owned(), "0".to_owned()),
                ("Unattended-Upgrade".to_owned(), "1".to_owned()),
            ])
        );
        assert!(parse_periodic("").is_empty());
    }

    #[test]
    fn timer_states() {
        let unit = |load: &str, active: &str, file: &str| {
            Unit::from([
                ("LoadState".to_owned(), load.to_owned()),
                ("ActiveState".to_owned(), active.to_owned()),
                ("UnitFileState".to_owned(), file.to_owned()),
            ])
        };
        // Real `systemctl show` output: masking a running timer fails it.
        let cases = [
            (unit("loaded", "active", "enabled"), "active"),
            (unit("masked", "failed", "masked"), "masked"),
            (unit("not-found", "inactive", ""), "not-found"),
            (unit("loaded", "inactive", "enabled"), "inactive"),
            (unit("loaded", "active", "disabled"), "disabled"),
        ];
        for (unit, want) in cases {
            assert_eq!(timer_state(&unit), want, "{unit:?}");
        }
    }

    #[test]
    fn timers_are_read_only_under_systemd() {
        let runner = FakeRunner::new().on(
            "apt-config",
            ["dump"],
            Output::success("APT::Periodic::Unattended-Upgrade \"1\";\n"),
        );
        let fs = FakeFs::new().with_file(UNATTENDED_UPGRADE, "");
        let mut notices = Vec::new();
        let apt = detect(&fs, &runner, &Init::OpenRc, &mut notices).unwrap();
        assert!(apt.unattended_upgrades);
        assert!(apt.timers.is_empty());
        assert!(notices.is_empty(), "{notices:?}");
        assert!(runner.calls().iter().all(|c| c.program == "apt-config"));
    }

    #[test]
    fn missing_apt_config_is_a_notice() {
        let mut notices = Vec::new();
        let apt = detect(
            &FakeFs::new(),
            &FakeRunner::new(),
            &Init::Systemd,
            &mut notices,
        );
        assert_eq!(apt, None);
        assert_eq!(notices.len(), 1, "{notices:?}");
    }
}
