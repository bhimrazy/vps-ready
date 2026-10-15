//! Automatic updates through apt, on Debian and Ubuntu.
//!
//! apt's daily jobs run `unattended-upgrade` when the `APT::Periodic`
//! settings ask for it. Under systemd the jobs are started by two timers;
//! without systemd, by cron. The settings are read with `apt-config`, which
//! applies apt's own rules across `apt.conf.d/`, as `sshd -T` does for SSH.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use super::{Init, Probe, Unit, probe, prop, systemctl_show};
use crate::sys::{Cmd, Fs, Runner};

/// apt's daily jobs under systemd: `apt-daily` refreshes the package lists
/// and `apt-daily-upgrade` installs the updates. Each timer starts the
/// service of the same name.
const UNITS: [&str; 4] = [
    "apt-daily.timer",
    "apt-daily-upgrade.timer",
    "apt-daily.service",
    "apt-daily-upgrade.service",
];

/// The program the `unattended-upgrades` package installs.
const UNATTENDED_UPGRADE: &str = "/usr/bin/unattended-upgrade";

/// How apt updates the host on its own.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AptUpdates {
    /// Whether the `unattended-upgrades` package is installed.
    pub unattended_upgrades: bool,
    /// Effective `APT::Periodic` settings, without the prefix, e.g.
    /// `Unattended-Upgrade` = `1`. A value is an interval: days by default,
    /// or e.g. `12h` or `always`. `0` or unset turns the job off.
    pub periodic: BTreeMap<String, String>,
    /// State of apt's timers and services: `ok`, or what keeps the job from
    /// running, e.g. `masked`, `disabled` or `inactive`. `None` without
    /// systemd, where cron may run the jobs instead, or when `systemctl`
    /// could not answer.
    pub units: Option<BTreeMap<String, String>>,
}

pub(super) fn detect(
    fs: &dyn Fs,
    runner: &dyn Runner,
    init: &Init,
    notices: &mut Vec<String>,
) -> Option<AptUpdates> {
    let periodic = periodic(runner, notices)?;
    let units = if *init == Init::Systemd {
        systemctl_show(runner, &UNITS, "apt's daily jobs are unknown", notices).map(|units| {
            units
                .iter()
                .map(|unit| (prop(unit, "Id").to_owned(), unit_state(unit).to_owned()))
                .collect()
        })
    } else {
        None
    };
    Some(AptUpdates {
        unattended_upgrades: fs.exists(Path::new(UNATTENDED_UPGRADE)),
        periodic,
        units,
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

/// `ok`, or the first thing that keeps the job from running. Masking the
/// services is a common way to silence apt lock errors, and it leaves the
/// timers active. A service only runs when its timer starts it, so only a
/// timer has to be active, and enabled so that it comes back after a
/// reboot (`enabled-runtime` does not).
fn unit_state(unit: &Unit) -> &str {
    let load = prop(unit, "LoadState");
    if load != "loaded" {
        return load;
    }
    if !prop(unit, "Id").ends_with(".timer") {
        return "ok";
    }
    match (prop(unit, "ActiveState"), prop(unit, "UnitFileState")) {
        (active, _) if active != "active" => active,
        (_, "") => "not enabled",
        (_, file) if file != "enabled" => file,
        _ => "ok",
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
    fn unit_states() {
        let unit = |id: &str, load: &str, active: &str, file: &str| {
            Unit::from([
                ("Id".to_owned(), id.to_owned()),
                ("LoadState".to_owned(), load.to_owned()),
                ("ActiveState".to_owned(), active.to_owned()),
                ("UnitFileState".to_owned(), file.to_owned()),
            ])
        };
        let timer = |load, active, file| unit("apt-daily.timer", load, active, file);
        let service = |load, active, file| unit("apt-daily.service", load, active, file);
        // States as `systemctl show` prints them on Debian 13.
        let cases = [
            (timer("loaded", "active", "enabled"), "ok"),
            (timer("masked", "failed", "masked"), "masked"),
            (timer("not-found", "inactive", ""), "not-found"),
            (timer("loaded", "inactive", "enabled"), "inactive"),
            (timer("loaded", "active", "disabled"), "disabled"),
            (
                timer("loaded", "active", "enabled-runtime"),
                "enabled-runtime",
            ),
            (service("loaded", "inactive", "static"), "ok"),
            (service("masked", "inactive", "masked"), "masked"),
        ];
        for (unit, want) in cases {
            assert_eq!(unit_state(&unit), want, "{unit:?}");
        }
    }

    #[test]
    fn units_are_queried_only_under_systemd() {
        let runner = FakeRunner::new().on(
            "apt-config",
            ["dump"],
            Output::success("APT::Periodic::Unattended-Upgrade \"1\";\n"),
        );
        let fs = FakeFs::new().with_file(UNATTENDED_UPGRADE, "");
        let mut notices = Vec::new();
        let apt = detect(&fs, &runner, &Init::OpenRc, &mut notices).unwrap();
        assert!(apt.unattended_upgrades);
        assert_eq!(apt.units, None);
        assert!(notices.is_empty(), "{notices:?}");
        assert!(runner.calls().iter().all(|c| c.program == "apt-config"));
    }

    /// The settings can still fail the control when systemd cannot be asked.
    #[test]
    fn failed_systemctl_keeps_the_settings() {
        let runner = FakeRunner::new().on(
            "apt-config",
            ["dump"],
            Output::success("APT::Periodic::Enable \"0\";\n"),
        );
        let mut notices = Vec::new();
        let apt = detect(&FakeFs::new(), &runner, &Init::Systemd, &mut notices).unwrap();
        assert_eq!(apt.periodic.get("Enable").map(String::as_str), Some("0"));
        assert_eq!(apt.units, None);
        assert_eq!(
            notices,
            ["systemctl not found; apt's daily jobs are unknown"]
        );
    }

    #[test]
    fn failed_apt_config_is_a_notice() {
        let failing = Output {
            status: 100,
            ..Output::success("")
        };
        for runner in [
            FakeRunner::new(),
            FakeRunner::new().on("apt-config", ["dump"], failing),
        ] {
            let mut notices = Vec::new();
            let apt = detect(&FakeFs::new(), &runner, &Init::Systemd, &mut notices);
            assert_eq!(apt, None);
            assert_eq!(notices.len(), 1, "{notices:?}");
        }
    }
}
