//! The [`Service`] resource.

use std::time::Duration;

use super::{Backup, ResourceError, run};
use crate::facts::{parse_units, prop};
use crate::sys::{Cmd, Sys};

/// A systemd unit that must be enabled or disabled, and active or not.
///
/// Only a unit whose unit file state is `enabled` or `disabled` (or that
/// does not exist yet) is managed; a masked, static or runtime-enabled unit
/// is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// Unit name with its suffix, e.g. `fail2ban.service`.
    pub unit: String,
    /// Whether it must be enabled.
    pub enabled: bool,
    /// Whether it must be active.
    pub active: bool,
}

/// Kill timeout of a `systemctl` command that changes something: longer than
/// systemd's default start and stop timeout of 90 s, which a start waits for.
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct State {
    enabled: bool,
    active: bool,
}

impl Service {
    /// The summary of the change, or `None`.
    pub(super) fn diff(&self, sys: Sys) -> Result<Option<(String, Option<String>)>, ResourceError> {
        let now = state(sys, &self.unit)?;
        let mut verbs = Vec::new();
        // In the order apply runs them.
        if now.active && !self.active {
            verbs.push("stop");
        }
        if now.enabled != self.enabled {
            verbs.push(if self.enabled { "enable" } else { "disable" });
        }
        if !now.active && self.active {
            verbs.push("start");
        }
        Ok((!verbs.is_empty()).then(|| (format!("{} {}", verbs.join(" and "), self.unit), None)))
    }

    pub(super) fn snapshot(&self, sys: Sys) -> Result<Backup, ResourceError> {
        let now = state(sys, &self.unit)?;
        Ok(Backup::Service {
            unit: self.unit.clone(),
            was_enabled: now.enabled,
            was_active: now.active,
            enabled: self.enabled,
            active: self.active,
        })
    }

    /// Reloads systemd first, since the unit file may be new in the same
    /// transaction.
    pub(super) fn apply(&self, sys: Sys) -> Result<(), ResourceError> {
        valid(&self.unit)?;
        run(sys, &systemctl(["daemon-reload"]))?;
        converge(sys, &self.unit, self.enabled, self.active)
    }
}

pub(super) fn restore(
    sys: Sys,
    unit: &str,
    was_enabled: bool,
    was_active: bool,
) -> Result<(), ResourceError> {
    converge(sys, unit, was_enabled, was_active)
}

/// The safety check: whether enabled and active are each the original or
/// the applied value. A unit that can no longer be managed (e.g. masked)
/// counts as changed.
pub(crate) fn unchanged(sys: Sys, backup: &Backup) -> Result<bool, ResourceError> {
    let Backup::Service {
        unit,
        was_enabled,
        was_active,
        enabled,
        active,
    } = backup
    else {
        return Ok(false);
    };
    let now = match state(sys, unit) {
        Ok(now) => now,
        Err(ResourceError::Unit { .. }) => return Ok(false),
        Err(e) => return Err(e),
    };
    Ok((now.enabled == *was_enabled || now.enabled == *enabled)
        && (now.active == *was_active || now.active == *active))
}

/// How to restore `backup` by hand; `None` if apply changed nothing.
pub(crate) fn by_hand(backup: &Backup) -> Option<String> {
    let Backup::Service {
        unit,
        was_enabled,
        was_active,
        enabled,
        active,
    } = backup
    else {
        return None;
    };
    let enable = (was_enabled != enabled).then_some(*was_enabled);
    let start = (was_active != active).then_some(*was_active);
    let step = match (enable, start) {
        (Some(true), Some(true)) => format!("systemctl enable --now {unit}"),
        (Some(false), Some(false)) => format!("systemctl disable --now {unit}"),
        (Some(on), Some(_)) => format!(
            "systemctl {} {unit}; systemctl {} {unit}",
            if on { "enable" } else { "disable" },
            if *was_active { "start" } else { "stop" }
        ),
        (Some(on), None) => format!("systemctl {} {unit}", if on { "enable" } else { "disable" }),
        (None, Some(on)) => format!("systemctl {} {unit}", if on { "start" } else { "stop" }),
        (None, None) => return None,
    };
    Some(step)
}

/// Brings `unit` to `enabled` and `active`: stops first, starts last.
fn converge(sys: Sys, unit: &str, enabled: bool, active: bool) -> Result<(), ResourceError> {
    let now = state(sys, unit)?;
    if now.active && !active {
        run(sys, &systemctl(["stop", unit]))?;
    }
    if now.enabled != enabled {
        let verb = if enabled { "enable" } else { "disable" };
        run(sys, &systemctl([verb, unit]))?;
    }
    if !now.active && active {
        run(sys, &systemctl(["start", unit]))?;
    }
    Ok(())
}

/// The unit's state from `systemctl show`. A unit systemd does not know
/// (`LoadState=not-found`) is disabled and inactive.
fn state(sys: Sys, unit: &str) -> Result<State, ResourceError> {
    valid(unit)?;
    let cmd = Cmd::new("systemctl")
        .args(["show", "--property=LoadState,UnitFileState,ActiveState"])
        .arg(unit);
    let out = run(sys, &cmd)?;
    let units = parse_units(out.stdout_str()?);
    let props = units.first().cloned().unwrap_or_default();
    let refuse = |reason: String| ResourceError::Unit {
        unit: unit.to_owned(),
        reason,
    };
    if prop(&props, "LoadState") == "masked" {
        return Err(refuse("it is masked".to_owned()));
    }
    let enabled = match prop(&props, "UnitFileState") {
        "enabled" => true,
        "disabled" | "" => false,
        other => return Err(refuse(format!("its unit file state is {other}"))),
    };
    let active = matches!(
        prop(&props, "ActiveState"),
        "active" | "reloading" | "refreshing"
    );
    Ok(State { enabled, active })
}

/// A unit name with a suffix, made of the characters systemd allows, that
/// cannot pass as an option.
fn valid(unit: &str) -> Result<(), ResourceError> {
    let ok = !unit.starts_with('-')
        && unit.contains('.')
        && unit
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ":-_.@\\".contains(c));
    if ok {
        Ok(())
    } else {
        Err(ResourceError::InvalidName {
            kind: "unit",
            name: unit.to_owned(),
        })
    }
}

fn systemctl<'a>(args: impl IntoIterator<Item = &'a str>) -> Cmd {
    Cmd::new("systemctl").args(args).timeout(SYSTEMCTL_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::super::{Change, Resource, Reversibility, restore};
    use super::*;
    use crate::sys::Output;
    use crate::sys::fake::{FakeFs, FakeRunner};

    const UNIT: &str = "fail2ban.service";
    const TXN: &str = "/var/lib/vps-ready/txn/20261023T114246Z";

    fn service(enabled: bool, active: bool) -> Resource {
        Resource::Service(Service {
            unit: UNIT.into(),
            enabled,
            active,
        })
    }

    /// `systemctl show` output as systemd prints it.
    fn show(load: &str, file: &str, active: &str) -> Output {
        Output::success(format!(
            "LoadState={load}\nActiveState={active}\nUnitFileState={file}\n"
        ))
    }

    fn show_cmd() -> Cmd {
        Cmd::new("systemctl").args([
            "show",
            "--property=LoadState,UnitFileState,ActiveState",
            UNIT,
        ])
    }

    fn change(verb: &str, unit: &str) -> Cmd {
        Cmd::new("systemctl")
            .args([verb, unit])
            .timeout(Duration::from_secs(120))
    }

    fn runner(out: Output) -> FakeRunner {
        FakeRunner::new().on("systemctl", ["show"], out).on(
            "systemctl",
            Vec::<String>::new(),
            Output::success(""),
        )
    }

    fn diff_with(resource: &Resource, out: Output) -> Result<Option<Change>, ResourceError> {
        let fs = FakeFs::new();
        let runner = runner(out);
        let result = resource.diff(Sys {
            fs: &fs,
            runner: &runner,
        });
        assert_eq!(runner.calls(), [show_cmd()]);
        result
    }

    #[test]
    fn diff_lists_the_steps_in_order() {
        let off = || show("loaded", "disabled", "inactive");
        let on = || show("loaded", "enabled", "active");
        let summary = |r: &Resource, out| diff_with(r, out).unwrap().map(|c| c.summary);
        assert_eq!(
            summary(&service(true, true), off()).as_deref(),
            Some("enable and start fail2ban.service")
        );
        assert_eq!(
            summary(&service(false, false), on()).as_deref(),
            Some("stop and disable fail2ban.service")
        );
        assert_eq!(
            summary(&service(true, false), off()).as_deref(),
            Some("enable fail2ban.service")
        );
        assert_eq!(summary(&service(true, true), on()), None);
        let change = diff_with(&service(true, true), off()).unwrap().unwrap();
        assert_eq!(change.id, "service:fail2ban.service");
        assert_eq!(change.reversibility, Reversibility::Reversible);
    }

    #[test]
    fn a_unit_systemd_does_not_know_is_off() {
        let summary = diff_with(&service(true, true), show("not-found", "", "inactive"))
            .unwrap()
            .map(|c| c.summary);
        assert_eq!(
            summary.as_deref(),
            Some("enable and start fail2ban.service")
        );
    }

    #[test]
    fn masked_and_static_units_are_refused() {
        let err =
            diff_with(&service(true, true), show("masked", "masked", "inactive")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "refusing to manage unit fail2ban.service: it is masked"
        );
        let err =
            diff_with(&service(true, true), show("loaded", "static", "inactive")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "refusing to manage unit fail2ban.service: its unit file state is static"
        );
    }

    #[test]
    fn a_name_that_could_be_an_option_is_refused() {
        let fs = FakeFs::new();
        let runner = FakeRunner::new();
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        for unit in ["--now", "fail2ban", "a b.service", "x/y.service"] {
            let resource = Resource::Service(Service {
                unit: unit.into(),
                enabled: true,
                active: true,
            });
            let err = resource.diff(sys).unwrap_err();
            assert!(
                matches!(err, ResourceError::InvalidName { kind: "unit", .. }),
                "{err:?}"
            );
            assert!(resource.apply(sys).is_err());
        }
        assert_eq!(runner.calls(), []);
    }

    #[test]
    fn apply_reloads_then_enables_and_starts() {
        let fs = FakeFs::new();
        let runner = runner(show("not-found", "", "inactive"));
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        service(true, true).apply(sys).unwrap();
        assert_eq!(
            runner.calls(),
            [
                Cmd::new("systemctl")
                    .arg("daemon-reload")
                    .timeout(Duration::from_secs(120)),
                show_cmd(),
                change("enable", UNIT),
                change("start", UNIT),
            ]
        );
    }

    #[test]
    fn apply_fails_when_start_fails() {
        let fs = FakeFs::new();
        let runner = FakeRunner::new()
            .on(
                "systemctl",
                ["show"],
                show("loaded", "disabled", "inactive"),
            )
            .on(
                "systemctl",
                ["start"],
                Output {
                    status: 1,
                    stdout: Vec::new(),
                    stderr: b"Job for fail2ban.service failed.\n".to_vec(),
                },
            )
            .on("systemctl", Vec::<String>::new(), Output::success(""));
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let err = service(true, true).apply(sys).unwrap_err();
        assert_eq!(
            err.to_string(),
            "`systemctl` exited with status 1: Job for fail2ban.service failed."
        );
    }

    #[test]
    fn snapshot_and_restore() {
        let fs = FakeFs::new();
        let runner = runner(show("loaded", "enabled", "active"));
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let backup = service(true, true)
            .snapshot(sys, Path::new(TXN), 1)
            .unwrap();
        assert_eq!(
            backup,
            Backup::Service {
                unit: UNIT.into(),
                was_enabled: true,
                was_active: true,
                enabled: true,
                active: true,
            }
        );
        // Restoring a unit that was off stops it before disabling it.
        let off = Backup::Service {
            unit: UNIT.into(),
            was_enabled: false,
            was_active: false,
            enabled: true,
            active: true,
        };
        restore(sys, Path::new(TXN), &off).unwrap();
        assert_eq!(
            runner.calls()[1..],
            [show_cmd(), change("stop", UNIT), change("disable", UNIT)]
        );
    }

    #[test]
    fn restore_of_a_unit_already_back_does_nothing() {
        let fs = FakeFs::new();
        let runner = runner(show("loaded", "disabled", "inactive"));
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let backup = Backup::Service {
            unit: UNIT.into(),
            was_enabled: false,
            was_active: false,
            enabled: true,
            active: true,
        };
        restore(sys, Path::new(TXN), &backup).unwrap();
        assert_eq!(runner.calls(), [show_cmd()]);
    }

    #[test]
    fn unchanged_allows_original_or_applied() {
        let backup = |was_active, active| Backup::Service {
            unit: UNIT.into(),
            was_enabled: false,
            was_active,
            enabled: true,
            active,
        };
        let check = |out: Output, backup: &Backup| {
            let fs = FakeFs::new();
            let runner = runner(out);
            unchanged(
                Sys {
                    fs: &fs,
                    runner: &runner,
                },
                backup,
            )
            .unwrap()
        };
        let started = backup(false, true);
        assert!(check(show("loaded", "enabled", "active"), &started));
        assert!(check(show("loaded", "disabled", "inactive"), &started));
        assert!(check(show("loaded", "enabled", "inactive"), &started));
        // Apply only enabled a running unit; someone stopped it since.
        let enabled_only = backup(true, true);
        assert!(check(show("loaded", "enabled", "active"), &enabled_only));
        assert!(!check(show("loaded", "enabled", "inactive"), &enabled_only));
        assert!(!check(show("masked", "masked", "inactive"), &started));
    }

    #[test]
    fn by_hand_steps() {
        let step = |was_enabled, was_active, enabled, active| {
            by_hand(&Backup::Service {
                unit: UNIT.into(),
                was_enabled,
                was_active,
                enabled,
                active,
            })
        };
        assert_eq!(
            step(false, false, true, true).as_deref(),
            Some("systemctl disable --now fail2ban.service")
        );
        assert_eq!(
            step(true, true, false, false).as_deref(),
            Some("systemctl enable --now fail2ban.service")
        );
        assert_eq!(
            step(false, true, true, false).as_deref(),
            Some("systemctl disable fail2ban.service; systemctl start fail2ban.service")
        );
        assert_eq!(
            step(true, false, true, true).as_deref(),
            Some("systemctl stop fail2ban.service")
        );
        assert_eq!(step(true, true, true, true), None);
    }
}
