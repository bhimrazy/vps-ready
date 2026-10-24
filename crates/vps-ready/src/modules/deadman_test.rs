//! `test.deadman`: a harmless module that needs the dead-man switch, so the
//! VM tests can arm it, let it fire and reboot during its window. Only in a
//! build with the `testing` feature.

use super::{Applicability, Module, ModuleError, ModuleSteps, NoParams, PlanCx};
use crate::engine::Reload;
use crate::facts::{Facts, Init};
use crate::resource::{File, Resource};
use crate::sys::{FileOwner, Sys};

/// The one file it writes.
pub const PATH: &str = "/etc/vps-ready-deadman-test.conf";

/// Writes [`PATH`] and reloads sshd (with an unchanged config), so a
/// rollback replays a real reload, also at boot before sshd runs.
#[derive(Debug, Clone, Copy)]
pub struct DeadmanTest;

impl Module for DeadmanTest {
    fn id(&self) -> &'static str {
        "test.deadman"
    }

    fn title(&self) -> &'static str {
        "Exercise the dead-man switch (test builds only)"
    }

    fn why(&self) -> &'static str {
        "Lets the VM tests check that an unconfirmed apply reverts."
    }

    fn needs_deadman(&self) -> bool {
        true
    }

    fn force_restore(&self) -> bool {
        true
    }

    fn applicable(&self, facts: &Facts) -> Applicability {
        if facts.init == Init::Systemd {
            Applicability::Applicable
        } else {
            Applicability::NotApplicable {
                reason: "the dead-man switch needs systemd".into(),
            }
        }
    }

    fn plan(&self, cx: &PlanCx, _: Sys) -> Result<ModuleSteps, ModuleError> {
        let NoParams {} = cx.params()?;
        Ok(ModuleSteps {
            resources: vec![Resource::File(File {
                path: PATH.into(),
                content:
                    b"# Written by the vps-ready test module; an unconfirmed apply removes it.\n"
                        .to_vec(),
                owner: FileOwner {
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                },
                validate: None,
            })],
            reloads: vec![Reload::SshdReload],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_the_dead_man_and_systemd() {
        let mut facts = crate::facts::fixtures::host("debian-13", &[]);
        assert!(DeadmanTest.needs_deadman() && DeadmanTest.force_restore());
        assert_eq!(DeadmanTest.applicable(&facts), Applicability::Applicable);
        facts.init = Init::OpenRc;
        assert!(matches!(
            DeadmanTest.applicable(&facts),
            Applicability::NotApplicable { .. }
        ));
    }
}
