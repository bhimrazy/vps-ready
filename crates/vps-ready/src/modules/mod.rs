//! Modules: the policy that decides which [`Resource`]s a fix needs. They
//! only plan and verify; the engine applies and rolls back.

use serde::de::DeserializeOwned;

use crate::audit::CatalogError;
use crate::engine::Reload;
use crate::facts::Facts;
use crate::resource::{Resource, ResourceError};
use crate::sys::{Sys, SysError};

#[cfg(feature = "testing")]
mod deadman_test;
pub mod kernel_sysctl;
pub mod ssh_bruteforce;
mod updates_auto;

#[cfg(feature = "testing")]
pub use deadman_test::DeadmanTest;
pub use kernel_sysctl::KernelSysctl;
pub use ssh_bruteforce::SshBruteforce;
pub use updates_auto::UpdatesAuto;

/// Errors from planning a module.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ModuleError {
    /// A resource could not be read.
    #[error(transparent)]
    Resource(#[from] ResourceError),
    /// The system boundary failed.
    #[error(transparent)]
    Sys(#[from] SysError),
    /// The controls catalog did not parse. Boxed: the parse error is large.
    #[error(transparent)]
    Catalog(Box<CatalogError>),
    /// The module's params did not parse, e.g. an unknown field. Boxed:
    /// the parse error is large.
    #[error("invalid params: {0}")]
    Params(#[source] Box<toml::de::Error>),
}

impl From<CatalogError> for ModuleError {
    fn from(err: CatalogError) -> Self {
        Self::Catalog(Box::new(err))
    }
}

/// Whether a module can run on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applicability {
    /// It can.
    Applicable,
    /// It cannot, and why, e.g. `apt not found`.
    NotApplicable {
        /// Shown in the plan.
        reason: String,
    },
}

/// What a module plans and verifies with.
#[derive(Debug, Clone, Copy)]
pub struct PlanCx<'a> {
    /// The host.
    pub facts: &'a Facts,
    /// The module's table from the profile; empty when there is none.
    pub params: &'a toml::Table,
}

impl PlanCx<'_> {
    /// Parses [`PlanCx::params`] into the module's params, a
    /// `#[serde(deny_unknown_fields)]` struct, so that a typo is an error.
    ///
    /// # Errors
    ///
    /// [`ModuleError::Params`].
    pub fn params<T: DeserializeOwned>(&self) -> Result<T, ModuleError> {
        parse_params(self.params)
    }
}

/// Parses a module's table into its params `T`.
///
/// # Errors
///
/// [`ModuleError::Params`].
pub fn parse_params<T: DeserializeOwned>(params: &toml::Table) -> Result<T, ModuleError> {
    toml::Value::Table(params.clone())
        .try_into()
        .map_err(|e| ModuleError::Params(Box::new(e)))
}

/// The params of a module that takes none: any field is an error.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

/// What a module plans: its resources and the reloads they need.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleSteps {
    /// In their desired state, in apply order.
    pub resources: Vec<Resource>,
    /// Run in order after the module's resources are applied, if any of
    /// them changed.
    pub reloads: Vec<Reload>,
}

impl From<Vec<Resource>> for ModuleSteps {
    fn from(resources: Vec<Resource>) -> Self {
        Self {
            resources,
            reloads: Vec::new(),
        }
    }
}

/// A fix that vps-ready can apply.
pub trait Module {
    /// Stable ID, e.g. `kernel.sysctl`.
    fn id(&self) -> &'static str;
    /// One line for the plan.
    fn title(&self) -> &'static str;
    /// Why the change matters.
    fn why(&self) -> &'static str;
    /// Whether its changes can lock the admin out, so apply arms the
    /// dead-man switch and waits for a confirm.
    fn needs_deadman(&self) -> bool {
        false
    }
    /// Whether a dead-man rollback restores its resources even if they
    /// changed since apply, since leaving them is the lockout.
    fn force_restore(&self) -> bool {
        false
    }
    /// Whether it can run on this host.
    fn applicable(&self, facts: &Facts) -> Applicability;
    /// What the plan should say besides its changes, e.g. something the
    /// module leaves alone. Asked only when it applies.
    fn notes(&self, _facts: &Facts) -> Vec<String> {
        Vec::new()
    }
    /// Checks a profile's table for this module without planning, so a typo
    /// is found even on a host the module does not apply to. The default is
    /// for a module that takes no params; one that does parses the same
    /// struct as [`PlanCx::params`].
    ///
    /// # Errors
    ///
    /// [`ModuleError::Params`].
    fn check_params(&self, params: &toml::Table) -> Result<(), ModuleError> {
        parse_params::<NoParams>(params).map(|NoParams {}| ())
    }
    /// The resources in their desired state and the reloads they need. May
    /// read, never writes.
    ///
    /// # Errors
    ///
    /// [`ModuleError`] if its params are invalid or what it needs cannot be
    /// read.
    fn plan(&self, cx: &PlanCx, sys: Sys) -> Result<ModuleSteps, ModuleError>;
    /// Checks after apply and reloads, beyond every resource being in its
    /// desired state, e.g. that a daemon runs with the new settings. May
    /// read, never writes.
    ///
    /// # Errors
    ///
    /// What is wrong, for the message.
    fn verify(&self, _cx: &PlanCx, _sys: Sys) -> Result<(), String> {
        Ok(())
    }
}

/// Every module, in the order the plan lists and applies them.
#[must_use]
pub fn all() -> &'static [&'static dyn Module] {
    &[
        &SshBruteforce::ROOT,
        &KernelSysctl::ROOT,
        &UpdatesAuto::ROOT,
    ]
}

/// [`all`] and the test module [`DeadmanTest`]; only in a build with the
/// `testing` feature.
#[cfg(feature = "testing")]
#[must_use]
pub fn with_test() -> &'static [&'static dyn Module] {
    &[
        &SshBruteforce::ROOT,
        &KernelSysctl::ROOT,
        &UpdatesAuto::ROOT,
        &DeadmanTest,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_ids_are_unique() {
        let mut ids: Vec<_> = all().iter().map(|m| m.id()).collect();
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), count, "{ids:?}");
    }

    #[test]
    fn every_module_rejects_unknown_params() {
        let facts = crate::facts::fixtures::host("debian-13", &[]);
        let params: toml::Table = toml::from_str("typo = 1").unwrap();
        let cx = PlanCx {
            facts: &facts,
            params: &params,
        };
        let (fs, runner) = (
            crate::sys::fake::FakeFs::new(),
            crate::sys::fake::FakeRunner::new(),
        );
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        for m in all() {
            for err in [
                m.plan(&cx, sys).unwrap_err(),
                m.check_params(&params).unwrap_err(),
            ] {
                assert!(
                    err.to_string().contains("unknown field `typo`"),
                    "{}: {err}",
                    m.id()
                );
            }
        }
    }

    #[test]
    fn every_fix_names_a_registered_module() {
        let ids: Vec<_> = all().iter().map(|m| m.id()).collect();
        for c in crate::audit::catalog().unwrap() {
            if let Some(fix) = &c.fix {
                assert!(ids.contains(&fix.as_str()), "{}: fix = {fix:?}", c.id);
            }
        }
    }
}
