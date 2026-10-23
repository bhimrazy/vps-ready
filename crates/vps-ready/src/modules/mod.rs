//! Modules: the policy that decides which [`Resource`]s a fix needs. They
//! only plan; the engine applies and rolls back.

use crate::audit::CatalogError;
use crate::facts::Facts;
use crate::resource::{Resource, ResourceError};
use crate::sys::{Sys, SysError};

pub mod kernel_sysctl;
mod updates_auto;

pub use kernel_sysctl::KernelSysctl;
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

/// A fix that vps-ready can apply.
pub trait Module {
    /// Stable ID, e.g. `kernel.sysctl`.
    fn id(&self) -> &'static str;
    /// One line for the plan.
    fn title(&self) -> &'static str;
    /// Why the change matters.
    fn why(&self) -> &'static str;
    /// Whether it can run on this host.
    fn applicable(&self, facts: &Facts) -> Applicability;
    /// What the plan should say besides its changes, e.g. something the
    /// module leaves alone. Asked only when it applies.
    fn notes(&self, _facts: &Facts) -> Vec<String> {
        Vec::new()
    }
    /// The resources in their desired state, in apply order. May read, never
    /// writes.
    ///
    /// # Errors
    ///
    /// [`ModuleError`] if what it needs cannot be read.
    fn plan(&self, facts: &Facts, sys: Sys) -> Result<Vec<Resource>, ModuleError>;
}

/// Every module, in the order the plan lists and applies them.
#[must_use]
pub fn all() -> &'static [&'static dyn Module] {
    &[&KernelSysctl::ROOT]
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
    fn every_fix_names_a_registered_module() {
        let ids: Vec<_> = all().iter().map(|m| m.id()).collect();
        for c in crate::audit::catalog().unwrap() {
            if let Some(fix) = &c.fix {
                assert!(ids.contains(&fix.as_str()), "{}: fix = {fix:?}", c.id);
            }
        }
    }
}
