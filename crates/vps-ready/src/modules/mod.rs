//! Modules: the policy that decides which [`Resource`]s a fix needs. They
//! only plan; the engine applies and rolls back.

use crate::facts::Facts;
use crate::resource::{Resource, ResourceError};
use crate::sys::{Sys, SysError};

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
    /// The resources in their desired state, in apply order. May read, never
    /// writes.
    ///
    /// # Errors
    ///
    /// [`ModuleError`] if what it needs cannot be read.
    fn plan(&self, facts: &Facts, sys: Sys) -> Result<Vec<Resource>, ModuleError>;
}
