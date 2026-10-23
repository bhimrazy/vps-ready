//! Planning: what the modules would change on this host.

use serde::Serialize;

use super::EngineError;
use crate::facts::Facts;
use crate::modules::{Applicability, Module};
use crate::resource::{Change, Resource};
use crate::sys::Sys;

/// What `apply` would change, module by module. Serializes for `plan --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    /// In the order the modules were given.
    pub modules: Vec<ModulePlan>,
}

/// One module's part of a [`Plan`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModulePlan {
    /// [`Module::id`].
    pub id: &'static str,
    /// [`Module::title`].
    pub title: &'static str,
    /// Whether it applies, and its changes if it does.
    #[serde(flatten)]
    pub status: ModuleStatus,
    /// [`Module::notes`]; empty when it does not apply.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Whether a module applies, with its changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum ModuleStatus {
    /// It applies; `changes` is empty when nothing needs to change.
    Applicable {
        /// In apply order.
        changes: Vec<Step>,
    },
    /// It does not apply.
    NotApplicable {
        /// Why not.
        reason: String,
    },
}

/// A resource that has a change, and the change as shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Step {
    /// What [`Resource::diff`] returned at plan time.
    #[serde(flatten)]
    pub change: Change,
    /// The resource in its desired state.
    #[serde(skip)]
    pub resource: Resource,
}

impl Plan {
    /// Every step, in apply order.
    pub fn steps(&self) -> impl Iterator<Item = &Step> {
        self.modules.iter().flat_map(|m| match &m.status {
            ModuleStatus::Applicable { changes } => changes.as_slice(),
            ModuleStatus::NotApplicable { .. } => &[],
        })
    }

    /// The IDs of the modules with at least one change.
    #[must_use]
    pub fn changed_modules(&self) -> Vec<String> {
        self.modules
            .iter()
            .filter(|m| matches!(&m.status, ModuleStatus::Applicable { changes } if !changes.is_empty()))
            .map(|m| m.id.to_owned())
            .collect()
    }
}

/// Plans `modules` in order. A module that does not apply is listed with its
/// reason; a resource already in its desired state is left out. Only reads.
///
/// # Errors
///
/// [`EngineError::Module`] or [`EngineError::Resource`].
pub fn plan(modules: &[&dyn Module], facts: &Facts, sys: Sys) -> Result<Plan, EngineError> {
    let mut plans = Vec::new();
    for module in modules {
        let mut notes = Vec::new();
        let status = match module.applicable(facts) {
            Applicability::NotApplicable { reason } => ModuleStatus::NotApplicable { reason },
            Applicability::Applicable => {
                notes = module.notes(facts);
                let resources = module
                    .plan(facts, sys)
                    .map_err(|source| EngineError::Module {
                        module: module.id(),
                        source,
                    })?;
                let mut changes = Vec::new();
                for resource in resources {
                    let change = resource.diff(sys).map_err(|source| EngineError::Resource {
                        id: resource.id(),
                        source,
                    })?;
                    if let Some(change) = change {
                        changes.push(Step { change, resource });
                    }
                }
                ModuleStatus::Applicable { changes }
            }
        };
        plans.push(ModulePlan {
            id: module.id(),
            title: module.title(),
            status,
            notes,
        });
    }
    Ok(Plan { modules: plans })
}
