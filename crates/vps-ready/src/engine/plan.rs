//! Planning: what the modules would change on this host.

use std::fmt;
use std::sync::LazyLock;

use serde::Serialize;

use super::{EngineError, Reload};
use crate::facts::Facts;
use crate::modules::{Applicability, Module, ModuleSteps, PlanCx};
use crate::resource::{Change, Resource};
use crate::sys::Sys;

/// A module to plan, with its params.
#[derive(Clone, Copy)]
pub struct Selected<'a> {
    /// The module.
    pub module: &'a dyn Module,
    /// Its table from the profile.
    pub params: &'a toml::Table,
}

impl<'a> Selected<'a> {
    /// `module` with no params.
    #[must_use]
    pub fn new(module: &'a dyn Module) -> Self {
        static EMPTY: LazyLock<toml::Table> = LazyLock::new(toml::Table::new);
        Self {
            module,
            params: &EMPTY,
        }
    }
}

/// What `apply` would change, module by module. Serializes for `plan --json`.
/// Keeps the modules, their params and the facts, for verify.
#[derive(Debug, Clone, Serialize)]
pub struct Plan<'a> {
    /// In the order the modules were given.
    pub modules: Vec<ModulePlan<'a>>,
    #[serde(skip)]
    pub(super) facts: &'a Facts,
}

/// One module's part of a [`Plan`].
#[derive(Clone, Serialize)]
pub struct ModulePlan<'a> {
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
    #[serde(skip)]
    pub(super) selected: Selected<'a>,
}

impl fmt::Debug for ModulePlan<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModulePlan")
            .field("id", &self.id)
            .field("title", &self.title)
            .field("status", &self.status)
            .field("notes", &self.notes)
            .field("params", self.selected.params)
            .finish()
    }
}

/// Whether a module applies, with its changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum ModuleStatus {
    /// It applies; `changes` is empty when nothing needs to change.
    Applicable {
        /// In apply order.
        changes: Vec<Step>,
        /// Run after `changes`; empty when there are none.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        reloads: Vec<Reload>,
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

impl Plan<'_> {
    /// Every step, in apply order.
    pub fn steps(&self) -> impl Iterator<Item = &Step> {
        self.modules.iter().flat_map(|m| m.changes())
    }

    /// The IDs of the modules with at least one change.
    #[must_use]
    pub fn changed_modules(&self) -> Vec<String> {
        self.modules
            .iter()
            .filter(|m| !m.changes().is_empty())
            .map(|m| m.id.to_owned())
            .collect()
    }
}

impl ModulePlan<'_> {
    /// Its changes; empty when it does not apply.
    #[must_use]
    pub fn changes(&self) -> &[Step] {
        match &self.status {
            ModuleStatus::Applicable { changes, .. } => changes,
            ModuleStatus::NotApplicable { .. } => &[],
        }
    }

    /// Its reloads; empty when it has no changes.
    #[must_use]
    pub fn reloads(&self) -> &[Reload] {
        match &self.status {
            ModuleStatus::Applicable { reloads, .. } => reloads,
            ModuleStatus::NotApplicable { .. } => &[],
        }
    }

    /// Runs [`Module::verify`] with the module's params and `facts`.
    pub(super) fn verify(&self, facts: &Facts, sys: Sys) -> Result<(), String> {
        let cx = PlanCx {
            facts,
            params: self.selected.params,
        };
        self.selected.module.verify(&cx, sys)
    }
}

/// Plans `modules` in order. A module that does not apply is listed with its
/// reason; a resource already in its desired state is left out, and so are
/// the reloads of a module with no change. Only reads.
///
/// # Errors
///
/// [`EngineError::Module`] or [`EngineError::Resource`].
pub fn plan<'a>(
    modules: &[Selected<'a>],
    facts: &'a Facts,
    sys: Sys,
) -> Result<Plan<'a>, EngineError> {
    let mut plans = Vec::new();
    for &selected in modules {
        let module = selected.module;
        let mut notes = Vec::new();
        let status = match module.applicable(facts) {
            Applicability::NotApplicable { reason } => ModuleStatus::NotApplicable { reason },
            Applicability::Applicable => {
                notes = module.notes(facts);
                let cx = PlanCx {
                    facts,
                    params: selected.params,
                };
                let ModuleSteps {
                    resources,
                    mut reloads,
                } = module
                    .plan(&cx, sys)
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
                if changes.is_empty() {
                    reloads.clear();
                }
                ModuleStatus::Applicable { changes, reloads }
            }
        };
        plans.push(ModulePlan {
            id: module.id(),
            title: module.title(),
            status,
            notes,
            selected,
        });
    }
    Ok(Plan {
        modules: plans,
        facts,
    })
}
