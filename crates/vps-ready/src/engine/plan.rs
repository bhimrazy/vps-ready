//! Planning: what the modules would change on this host.

use std::fmt;
use std::sync::LazyLock;

use serde::Serialize;

use super::{EngineError, Reload};
use crate::facts::Facts;
use crate::modules::{Applicability, Module, ModuleSteps, PlanCx};
use crate::resource::{Change, Resource, keyed_users};
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
    /// [`PlanCx::planned`] when it was planned, for verify.
    #[serde(skip)]
    pub(super) planned: Vec<Resource>,
    /// [`keyed_users`] of all its desired resources, changed or not.
    #[serde(skip)]
    pub(super) keyed: Vec<String>,
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

    /// Who must log in to confirm it: the users other than root that its
    /// modules give SSH keys, whether or not those keys change now (an
    /// admin set up by an earlier apply still counts). If there are none
    /// and it needs the dead-man switch, the user of the session applying
    /// it, unless that is root. Empty means any user.
    #[must_use]
    pub fn admins(&self) -> Vec<String> {
        let mut admins: Vec<String> = Vec::new();
        for user in self.modules.iter().flat_map(|m| &m.keyed) {
            if !admins.contains(user) {
                admins.push(user.clone());
            }
        }
        if admins.is_empty() && self.needs_deadman() {
            admins.extend(
                self.facts
                    .session
                    .as_ref()
                    .and_then(|s| s.user.clone())
                    .filter(|u| u != "root"),
            );
        }
        admins
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

    /// Whether a module with a change needs the dead-man switch.
    #[must_use]
    pub fn needs_deadman(&self) -> bool {
        self.modules
            .iter()
            .any(|m| !m.changes().is_empty() && m.selected.module.needs_deadman())
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

    /// [`Module::force_restore`].
    #[must_use]
    pub fn force_restore(&self) -> bool {
        self.selected.module.force_restore()
    }

    /// [`Module::verify_timeout`].
    pub(super) fn verify_timeout(&self) -> std::time::Duration {
        self.selected.module.verify_timeout()
    }

    /// Runs [`Module::verify`] with the module's params and `facts`.
    pub(super) fn verify(&self, facts: &Facts, sys: Sys) -> Result<(), String> {
        let cx = PlanCx {
            facts,
            params: self.selected.params,
            planned: &self.planned,
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
    let mut planned = Vec::new();
    for &selected in modules {
        let module = selected.module;
        let mut notes = Vec::new();
        let before = planned.clone();
        let mut keyed = Vec::new();
        let status = match module.applicable(facts) {
            Applicability::NotApplicable { reason } => ModuleStatus::NotApplicable { reason },
            Applicability::Applicable => {
                notes = module.notes(facts);
                let cx = PlanCx {
                    facts,
                    params: selected.params,
                    planned: &before,
                };
                let ModuleSteps {
                    resources,
                    mut reloads,
                    notes: found,
                } = module.plan(&cx, sys).map_err(|error| EngineError::Module {
                    module: module.id(),
                    error,
                })?;
                notes.extend(found);
                keyed = keyed_users(&resources);
                planned.extend(resources.iter().cloned());
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
            planned: before,
            keyed,
        });
    }
    Ok(Plan {
        modules: plans,
        facts,
    })
}
