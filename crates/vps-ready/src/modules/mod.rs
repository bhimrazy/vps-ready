//! Modules: the policy that decides which [`Resource`]s a fix needs. They
//! only plan and verify; the engine applies and rolls back.

use std::time::Duration;

use serde::de::DeserializeOwned;

use crate::audit::CatalogError;
use crate::engine::Reload;
use crate::facts::Facts;
use crate::resource::{Resource, ResourceError};
use crate::sys::{Cmd, Sys, SysError};

#[cfg(feature = "testing")]
mod deadman_test;
pub mod deploy_docker;
pub mod deploy_proxy;
pub mod deploy_user;
pub mod firewall_inbound;
pub mod kernel_sysctl;
pub mod ssh_bruteforce;
pub mod ssh_server;
mod updates_auto;
pub mod user_admin;

#[cfg(feature = "testing")]
pub use deadman_test::DeadmanTest;
pub use deploy_docker::DeployDocker;
pub use deploy_proxy::DeployProxy;
pub use deploy_user::DeployUser;
pub use firewall_inbound::FirewallInbound;
pub use kernel_sysctl::KernelSysctl;
pub use ssh_bruteforce::SshBruteforce;
pub use ssh_server::SshServer;
pub use updates_auto::UpdatesAuto;
pub use user_admin::UserAdmin;

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
    /// A file's template did not render.
    #[error("rendering a template: {0}")]
    Template(#[from] askama::Error),
    /// The module cannot plan on this host as configured, and why.
    #[error("{0}")]
    Refused(String),
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
    /// The resources of the modules planned before this one in the same
    /// plan, in their desired state, e.g. the admin `user.admin` creates.
    pub planned: &'a [Resource],
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

/// Docker Engine's package from Docker's repository, which creates the
/// `docker` group. `deploy.docker` plans it when Docker is not installed
/// yet; a module after it that sees it planned, such as `deploy.user` with
/// `docker = true` or `firewall.inbound`, plans as if Docker were present.
pub const DOCKER_PACKAGE: &str = "docker-ce";

/// A [`ModuleError::Refused`] with `reason`.
pub(crate) fn refuse<T>(reason: &str) -> Result<T, ModuleError> {
    Err(ModuleError::Refused(reason.to_owned()))
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

/// One param of a module, for `vps-ready modules <ID>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ParamDoc {
    /// The key in the module's profile table.
    pub name: &'static str,
    /// The value used when the key is absent, as written in TOML.
    pub default: &'static str,
    /// One line.
    pub help: &'static str,
}

/// What a module plans: its resources and the reloads they need.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleSteps {
    /// In their desired state, in apply order.
    pub resources: Vec<Resource>,
    /// Run in order after the module's resources are applied, if any of
    /// them changed.
    pub reloads: Vec<Reload>,
    /// Shown after [`Module::notes`], for what only planning finds out.
    pub notes: Vec<String>,
}

impl From<Vec<Resource>> for ModuleSteps {
    fn from(resources: Vec<Resource>) -> Self {
        Self {
            resources,
            ..Self::default()
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
    /// The params its profile table accepts; empty for a module with none.
    fn params_doc(&self) -> &'static [ParamDoc] {
        &[]
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
    /// The longest [`Module::verify`] may run, by the timeouts of its
    /// commands; the dead-man's first deadline leaves apply this long.
    fn verify_timeout(&self) -> Duration {
        Cmd::DEFAULT_TIMEOUT
    }
}

/// Every module, in the order the plan lists and applies them.
/// `deploy.docker` comes before `firewall.inbound`, which then accepts
/// input from the bridges of a Docker it installs; `deploy.proxy` after
/// `firewall.inbound`, whose planned ruleset it reads for ports 80 and 443;
/// and `deploy.user` last, after Docker, which creates the `docker` group.
#[must_use]
pub fn all() -> &'static [&'static dyn Module] {
    &[
        &UserAdmin,
        &SshServer,
        &DeployDocker,
        &FirewallInbound,
        &SshBruteforce::ROOT,
        &KernelSysctl::ROOT,
        &UpdatesAuto::ROOT,
        &DeployProxy,
        &DeployUser,
    ]
}

/// [`all`] and the test module [`DeadmanTest`]; only in a build with the
/// `testing` feature.
#[cfg(feature = "testing")]
#[must_use]
pub fn with_test() -> &'static [&'static dyn Module] {
    &[
        &UserAdmin,
        &SshServer,
        &DeployDocker,
        &FirewallInbound,
        &SshBruteforce::ROOT,
        &KernelSysctl::ROOT,
        &UpdatesAuto::ROOT,
        &DeployProxy,
        &DeployUser,
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
            planned: &[],
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

    /// Each documented param, set to its documented default, is accepted.
    #[test]
    fn documented_params_are_accepted() {
        for m in all() {
            for p in m.params_doc() {
                let params: toml::Table = toml::from_str(&format!("{} = {}", p.name, p.default))
                    .unwrap_or_else(|e| panic!("{}.{}: {e}", m.id(), p.name));
                if let Err(e) = m.check_params(&params) {
                    panic!("{}.{}: {e}", m.id(), p.name);
                }
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
