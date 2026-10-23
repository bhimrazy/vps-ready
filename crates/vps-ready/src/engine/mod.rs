//! The transaction engine: planning, apply with automatic rollback, manual
//! rollback and history, over the state directory, its lock and the journal
//! that records each transaction.

pub mod id;
pub mod journal;
mod plan;
mod run;
mod state;
#[cfg(test)]
mod tests;

pub use journal::{Event, Record, RollbackReason, TxnState};
pub use plan::{ModulePlan, ModuleStatus, Plan, Step, plan};
pub use run::{ApplyOutcome, ByHand, Engine, Progress, Rollback, Target, TxnInfo, history};
pub use state::{StateDir, Txn};

use crate::modules::ModuleError;
use crate::resource::ResourceError;
use crate::sys::SysError;

/// Errors from the engine.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EngineError {
    /// A filesystem operation failed.
    #[error(transparent)]
    Sys(#[from] SysError),
    /// The lock is held by another process.
    #[error("another vps-ready is running")]
    Busy,
    /// The state directory failed its permission check.
    #[error("refusing to use state directory {path}: {reason}")]
    UnsafeStateDir {
        /// The directory.
        path: String,
        /// What is wrong with it.
        reason: String,
    },
    /// A journal line other than a torn final one does not parse.
    #[error("{path} line {line}: {source}")]
    Journal {
        /// The journal file.
        path: String,
        /// Line number, from 1.
        line: usize,
        /// The parse error.
        #[source]
        source: serde_json::Error,
    },
    /// A record could not be encoded.
    #[error("encoding a journal record: {0}")]
    Encode(#[source] serde_json::Error),
    /// A journal event that cannot follow the transaction's state.
    #[error(
        "illegal journal event `{event}` in state {}",
        .from.map_or_else(|| "none (no begin record)".to_owned(), |s| s.to_string())
    )]
    Transition {
        /// The state before the event; `None` before the `begin` record.
        from: Option<TxnState>,
        /// The event's tag.
        event: &'static str,
    },
    /// A module failed to plan.
    #[error("planning {module}: {source}")]
    Module {
        /// Module ID.
        module: &'static str,
        /// The failure.
        #[source]
        source: ModuleError,
    },
    /// A resource failed to diff, snapshot, apply or restore.
    #[error("{id}: {source}")]
    Resource {
        /// Resource ID.
        id: String,
        /// The failure.
        #[source]
        source: ResourceError,
    },
    /// A transaction stopped during an apply or a rollback.
    #[error("transaction {0} did not finish; run `vps-ready rollback --txn {0}`")]
    Unfinished(String),
    /// A change differs from the plan that was shown.
    #[error("the plan changed after it was shown ({0}); nothing was changed")]
    PlanChanged(String),
    /// Resources still differ from their desired state after apply.
    #[error("not in the desired state after apply: {}", .0.join(", "))]
    VerifyFailed(Vec<String>),
    /// No transaction to roll back.
    #[error("nothing to roll back")]
    NothingToRollBack,
    /// No transaction has this ID.
    #[error("no transaction {0}")]
    UnknownTxn(String),
    /// The transaction was already rolled back.
    #[error("transaction {0} is already rolled back")]
    AlreadyRolledBack(String),
    /// The safety check found resources changed since apply; nothing was
    /// restored.
    #[error(
        "refusing to roll back transaction {txn}: these changed since apply, so nothing \
         was restored and its other changes are untouched. Put these back by hand, then \
         run `vps-ready rollback --txn {txn}` again:{}",
        list(.changed)
    )]
    Changed {
        /// Transaction ID.
        txn: String,
        /// Each changed resource.
        changed: Vec<ByHand>,
    },
    /// A rollback stopped part way; running it again continues it.
    #[error(
        "rollback of transaction {txn} ({dir}) did not complete: {source}. {}",
        next_steps(.txn, .left.as_deref())
    )]
    RollbackIncomplete {
        /// Transaction ID.
        txn: String,
        /// The transaction directory.
        dir: String,
        /// The resources not yet restored, in journal order; `None` if the
        /// journal could not be re-read.
        left: Option<Vec<ByHand>>,
        /// The failure.
        #[source]
        source: Box<EngineError>,
    },
    /// Two steps of a plan change the same resource.
    #[error("the plan changes {0} twice")]
    DuplicateResource(String),
}

fn list(items: &[ByHand]) -> String {
    items.iter().map(|i| format!("\n  {i}")).collect()
}

fn next_steps(txn: &str, left: Option<&[ByHand]>) -> String {
    let rerun = format!("`vps-ready rollback --txn {txn}`");
    match left {
        None => format!("The journal could not be re-read, so run {rerun} again."),
        Some([]) => format!("Run {rerun} again."),
        Some(left) => format!("Run {rerun} again, or restore by hand:{}", list(left)),
    }
}
