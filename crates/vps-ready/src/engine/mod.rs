//! The transaction engine: planning, apply with automatic rollback, the
//! dead-man switch, manual rollback and history, over the state directory,
//! its lock and the journal that records each transaction.

pub mod deadman;
pub mod id;
pub mod journal;
mod plan;
mod reload;
mod run;
mod state;
#[cfg(test)]
mod tests;

pub use deadman::Deadman;
pub use journal::{Deadline, Event, Record, RollbackReason, TxnState};
pub use plan::{ModulePlan, ModuleStatus, Plan, Selected, Step, plan};
pub use reload::Reload;
pub use run::{
    ApplyOutcome, ByHand, DeadmanOutcome, Engine, Progress, Rollback, Target, TxnInfo, history,
};
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
    /// A module failed to plan. The failure is in the message, not the
    /// source chain, so `{:#}` does not print it twice.
    #[error("planning {module}: {error}")]
    Module {
        /// Module ID.
        module: &'static str,
        /// The failure.
        error: ModuleError,
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
    /// A transaction waits for a confirm, so no other may start.
    #[error(
        "transaction {0} is waiting for a confirm; it reverts at its deadline, \
         or now with `vps-ready rollback --txn {0}`"
    )]
    Pending(String),
    /// The binary cannot be trusted to run as root from a timer.
    #[error(
        "refusing to arm the dead-man switch with {path}: {reason}. Install vps-ready to \
         /usr/local/bin first, or, where that is group-writable (root:staff 2775 on older \
         Debian), to /usr/bin or /opt/vps-ready/bin"
    )]
    UnsafeBinary {
        /// The binary.
        path: String,
        /// What is wrong with it.
        reason: String,
    },
    /// The dead-man switch could not be armed, re-armed or read.
    #[error("dead-man switch: {0}")]
    Deadman(String),
    /// A change differs from the plan that was shown.
    #[error("the plan changed after it was shown ({0}); nothing was changed")]
    PlanChanged(String),
    /// The check of a reload failed, so the reload was not run.
    #[error("not running {reload}: {reason}")]
    ReloadCheck {
        /// The reload.
        reload: Reload,
        /// Exit status and stderr of the check, or why it could not run.
        reason: String,
    },
    /// A reload failed.
    #[error("{reload} failed: {reason}")]
    Reload {
        /// The reload.
        reload: Reload,
        /// Exit status and stderr, or why it could not run.
        reason: String,
    },
    /// Resources still differ from their desired state after apply, or a
    /// module's own verify failed.
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
         run `vps-ready rollback --txn {txn}` again:{}{}",
        list(.changed),
        if *.armed { deadman_note(.txn) } else { String::new() }
    )]
    Changed {
        /// Transaction ID.
        txn: String,
        /// Each changed resource.
        changed: Vec<ByHand>,
        /// Whether its dead-man switch is armed.
        armed: bool,
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

fn deadman_note(txn: &str) -> String {
    format!(
        "\nIts dead-man rollback (the timer, or `vps-ready rollback --txn {txn} --deadman`) \
         still restores the files that can lock you out, changed or not."
    )
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
