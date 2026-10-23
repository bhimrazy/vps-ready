//! The transaction engine. So far: the state directory, its lock, and the
//! journal that records each transaction.

pub mod id;
pub mod journal;
mod state;

pub use journal::{Event, Record, RollbackReason, TxnState};
pub use state::{StateDir, Txn};

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
}
