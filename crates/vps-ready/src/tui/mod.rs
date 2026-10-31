//! The questions of the wizard, behind [`Prompt`]: [`Terminal`] asks them
//! with `dialoguer`, and tests answer them from a script. Nothing else in
//! the crate uses `dialoguer`.

use std::io;

#[cfg(test)]
pub(crate) mod script;
mod term;

pub use term::Terminal;

/// Asks the user.
pub trait Prompt {
    /// One of `items`, starting at `default`; returns its index.
    ///
    /// # Errors
    ///
    /// [`PromptError`].
    fn select(
        &mut self,
        question: &str,
        items: &[String],
        default: usize,
    ) -> Result<usize, PromptError>;

    /// Any of `items`; returns the indexes of those checked.
    ///
    /// # Errors
    ///
    /// [`PromptError`].
    fn multi_select(&mut self, question: &str, items: &[Item]) -> Result<Vec<usize>, PromptError>;

    /// A line of text; `default` when the answer is empty.
    ///
    /// # Errors
    ///
    /// [`PromptError`].
    fn input(&mut self, question: &str, default: &str) -> Result<String, PromptError>;

    /// Yes or no.
    ///
    /// # Errors
    ///
    /// [`PromptError`].
    fn confirm(&mut self, question: &str, default: bool) -> Result<bool, PromptError>;
}

/// An entry of [`Prompt::multi_select`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// What is shown.
    pub label: String,
    /// Whether it starts checked.
    pub checked: bool,
    /// Shown greyed out, e.g. a module that does not apply.
    pub dim: bool,
}

/// Why a question got no answer.
#[derive(Debug, thiserror::Error)]
pub enum PromptError {
    /// Ctrl-C.
    #[error("interrupted")]
    Interrupted,
    /// The terminal failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}
