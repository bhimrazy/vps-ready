//! [`Prompt`] on the terminal, with `dialoguer`.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use dialoguer::console::{Term, style};
use dialoguer::theme::{ColorfulTheme, SimpleTheme, Theme};
use dialoguer::{Confirm, Input, MultiSelect, Select};

use super::{Item, Prompt, PromptError};

/// Asks on stdout and reads keys from the terminal.
///
/// A question reads keys in raw mode, where Ctrl-C is a key: `console`
/// then raises SIGINT itself and the read fails as interrupted. The handler
/// [`Terminal::new`] installs ignores that SIGINT during a question and
/// ends the process as usual otherwise.
pub struct Terminal {
    term: Term,
    theme: Box<dyn Theme>,
    color: bool,
    ends: Arc<AtomicBool>,
}

impl Terminal {
    /// Installs the SIGINT handler; `color` picks the colored theme.
    ///
    /// # Errors
    ///
    /// If the handler cannot be installed.
    pub fn new(color: bool) -> io::Result<Self> {
        let ends = Arc::new(AtomicBool::new(true));
        signal_hook::flag::register_conditional_default(
            signal_hook::consts::SIGINT,
            Arc::clone(&ends),
        )?;
        let theme: Box<dyn Theme> = if color {
            Box::new(ColorfulTheme::default())
        } else {
            Box::new(SimpleTheme)
        };
        Ok(Self {
            term: Term::stdout(),
            theme,
            color,
            ends,
        })
    }

    /// While set, Ctrl-C ends the process. Clear it where something else
    /// handles Ctrl-C.
    #[must_use]
    pub fn sigint_ends(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.ends)
    }

    fn ask<T>(&self, f: impl FnOnce(&Term) -> dialoguer::Result<T>) -> Result<T, PromptError> {
        self.ends.store(false, Ordering::SeqCst);
        let answer = f(&self.term);
        self.ends.store(true, Ordering::SeqCst);
        answer.map_err(|dialoguer::Error::IO(e)| {
            if e.kind() == io::ErrorKind::Interrupted {
                // The question hid it.
                let _ = self.term.show_cursor();
                let _ = self.term.write_line("");
                PromptError::Interrupted
            } else {
                PromptError::Io(e)
            }
        })
    }
}

impl Prompt for Terminal {
    fn select(
        &mut self,
        question: &str,
        items: &[String],
        default: usize,
    ) -> Result<usize, PromptError> {
        self.ask(|term| {
            Select::with_theme(&*self.theme)
                .with_prompt(question)
                .items(items)
                .default(default)
                .interact_on(term)
        })
    }

    fn multi_select(&mut self, question: &str, items: &[Item]) -> Result<Vec<usize>, PromptError> {
        let shown = items.iter().map(|i| {
            let label = if i.dim && self.color {
                style(&i.label).dim().to_string()
            } else {
                i.label.clone()
            };
            (label, i.checked)
        });
        self.ask(|term| {
            MultiSelect::with_theme(&*self.theme)
                .with_prompt(question)
                .items_checked(shown)
                .interact_on(term)
        })
    }

    fn input(&mut self, question: &str, default: &str) -> Result<String, PromptError> {
        self.ask(|term| {
            // `interact_text` reads keys in raw mode, so Ctrl-C reaches `ask`.
            let input = Input::<String>::with_theme(&*self.theme).with_prompt(question);
            if default.is_empty() {
                input.allow_empty(true).interact_text_on(term)
            } else {
                input.default(default.to_owned()).interact_text_on(term)
            }
        })
    }

    fn confirm(&mut self, question: &str, default: bool) -> Result<bool, PromptError> {
        self.ask(|term| {
            Confirm::with_theme(&*self.theme)
                .with_prompt(question)
                .default(default)
                .interact_on(term)
        })
    }
}
