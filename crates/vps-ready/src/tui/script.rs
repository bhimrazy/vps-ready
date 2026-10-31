//! [`Prompt`] answered from a script, for tests. Each question and its
//! answer go to a [`Transcript`], which the code under test writes to too.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, Write};
use std::rc::Rc;

use super::{Item, MULTI_HINT, Prompt, PromptError};

/// An answer to the next question.
#[derive(Debug, Clone)]
pub(crate) enum Answer {
    /// Enter: the default.
    Enter,
    /// The item at this index, for `select`.
    Pick(usize),
    /// Exactly these items checked, for `multi_select`.
    Check(Vec<usize>),
    /// This text, for `input`.
    Type(String),
    /// Yes or no, for `confirm`.
    Say(bool),
    /// Ctrl-C.
    CtrlC,
}

/// Shared text that both a [`Script`] and its caller write to.
#[derive(Debug, Clone, Default)]
pub(crate) struct Transcript(Rc<RefCell<Vec<u8>>>);

impl Transcript {
    pub(crate) fn text(&self) -> String {
        String::from_utf8(self.0.borrow().clone()).unwrap()
    }
}

impl Write for Transcript {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Answers questions in order; a question past the end panics.
pub(crate) struct Script {
    answers: VecDeque<Answer>,
    log: Transcript,
}

impl Script {
    pub(crate) fn new(answers: impl IntoIterator<Item = Answer>, log: &Transcript) -> Self {
        Self {
            answers: answers.into_iter().collect(),
            log: log.clone(),
        }
    }

    /// Whether every answer was used.
    pub(crate) fn done(&self) -> bool {
        self.answers.is_empty()
    }

    fn next(&mut self, question: &str) -> Result<Answer, PromptError> {
        let answer = self
            .answers
            .pop_front()
            .unwrap_or_else(|| panic!("no answer left for {question:?}"));
        if matches!(answer, Answer::CtrlC) {
            writeln!(self.log, "? {question} ^C")?;
            return Err(PromptError::Interrupted);
        }
        Ok(answer)
    }
}

impl Prompt for Script {
    fn select(
        &mut self,
        question: &str,
        items: &[String],
        default: usize,
    ) -> Result<usize, PromptError> {
        let pick = match self.next(question)? {
            Answer::Enter => default,
            Answer::Pick(i) => i,
            other => panic!("{other:?} for select {question:?}"),
        };
        writeln!(self.log, "? {question}")?;
        for (i, item) in items.iter().enumerate() {
            let mark = if i == pick { '>' } else { ' ' };
            writeln!(self.log, "  {mark} {item}")?;
        }
        Ok(pick)
    }

    fn multi_select(&mut self, question: &str, items: &[Item]) -> Result<Vec<usize>, PromptError> {
        let checked = match self.next(question)? {
            Answer::Enter => (0..items.len()).filter(|&i| items[i].checked).collect(),
            Answer::Check(checked) => checked,
            other => panic!("{other:?} for multi_select {question:?}"),
        };
        writeln!(self.log, "? {question} {MULTI_HINT}")?;
        for (i, item) in items.iter().enumerate() {
            let mark = if checked.contains(&i) { 'x' } else { ' ' };
            writeln!(self.log, "  [{mark}] {}", item.label)?;
        }
        Ok(checked)
    }

    fn input(&mut self, question: &str, default: &str) -> Result<String, PromptError> {
        let text = match self.next(question)? {
            Answer::Enter => default.to_owned(),
            Answer::Type(text) => text,
            other => panic!("{other:?} for input {question:?}"),
        };
        writeln!(self.log, "? {question}: {text}")?;
        Ok(text)
    }

    fn confirm(&mut self, question: &str, default: bool) -> Result<bool, PromptError> {
        let yes = match self.next(question)? {
            Answer::Enter => default,
            Answer::Say(yes) => yes,
            other => panic!("{other:?} for confirm {question:?}"),
        };
        let hint = if default { "Y/n" } else { "y/N" };
        let said = if yes { "yes" } else { "no" };
        writeln!(self.log, "? {question} ({hint}) {said}")?;
        Ok(yes)
    }
}
