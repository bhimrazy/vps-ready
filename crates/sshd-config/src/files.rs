//! `sshd_config` and its `Include` files.
//!
//! [`Config::read`] flattens the main file and everything it includes into one
//! list of [`Directive`]s in the order sshd reads them. sshd takes the first
//! value it reads for most keywords, so list order is what decides which file
//! wins.
//!
//! Choices where `sshd_config(5)` leaves room:
//! - A `Match` block in an included file ends at the end of that file.
//! - An `Include` that matches nothing is skipped, as in sshd.
//! - Tokens in paths (`%h` and the like) and `~` are not expanded; sshd does
//!   not expand them in `Include` either.

use std::fmt;
use std::io;
use std::path::{Component, Path, PathBuf};

/// Where relative `Include` paths are resolved.
const DEFAULT_DIR: &str = "/etc/ssh";

/// sshd stops following `Include` chains at this depth.
const MAX_DEPTH: usize = 16;

/// Where files are read from, so the reader works on a real host, a fake
/// filesystem or a test fixture.
pub trait Source {
    /// The contents of the file at `path`.
    ///
    /// # Errors
    /// Any I/O error; `NotFound` is how a missing file is reported.
    fn read(&self, path: &Path) -> io::Result<String>;

    /// The names (not paths) of the entries of the directory `dir`, in any order.
    ///
    /// # Errors
    /// Any I/O error; `NotFound` is how a missing directory is reported.
    fn list(&self, dir: &Path) -> io::Result<Vec<String>>;
}

/// The real filesystem. Contents that are not UTF-8 are converted lossily.
#[derive(Debug, Clone, Copy, Default)]
pub struct Os;

impl Source for Os {
    fn read(&self, path: &Path) -> io::Result<String> {
        Ok(String::from_utf8_lossy(&std::fs::read(path)?).into_owned())
    }

    fn list(&self, dir: &Path) -> io::Result<Vec<String>> {
        std::fs::read_dir(dir)?
            .map(|e| Ok(e?.file_name().to_string_lossy().into_owned()))
            .collect()
    }
}

/// Why a configuration could not be read.
#[derive(Debug)]
pub enum Error {
    /// A file could not be read.
    Io {
        /// The file or directory.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// A line could not be split into words.
    Syntax {
        /// The file.
        path: PathBuf,
        /// The 1-based line number.
        line: usize,
        /// What is wrong.
        reason: &'static str,
    },
    /// `Include` files nest deeper than sshd follows them (or include each other).
    TooDeep {
        /// The file whose `Include` went too deep.
        path: PathBuf,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Syntax { path, line, reason } => {
                write!(f, "{}:{line}: {reason}", path.display())
            }
            Self::TooDeep { path } => {
                write!(
                    f,
                    "{}: Include nested more than {MAX_DEPTH} deep",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// One line of configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    /// The file the line is in.
    pub file: PathBuf,
    /// The 1-based line number.
    pub line: usize,
    /// The keyword, lowercased.
    pub keyword: String,
    /// The arguments, unquoted.
    pub args: Vec<String>,
    /// Whether the line is inside a `Match` block, so it applies only to some
    /// connections. For a `Match` line itself, whether the previous block was.
    pub in_match: bool,
}

/// The answer to "is this drop-in read early enough".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncludeCheck {
    /// An `Include` covers the file before any `Match` and before any of the keywords.
    Covered,
    /// No `Include` covers the file.
    Missing,
    /// A `Match` comes first, so the `Include` (if any) is too late.
    AfterMatch {
        /// The file with the `Match`.
        file: PathBuf,
        /// Its line.
        line: usize,
    },
    /// One of the keywords is set before the `Include`, and wins over it.
    AfterKeyword {
        /// The keyword, lowercased.
        keyword: String,
        /// The file that sets it.
        file: PathBuf,
        /// Its line.
        line: usize,
    },
}

/// A configuration file with its includes expanded, in the order sshd reads it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    directives: Vec<Directive>,
}

impl Config {
    /// Reads `main` (normally `/etc/ssh/sshd_config`) and the files it includes.
    ///
    /// # Errors
    /// [`Error`] when `main` or an included file cannot be read (a missing
    /// included file is skipped), a line is malformed, or includes nest too deep.
    pub fn read(source: &dyn Source, main: &Path) -> Result<Self, Error> {
        let mut directives = Vec::new();
        load(source, main, 0, false, &mut directives)?;
        Ok(Self { directives })
    }

    /// Every directive, in the order sshd reads them. An `Include` line is
    /// followed by the lines of the files it pulled in.
    #[must_use]
    pub fn directives(&self) -> &[Directive] {
        &self.directives
    }

    /// The first line that sets `keyword` for every connection (outside any
    /// `Match` block). For most keywords this is the one sshd uses.
    #[must_use]
    pub fn first(&self, keyword: &str) -> Option<&Directive> {
        self.directives
            .iter()
            .find(|d| !d.in_match && d.keyword.eq_ignore_ascii_case(keyword))
    }

    /// Whether `target`, a file that is or will be in an included directory,
    /// is read before any `Match` and before any line that sets one of
    /// `keywords`. Only an `Include` outside a `Match` block counts.
    #[must_use]
    pub fn include_check(&self, target: &Path, keywords: &[&str]) -> IncludeCheck {
        for d in &self.directives {
            if d.keyword == "match" {
                return IncludeCheck::AfterMatch {
                    file: d.file.clone(),
                    line: d.line,
                };
            }
            if d.in_match {
                continue;
            }
            if d.keyword == "include" {
                if d.args.iter().any(|p| pattern_covers(p, target)) {
                    return IncludeCheck::Covered;
                }
            } else if keywords.iter().any(|k| d.keyword.eq_ignore_ascii_case(k)) {
                return IncludeCheck::AfterKeyword {
                    keyword: d.keyword.clone(),
                    file: d.file.clone(),
                    line: d.line,
                };
            }
        }
        IncludeCheck::Missing
    }
}

fn load(
    source: &dyn Source,
    path: &Path,
    depth: usize,
    inherited_match: bool,
    out: &mut Vec<Directive>,
) -> Result<(), Error> {
    let text = source.read(path).map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })?;
    let mut in_match = inherited_match;
    for (i, raw) in text.lines().enumerate() {
        let line = i + 1;
        let parsed = split_line(raw).map_err(|reason| Error::Syntax {
            path: path.to_owned(),
            line,
            reason,
        })?;
        let Some((keyword, args)) = parsed else {
            continue;
        };
        let directive = Directive {
            file: path.to_owned(),
            line,
            keyword,
            args,
            in_match,
        };
        match directive.keyword.as_str() {
            "match" => in_match = true,
            "include" => {
                if depth >= MAX_DEPTH {
                    return Err(Error::TooDeep {
                        path: path.to_owned(),
                    });
                }
                let patterns = directive.args.clone();
                out.push(directive);
                for pattern in &patterns {
                    for file in expand(source, pattern)? {
                        match load(source, &file, depth + 1, in_match, out) {
                            Err(Error::Io { source, .. })
                                if source.kind() == io::ErrorKind::NotFound => {}
                            result => result?,
                        }
                    }
                }
                continue;
            }
            _ => {}
        }
        out.push(directive);
    }
    Ok(())
}

/// Splits a line into a lowercase keyword and its unquoted arguments.
/// `None` for blank and comment lines. Accepts `Keyword value` and
/// `Keyword=value`; `#` starts a comment where a word would start.
fn split_line(line: &str) -> Result<Option<(String, Vec<String>)>, &'static str> {
    let line = line.trim_start();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let end = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    let (keyword, rest) = line.split_at(end);
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest);
    Ok(Some((keyword.to_ascii_lowercase(), split_words(rest)?)))
}

fn split_words(s: &str) -> Result<Vec<String>, &'static str> {
    let mut words = Vec::new();
    let mut chars = s.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        if matches!(chars.peek(), None | Some('#')) {
            return Ok(words);
        }
        let mut word = String::new();
        let mut quoted = false;
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() && !quoted {
                break;
            }
            chars.next();
            match c {
                '"' => quoted = !quoted,
                '\\' => match chars.next_if(|n| matches!(n, '"' | '\\' | '\'' | ' ')) {
                    Some(escaped) => word.push(escaped),
                    None => word.push('\\'),
                },
                _ => word.push(c),
            }
        }
        if quoted {
            return Err("unterminated quote");
        }
        words.push(word);
    }
}

fn absolute(pattern: &str) -> PathBuf {
    Path::new(DEFAULT_DIR).join(pattern)
}

/// The files `pattern` matches, in lexical order.
fn expand(source: &dyn Source, pattern: &str) -> Result<Vec<PathBuf>, Error> {
    let mut paths = vec![PathBuf::new()];
    for component in absolute(pattern).components() {
        match component {
            Component::Normal(name) => {
                let name = name.to_string_lossy();
                if !has_magic(&name) {
                    for p in &mut paths {
                        p.push(&*name);
                    }
                    continue;
                }
                let mut next = Vec::new();
                for dir in &paths {
                    match source.list(dir) {
                        Ok(names) => next.extend(
                            names
                                .into_iter()
                                .filter(|n| glob_match(&name, n))
                                .map(|n| dir.join(n)),
                        ),
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                        Err(source) => {
                            return Err(Error::Io {
                                path: dir.clone(),
                                source,
                            });
                        }
                    }
                }
                paths = next;
            }
            other => {
                for p in &mut paths {
                    p.push(other.as_os_str());
                }
            }
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// Whether `pattern` (an `Include` argument) matches the path `target`,
/// without touching the filesystem.
fn pattern_covers(pattern: &str, target: &Path) -> bool {
    let pattern = absolute(pattern);
    let (mut p, mut t) = (pattern.components(), target.components());
    loop {
        match (p.next(), t.next()) {
            (None, None) => return true,
            (Some(Component::Normal(pc)), Some(Component::Normal(tc))) => {
                if !glob_match(&pc.to_string_lossy(), &tc.to_string_lossy()) {
                    return false;
                }
            }
            (Some(pc), Some(tc)) if pc == tc => {}
            _ => return false,
        }
    }
}

fn has_magic(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

/// One element of a compiled glob.
enum Tok {
    Lit(char),
    Any,
    Star,
    Class {
        negated: bool,
        items: Vec<(char, char)>,
    },
}

fn compile(pattern: &str) -> Vec<Tok> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        i += 1;
        match c {
            '*' => toks.push(Tok::Star),
            '?' => toks.push(Tok::Any),
            '\\' => {
                toks.push(Tok::Lit(chars.get(i).copied().unwrap_or('\\')));
                i += usize::from(i < chars.len());
            }
            '[' => match class(&chars, i) {
                Some((tok, next)) => {
                    toks.push(tok);
                    i = next;
                }
                None => toks.push(Tok::Lit('[')),
            },
            _ => toks.push(Tok::Lit(c)),
        }
    }
    toks
}

/// Parses a bracket class whose `[` is just before `start`. `None` when it is
/// never closed, in which case the `[` is a plain character.
fn class(chars: &[char], start: usize) -> Option<(Tok, usize)> {
    let mut i = start;
    let negated = matches!(chars.get(i), Some('!' | '^'));
    i += usize::from(negated);
    let mut items = Vec::new();
    let mut first = true;
    loop {
        let c = *chars.get(i)?;
        i += 1;
        if c == ']' && !first {
            return Some((Tok::Class { negated, items }, i));
        }
        first = false;
        if chars.get(i) == Some(&'-') && chars.get(i + 1).is_some_and(|&e| e != ']') {
            items.push((c, chars.get(i + 1).copied()?));
            i += 2;
        } else {
            items.push((c, c));
        }
    }
}

/// Matches one path component against a glob: `*`, `?` and `[...]`, with
/// `\` escaping. A leading `.` in `name` must be matched by a literal `.`.
fn glob_match(pattern: &str, name: &str) -> bool {
    if name.starts_with('.') && !pattern.starts_with('.') {
        return false;
    }
    let toks = compile(pattern);
    let name: Vec<char> = name.chars().collect();
    let (mut t, mut n) = (0, 0);
    let mut backtrack: Option<(usize, usize)> = None;
    while n < name.len() {
        let step = match toks.get(t) {
            Some(Tok::Star) => {
                backtrack = Some((t, n));
                t += 1;
                continue;
            }
            Some(Tok::Any) => true,
            Some(Tok::Lit(c)) => name.get(n) == Some(c),
            Some(Tok::Class { negated, items }) => name
                .get(n)
                .is_some_and(|&c| items.iter().any(|&(lo, hi)| lo <= c && c <= hi) != *negated),
            None => false,
        };
        if step {
            t += 1;
            n += 1;
        } else if let Some((star, at)) = backtrack {
            t = star + 1;
            n = at + 1;
            backtrack = Some((star, at + 1));
        } else {
            return false;
        }
    }
    toks.get(t..)
        .is_some_and(|rest| rest.iter().all(|tok| matches!(tok, Tok::Star)))
}

#[cfg(test)]
mod tests;
