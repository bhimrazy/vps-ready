//! Parser for `os-release` files, per the systemd `os-release(5)` spec.
//!
//! The format is a list of `KEY=VALUE` lines. Values may be unquoted, or
//! enclosed in single or double quotes; inside double quotes and in unquoted
//! values the escapes `\"`, `\\`, `\$` and `` \` `` are honoured, following
//! shell rules. Blank lines and lines starting with `#` are ignored, as are
//! malformed lines (bad key, unterminated quote), so a single odd line never
//! hides the rest of the file.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

/// Where `os-release` lives, in lookup order.
pub const PATHS: [&str; 2] = ["/etc/os-release", "/usr/lib/os-release"];

/// Distribution family, used to choose package managers and file locations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OsFamily {
    /// Debian, Ubuntu and derivatives (apt).
    Debian,
    /// RHEL, Fedora, Rocky, Alma, CentOS (dnf).
    Rhel,
    /// Alpine (apk).
    Alpine,
    /// Arch Linux (pacman).
    Arch,
    /// openSUSE and SLES (zypper).
    Suse,
    /// Anything else.
    Unknown,
}

impl OsFamily {
    /// Maps a single `ID` / `ID_LIKE` word to a family.
    fn from_id(id: &str) -> Option<Self> {
        Some(match id {
            "debian" | "ubuntu" | "raspbian" => Self::Debian,
            "rhel" | "fedora" | "centos" | "rocky" | "almalinux" | "ol" => Self::Rhel,
            "alpine" => Self::Alpine,
            "arch" | "archlinux" => Self::Arch,
            "suse" | "opensuse" | "opensuse-leap" | "opensuse-tumbleweed" | "sles" | "sled" => {
                Self::Suse
            }
            _ => return None,
        })
    }
}

impl fmt::Display for OsFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Debian => "debian",
            Self::Rhel => "rhel",
            Self::Alpine => "alpine",
            Self::Arch => "arch",
            Self::Suse => "suse",
            Self::Unknown => "unknown",
        })
    }
}

/// The fields of `os-release` that `vpsready` uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OsRelease {
    /// `ID`, e.g. `ubuntu`. Defaults to `linux` per the spec.
    pub id: String,
    /// `ID_LIKE`, e.g. `["debian"]`.
    pub id_like: Vec<String>,
    /// `VERSION_ID`, e.g. `24.04`.
    pub version_id: Option<String>,
    /// `PRETTY_NAME`, e.g. `Ubuntu 24.04.3 LTS`. Defaults to `Linux`.
    pub pretty_name: String,
    /// Family derived from `ID`, then `ID_LIKE` in order.
    pub family: OsFamily,
}

impl OsRelease {
    /// Parses the contents of an `os-release` file. Never fails; missing
    /// keys take the defaults from the spec.
    #[must_use]
    pub fn parse(input: &str) -> Self {
        let mut vars = parse_vars(input);
        let id = vars.remove("ID").unwrap_or_else(|| "linux".to_owned());
        let id_like: Vec<String> = vars
            .remove("ID_LIKE")
            .map(|v| v.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default();
        let family = std::iter::once(&id)
            .chain(&id_like)
            .find_map(|i| OsFamily::from_id(i))
            .unwrap_or(OsFamily::Unknown);
        Self {
            id,
            id_like,
            version_id: vars.remove("VERSION_ID"),
            pretty_name: vars
                .remove("PRETTY_NAME")
                .unwrap_or_else(|| "Linux".to_owned()),
            family,
        }
    }

    /// The value used when no `os-release` file exists.
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            id: "unknown".to_owned(),
            id_like: Vec::new(),
            version_id: None,
            pretty_name: "unknown".to_owned(),
            family: OsFamily::Unknown,
        }
    }
}

/// Parses every valid `KEY=VALUE` line. Later assignments win.
#[must_use]
pub fn parse_vars(input: &str) -> BTreeMap<String, String> {
    input.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (key, raw) = line.split_once('=')?;
    let valid_key = key
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid_key {
        return None;
    }
    Some((key.to_owned(), unquote(raw)?))
}

/// Shell-style unquoting. Returns `None` on an unterminated quote.
fn unquote(raw: &str) -> Option<String> {
    #[derive(PartialEq)]
    enum State {
        Bare,
        Single,
        Double,
    }
    let mut out = String::with_capacity(raw.len());
    let mut state = State::Bare;
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        match (&state, c) {
            (State::Single, '\'') | (State::Double, '"') => state = State::Bare,
            (State::Single, c) => out.push(c),
            (State::Bare, '\'') => state = State::Single,
            (State::Bare, '"') => state = State::Double,
            (State::Bare, '\\') => out.push(chars.next()?),
            (State::Double, '\\') => match chars.next()? {
                c @ ('"' | '\\' | '$' | '`') => out.push(c),
                c => {
                    out.push('\\');
                    out.push(c);
                }
            },
            (_, c) => out.push(c),
        }
    }
    (state == State::Bare).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_values() {
        let cases: &[(&str, Option<(&str, &str)>)] = &[
            ("ID=ubuntu", Some(("ID", "ubuntu"))),
            ("NAME=\"Rocky Linux\"", Some(("NAME", "Rocky Linux"))),
            ("NAME='Alpine Linux'", Some(("NAME", "Alpine Linux"))),
            ("  ID=debian  ", Some(("ID", "debian"))),
            ("X=\"a \\\"b\\\" c\"", Some(("X", "a \"b\" c"))),
            ("X=\"back\\\\slash\"", Some(("X", "back\\slash"))),
            ("X=\"\\$HOME \\`id\\`\"", Some(("X", "$HOME `id`"))),
            ("X=\"keep \\n\"", Some(("X", "keep \\n"))),
            ("X='no \\escapes'", Some(("X", "no \\escapes"))),
            ("X=bare\\ space", Some(("X", "bare space"))),
            ("X=", Some(("X", ""))),
            ("X=\"\"", Some(("X", ""))),
            ("X=a=b", Some(("X", "a=b"))),
            ("X=\"unterminated", None),
            ("X=trailing\\", None),
            ("# ID=commented", None),
            ("", None),
            ("   ", None),
            ("no equals sign", None),
            ("=value", None),
            ("1KEY=value", None),
            ("BAD-KEY=value", None),
        ];
        for (line, want) in cases {
            let got = parse_line(line);
            let want = want.map(|(k, v)| (k.to_owned(), v.to_owned()));
            assert_eq!(got, want, "line: {line:?}");
        }
    }

    #[test]
    fn derives_family() {
        let cases = [
            ("ID=ubuntu\nID_LIKE=debian", OsFamily::Debian),
            ("ID=linuxmint\nID_LIKE=\"ubuntu debian\"", OsFamily::Debian),
            ("ID=rocky\nID_LIKE=\"rhel centos fedora\"", OsFamily::Rhel),
            ("ID=fedora", OsFamily::Rhel),
            ("ID=alpine", OsFamily::Alpine),
            ("ID=arch", OsFamily::Arch),
            (
                "ID=opensuse-leap\nID_LIKE=\"suse opensuse\"",
                OsFamily::Suse,
            ),
            ("ID=nixos", OsFamily::Unknown),
            ("", OsFamily::Unknown),
        ];
        for (input, want) in cases {
            assert_eq!(OsRelease::parse(input).family, want, "input: {input:?}");
        }
    }

    #[test]
    fn applies_spec_defaults() {
        let os = OsRelease::parse("# empty\n\n");
        assert_eq!(os.id, "linux");
        assert_eq!(os.pretty_name, "Linux");
        assert_eq!(os.version_id, None);
        assert!(os.id_like.is_empty());
    }

    #[test]
    fn later_assignment_wins() {
        assert_eq!(OsRelease::parse("ID=a\nID=b").id, "b");
    }

    proptest! {
        #[test]
        fn never_panics(input in "\\PC*") {
            let _ = OsRelease::parse(&input);
        }

        #[test]
        fn never_panics_on_os_release_like_input(
            input in "([A-Z_]{1,8}=(\"|'|\\\\)?[ -~]{0,12}(\"|'|\\\\)?\n|#.*\n|\n){0,16}"
        ) {
            let _ = OsRelease::parse(&input);
        }
    }
}
