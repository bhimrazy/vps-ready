//! `modules` and `modules <ID>`: what each module does and whether it
//! applies to this host.

use std::io::{self, Write};

use serde::Serialize;

use super::wrap;
use crate::audit::{Control, Severity};
use crate::facts::Facts;
use crate::modules::{Applicability, Module, ParamDoc};

const WIDTH: usize = 80;

/// One module as `modules` lists it.
#[derive(Serialize)]
struct Entry {
    id: &'static str,
    title: &'static str,
    applies: bool,
    /// Why not, when it does not apply.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// Whether apply arms the safety timer for it.
    arms_safety_timer: bool,
}

/// One module as `modules <ID>` shows it.
#[derive(Serialize)]
struct Detail<'a> {
    #[serde(flatten)]
    entry: Entry,
    why: &'static str,
    params: &'static [ParamDoc],
    /// The audit controls this module fixes.
    controls: Vec<FixedControl<'a>>,
}

#[derive(Serialize)]
struct FixedControl<'a> {
    id: &'a str,
    severity: Severity,
    title: &'a str,
}

fn entry(module: &dyn Module, facts: &Facts) -> Entry {
    let (applies, reason) = match module.applicable(facts) {
        Applicability::Applicable => (true, None),
        Applicability::NotApplicable { reason } => (false, Some(reason)),
    };
    Entry {
        id: module.id(),
        title: module.title(),
        applies,
        reason,
        arms_safety_timer: module.needs_deadman(),
    }
}

/// Prints every module in `modules`.
pub(super) fn list(
    modules: &[&dyn Module],
    facts: &Facts,
    json: bool,
    out: &mut impl Write,
) -> io::Result<()> {
    let entries: Vec<_> = modules.iter().map(|m| entry(*m, facts)).collect();
    if json {
        serde_json::to_writer_pretty(&mut *out, &entries)?;
        return writeln!(out);
    }
    for e in &entries {
        write_entry(out, e)?;
        writeln!(out)?;
    }
    writeln!(out, "Details: vps-ready modules <ID>")
}

/// Prints `module` in full, with the `controls` it fixes.
pub(super) fn show(
    module: &dyn Module,
    facts: &Facts,
    controls: &[Control],
    json: bool,
    out: &mut impl Write,
) -> io::Result<()> {
    let detail = Detail {
        entry: entry(module, facts),
        why: module.why(),
        params: module.params_doc(),
        controls: controls
            .iter()
            .filter(|c| c.fix.as_deref() == Some(module.id()))
            .map(|c| FixedControl {
                id: &c.id,
                severity: c.severity,
                title: &c.title,
            })
            .collect(),
    };
    if json {
        serde_json::to_writer_pretty(&mut *out, &detail)?;
        return writeln!(out);
    }
    write_entry(out, &detail.entry)?;
    writeln!(out, "\nWhy")?;
    write_wrapped(out, detail.why, "  ")?;
    writeln!(out, "\nParams (in the module's profile table)")?;
    if detail.params.is_empty() {
        writeln!(out, "  none")?;
    }
    for p in detail.params {
        writeln!(out, "  {} (default {})", p.name, p.default)?;
        write_wrapped(out, p.help, "      ")?;
    }
    writeln!(out, "\nFixes these audit controls")?;
    if detail.controls.is_empty() {
        writeln!(out, "  none")?;
    }
    for c in &detail.controls {
        writeln!(out, "  {} [{}] {}", c.id, c.severity, c.title)?;
    }
    Ok(())
}

fn write_entry(out: &mut impl Write, e: &Entry) -> io::Result<()> {
    writeln!(out, "{}", e.id)?;
    write_wrapped(out, e.title, "  ")?;
    match &e.reason {
        None => writeln!(out, "  Applies to this host.")?,
        Some(reason) => write_wrapped(
            out,
            &format!("Does not apply to this host: {reason}."),
            "  ",
        )?,
    }
    if e.arms_safety_timer {
        writeln!(
            out,
            "  Arms the safety timer: confirm from a new SSH session."
        )?;
    }
    Ok(())
}

fn write_wrapped(out: &mut impl Write, text: &str, indent: &str) -> io::Result<()> {
    for line in wrap(text, WIDTH - indent.len()) {
        writeln!(out, "{indent}{line}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit;
    use crate::facts::OsFamily;
    use crate::facts::fixtures::host;
    use crate::modules;

    fn text(f: impl FnOnce(&mut Vec<u8>) -> io::Result<()>) -> String {
        let mut out = Vec::new();
        f(&mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn list_snapshots() {
        let mut other = host("debian-13", &[]);
        other.os.family = OsFamily::Unknown;
        for (name, facts) in [("debian-13", host("debian-13", &[])), ("other-os", other)] {
            for (kind, json) in [("text", false), ("json", true)] {
                let out = text(|o| list(modules::all(), &facts, json, o));
                insta::assert_snapshot!(format!("modules-list-{name}-{kind}"), out);
            }
        }
    }

    #[test]
    fn detail_snapshots() {
        let controls = audit::catalog().unwrap();
        let facts = host("debian-13", &[]);
        for id in ["user.admin", "firewall.inbound", "kernel.sysctl"] {
            let module = modules::all().iter().find(|m| m.id() == id).unwrap();
            for (kind, json) in [("text", false), ("json", true)] {
                let out = text(|o| show(*module, &facts, &controls, json, o));
                insta::assert_snapshot!(format!("modules-{id}-{kind}"), out);
            }
        }
    }
}
