//! The wizard, bare `vps-ready` on a terminal: a few questions build a
//! profile, which [`change::apply_profile`] applies as `apply --profile`
//! would.

use std::io::{BufRead, Write};
use std::net::IpAddr;
use std::path::Path;

use anyhow::bail;

use super::EXIT_INTERRUPTED;
use super::change::{self, Host, Selection, plural};
use crate::VERSION_INFO;
use crate::audit::{self, Outcome, Severity};
use crate::config::ProfileBuilder;
use crate::engine::{self, Engine, EngineError, StateDir};
use crate::facts::{Facts, OsFamily, Proto, Virt};
use crate::modules::firewall_inbound::{self, Allow};
use crate::modules::user_admin::{self, SessionKeys};
use crate::modules::{Applicability, Module, ModuleError};
use crate::resource::ResourceError;
use crate::sys::FileOwner;
use crate::tui::{Item, Prompt, PromptError};

/// Where the answers are saved, in the current directory.
const SAVE_AS: &str = "vps-ready.toml";

/// Runs the wizard. `cwd` is where the answers are saved; `stdin` gives the
/// terminal for apply's own question, called after the last of `prompt`'s.
pub(super) fn run<R: BufRead>(
    host: &Host,
    prompt: &mut dyn Prompt,
    cwd: &Path,
    stdin: impl FnOnce() -> R,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<u8> {
    start_checks(host)?;
    let facts = (host.facts)(host.sys)?;
    header(&facts, out)?;
    let builder = match ask(host, &facts, prompt, out) {
        Err(e) if interrupted(&e) => {
            writeln!(out, "Nothing was changed.")?;
            return Ok(EXIT_INTERRUPTED);
        }
        answers => answers?,
    };
    let profile = builder.build(host.modules)?;
    writeln!(out)?;
    let mut input = stdin();
    let code = change::apply_profile(
        host,
        Some(profile),
        &Selection::default(),
        false,
        engine::deadman::DEFAULT_WINDOW,
        Some(&mut input),
        out,
        err,
    )?;
    if code != 0 {
        return Ok(code);
    }
    match next_time(host, &builder, prompt, cwd, out) {
        Err(e) if interrupted(&e) => Ok(EXIT_INTERRUPTED),
        done => done.map(|()| 0),
    }
}

fn interrupted(err: &anyhow::Error) -> bool {
    matches!(err.downcast_ref(), Some(PromptError::Interrupted))
}

/// Stops before the first question for what would stop apply anyway.
fn start_checks(host: &Host) -> anyhow::Result<()> {
    if !host.root {
        bail!("setting up this server needs root. Run it with sudo: sudo vps-ready");
    }
    engine::deadman::check_binary(host.sys.fs, &host.binary).map_err(|reason| {
        EngineError::UnsafeBinary {
            path: host.binary.display().to_string(),
            reason,
        }
    })?;
    let state = StateDir::create(host.sys.fs, host.state_dir, host.state_uid)?;
    Engine::lock(&state, host.sys)?.ensure_finished()?;
    Ok(())
}

/// e.g. `vps-ready 0.4.0 on Ubuntu 24.04.3 LTS (kvm)`, then the audit in a
/// line.
fn header(facts: &Facts, out: &mut dyn Write) -> anyhow::Result<()> {
    let os = if facts.os.family == OsFamily::Unknown {
        "this host"
    } else {
        &facts.os.pretty_name
    };
    let virt = match (&facts.virtualization.container, &facts.virtualization.vm) {
        (Virt::Detected(c), Virt::Detected(vm)) => format!(" ({c} container on {vm})"),
        (Virt::Detected(c), _) => format!(" ({c} container)"),
        (_, Virt::Detected(vm)) => format!(" ({vm})"),
        _ => String::new(),
    };
    writeln!(out, "vps-ready {} on {os}{virt}", VERSION_INFO.version)?;

    let report = audit::run(audit::catalog()?, facts);
    let s = report.summary;
    let failed = || {
        report
            .findings
            .iter()
            .filter(|f| matches!(f.outcome, Outcome::Fail { .. }))
    };
    let mut line = format!("Audit: {} passed, {} failed", s.passed, s.failed);
    let by_severity: Vec<String> = [Severity::High, Severity::Medium, Severity::Low]
        .into_iter()
        .filter_map(|sev| {
            let n = failed().filter(|f| f.control.severity == sev).count();
            (n > 0).then(|| format!("{n} {sev}"))
        })
        .collect();
    if !by_severity.is_empty() {
        line.push_str(&format!(" ({})", by_severity.join(", ")));
    }
    if s.unknown > 0 {
        line.push_str(&format!(", {} unknown", s.unknown));
    }
    line.push('.');
    match failed().filter(|f| f.control.fix.is_some()).count() {
        0 => {}
        1 if s.failed == 1 => line.push_str(" vps-ready can fix it."),
        n if n == s.failed => line.push_str(" vps-ready can fix all of them."),
        n => line.push_str(&format!(" vps-ready can fix {n} of them.")),
    }
    writeln!(out, "{line}\n")?;
    Ok(())
}

/// The questions, in order; the answers as a profile.
fn ask(
    host: &Host,
    facts: &Facts,
    prompt: &mut dyn Prompt,
    out: &mut dyn Write,
) -> anyhow::Result<ProfileBuilder> {
    let mut builder = ask_profile(facts, prompt)?;
    ask_admin(host, facts, prompt, out, &mut builder)?;
    ask_ports(host, facts, prompt, out, &mut builder)?;
    if prompt.confirm("Change the module list?", false)? {
        ask_modules(host, facts, prompt, out, &mut builder)?;
    }
    Ok(builder)
}

/// `web` or `minimal`, the recommended one first.
fn ask_profile(facts: &Facts, prompt: &mut dyn Prompt) -> anyhow::Result<ProfileBuilder> {
    let web = "Web apps or Docker: opens ports 80 and 443";
    let ssh = "Something else: SSH only";
    let serving = facts
        .listeners
        .iter()
        .find(|l| matches!(l.port, 80 | 443) && public(&l.addr));
    let why_web = if facts.docker {
        Some("Docker is installed".to_owned())
    } else {
        serving.map(|l| format!("something listens on port {}", l.port))
    };
    let (items, bases) = match why_web {
        Some(why) => (
            [format!("{web} (recommended: {why})"), ssh.to_owned()],
            ["web", "minimal"],
        ),
        None => (
            [
                format!("{ssh} (recommended: no Docker or web server found)"),
                web.to_owned(),
            ],
            ["minimal", "web"],
        ),
    };
    let i = prompt.select("What will this server run?", &items, 0)?;
    Ok(ProfileBuilder::new(bases[i])?)
}

/// The admin's name, checked as `user.admin` checks it, and a key when
/// there is none to copy.
fn ask_admin(
    host: &Host,
    facts: &Facts,
    prompt: &mut dyn Prompt,
    out: &mut dyn Write,
    builder: &mut ProfileBuilder,
) -> anyhow::Result<()> {
    let module = find(host, "user.admin");
    if let Some(Applicability::NotApplicable { reason }) = module.map(|m| m.applicable(facts)) {
        writeln!(out, "Admin user: skipped, {reason}.")?;
        return Ok(());
    }
    let keys = match user_admin::session_keys(facts, host.sys) {
        Ok(keys) => Some(keys),
        // The login user has no passwd entry: there is nothing to copy.
        Err(ModuleError::Refused(_)) => None,
        Err(e) => return Err(e.into()),
    };
    let found = keys.as_ref().filter(|k| !k.keys.is_empty());
    let with_keys = match found {
        Some(k) => format!(
            "{} {} from {}",
            k.keys.len(),
            plural(k.keys.len(), "key"),
            k.path.display()
        ),
        None => "the public key you paste next".to_owned(),
    };
    let session = facts
        .session
        .as_ref()
        .and_then(|s| s.user.as_deref())
        .filter(|u| *u != "root");
    let default = session.unwrap_or(user_admin::DEFAULT_NAME);
    let name = loop {
        let name = prompt.input("Admin user (logs in with an SSH key, uses sudo)", default)?;
        let name = name.trim().to_owned();
        match user_admin::check_name(host.sys, &name) {
            Ok(None) => writeln!(out, "  created, with {with_keys}")?,
            Ok(Some(_)) if session == Some(name.as_str()) => writeln!(
                out,
                "  existing account (the one you logged in as): gets sudo and {with_keys}"
            )?,
            Ok(Some(_)) => writeln!(out, "  existing account: gets sudo and {with_keys}")?,
            Err(ModuleError::Refused(why)) => {
                writeln!(out, "  {why}")?;
                continue;
            }
            Err(ModuleError::Resource(ResourceError::InvalidName { .. })) => {
                writeln!(
                    out,
                    "  {name:?} is not a user name: start with a lowercase letter, then use \
                     lowercase letters, digits, `-` or `_`"
                )?;
                continue;
            }
            Err(e) => return Err(e.into()),
        }
        break name;
    };
    let mut params = toml::Table::new();
    if name != user_admin::DEFAULT_NAME {
        params.insert("name".to_owned(), name.into());
    }
    if found.is_none() {
        let key = ask_key(keys.as_ref(), prompt, out)?;
        params.insert(
            "authorized_keys".to_owned(),
            toml::Value::Array(vec![key.into()]),
        );
    }
    builder.set_params("user.admin", params);
    Ok(())
}

/// A pasted public key: `user.admin` would have no key to give the admin.
fn ask_key(
    keys: Option<&SessionKeys>,
    prompt: &mut dyn Prompt,
    out: &mut dyn Write,
) -> anyhow::Result<String> {
    match keys {
        Some(k) if k.skipped > 0 => writeln!(
            out,
            "  {} has no key to copy ({} {} with options skipped).",
            k.path.display(),
            k.skipped,
            plural(k.skipped, "line")
        )?,
        Some(k) => writeln!(out, "  {} has no key to copy.", k.path.display())?,
        None => writeln!(out, "  There is no SSH key to copy.")?,
    }
    loop {
        let key = prompt.input(
            "Paste your public key (the line in ~/.ssh/id_ed25519.pub on your computer)",
            "",
        )?;
        let key = key.trim();
        if user_admin::is_plain_key(key) {
            return Ok(key.to_owned());
        }
        writeln!(
            out,
            "  That is not a public key: it starts with ssh-ed25519, ssh-rsa, ecdsa- or sk-, \
             then the key."
        )?;
    }
}

/// The ports `firewall.inbound` accepts besides SSH: the profile's, the
/// ports something listens on publicly, and typed ones.
fn ask_ports(
    host: &Host,
    facts: &Facts,
    prompt: &mut dyn Prompt,
    out: &mut dyn Write,
    builder: &mut ProfileBuilder,
) -> anyhow::Result<()> {
    let module = find(host, "firewall.inbound");
    if let Some(Applicability::NotApplicable { reason }) = module.map(|m| m.applicable(facts)) {
        writeln!(out, "Open ports: skipped, {reason}.")?;
        return Ok(());
    }
    let profile = builder.build(host.modules)?;
    let Some(params) = profile.params("firewall.inbound") else {
        return Ok(());
    };
    let base: Vec<String> = params
        .get("allow")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    let ssh = firewall_inbound::ssh_ports(facts);
    let is_ssh = |text: &str| {
        Allow::try_from(text.to_owned())
            .is_ok_and(|a| a.proto == Proto::Tcp && ssh.contains(&a.port))
    };
    // (`allow` entry, label, checked)
    let mut offered: Vec<(String, String, bool)> = base
        .iter()
        .filter(|t| !is_ssh(t))
        .map(|t| (t.clone(), t.clone(), true))
        .collect();
    for l in &facts.listeners {
        // Docker forwards its published ports before this firewall sees them.
        if !public(&l.addr) || l.processes.iter().any(|p| p == "docker-proxy") {
            continue;
        }
        let text = format!("{}/{}", l.port, l.proto);
        if is_ssh(&text) || offered.iter().any(|(t, ..)| *t == text) {
            continue;
        }
        let label = if l.processes.is_empty() {
            text.clone()
        } else {
            format!("{text} ({})", l.processes.join(", "))
        };
        offered.push((text, label, false));
    }

    let ssh_list: Vec<String> = ssh.iter().map(u16::to_string).collect();
    let mut picked: Vec<String> = Vec::new();
    if !offered.is_empty() {
        writeln!(out, "Unchecked ports will be blocked.")?;
        let items: Vec<Item> = offered
            .iter()
            .map(|(_, label, checked)| Item {
                label: label.clone(),
                checked: *checked,
                dim: false,
            })
            .collect();
        let question = if ssh_list.is_empty() {
            "Open ports besides SSH".to_owned()
        } else {
            format!(
                "Open ports besides SSH ({}, always open)",
                ssh_list.join(", ")
            )
        };
        for i in prompt.multi_select(&question, &items)? {
            picked.extend(offered.get(i).map(|(t, ..)| t.clone()));
        }
    }
    let typed = loop {
        let text = prompt.input("Other ports to open, like 8080/tcp (Enter for none)", "")?;
        let parsed: Result<Vec<String>, String> = text
            .split([' ', ','])
            .filter(|t| !t.is_empty())
            .map(|t| Allow::try_from(t.to_owned()).map(|a| format!("{}/{}", a.port, a.proto)))
            .collect();
        match parsed {
            Ok(typed) => break typed,
            Err(e) => writeln!(out, "  {e}")?,
        }
    };

    // The base's order, so unchanged answers write nothing.
    let mut allow: Vec<String> = base
        .iter()
        .filter(|t| is_ssh(t) || picked.contains(t))
        .cloned()
        .collect();
    for text in picked.into_iter().chain(typed) {
        if !allow.contains(&text) {
            allow.push(text);
        }
    }
    let allow = toml::Value::Array(allow.into_iter().map(toml::Value::from).collect());
    builder.set_params(
        "firewall.inbound",
        toml::Table::from_iter([("allow".to_owned(), allow)]),
    );
    Ok(())
}

/// Every module, checked if the profile runs it. A list a module refuses
/// to plan, e.g. `ssh.server` without an admin to log in with, is asked
/// again.
fn ask_modules(
    host: &Host,
    facts: &Facts,
    prompt: &mut dyn Prompt,
    out: &mut dyn Write,
    builder: &mut ProfileBuilder,
) -> anyhow::Result<()> {
    let profile = builder.build(host.modules)?;
    let items: Vec<Item> = host
        .modules
        .iter()
        .map(|m| {
            let mut label = format!("{}: {}", m.id(), m.title());
            if m.needs_deadman() {
                label.push_str(" (arms the safety timer)");
            }
            let reason = match m.applicable(facts) {
                Applicability::NotApplicable { reason } => Some(reason),
                Applicability::Applicable => None,
            };
            if let Some(reason) = &reason {
                label.push_str(&format!(" (does not apply: {reason})"));
            }
            Item {
                label,
                checked: profile.params(m.id()).is_some(),
                dim: reason.is_some(),
            }
        })
        .collect();
    loop {
        let checked = prompt.multi_select("Modules to run", &items)?;
        let mut changed = builder.clone();
        for (i, (m, item)) in host.modules.iter().zip(&items).enumerate() {
            match (checked.contains(&i), item.checked) {
                (true, false) => changed.set_params(m.id(), toml::Table::new()),
                (false, true) => changed.remove(m.id()),
                _ => continue,
            };
        }
        let profile = changed.build(host.modules)?;
        let selected = Selection::default().select(host.modules, Some(&profile))?;
        match engine::plan(&selected, facts, host.sys) {
            Ok(_) => {
                *builder = changed;
                return Ok(());
            }
            Err(EngineError::Module {
                module,
                error: ModuleError::Refused(why),
            }) => writeln!(out, "  {module}: {why}")?,
            Err(e) => return Err(e.into()),
        }
    }
}

/// The command that repeats this without questions: the built-in profile,
/// or the answers saved to [`SAVE_AS`] if they differ from it.
fn next_time(
    host: &Host,
    builder: &ProfileBuilder,
    prompt: &mut dyn Prompt,
    cwd: &Path,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let repeat = |out: &mut dyn Write, profile: &str| {
        writeln!(
            out,
            "\nNext time, without questions:\n  sudo vps-ready apply --profile {profile}"
        )
    };
    if builder.is_unchanged() {
        repeat(out, builder.base())?;
        return Ok(());
    }
    writeln!(out)?;
    let path = cwd.join(SAVE_AS);
    let save = prompt.confirm(
        &format!("Save your answers to {SAVE_AS} to repeat them later?"),
        true,
    )? && (!host.sys.fs.exists(&path)
        || prompt.confirm(&format!("{} exists. Replace it?", path.display()), false)?);
    let text = builder.to_toml();
    if !save {
        writeln!(
            out,
            "Not saved. To repeat this, save these lines to a file and run \
             `sudo vps-ready apply --profile <file>`:\n\n{text}"
        )?;
        return Ok(());
    }
    let owner = FileOwner {
        mode: 0o644,
        uid: 0,
        gid: 0,
    };
    host.sys.fs.write_atomic(&path, text.as_bytes(), owner)?;
    writeln!(out, "Saved {}.", path.display())?;
    repeat(out, &path.display().to_string())?;
    Ok(())
}

fn find<'a>(host: &Host<'a>, id: &str) -> Option<&'a dyn Module> {
    host.modules.iter().copied().find(|m| m.id() == id)
}

/// Whether a listener on `addr` is reachable from other hosts: any address
/// but loopback, ignoring a `%zone`.
fn public(addr: &str) -> bool {
    let addr = addr.split_once('%').map_or(addr, |(a, _)| a);
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => !ip.is_loopback(),
        Ok(IpAddr::V6(ip)) => {
            !ip.is_loopback() && !ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        // `*`: every address.
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests;
