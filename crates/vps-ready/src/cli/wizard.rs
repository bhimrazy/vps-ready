//! The wizard, bare `vps-ready` on a terminal: a few questions build a
//! profile, which [`change::apply_profile`] applies as `apply --profile`
//! would.

use std::io::{BufRead, Write};
use std::net::IpAddr;
use std::path::Path;

use anyhow::bail;

use super::change::{self, Applied, Host, Selection, plural};
use super::{EXIT_INTERRUPTED, wrap};
use crate::VERSION_INFO;
use crate::audit::{self, Outcome, Severity};
use crate::config::{Profile, ProfileBuilder};
use crate::engine::CADDYFILE;
use crate::engine::{self, Engine, EngineError, StateDir};
use crate::facts::{Facts, OsFamily, Proto, Virt};
use crate::modules::deploy_proxy::{self, Caddyfile, Domain, Upstream};
use crate::modules::firewall_inbound::{self, Allow};
use crate::modules::user_admin::{self, SessionKeys};
use crate::modules::{Applicability, Module, ModuleError};
use crate::resource::ResourceError;
use crate::resource::authorized_keys::is_plain_key;
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
    let (builder, picked) = match ask(host, &facts, prompt, out) {
        Err(e) if interrupted(&e) => {
            writeln!(out, "Nothing was changed.")?;
            return Ok(EXIT_INTERRUPTED);
        }
        answers => answers?,
    };
    let profile = builder.build(host.modules)?;
    if arms_timer(host, &facts, &profile) {
        let minutes = engine::deadman::DEFAULT_WINDOW.as_secs() / 60;
        writeln!(out)?;
        say(
            out,
            "",
            &format!(
                "After you apply, you have {minutes} minutes to log in from a new terminal \
                 and confirm. If you don't, every change is undone."
            ),
        )?;
    }
    writeln!(out)?;
    let mut input = stdin();
    let applied = change::apply_profile(
        host,
        Some(profile),
        &Selection::default(),
        false,
        engine::deadman::DEFAULT_WINDOW,
        Some(&mut input),
        out,
        err,
    )?;
    match applied {
        // "Nothing was changed." ends it.
        Applied::Declined => return Ok(0),
        Applied::Ran(code) if code != 0 => return Ok(code),
        Applied::Ran(_) => {}
        Applied::Nothing if picked => writeln!(out, "\nNothing to do with the modules you chose.")?,
        Applied::Nothing => writeln!(out, "\nNothing to do: this server already matches.")?,
    }
    match next_time(host, &builder, prompt, cwd, out) {
        Err(e) if interrupted(&e) => {
            writeln!(out, "Not saved.")?;
            Ok(EXIT_INTERRUPTED)
        }
        done => done.map(|()| 0),
    }
}

/// Whether `profile` runs a module that arms the safety timer here.
fn arms_timer(host: &Host, facts: &Facts, profile: &Profile) -> bool {
    host.modules.iter().any(|m| {
        m.needs_deadman()
            && profile.params(m.id()).is_some()
            && m.applicable(facts) == Applicability::Applicable
    })
}

/// `text` wrapped at 80 columns, each line after `indent`.
fn say(out: &mut dyn Write, indent: &str, text: &str) -> std::io::Result<()> {
    for line in wrap(text, 80 - indent.len()) {
        writeln!(out, "{indent}{line}")?;
    }
    Ok(())
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

/// The questions, in order; the answers as a profile, and whether the
/// module list was changed.
fn ask(
    host: &Host,
    facts: &Facts,
    prompt: &mut dyn Prompt,
    out: &mut dyn Write,
) -> anyhow::Result<(ProfileBuilder, bool)> {
    let mut builder = ask_profile(facts, prompt)?;
    ask_admin(host, facts, prompt, out, &mut builder)?;
    ask_ports(host, facts, prompt, out, &mut builder)?;
    let picked = prompt.confirm("Pick which modules to run yourself?", false)?
        && ask_modules(host, facts, prompt, out, &mut builder)?;
    ask_sites(host, facts, prompt, out, &mut builder)?;
    Ok((builder, picked))
}

/// `web` or `minimal`, the recommended one first.
fn ask_profile(facts: &Facts, prompt: &mut dyn Prompt) -> anyhow::Result<ProfileBuilder> {
    let web = "Web apps or Docker: opens ports 80 and 443";
    let ssh = "Something else: only SSH is open";
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
    let (copied, from) = match found {
        Some(k) => {
            let n = format!("{} {}", k.keys.len(), plural(k.keys.len(), "key"));
            let path = k.path.display();
            (
                format!("{n} copied from {path}"),
                format!("{n} from {path}"),
            )
        }
        None => {
            let next = "the public key you paste next".to_owned();
            (next.clone(), next)
        }
    };
    let session = facts
        .session
        .as_ref()
        .and_then(|s| s.user.as_deref())
        .filter(|u| *u != "root");
    let default = match session {
        Some(user) => user,
        None => root_default(host)?,
    };
    let name = loop {
        let name = prompt.input("Admin user for logging in", default)?;
        let name = name.trim().to_owned();
        let what = match user_admin::check_name(host.sys, &name) {
            Ok(None) => format!("new account: logs in with {copied}; sudo without a password."),
            Ok(Some(_)) => {
                let who = if session == Some(name.as_str()) {
                    "existing account (the one you logged in as)"
                } else {
                    "existing account"
                };
                // `user.admin` keeps the rules an account already has.
                if user_admin::has_sudo_rules(host.sys, &name)? {
                    format!("{who}: keeps its sudo rules and logs in with {from}")
                } else {
                    format!("{who}: gets sudo without a password and {from}")
                }
            }
            Err(ModuleError::Refused(why)) => {
                say(out, "  ", &why)?;
                continue;
            }
            Err(ModuleError::Resource(ResourceError::InvalidName { .. })) => {
                say(
                    out,
                    "  ",
                    &format!(
                        "{name:?} is not a user name: start with a lowercase letter, then use \
                         lowercase letters, digits, `-` or `_`"
                    ),
                )?;
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        say(out, "  ", &what)?;
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
    if builder.build(host.modules)?.params("ssh.server").is_some() {
        let keys = if found.is_some_and(|k| k.keys.len() > 1) {
            "these keys are"
        } else {
            "this key is"
        };
        say(
            out,
            "  ",
            &format!("Root and password logins will be turned off, so {keys} how you log in."),
        )?;
    }
    Ok(())
}

/// The admin name offered to a root login: the first of `admin` and
/// `sysadmin` that `user.admin` accepts, or none. Ubuntu's cloud images
/// have an `admin` group and no such user, which `user.admin` refuses.
fn root_default(host: &Host) -> anyhow::Result<&'static str> {
    for name in [user_admin::DEFAULT_NAME, "sysadmin"] {
        match user_admin::check_name(host.sys, name) {
            Ok(_) => return Ok(name),
            Err(ModuleError::Refused(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok("")
}

/// A pasted public key: `user.admin` would have no key to give the admin.
fn ask_key(
    keys: Option<&SessionKeys>,
    prompt: &mut dyn Prompt,
    out: &mut dyn Write,
) -> anyhow::Result<String> {
    let none = match keys {
        Some(k) if k.skipped > 0 => format!(
            "{} has no key we can copy ({} {} with options skipped), so paste one.",
            k.path.display(),
            k.skipped,
            plural(k.skipped, "line")
        ),
        Some(k) => format!("{} has no key we can copy, so paste one.", k.path.display()),
        None => "There is no SSH key we can copy, so paste one.".to_owned(),
    };
    say(out, "  ", &none)?;
    say(
        out,
        "  ",
        "Paste the public key from your own computer (the .pub file, e.g. \
         ~/.ssh/id_ed25519.pub).",
    )?;
    loop {
        let key = prompt.input("Public key", "")?;
        let key = key.trim();
        if is_plain_key(key) {
            return Ok(key.to_owned());
        }
        say(
            out,
            "  ",
            "That is not a public key. It starts with ssh-ed25519, ssh-rsa, ecdsa- or sk-. \
             Never paste a private key.",
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
    let mut docker = false;
    for l in facts.listeners.iter().filter(|l| public(&l.addr)) {
        let text = format!("{}/{}", l.port, l.proto);
        if is_ssh(&text) || offered.iter().any(|(t, ..)| *t == text) {
            continue;
        }
        // Docker forwards its published ports before this firewall sees them.
        if l.processes.iter().any(|p| p == "docker-proxy") {
            docker = true;
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
    writeln!(out, "All other incoming ports are blocked.")?;
    if docker {
        say(
            out,
            "",
            "Ports published by Docker are not listed: Docker opens them itself, and this \
             firewall does not block them.",
        )?;
    }
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
        let text = prompt.input(
            "More ports to open, e.g. 8080/tcp or 53/udp (Enter for none)",
            "",
        )?;
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

/// Whether `profile` runs `deploy.proxy` with no sites yet: picked in the
/// module list, for [`ask_sites`] to fill in.
fn proxy_without_sites(profile: &Profile) -> bool {
    profile.params("deploy.proxy").is_some_and(|p| {
        p.get("sites")
            .and_then(toml::Value::as_array)
            .is_none_or(Vec::is_empty)
    })
}

/// With `deploy.docker` still in the profile after the module list, or
/// `deploy.proxy` picked there, the sites `deploy.proxy` serves: none is
/// fine, and at least one adds the module.
fn ask_sites(
    host: &Host,
    facts: &Facts,
    prompt: &mut dyn Prompt,
    out: &mut dyn Write,
    builder: &mut ProfileBuilder,
) -> anyhow::Result<()> {
    let profile = builder.build(host.modules)?;
    let picked = proxy_without_sites(&profile);
    if profile.params("deploy.docker").is_none() && !picked {
        return Ok(());
    }
    let Some(module) = find(host, "deploy.proxy") else {
        return Ok(());
    };
    if let Applicability::NotApplicable { reason } = module.applicable(facts) {
        writeln!(out, "HTTPS sites: skipped, {reason}.")?;
        return Ok(());
    }
    say(
        out,
        "",
        "Caddy can serve your apps over HTTPS and get their certificates. Each domain \
         needs a DNS record for this server.",
    )?;
    if deploy_proxy::caddyfile_state(host.sys)? == Caddyfile::Other {
        say(
            out,
            "  ",
            &format!(
                "{CADDYFILE} was not written by vps-ready, so these domains are not used \
                 unless you move it away first."
            ),
        )?;
    }
    let mut sites: Vec<(String, String)> = Vec::new();
    loop {
        let question = if sites.is_empty() {
            "Domain to serve, e.g. app.example.com (Enter for none)"
        } else {
            "Another domain (Enter for no more)"
        };
        let domain = prompt.input(question, "")?.trim().to_owned();
        if domain.is_empty() {
            break;
        }
        if let Err(why) = Domain::try_from(domain.clone()) {
            say(out, "  ", &why)?;
            continue;
        }
        if sites.iter().any(|(d, _)| *d == domain) {
            say(out, "  ", &format!("{domain} is already listed"))?;
            continue;
        }
        let upstream = loop {
            let text = prompt.input(
                &format!("Address of the app behind {domain}, e.g. 127.0.0.1:8080"),
                "",
            )?;
            let text = text.trim().to_owned();
            match Upstream::try_from(text.clone()) {
                Ok(_) => break text,
                Err(why) => say(out, "  ", &why)?,
            }
        };
        sites.push((domain, upstream));
    }
    if sites.is_empty() {
        if picked {
            builder.remove("deploy.proxy");
            writeln!(out, "  deploy.proxy is left out: it needs a domain.")?;
        }
        return Ok(());
    }
    let sites = sites
        .into_iter()
        .map(|(domain, upstream)| {
            toml::Value::Table(toml::Table::from_iter([
                ("domain".to_owned(), domain.into()),
                ("upstream".to_owned(), upstream.into()),
            ]))
        })
        .collect();
    builder.set_params(
        "deploy.proxy",
        toml::Table::from_iter([("sites".to_owned(), toml::Value::Array(sites))]),
    );
    Ok(())
}

/// Every module, checked if the profile runs it. A list a module refuses
/// to plan, e.g. `ssh.server` without an admin to log in with, is asked
/// again. Returns whether the list changed.
fn ask_modules(
    host: &Host,
    facts: &Facts,
    prompt: &mut dyn Prompt,
    out: &mut dyn Write,
    builder: &mut ProfileBuilder,
) -> anyhow::Result<bool> {
    let profile = builder.build(host.modules)?;
    let items: Vec<Item> = host
        .modules
        .iter()
        .map(|m| {
            let mut label = format!("{}: {}", m.id(), m.title());
            if m.needs_deadman() {
                label.push_str(" (can lock you out; undone unless you confirm)");
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
        let mut any = false;
        for (i, (m, item)) in host.modules.iter().zip(&items).enumerate() {
            match (checked.contains(&i), item.checked) {
                (true, false) => changed.set_params(m.id(), toml::Table::new()),
                (false, true) => changed.remove(m.id()),
                _ => continue,
            };
            any = true;
        }
        // `deploy.proxy` picked here gets its sites from the next question.
        let mut checked_builder = changed.clone();
        if proxy_without_sites(&changed.build(host.modules)?) {
            checked_builder.remove("deploy.proxy");
        }
        let profile = checked_builder.build(host.modules)?;
        let selected = Selection::default().select(host.modules, Some(&profile))?;
        match engine::plan(&selected, facts, host.sys) {
            Ok(_) => {
                *builder = changed;
                return Ok(any);
            }
            Err(EngineError::Module {
                module,
                error: ModuleError::Refused(mut why),
            }) => {
                // `ssh.server` found no other user with a key and sudo.
                if module == "ssh.server" && why.starts_with("refusing to turn off") {
                    why.push_str(". Keep user.admin checked, or add a sudo user first.");
                }
                say(out, "  ", &format!("{module}: {why}"))?;
            }
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
        write!(
            out,
            "Not saved. To repeat this, save these lines to a file and run:\n  \
             sudo vps-ready apply --profile <file>\n\n{text}"
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
    writeln!(out, "Review it before you use it on another server.")?;
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
