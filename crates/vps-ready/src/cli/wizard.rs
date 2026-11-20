//! The wizard, bare `vps-ready` on a terminal: a few questions build a
//! profile, which [`change::apply_profile`] applies as `apply --profile`
//! would.

use std::ffi::c_int;
use std::io::{BufRead, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::bail;
use zeroize::Zeroizing;

use super::change::{self, Applied, Host, Selection, plural};
use super::export::{self, Refusal};
use super::{EXIT_INTERRUPTED, wrap};
use crate::VERSION_INFO;
use crate::audit::{self, Outcome, Severity};
use crate::config::{Profile, ProfileBuilder, ProfileError, STAGED_VIA, VPNS};
use crate::engine::CADDYFILE;
use crate::engine::{self, Engine, EngineError, StateDir};
use crate::facts::{Facts, OsFamily, Proto, Virt};
use crate::modules::deploy_proxy::{self, Caddyfile, Domain, Upstream};
use crate::modules::firewall_inbound::{self, Allow};
use crate::modules::user_admin::{self, SessionKeys};
use crate::modules::{Applicability, Module, ModuleError};
use crate::modules::{net_tailscale, net_tunnel, net_wireguard};
use crate::resource::ResourceError;
use crate::resource::authorized_keys::is_plain_key;
use crate::sys::{FileKind, FileOwner, Fs, SysError};
use crate::tui::{Defer, Item, Prompt, PromptError};

/// Where the answers are saved, in the current directory.
const SAVE_AS: &str = "vps-ready.toml";

/// A pasted Tailscale auth key, for one apply.
const AUTH_KEY_FILE: &str = net_tailscale::WIZARD_KEY_FILE;

/// [`Fs::write_atomic`]'s temp file for [`AUTH_KEY_FILE`], left by a crash
/// between its create and rename.
const AUTH_KEY_TEMP: &str = "/run/vps-ready/.tailscale-auth-key.vps-ready-tmp";

/// What every Tailscale auth key starts with. Split, so that no text in
/// the source looks like a key.
const AUTH_KEY_PREFIX: &str = concat!("tskey", "-");

/// A pasted tunnel token, kept for every start of the connector.
const TOKEN_FILE: &str = net_tunnel::WIZARD_TOKEN_FILE;

/// What the private profile opens when `deploy.proxy` serves a site.
const WEB_PORTS: [&str; 3] = ["80/tcp", "443/tcp", "443/udp"];

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
    if let Some(step) = step_two(host, &facts, cwd) {
        match ask_step_two(&facts, &step, prompt, out) {
            Err(e) if interrupted(&e) => {
                writeln!(out, "Nothing was changed.")?;
                return Ok(EXIT_INTERRUPTED);
            }
            Ok(true) => return run_step_two(host, &facts, &step, &mut stdin(), out, err),
            Ok(false) => {}
            Err(e) => return Err(e),
        }
    }
    let Answers {
        builder,
        picked,
        auth_key,
        tunnel,
    } = match ask(host, &facts, prompt, out) {
        Err(e) if interrupted(&e) => {
            writeln!(out, "Nothing was changed.")?;
            return Ok(EXIT_INTERRUPTED);
        }
        answers => answers?,
    };
    // Before the plan, which checks the file's owner and mode.
    let token = match tunnel {
        Some(TunnelToken::New { token, replace }) => {
            Some(TokenFile::write(host.sys.fs, &token, replace)?)
        }
        Some(TunnelToken::Keep) | None => None,
    };
    // The key goes only into the profile applied now, never the saved one.
    let mut applied = builder.clone();
    let mut key = match auth_key {
        Some(key) => {
            applied.set_params(
                "net.tailscale",
                toml::Table::from_iter([("auth_key_file".to_owned(), AUTH_KEY_FILE.into())]),
            );
            Some(KeyFile::placeholder(host, key)?)
        }
        None => None,
    };
    let profile = applied.build(host.modules)?;
    if arms_timer(host, &facts, &profile) {
        // The private profile limits SSH in this apply when the login
        // comes through its VPN already.
        let via = staged_via(&profile)
            .filter(|via| firewall_inbound::through(&facts, via))
            .map(str::to_owned)
            .or_else(|| firewall_inbound::ssh_via(&[], host.sys).ok().flatten());
        timer_note(out, via.as_deref())?;
    }
    writeln!(out)?;
    let mut input = stdin();
    let mut plain = change::Plain;
    let applied = change::apply_profile(
        host,
        Some(profile),
        &Selection::default(),
        false,
        Some(engine::deadman::DEFAULT_WINDOW),
        Some(&mut input),
        match &mut key {
            Some(key) => key as &mut dyn change::Around,
            None => &mut plain,
        },
        out,
        err,
    );
    let signal = key.take().and_then(KeyFile::finish);
    if let (Some(token), Ok(Applied::Declined)) = (token, &applied) {
        token.discard(host.sys.fs, out)?;
    }
    if let Some(sig) = signal {
        // Now that the key is gone and the outcome is printed, an error
        // too.
        if let Err(e) = &applied {
            writeln!(err, "error: {e:#}")?;
        }
        writeln!(out, "Stopped by signal {sig}.")?;
        return Ok(u8::try_from(128 + sig).unwrap_or(EXIT_INTERRUPTED));
    }
    let applied = applied?;
    match applied {
        // "Nothing was changed." ends it.
        Applied::Declined => return Ok(0),
        Applied::Ran(code) if code != 0 => return Ok(code),
        Applied::Ran(_) => {}
        Applied::Nothing if picked => writeln!(out, "\nNothing to do with the modules you chose.")?,
        Applied::Nothing => writeln!(out, "\nNothing to do: this server already matches.")?,
    }
    let name = match next_time(host, &builder, prompt, cwd, out) {
        Err(e) if interrupted(&e) => {
            writeln!(out, "Not saved.")?;
            return Ok(EXIT_INTERRUPTED);
        }
        name => name?,
    };
    step_one_done(host, &builder, &name, out)?;
    Ok(0)
}

/// What the wizard says before an apply that arms the safety timer; `via`
/// when the confirm must come through that interface.
fn timer_note(out: &mut dyn Write, via: Option<&str>) -> std::io::Result<()> {
    let minutes = engine::deadman::DEFAULT_WINDOW.as_secs() / 60;
    let through = via.map(|v| format!(" through {v}")).unwrap_or_default();
    writeln!(out)?;
    say(
        out,
        "",
        &format!(
            "After you apply, you have {minutes} minutes to log in{through} from a new \
             terminal and confirm. If you don't, every change is undone."
        ),
    )
}

/// [`AUTH_KEY_FILE`] for one apply. It is created empty before the plan,
/// which checks its owner and mode, and holds the key only from the yes
/// until the engine is done, while [`Defer`] holds back the signals that
/// would end the wizard. Dropping it removes the file; a crash or SIGKILL
/// leaves it for [`remove_key_file`] at the next start.
struct KeyFile<'a> {
    fs: &'a dyn Fs,
    key: Zeroizing<String>,
    defer: Option<Defer>,
    /// Set when a held-back signal arrived, so a wait for a confirm ends.
    stop: Arc<AtomicBool>,
    /// The last signal held back.
    signal: Option<c_int>,
}

impl<'a> KeyFile<'a> {
    /// Creates [`AUTH_KEY_FILE`] empty, root's with mode 0600, in a
    /// directory only root can write to, as `net.tailscale` requires.
    fn placeholder(host: &Host<'a>, key: Zeroizing<String>) -> anyhow::Result<Self> {
        let file = Self {
            fs: host.sys.fs,
            key,
            defer: host.defer.clone(),
            stop: Arc::clone(&host.stop),
            signal: None,
        };
        let path = Path::new(AUTH_KEY_FILE);
        let Some(dir) = path.parent() else {
            bail!("{AUTH_KEY_FILE} has no directory");
        };
        if !file.fs.exists(dir) {
            file.fs.create_dir(dir, root_only(0o700))?;
        }
        let meta = file.fs.metadata(dir)?;
        if meta.kind != FileKind::Dir || meta.uid != 0 || meta.mode & 0o022 != 0 {
            bail!(
                "{} is not a directory only root can write to, so the auth key is not \
                 written there",
                dir.display()
            );
        }
        file.write(b"")?;
        Ok(file)
    }

    /// Through a temp file created with O_EXCL and mode 0600.
    fn write(&self, bytes: &[u8]) -> Result<(), SysError> {
        self.fs
            .write_atomic(Path::new(AUTH_KEY_FILE), bytes, root_only(0o600))
    }

    /// Removes the file and lets the signals end the process again.
    /// Returns the last one held back, for the caller to end with.
    fn finish(mut self) -> Option<c_int> {
        self.release();
        self.signal
    }

    fn release(&mut self) {
        if let Err(e) = remove_key_file(self.fs) {
            tracing::warn!("removing {AUTH_KEY_FILE}: {e}; delete it yourself");
        }
        if let Some(sig) = self.defer.as_ref().and_then(Defer::release) {
            self.signal = Some(sig);
            self.stop.store(true, Ordering::SeqCst);
        }
    }

    /// Whether a held-back signal arrived.
    fn signalled(&self) -> bool {
        self.defer.as_ref().is_some_and(Defer::pending)
    }
}

impl change::Around for KeyFile<'_> {
    /// Writes the key, unless a signal came first: that declines.
    fn before(&mut self) -> anyhow::Result<bool> {
        if let Some(defer) = &self.defer {
            defer.hold();
        }
        if !self.signalled() {
            self.write(self.key.as_bytes())?;
        }
        if self.signalled() {
            self.release();
            return Ok(false);
        }
        Ok(true)
    }

    /// Removes the file before a wait for a confirm. A signal held back
    /// meanwhile stops that wait, so the outcome is printed first.
    fn after(&mut self) {
        self.release();
    }
}

impl Drop for KeyFile<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

/// Mode `mode`, owned by root.
fn root_only(mode: u32) -> FileOwner {
    FileOwner {
        mode,
        uid: 0,
        gid: 0,
    }
}

/// Removes [`AUTH_KEY_FILE`] and the temp file `write_atomic` makes for it,
/// whichever exist.
fn remove_key_file(fs: &dyn Fs) -> Result<(), SysError> {
    for path in [AUTH_KEY_FILE, AUTH_KEY_TEMP] {
        match fs.remove(Path::new(path)) {
            Ok(()) | Err(SysError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// The tunnel's token, from [`ask_tunnel_token`].
enum TunnelToken {
    /// [`TOKEN_FILE`] holds one already.
    Keep,
    /// Pasted; `replace` when [`TOKEN_FILE`] exists.
    New {
        token: Zeroizing<String>,
        replace: bool,
    },
}

/// [`TOKEN_FILE`] as this run wrote it, outside the transaction: it is
/// never a resource, so the journal never copies it, and rollback keeps it.
struct TokenFile {
    /// No file was there before.
    created: bool,
    /// Nor its directory.
    created_dir: bool,
}

impl TokenFile {
    /// Writes `token` to a new [`TOKEN_FILE`] (O_EXCL, root's, 0600) in a
    /// directory only root can write to; `replace` removes the old one
    /// first.
    fn write(fs: &dyn Fs, token: &str, replace: bool) -> anyhow::Result<Self> {
        let path = Path::new(TOKEN_FILE);
        let Some(dir) = path.parent() else {
            bail!("{TOKEN_FILE} has no directory");
        };
        let created_dir = !fs.exists(dir);
        if created_dir {
            fs.create_dir(dir, root_only(0o755))?;
        }
        let meta = fs.metadata(dir)?;
        if meta.kind != FileKind::Dir || meta.uid != 0 || meta.mode & 0o022 != 0 {
            bail!(
                "{} is not a directory only root can write to, so the tunnel token is not \
                 written there",
                dir.display()
            );
        }
        if replace {
            match fs.remove(path) {
                Ok(()) | Err(SysError::NotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        fs.create_new(path, token.as_bytes(), root_only(0o600))?;
        Ok(Self {
            created: !replace,
            created_dir,
        })
    }

    /// After a declined apply: removes a file this run created, so nothing
    /// was changed; a replaced one cannot come back.
    fn discard(self, fs: &dyn Fs, out: &mut dyn Write) -> anyhow::Result<()> {
        if !self.created {
            writeln!(out, "The new tunnel token stays in {TOKEN_FILE}.")?;
            return Ok(());
        }
        let path = Path::new(TOKEN_FILE);
        fs.remove(path)?;
        if self.created_dir
            && let Some(dir) = path.parent()
        {
            fs.remove_dir(dir)?;
        }
        Ok(())
    }
}

/// The private profile's `ssh_via` before it takes effect: its interface.
fn staged_via(profile: &Profile) -> Option<&str> {
    profile
        .params("firewall.inbound")?
        .get("ssh_via")?
        .as_str()?
        .strip_prefix(STAGED_VIA)
}

/// The private profile saved here, in step 1 of 2.
struct StepTwo {
    path: PathBuf,
    profile: Profile,
    /// The interface SSH is to be limited to.
    via: String,
}

/// [`SAVE_AS`] in `cwd` when it is root's, holds the private profile in
/// step 1, and this is a login through its VPN: step 2 can run.
///
/// The directory is not checked. The owner and mode come from the same
/// open as the bytes, with no symlink followed, so swapping the file after
/// the check changes nothing; another user cannot make a file root's, and
/// a hard link to one of root's needs `fs.protected_hardlinks` off. The
/// plan is shown and asked for after this too.
fn step_two(host: &Host, facts: &Facts, cwd: &Path) -> Option<StepTwo> {
    let path = cwd.join(SAVE_AS);
    let (bytes, meta) = host.sys.fs.read_nofollow(&path).ok()?;
    // A file someone else can write is not offered as root's next step.
    if meta.uid != 0 || meta.mode & 0o022 != 0 {
        return None;
    }
    let profile = Profile::parse(std::str::from_utf8(&bytes).ok()?, host.modules).ok()?;
    let via = staged_via(&profile)?.to_owned();
    let loaded = firewall_inbound::ssh_via(&[], host.sys).ok().flatten();
    if !firewall_inbound::through(facts, &via) || loaded.as_deref() == Some(via.as_str()) {
        return None;
    }
    Some(StepTwo { path, profile, via })
}

/// Whether to run step 2, with the console note first.
fn ask_step_two(
    facts: &Facts,
    step: &StepTwo,
    prompt: &mut dyn Prompt,
    out: &mut dyn Write,
) -> anyhow::Result<bool> {
    let StepTwo { path, via, .. } = step;
    say(
        out,
        "",
        &format!(
            "{} is in step 1 of 2, and this login comes through {via}.",
            path.display()
        ),
    )?;
    console_note(facts, via, out)?;
    Ok(prompt.confirm(
        &format!("Apply step 2: accept SSH only through {via}?"),
        false,
    )?)
}

/// How to get back in from the console once SSH depends on `via`, as a
/// sentence.
fn console_note(facts: &Facts, via: &str, out: &mut dyn Write) -> std::io::Result<()> {
    let mut note = firewall_inbound::console(facts, via);
    if let Some(first) = note.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    say(out, "  ", &format!("{note}."))
}

/// Applies step 2 as `apply --profile` would; returns the exit code.
fn run_step_two(
    host: &Host,
    facts: &Facts,
    step: &StepTwo,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<u8> {
    if arms_timer(host, facts, &step.profile) {
        timer_note(out, Some(&step.via))?;
    }
    writeln!(out)?;
    let applied = change::apply_profile(
        host,
        Some(step.profile.clone()),
        &Selection::default(),
        false,
        Some(engine::deadman::DEFAULT_WINDOW),
        Some(input),
        &mut change::Plain,
        out,
        err,
    )?;
    match applied {
        Applied::Declined => return Ok(0),
        Applied::Ran(code) if code != 0 => return Ok(code),
        Applied::Ran(_) => {}
        Applied::Nothing => writeln!(out, "\nNothing to do: this server already matches.")?,
    }
    writeln!(
        out,
        "\nNext time, without questions:\n  sudo vps-ready apply --profile {}",
        step.path.display()
    )?;
    Ok(0)
}

/// After step 1 of the private profile, the login through the VPN that
/// runs step 2. `name` is the profile as `--profile` takes it.
fn step_one_done(
    host: &Host,
    builder: &ProfileBuilder,
    name: &str,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let profile = builder.build(host.modules)?;
    let Some(via) = staged_via(&profile) else {
        return Ok(());
    };
    // The VPN came up only in this apply.
    let facts = (host.facts)(host.sys)?;
    if firewall_inbound::through(&facts, via) {
        return Ok(());
    }
    let user = profile
        .params("user.admin")
        .and_then(|p| p.get("name"))
        .and_then(toml::Value::as_str)
        .unwrap_or(user_admin::DEFAULT_NAME);
    let to = firewall_inbound::address(&facts, via)
        .map_or_else(|| format!("<address of {via}>"), |ip| ip.to_string());
    writeln!(out)?;
    say(
        out,
        "",
        &format!(
            "Step 2 of 2: SSH is still open to the internet. To close it, log in through \
             {via} and apply the same profile again:"
        ),
    )?;
    if profile.params("net.wireguard").is_some() {
        say(
            out,
            "  ",
            "First add the client config printed above to your device, with its private \
             key (`sudo vps-ready wireguard-config` prints it again).",
        )?;
    }
    writeln!(
        out,
        "  ssh -t {user}@{to} sudo vps-ready apply --profile {name}"
    )?;
    Ok(())
}

/// Whether `profile` runs a module that arms the safety timer here. Under
/// a loaded `ssh_via` on its interface, `net.tailscale` or `net.wireguard`
/// arms it too, if it changes anything.
fn arms_timer(host: &Host, facts: &Facts, profile: &Profile) -> bool {
    let via = firewall_inbound::ssh_via(&[], host.sys).ok().flatten();
    let via_tailscale = via
        .as_deref()
        .is_some_and(|via| firewall_inbound::is_tailscale(facts, via));
    let via_wireguard = via.as_deref() == Some(net_wireguard::INTERFACE);
    host.modules.iter().any(|m| {
        (m.needs_deadman()
            || (via_tailscale && m.id() == "net.tailscale")
            || (via_wireguard && m.id() == "net.wireguard"))
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
    let engine = Engine::lock(&state, host.sys)?;
    // An auth key from a run that ended without its cleanup, removed
    // before an unfinished transaction can stop the start.
    remove_key_file(host.sys.fs)?;
    engine.ensure_finished()?;
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

/// What [`ask`] gathers.
struct Answers {
    /// The answers as a profile, saved as they are.
    builder: ProfileBuilder,
    /// Whether the module list was changed.
    picked: bool,
    /// A pasted Tailscale auth key, for this apply only.
    auth_key: Option<Zeroizing<String>>,
    /// The tunnel's token, when the sites go through one.
    tunnel: Option<TunnelToken>,
}

/// The questions, in order.
fn ask(
    host: &Host,
    facts: &Facts,
    prompt: &mut dyn Prompt,
    out: &mut dyn Write,
) -> anyhow::Result<Answers> {
    let mut builder = ask_profile(facts, prompt)?;
    ask_admin(host, facts, prompt, out, &mut builder)?;
    // Before the ports: a VPN starts them from the private profile's none.
    let auth_key = ask_private(host, facts, prompt, out, &mut builder)?;
    ask_ports(host, facts, prompt, out, &mut builder)?;
    let picked = prompt.confirm("Pick which modules to run yourself?", false)?
        && ask_modules(host, facts, prompt, out, &mut builder)?;
    let tunnel = ask_sites(host, facts, prompt, out, &mut builder)?;
    Ok(Answers {
        builder,
        picked,
        auth_key,
        tunnel,
    })
}

/// Whether `firewall.inbound` runs here, so its ports are asked.
fn firewall_applies(host: &Host, facts: &Facts) -> bool {
    find(host, "firewall.inbound").is_some_and(|m| m.applicable(facts) == Applicability::Applicable)
}

/// Private access for SSH: none, or a VPN module that the private profile
/// limits SSH to. A VPN moves the answers onto that profile. Returns a
/// pasted Tailscale auth key.
fn ask_private(
    host: &Host,
    facts: &Facts,
    prompt: &mut dyn Prompt,
    out: &mut dyn Write,
    builder: &mut ProfileBuilder,
) -> anyhow::Result<Option<Zeroizing<String>>> {
    let current = builder.build(host.modules)?;
    if !firewall_applies(host, facts) || current.params("firewall.inbound").is_none() {
        return Ok(None);
    }
    // Only a registered VPN module: the profile would not load without it.
    let vpns: Vec<(&str, &str)> = VPNS
        .iter()
        .copied()
        .filter(|(id, _)| {
            find(host, id).is_some_and(|m| m.applicable(facts) == Applicability::Applicable)
        })
        .collect();
    if vpns.is_empty() {
        return Ok(None);
    }
    let mut items = vec!["None: SSH stays reachable from the internet, with keys only".to_owned()];
    items.extend(vpns.iter().map(|(id, _)| match *id {
        "net.tailscale" => "Tailscale (the private profile)".to_owned(),
        _ => "WireGuard on this server (the private profile)".to_owned(),
    }));
    let i = prompt.select("Private access for SSH", &items, 0)?;
    let Some(&(id, via)) = i.checked_sub(1).and_then(|i| vpns.get(i)) else {
        return Ok(None);
    };
    let mut private = ProfileBuilder::new("private")?;
    if let Some(admin) = current.params("user.admin") {
        private.set_params("user.admin", admin.clone());
    }
    // The answer "Web apps or Docker" keeps Docker.
    if current.params("deploy.docker").is_some() {
        private.set_params("deploy.docker", toml::Table::new());
    }
    if firewall_inbound::through(facts, via) {
        // firewall.inbound skips step 1 for a login through the VPN.
        say(
            out,
            "  ",
            &format!(
                "This login comes through {via}, so this apply closes SSH to the internet \
                 and accepts it only through {via}."
            ),
        )?;
        console_note(facts, via, out)?;
    } else {
        say(
            out,
            "  ",
            &format!(
                "Two steps: this apply sets it up and keeps SSH public; applying again from \
                 a login through {via} closes SSH to the internet."
            ),
        )?;
    }
    let (params, key) = if id == "net.tailscale" {
        (toml::Table::new(), ask_tailscale_key(prompt, out)?)
    } else {
        (ask_wireguard_peer(host, id, prompt, out)?, None)
    };
    private.set_params(id, params);
    *builder = private;
    Ok(key)
}

/// A Tailscale auth key, hidden as it is typed and asked again unless it
/// looks like one; `None` to log in by hand.
fn ask_tailscale_key(
    prompt: &mut dyn Prompt,
    out: &mut dyn Write,
) -> anyhow::Result<Option<Zeroizing<String>>> {
    say(
        out,
        "  ",
        "An auth key from the Tailscale admin console logs this server in during the \
         apply. It is used once and never saved.",
    )?;
    loop {
        let typed =
            Zeroizing::new(prompt.password("Auth key (hidden; Enter to log in yourself after)")?);
        let key = typed.trim();
        if key.is_empty() {
            return Ok(None);
        }
        if key.starts_with(AUTH_KEY_PREFIX) {
            return Ok(Some(Zeroizing::new(key.to_owned())));
        }
        say(
            out,
            "  ",
            &format!("That is not an auth key: it starts with {AUTH_KEY_PREFIX}"),
        )?;
    }
}

/// The device that connects to WireGuard on this server, as module `id`'s
/// params, checked by the module itself and asked again on a bad value.
fn ask_wireguard_peer(
    host: &Host,
    id: &str,
    prompt: &mut dyn Prompt,
    out: &mut dyn Write,
) -> anyhow::Result<toml::Table> {
    let Some(module) = find(host, id) else {
        bail!("{id} is not a module");
    };
    say(
        out,
        "  ",
        "Make a key pair on the device you will connect from: `(umask 077; wg genkey | tee \
         laptop.key | wg pubkey)`, or \"Add tunnel\" in the WireGuard app.",
    )?;
    loop {
        let name = prompt.input("Name of the device", "laptop")?;
        let key = prompt.input("Its public key", "")?;
        let peer = toml::Table::from_iter([
            ("name".to_owned(), name.trim().into()),
            ("public_key".to_owned(), key.trim().into()),
            ("host".to_owned(), 2.into()),
        ]);
        let params = toml::Table::from_iter([(
            "peers".to_owned(),
            toml::Value::Array(vec![toml::Value::Table(peer)]),
        )]);
        match module.check_params(&params) {
            Ok(()) => return Ok(params),
            Err(ModuleError::Refused(why)) => say(out, "  ", &why)?,
            Err(e) => return Err(e.into()),
        }
    }
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
        let via = params
            .get("ssh_via")
            .and_then(toml::Value::as_str)
            .and_then(|v| v.strip_prefix(STAGED_VIA));
        let question = match via {
            Some(via) => format!("Open ports besides SSH (only through {via} after step 2)"),
            None if ssh_list.is_empty() => "Open ports besides SSH".to_owned(),
            None => format!(
                "Open ports besides SSH ({}, always open)",
                ssh_list.join(", ")
            ),
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
/// fine, and at least one adds the module. On the private profile, they go
/// through a Cloudflare Tunnel or open 80 and 443; returns the tunnel's
/// token.
fn ask_sites(
    host: &Host,
    facts: &Facts,
    prompt: &mut dyn Prompt,
    out: &mut dyn Write,
    builder: &mut ProfileBuilder,
) -> anyhow::Result<Option<TunnelToken>> {
    let profile = builder.build(host.modules)?;
    let picked = proxy_without_sites(&profile);
    if profile.params("deploy.docker").is_none() && !picked {
        return Ok(None);
    }
    let Some(module) = find(host, "deploy.proxy") else {
        return Ok(None);
    };
    if let Applicability::NotApplicable { reason } = module.applicable(facts) {
        writeln!(out, "HTTPS sites: skipped, {reason}.")?;
        return Ok(None);
    }
    let private = builder.base() == "private";
    let tunnel = private
        && find(host, "net.tunnel")
            .is_some_and(|m| m.applicable(facts) == Applicability::Applicable);
    say(
        out,
        "",
        if tunnel {
            "Caddy can serve your apps over HTTPS, through a Cloudflare Tunnel or directly \
             (asked after the domains)."
        } else {
            "Caddy can serve your apps over HTTPS and get their certificates. Each domain \
             needs a DNS record for this server."
        },
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
        return Ok(None);
    }
    let count = sites.len();
    let sites = sites
        .into_iter()
        .map(|(domain, upstream)| {
            toml::Value::Table(toml::Table::from_iter([
                ("domain".to_owned(), domain.into()),
                ("upstream".to_owned(), upstream.into()),
            ]))
        })
        .collect();
    let mut proxy = toml::Table::from_iter([("sites".to_owned(), toml::Value::Array(sites))]);
    if tunnel && ask_through_tunnel(prompt, count)? {
        let token = ask_tunnel_token(host, prompt, out)?;
        let mut params = toml::Table::new();
        if token.is_some() {
            params.insert("token_file".to_owned(), TOKEN_FILE.into());
        }
        builder.set_params("net.tunnel", params);
        proxy.insert("behind_tunnel".to_owned(), true.into());
        builder.set_params("deploy.proxy", proxy);
        say(
            out,
            "  ",
            "No port is opened: cloudflared connects out to Cloudflare, and Caddy listens on \
             loopback only.",
        )?;
        return Ok(token);
    }
    builder.set_params("deploy.proxy", proxy);
    if private {
        open_web_ports(host, out, builder)?;
    }
    Ok(None)
}

/// Whether visitors reach the `count` sites through a Cloudflare Tunnel
/// rather than on 80 and 443.
fn ask_through_tunnel(prompt: &mut dyn Prompt, count: usize) -> anyhow::Result<bool> {
    let items = [
        "Through a Cloudflare Tunnel (no public ports; DNS on Cloudflare)".to_owned(),
        "Directly, on ports 80 and 443 (Caddy gets the certificate)".to_owned(),
    ];
    let question = if count == 1 {
        "How do visitors reach this site"
    } else {
        "How do visitors reach these sites"
    };
    Ok(prompt.select(question, &items, 0)? == 0)
}

/// The tunnel's token, hidden as it is typed and asked again unless it has
/// the shape of one; [`TOKEN_FILE`] kept if it holds one and the answer is
/// yes. `None` to add it later.
fn ask_tunnel_token(
    host: &Host,
    prompt: &mut dyn Prompt,
    out: &mut dyn Write,
) -> anyhow::Result<Option<TunnelToken>> {
    let fs = host.sys.fs;
    let path = Path::new(TOKEN_FILE);
    let replace = match fs.metadata(path) {
        Ok(_) => true,
        Err(SysError::NotFound(_)) => false,
        Err(e) => return Err(e.into()),
    };
    if replace {
        // Root's and private, as the plan requires, and a token.
        let usable = fs.read_nofollow(path).is_ok_and(|(bytes, meta)| {
            let bytes = Zeroizing::new(bytes);
            meta.uid == 0
                && meta.mode & 0o077 == 0
                && std::str::from_utf8(&bytes).is_ok_and(net_tunnel::is_token)
        });
        if usable {
            if prompt.confirm(
                &format!("{TOKEN_FILE} holds a tunnel token. Keep it?"),
                true,
            )? {
                return Ok(Some(TunnelToken::Keep));
            }
        } else {
            say(
                out,
                "  ",
                &format!(
                    "{TOKEN_FILE} holds no tunnel token that only root can read, so the token \
                     you paste replaces it."
                ),
            )?;
        }
    }
    say(
        out,
        "  ",
        &format!(
            "Create a tunnel in the Cloudflare dashboard and copy its token, the long string \
             in the install command it shows. It is saved to {TOKEN_FILE}, readable only by \
             root, for the connector to read at each start."
        ),
    )?;
    loop {
        let typed =
            Zeroizing::new(prompt.password("Tunnel token (hidden; Enter to add it later)")?);
        // The whole install command works too: the token is its last word.
        let token = typed.split_whitespace().last().unwrap_or_default();
        if token.is_empty() {
            return Ok(None);
        }
        if net_tunnel::is_token(token) {
            return Ok(Some(TunnelToken::New {
                token: Zeroizing::new(token.to_owned()),
                replace,
            }));
        }
        say(
            out,
            "  ",
            "That is not a tunnel token: copy it from the install command in the Cloudflare \
             dashboard.",
        )?;
    }
}

/// Adds [`WEB_PORTS`] to `firewall.inbound`'s `allow`, which the private
/// profile leaves empty.
fn open_web_ports(
    host: &Host,
    out: &mut dyn Write,
    builder: &mut ProfileBuilder,
) -> anyhow::Result<()> {
    let profile = builder.build(host.modules)?;
    let Some(params) = profile.params("firewall.inbound") else {
        return Ok(());
    };
    let mut allow: Vec<toml::Value> = params
        .get("allow")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();
    for port in WEB_PORTS {
        if !allow.iter().any(|v| v.as_str() == Some(port)) {
            allow.push(port.into());
        }
    }
    builder.set_params(
        "firewall.inbound",
        toml::Table::from_iter([("allow".to_owned(), toml::Value::Array(allow))]),
    );
    say(
        out,
        "  ",
        "Ports 80/tcp, 443/tcp and 443/udp are opened for Caddy.",
    )?;
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
        let built = match changed.build(host.modules) {
            Ok(profile) => profile,
            // The private profile without its one VPN module.
            Err(ProfileError::Vpn(why)) => {
                say(out, "  ", &why)?;
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        // `deploy.proxy` picked here gets its sites from the next question.
        let mut checked_builder = changed.clone();
        if proxy_without_sites(&built) {
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
/// or the answers saved to [`SAVE_AS`] if they differ from it. Returns the
/// profile as `--profile` takes it.
fn next_time(
    host: &Host,
    builder: &ProfileBuilder,
    prompt: &mut dyn Prompt,
    cwd: &Path,
    out: &mut dyn Write,
) -> anyhow::Result<String> {
    let repeat = |out: &mut dyn Write, profile: &str| {
        writeln!(
            out,
            "\nNext time, without questions:\n  sudo vps-ready apply --profile {profile}"
        )
    };
    if builder.is_unchanged() {
        repeat(out, builder.base())?;
        new_server(host, builder, Saved::Base, out)?;
        return Ok(builder.base().to_owned());
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
        new_server(host, builder, Saved::No, out)?;
        return Ok("<file>".to_owned());
    }
    let owner = FileOwner {
        mode: 0o644,
        uid: 0,
        gid: 0,
    };
    host.sys.fs.write_atomic(&path, text.as_bytes(), owner)?;
    writeln!(out, "Saved {}.", path.display())?;
    writeln!(out, "Review it before you use it on another server.")?;
    let name = path.display().to_string();
    repeat(out, &name)?;
    new_server(host, builder, Saved::To(&path), out)?;
    Ok(name)
}

/// Where [`next_time`] left the answers.
enum Saved<'a> {
    /// Nothing to save: the built-in profile as it is.
    Base,
    /// Printed, not saved.
    No,
    To(&'a Path),
}

/// The closing line: the export that sets up a new server the same way at
/// its first boot.
fn new_server(
    host: &Host,
    builder: &ProfileBuilder,
    saved: Saved,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let refused = export::refusal(&builder.build(host.modules)?);
    let (name, first) = match (saved, refused) {
        (Saved::To(path), None) => (path.display().to_string(), String::new()),
        (Saved::To(path), Some(Refusal::NoAdminKeys)) => {
            let path = path.display().to_string();
            let first = format!(" (add the admin's `authorized_keys` to {path} first)");
            (path, first)
        }
        (Saved::To(path), Some(Refusal::TailscaleAuthKey)) => {
            let path = path.display().to_string();
            let first = format!(" (remove net.tailscale's `auth_key_file` from {path} first)");
            (path, first)
        }
        (Saved::No, None) => ("<file>".to_owned(), String::new()),
        (Saved::No, Some(Refusal::NoAdminKeys)) => (
            "<file>".to_owned(),
            " (with the admin's `authorized_keys` in the file)".to_owned(),
        ),
        (Saved::To(path), Some(Refusal::SshVia)) => {
            let path = path.display().to_string();
            let first = format!(" (remove firewall.inbound's `ssh_via` from {path} first)");
            (path, first)
        }
        (Saved::No, Some(Refusal::TailscaleAuthKey)) => (
            "<file>".to_owned(),
            " (without net.tailscale's `auth_key_file`)".to_owned(),
        ),
        (Saved::No, Some(Refusal::SshVia)) => (
            "<file>".to_owned(),
            " (without firewall.inbound's `ssh_via`)".to_owned(),
        ),
        (Saved::To(path), Some(Refusal::TunnelToken)) => {
            let path = path.display().to_string();
            let first = format!(" (remove net.tunnel's `token_file` from {path} first)");
            (path, first)
        }
        (Saved::No, Some(Refusal::TunnelToken)) => (
            "<file>".to_owned(),
            " (without net.tunnel's `token_file`)".to_owned(),
        ),
        // A built-in profile has no keys.
        (Saved::Base, _) => (
            "<file>".to_owned(),
            format!(
                " (a file with `extends = \"{}\"` and the admin's `authorized_keys`)",
                builder.base()
            ),
        ),
    };
    writeln!(
        out,
        "\nSame setup for a new server, at its first boot{first}:\n  \
         vps-ready export cloud-init --profile {name} --checksums checksums.txt"
    )?;
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
