//! The dead-man switch on the host: the transient timer that rolls back an
//! unconfirmed transaction, the boot hook that does it after a reboot, the
//! clock its deadlines use and the check of the binary both run.

use std::path::Path;
use std::time::Duration;

use super::EngineError;
use super::journal::{Deadline, Event, Record};
use super::reload::{self, SYSTEMCTL_TIMEOUT};
use crate::sys::{Cmd, FileKind, FileOwner, Fs, Output, Runner, Sys, SysError};

/// The window a confirm has by default.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(5 * 60);
/// The shortest window `apply --deadman` takes.
pub const MIN_WINDOW: Duration = Duration::from_secs(60);
/// The longest window `apply --deadman` takes.
pub const MAX_WINDOW: Duration = Duration::from_secs(30 * 60);

/// The longest `confirm --extend` moves the deadline ahead of now.
pub const MAX_EXTEND: Duration = MAX_WINDOW;
/// The longest a transaction waits for a confirm, from when its changes
/// went live, however often it is extended.
pub const MAX_PENDING: Duration = Duration::from_secs(2 * 60 * 60);

/// The boot hook's unit file. Engine infrastructure, not a resource: no
/// transaction backs it up or removes it.
pub const HOOK: &str = "/etc/systemd/system/vps-ready-deadman.service";
const HOOK_UNIT: &str = "vps-ready-deadman.service";

/// `CLOCK_BOOTTIME`, as `/proc/uptime` shows it.
const UPTIME: &str = "/proc/uptime";

/// Directories a root timer must not run a binary from: their files can
/// belong to, or be replaced by, other users.
const UNSAFE_DIRS: [&str; 4] = ["/home", "/tmp", "/var/tmp", "/dev/shm"];

/// What [`super::Engine::apply`] arms the dead-man switch with, when a
/// module needs it.
#[derive(Debug, Clone)]
pub struct Deadman {
    /// How long a confirm has once the changes are live.
    pub window: Duration,
    /// The binary to copy for the timer and the boot hook: this one,
    /// [`std::env::current_exe`]. [`check_binary`] must accept it.
    pub binary: std::path::PathBuf,
}

impl Default for Deadman {
    /// [`DEFAULT_WINDOW`] and no binary, which is enough for a plan that
    /// does not need the switch.
    fn default() -> Self {
        Self {
            window: DEFAULT_WINDOW,
            binary: std::path::PathBuf::new(),
        }
    }
}

/// The `n`-th transient unit of transaction `txn`.
#[must_use]
pub fn unit_name(txn: &str, n: usize) -> String {
    format!("vps-ready-deadman-{txn}-{n}")
}

/// The unit the journal names last, and how many it names.
pub(super) fn last_unit(records: &[Record]) -> Option<(&str, usize)> {
    let units: Vec<&str> = records
        .iter()
        .filter_map(|r| match &r.event {
            Event::Armed { unit, .. }
            | Event::Extended { unit, .. }
            | Event::Retry { unit, .. }
            | Event::State {
                unit: Some(unit), ..
            } => Some(unit.as_str()),
            _ => None,
        })
        .collect();
    units.last().map(|u| (*u, units.len()))
}

/// The units a confirm stops: the one the journal names last and every
/// retry, so none of them rolls back a confirmed transaction.
pub(super) fn live_units(records: &[Record]) -> Vec<&str> {
    let mut units: Vec<&str> = records
        .iter()
        .filter_map(|r| match &r.event {
            Event::Retry { unit, .. } => Some(unit.as_str()),
            _ => None,
        })
        .collect();
    if let Some((last, _)) = last_unit(records)
        && !units.contains(&last)
    {
        units.push(last);
    }
    units
}

/// The dead-man switch of a transaction, from its journal: the boot of its
/// `armed` record and its current deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Switch {
    pub boot_id: String,
    pub deadline: Deadline,
}

/// The switch of `records`; `None` if the transaction was never armed.
pub(super) fn switch(records: &[Record]) -> Option<Switch> {
    let mut switch = None;
    for record in records {
        match &record.event {
            Event::Armed {
                boot_id, deadline, ..
            } => {
                switch = Some(Switch {
                    boot_id: boot_id.clone(),
                    deadline: *deadline,
                });
            }
            Event::State {
                state: super::TxnState::PendingConfirm { deadline, .. },
                ..
            }
            | Event::Extended { deadline, .. } => {
                if let Some(s) = &mut switch {
                    s.deadline = *deadline;
                }
            }
            _ => {}
        }
    }
    switch
}

impl Switch {
    /// Why it would roll back now: its boot is gone, or its deadline passed.
    /// A clock that cannot be read counts as passed, since keeping an
    /// unconfirmed change is the lockout.
    pub(super) fn expired(&self, fs: &dyn Fs) -> Option<super::RollbackReason> {
        if crate::resource::sysctl::boot_id(fs).as_deref() != Some(self.boot_id.as_str()) {
            return Some(super::RollbackReason::DeadmanReboot);
        }
        match boottime(fs) {
            Ok(now) if now < self.deadline.boottime => None,
            _ => Some(super::RollbackReason::DeadmanTimeout),
        }
    }
}

/// Whole seconds since boot, on `CLOCK_BOOTTIME`, which counts suspend and
/// which an NTP step does not move.
///
/// # Errors
///
/// [`EngineError::Deadman`] if `/proc/uptime` cannot be read or parsed.
pub fn boottime(fs: &dyn Fs) -> Result<u64, EngineError> {
    let bad = |why: String| EngineError::Deadman(format!("reading {UPTIME}: {why}"));
    let bytes = fs.read(Path::new(UPTIME)).map_err(|e| bad(e.to_string()))?;
    let text = String::from_utf8_lossy(&bytes);
    text.split(['.', ' '])
        .next()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| bad(format!("unexpected content {:?}", text.trim())))
}

/// Checks that a root timer may run `path`: an absolute path of plain
/// characters (it goes into a unit file) without `.` or `..` components,
/// not under `/home`, `/tmp`,
/// `/var/tmp` or `/dev/shm`, a regular file, and it and every parent
/// directory owned by root and not writable by group or others. Otherwise the user who could replace it
/// would get a root shell. Returns why not.
///
/// # Errors
///
/// The reason, for [`EngineError::UnsafeBinary`].
pub fn check_binary(fs: &dyn Fs, path: &Path) -> Result<(), String> {
    let plain = path.to_str().is_some_and(|s| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._+-".contains(&b))
    });
    if !path.is_absolute() || !plain {
        return Err("it is not an absolute path of letters, digits and `/._+-`".into());
    }
    // `Path::components` drops a `.` inside the path, so split the text.
    if path
        .to_str()
        .is_some_and(|s| s.split('/').any(|c| c == "." || c == ".."))
    {
        return Err("it has a `.` or `..` component".into());
    }
    if let Some(dir) = UNSAFE_DIRS.iter().find(|d| path.starts_with(d)) {
        return Err(format!("it is under {dir}"));
    }
    for (i, p) in path.ancestors().enumerate() {
        let meta = fs
            .metadata(p)
            .map_err(|e| format!("cannot check {}: {e}", p.display()))?;
        let expected = if i == 0 {
            FileKind::File
        } else {
            FileKind::Dir
        };
        let shown = p.display();
        if meta.kind != expected {
            return Err(format!("{shown} is a {:?}, not a {expected:?}", meta.kind));
        }
        if meta.uid != 0 {
            return Err(format!("{shown} is owned by uid {}, not root", meta.uid));
        }
        if meta.mode & 0o022 != 0 {
            return Err(format!(
                "{shown} is writable by group or others (mode {:04o})",
                meta.mode
            ));
        }
    }
    Ok(())
}

/// The boot hook. Only the ordering edges it needs: every extra one is a
/// chance for a cycle, which systemd breaks by dropping a unit, perhaps
/// `ssh.socket`. `DefaultDependencies=no` avoids the default
/// `After=basic.target`, which with `Before=ssh.socket` is such a cycle.
/// sshd, Docker and Caddy start after it, so they read the restored config.
/// `TimeoutStartSec` bounds a hung rollback, after which sshd starts anyway.
#[must_use]
pub fn hook_unit(binary: &Path) -> String {
    format!(
        "[Unit]
Description=vps-ready: roll back an unconfirmed change after a reboot
DefaultDependencies=no
After=local-fs.target vps-ready-firewall.service
Before=ssh.service ssh.socket docker.service caddy.service shutdown.target
Conflicts=shutdown.target
[Service]
Type=oneshot
TimeoutStartSec=120
ExecStart={} rollback --deadman-boot
[Install]
WantedBy=multi-user.target
",
        binary.display()
    )
}

/// Where `install_copy` puts the binary the timer and the boot hook run,
/// for the state directory `state`.
#[must_use]
pub fn private_binary(state: &Path) -> std::path::PathBuf {
    state.join("bin").join("vps-ready")
}

/// Copies `src`, which [`check_binary`] accepted, to [`private_binary`]
/// (mode 0755, root, written through a temp file, synced and renamed) and
/// checks the copy the same way. One file, overwritten by each apply that
/// arms the switch: a copy left by a crash or a finished transaction does
/// no harm, and a pending transaction is the newest, so nothing else uses
/// it. Returns its path.
pub(super) fn install_copy(
    fs: &dyn Fs,
    state: &Path,
    src: &Path,
) -> Result<std::path::PathBuf, EngineError> {
    let dest = private_binary(state);
    if src == dest {
        return Ok(dest);
    }
    let fail = |why: String| {
        EngineError::Deadman(format!(
            "copying {} to {}: {why}",
            src.display(),
            dest.display()
        ))
    };
    let dir = state.join("bin");
    fs.create_dir_all(&dir, 0o700)
        .map_err(|e| fail(e.to_string()))?;
    let bytes = fs.read(src).map_err(|e| fail(e.to_string()))?;
    let owner = FileOwner {
        mode: 0o755,
        uid: 0,
        gid: 0,
    };
    fs.write_atomic(&dest, &bytes, owner)
        .map_err(|e| fail(e.to_string()))?;
    check_copy(fs, state, &dest)?;
    Ok(dest)
}

/// [`check_binary`] on the copy, with advice for its own directory.
fn check_copy(fs: &dyn Fs, state: &Path, dest: &Path) -> Result<(), EngineError> {
    check_binary(fs, dest).map_err(|reason| {
        EngineError::Deadman(format!(
            "the copy at {}: {reason}; check the ownership and mode of {}",
            dest.display(),
            state.display()
        ))
    })
}

/// `install_copy`, then proof that the copy runs here (it can fail on a
/// `noexec` mount or a damaged file): `<copy> version` must print what this
/// binary prints. There is no fallback to the installed binary.
pub(super) fn make_copy(
    sys: Sys,
    state: &Path,
    src: &Path,
) -> Result<std::path::PathBuf, EngineError> {
    let copy = install_copy(sys.fs, state, src)?;
    let cannot = |why: String| {
        EngineError::Deadman(format!(
            "the copy at {} cannot run: {why}; is {} mounted noexec?",
            copy.display(),
            state.display()
        ))
    };
    let cmd = Cmd::new(copy.display().to_string())
        .arg("version")
        .timeout(Duration::from_secs(10));
    let out = sys.runner.run(&cmd).map_err(|e| cannot(e.to_string()))?;
    if !out.ok() {
        return Err(cannot(format!(
            "`version` exited with status {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let (got, want) = (
        out.stdout_str().unwrap_or("").trim(),
        crate::VERSION_INFO.to_string(),
    );
    if got != want {
        return Err(cannot(format!("`version` printed {got:?}, not {want:?}")));
    }
    Ok(copy)
}

/// The binary a re-arm of the pending transaction uses, for `confirm
/// --extend`. If the boot hook runs the private copy, that copy, so the
/// version that applied keeps going; it is made again from `running` if it
/// is gone. A hook that does not (armed before the copy existed) moves onto
/// a new copy of `running`, so a reboot in the extended window still rolls
/// back whatever happens to the installed binary.
pub(super) fn prepare_rearm(
    sys: Sys,
    state: &Path,
    running: &Path,
) -> Result<std::path::PathBuf, EngineError> {
    let copy = private_binary(state);
    if hook_binary(sys.fs).as_deref() == Some(copy.as_path()) {
        if sys.fs.exists(&copy) {
            check_copy(sys.fs, state, &copy)?;
            return Ok(copy);
        }
        checked(sys.fs, running)?;
        return make_copy(sys, state, running);
    }
    checked(sys.fs, running)?;
    let copy = make_copy(sys, state, running)?;
    install_hook(sys, &copy).map_err(EngineError::Deadman)?;
    Ok(copy)
}

fn checked(fs: &dyn Fs, binary: &Path) -> Result<(), EngineError> {
    check_binary(fs, binary).map_err(|reason| EngineError::UnsafeBinary {
        path: binary.display().to_string(),
        reason,
    })
}

/// The binary the installed boot hook runs, if the unit file is there and
/// names one.
pub(super) fn hook_binary(fs: &dyn Fs) -> Option<std::path::PathBuf> {
    let bytes = fs.read(Path::new(HOOK)).ok()?;
    String::from_utf8_lossy(&bytes)
        .lines()
        .find_map(|l| l.strip_prefix("ExecStart="))
        .and_then(|cmd| cmd.strip_suffix(" rollback --deadman-boot"))
        .map(std::path::PathBuf::from)
}

/// Writes the boot hook if it differs (then `daemon-reload`) and enables it.
pub(super) fn install_hook(sys: Sys, binary: &Path) -> Result<(), String> {
    let path = Path::new(HOOK);
    let text = hook_unit(binary);
    match sys.fs.read(path) {
        Ok(bytes) if bytes == text.as_bytes() => {}
        Ok(_) | Err(SysError::NotFound(_)) => {
            let owner = FileOwner {
                mode: 0o644,
                uid: 0,
                gid: 0,
            };
            sys.fs
                .write_atomic(path, text.as_bytes(), owner)
                .map_err(|e| format!("writing {HOOK}: {e}"))?;
            reload::run(sys, &systemctl(["daemon-reload"]))?;
        }
        Err(e) => return Err(format!("reading {HOOK}: {e}")),
    }
    reload::run(sys, &systemctl(["enable", HOOK_UNIT]))
}

/// Disables the boot hook; the unit file stays.
pub(super) fn disable_hook(sys: Sys) -> Result<(), String> {
    reload::run(sys, &systemctl(["disable", HOOK_UNIT]))
}

/// Starts the transient timer `unit`, which runs `binary rollback --txn
/// <txn> --deadman` in `after`, outside this process and its session.
pub(super) fn arm(
    sys: Sys,
    unit: &str,
    after: Duration,
    binary: &Path,
    txn: &str,
) -> Result<(), String> {
    let description = format!("vps-ready: roll back transaction {txn} unless confirmed");
    reload::run(sys, &timer(unit, after, &description, binary, txn))
}

/// The unit of the `attempt`-th retry of a timer rollback of `txn`.
#[must_use]
pub fn retry_name(txn: &str, attempt: u32) -> String {
    format!("vps-ready-deadman-{txn}-retry-{attempt}")
}

/// Starts the timer of the `attempt`-th retry of the timer rollback of
/// `txn`, in `after`. The attempt goes on its command line, so retries stay
/// bounded when the journal cannot be written.
pub(super) fn arm_retry(
    sys: Sys,
    attempt: u32,
    after: Duration,
    binary: &Path,
    txn: &str,
) -> Result<String, String> {
    let unit = retry_name(txn, attempt);
    let description = format!("vps-ready: retry the rollback of transaction {txn}");
    let cmd =
        timer(&unit, after, &description, binary, txn).args(["--attempt", &attempt.to_string()]);
    reload::run(sys, &cmd).map(|()| unit)
}

fn timer(unit: &str, after: Duration, description: &str, binary: &Path, txn: &str) -> Cmd {
    Cmd::new("systemd-run")
        .arg(format!("--unit={unit}"))
        .arg(format!("--on-active={}s", after.as_secs().max(1)))
        .arg("--timer-property=AccuracySec=1s")
        .arg(format!("--description={description}"))
        .arg(binary.display().to_string())
        .args(["rollback", "--txn", txn, "--deadman"])
}

/// Stops the timer `unit`, and with `service` the rollback it may have
/// started, which then waits for the lock this process holds. A dead-man
/// rollback stops only the timer: the service may be itself.
pub(super) fn stop(sys: Sys, unit: &str, service: bool) -> Result<(), String> {
    let timer = format!("{unit}.timer");
    let cmd = if service {
        systemctl(["stop", &timer, &format!("{unit}.service")])
    } else {
        systemctl(["stop", "--no-block", &timer])
    };
    reload::run(sys, &cmd)
}

/// A [`Runner`] that gives every command at most `max`. The boot hook runs
/// through one: it has 120 s in all before systemd gives up on it and
/// starts sshd, so one hung command must not use them up.
pub(super) struct Capped<'a> {
    pub inner: &'a dyn Runner,
    pub max: Duration,
}

impl Runner for Capped<'_> {
    fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
        let timeout = cmd.timeout.min(self.max);
        self.inner.run(&cmd.clone().timeout(timeout))
    }
}

fn systemctl<'a>(args: impl IntoIterator<Item = &'a str>) -> Cmd {
    Cmd::new("systemctl").args(args).timeout(SYSTEMCTL_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::fake::FakeFs;

    fn owned(fs: FakeFs, path: &str, mode: u32, uid: u32) -> FakeFs {
        fs.write_atomic(Path::new(path), b"\x7fELF", FileOwner { mode, uid, gid: 0 })
            .unwrap();
        fs
    }

    #[test]
    fn checks_the_binary_and_its_parents() {
        let bin = "/usr/local/bin/vps-ready";
        let fs = owned(FakeFs::new().with_file(bin, ""), bin, 0o755, 0);
        check_binary(&fs, Path::new(bin)).unwrap();

        let refused = [
            ("vps-ready", "not an absolute path"),
            ("/usr/local/bin/vps ready", "not an absolute path"),
            ("/opt/%n/vps-ready", "not an absolute path"),
            ("/usr/local/bin/../bin/vps-ready", "a `.` or `..` component"),
            ("/usr/./local/bin/vps-ready", "a `.` or `..` component"),
            ("/home/admin/vps-ready", "it is under /home"),
            ("/tmp/vps-ready", "it is under /tmp"),
            ("/var/tmp/vps-ready", "it is under /var/tmp"),
            ("/dev/shm/vps-ready", "it is under /dev/shm"),
            ("/usr/bin/missing", "cannot check /usr/bin/missing"),
        ];
        for (path, reason) in refused {
            let err = check_binary(&fs, Path::new(path)).unwrap_err();
            assert!(err.contains(reason), "{path}");
        }

        let cases = [
            (
                owned(FakeFs::new().with_file(bin, ""), bin, 0o755, 1000),
                "is owned by uid 1000",
            ),
            (
                owned(FakeFs::new().with_file(bin, ""), bin, 0o775, 0),
                "writable by group",
            ),
            (
                owned(FakeFs::new().with_file(bin, ""), bin, 0o757, 0),
                "writable by group or others",
            ),
        ];
        for (fs, reason) in cases {
            let err = check_binary(&fs, Path::new(bin)).unwrap_err();
            assert!(err.contains(reason), "{reason}");
        }

        // A parent directory that another user can write to.
        let fs = FakeFs::new().with_file(bin, "");
        fs.create_dir_all(Path::new("/opt/x"), 0o777).unwrap();
        let fs = owned(
            fs.with_file("/opt/x/vps-ready", ""),
            "/opt/x/vps-ready",
            0o755,
            0,
        );
        let err = check_binary(&fs, Path::new("/opt/x/vps-ready")).unwrap_err();
        assert_eq!(err, "/opt/x is writable by group or others (mode 0777)");

        let fs = FakeFs::new()
            .with_file("/usr/bin/real", "")
            .with_symlink("/usr/bin/link", "/usr/bin/real");
        let err = check_binary(&fs, Path::new("/usr/bin/link")).unwrap_err();
        assert!(err.contains("is a Symlink"));
    }

    #[test]
    fn reads_boottime() {
        let fs = FakeFs::new().with_file(UPTIME, "1234.56 4321.00\n");
        assert_eq!(boottime(&fs).unwrap(), 1234);
        let fs = FakeFs::new().with_file(UPTIME, "soon\n");
        assert!(boottime(&fs).is_err());
        assert!(boottime(&FakeFs::new()).is_err());
    }

    #[test]
    fn hook_unit_has_only_the_needed_edges() {
        insta::assert_snapshot!(hook_unit(Path::new("/usr/local/bin/vps-ready")));
    }
}
