//! The SSH session `vps-ready` was started from.
//!
//! Knowing the admin's address and the port they connected to is what lets
//! later milestones keep that path open: the firewall must allow it, and a
//! confirmation must arrive on a *different* connection.
//!
//! sudo's `env_reset` drops `SSH_CONNECTION`, so the session is found in the
//! process tree instead: the nearest ancestor that is a per-session sshd
//! process (`sshd: admin@pts/0`, or `sshd-session: admin@pts/0` since OpenSSH
//! 9.8). Its child in the chain still has `SSH_CONNECTION` in its `environ`.
//! Nothing above that process is read: on Debian 13 the `[priv]` process
//! above it has PPID 1, not the listener.
//!
//! The process's executable and owner are not checked: `confirm` runs as
//! root, so a spoofed title only lets an admin lock themselves out, and an
//! unprivileged user could run a genuine sshd anyway.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::sys::{Fs, SysError};

/// Inputs taken from the process, passed in explicitly so tests can supply
/// their own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Env {
    /// The process whose SSH session is looked for. `None` skips the lookup.
    pub pid: Option<u32>,
}

impl Env {
    /// This process.
    #[must_use]
    pub fn from_process() -> Self {
        Self {
            pid: Some(std::process::id()),
        }
    }
}

/// Start of every notice about the session, so commands that do not use the
/// session can leave them out.
pub const NOTICE: &str = "no SSH session: ";

/// Parents walked at most before giving up.
const MAX_DEPTH: usize = 64;

/// `USER_HZ`, the unit of start times in `/proc/<pid>/stat`: a fixed ABI
/// value, 100 on x86 and Arm.
const CLK_TCK: u64 = 100;

/// One sshd session process. PID reuse cannot fake a match, since a new
/// process with the same PID has a later start time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId {
    /// PID of the per-session sshd process.
    pub pid: u32,
    /// Its start time, in clock ticks since boot (field 22 of
    /// `/proc/<pid>/stat`).
    pub start: u64,
}

impl SessionId {
    /// Whether the process started after `live_since`, in whole seconds
    /// since boot from `/proc/uptime` or `CLOCK_BOOTTIME`, the clock of
    /// `start`. A start within that same second does not count.
    #[must_use]
    pub fn started_after(self, live_since: u64) -> bool {
        self.start / CLK_TCK > live_since
    }
}

/// The SSH login this process runs under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Session {
    /// The per-session sshd process.
    pub id: SessionId,
    /// The admin's address and source port.
    pub client: SocketAddr,
    /// The server address and port they connected to.
    pub server: SocketAddr,
    /// The login user: the real uid of the sshd process's child, which is
    /// `sudo` itself under `ssh host sudo ...`.
    pub uid: u32,
    /// That user's name from `/etc/passwd`, if listed there.
    pub user: Option<String>,
}

impl Session {
    /// Whether this session is a new login since a change went live at
    /// `live_since` (seconds since boot) from the session `applied`: a
    /// different sshd process that started after that moment.
    #[must_use]
    pub fn is_new(&self, applied: Option<SessionId>, live_since: u64) -> bool {
        applied != Some(self.id) && self.id.started_after(live_since)
    }
}

/// Why there is no session.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NoSession {
    /// No sshd process above this one.
    #[error("no sshd process above this one (the console, tmux, screen or mosh)")]
    NotSsh,
    /// The process tree could not be read or did not look as expected.
    #[error("{0}")]
    Unknown(String),
}

/// Finds the SSH session of process `pid`. Reading another user's `environ`
/// needs root.
///
/// # Errors
///
/// [`NoSession`] says why there is none.
pub fn detect(fs: &dyn Fs, pid: u32) -> Result<Session, NoSession> {
    let mut child = pid;
    let mut child_status = Status::read(fs, pid)?;
    for _ in 0..MAX_DEPTH {
        // Only PID 1 (or a namespace's init) has PPID 0.
        let ppid = child_status.ppid;
        if ppid == 0 {
            return Err(NoSession::NotSsh);
        }
        let parent = Status::read(fs, ppid)?;
        if parent.name == "sshd" || parent.name == "sshd-session" {
            return session(fs, ppid, &parent.name, child, child_status.uid);
        }
        child = ppid;
        child_status = parent;
    }
    Err(NoSession::Unknown(format!(
        "no sshd process within {MAX_DEPTH} parents of {pid}"
    )))
}

pub(super) fn collect(env: &Env, fs: &dyn Fs, notices: &mut Vec<String>) -> Option<Session> {
    let pid = env.pid?;
    detect(fs, pid)
        .inspect_err(|reason| notices.push(format!("{NOTICE}{reason}")))
        .ok()
}

/// The session of `sshd`, the nearest sshd process above `child`, whose real
/// uid is `uid`.
fn session(fs: &dyn Fs, sshd: u32, name: &str, child: u32, uid: u32) -> Result<Session, NoSession> {
    let cmdline = read(fs, &format!("/proc/{sshd}/cmdline"))?;
    let title = String::from_utf8_lossy(cmdline.split(|&b| b == 0).next().unwrap_or_default());
    let title = title.trim_end();
    if !is_session_title(name, title) {
        return Err(NoSession::Unknown(format!(
            "the nearest sshd process, {sshd} ({title:?}), is not a login session"
        )));
    }
    let stat_path = format!("/proc/{sshd}/stat");
    let start = start_time(&String::from_utf8_lossy(&read(fs, &stat_path)?))
        .ok_or_else(|| NoSession::Unknown(format!("could not parse {stat_path}")))?;
    let environ_path = format!("/proc/{child}/environ");
    let environ = fs.read(Path::new(&environ_path)).map_err(|err| match err {
        SysError::Permission(_) => NoSession::Unknown(format!(
            "reading SSH_CONNECTION from {environ_path} needs root"
        )),
        err => NoSession::Unknown(err.to_string()),
    })?;
    let value = environ
        .split(|&b| b == 0)
        .find_map(|var| var.strip_prefix(b"SSH_CONNECTION="))
        .ok_or_else(|| NoSession::Unknown(format!("no SSH_CONNECTION in {environ_path}")))?;
    let value = String::from_utf8_lossy(value);
    let (client, server) = parse_connection(&value)
        .ok_or_else(|| NoSession::Unknown(format!("could not parse SSH_CONNECTION={value:?}")))?;
    Ok(Session {
        id: SessionId { pid: sshd, start },
        client,
        server,
        uid,
        user: user_name(fs, uid),
    })
}

/// `<name>: <user>@<ttys>`, where `<ttys>` is `notty` or a comma-separated
/// list of `pts/N` (more than one through `ControlMaster`). The `[priv]`
/// process (`sshd: admin [priv]`) and the listener do not match.
fn is_session_title(name: &str, title: &str) -> bool {
    let Some((user, ttys)) = title
        .strip_prefix(name)
        .and_then(|t| t.strip_prefix(": "))
        .and_then(|t| t.split_once('@'))
    else {
        return false;
    };
    let pts = |t: &str| {
        t.strip_prefix("pts/")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    };
    !user.is_empty()
        && !user.contains(char::is_whitespace)
        && (ttys == "notty" || ttys.split(',').all(pts))
}

/// Field 22 of `/proc/<pid>/stat`. The name in field 2 can hold spaces and
/// parentheses, so fields are counted from its closing parenthesis.
fn start_time(stat: &str) -> Option<u64> {
    let (_, rest) = stat.rsplit_once(')')?;
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// The fields of `/proc/<pid>/status` the walk needs.
struct Status {
    name: String,
    ppid: u32,
    /// Real uid, the first value of `Uid:`.
    uid: u32,
}

impl Status {
    fn read(fs: &dyn Fs, pid: u32) -> Result<Self, NoSession> {
        let path = format!("/proc/{pid}/status");
        let text = String::from_utf8_lossy(&read(fs, &path)?).into_owned();
        let field = |key: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))
                .map(str::trim)
        };
        let number = |key: &str| field(key)?.split_whitespace().next()?.parse().ok();
        match (field("Name"), number("PPid"), number("Uid")) {
            (Some(name), Some(ppid), Some(uid)) => Ok(Self {
                name: name.to_owned(),
                ppid,
                uid,
            }),
            _ => Err(NoSession::Unknown(format!("could not parse {path}"))),
        }
    }
}

fn read(fs: &dyn Fs, path: &str) -> Result<Vec<u8>, NoSession> {
    fs.read(Path::new(path))
        .map_err(|err| NoSession::Unknown(err.to_string()))
}

/// The name of `uid` in `/etc/passwd`. Users known only through NSS (LDAP)
/// have none.
fn user_name(fs: &dyn Fs, uid: u32) -> Option<String> {
    let passwd = fs.read(Path::new("/etc/passwd")).ok()?;
    let uid = uid.to_string();
    String::from_utf8_lossy(&passwd).lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        (fields.nth(1)? == uid).then(|| name.to_owned())
    })
}

/// Parses `SSH_CONNECTION`: `client_ip client_port server_ip server_port`.
/// IPv6 addresses appear without brackets; a zone such as `%eth0` is dropped.
fn parse_connection(value: &str) -> Option<(SocketAddr, SocketAddr)> {
    let mut fields = value.split_whitespace();
    let mut addr = || -> Option<SocketAddr> {
        let ip = fields.next()?;
        let ip: IpAddr = ip.split('%').next()?.parse().ok()?;
        Some(SocketAddr::new(ip, fields.next()?.parse().ok()?))
    };
    let pair = (addr()?, addr()?);
    fields.next().is_none().then_some(pair)
}

#[cfg(test)]
mod tests;
