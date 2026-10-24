//! `confirm` and `confirm --extend`, and what `apply` prints and does while
//! its changes wait for a confirm.

use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::bail;

use super::{Host, audit_fixed, clock, print_progress, require_root};
use crate::cli::{EXIT_PENDING, EXIT_ROLLED_BACK};
use crate::engine::{
    self, Deadline, Engine, EngineError, Plan, Progress, Refusal, StateDir, TxnState, Watch,
};
use crate::facts::{Facts, NoSession, Session, SshActivation};
use crate::sys::{Cmd, Runner};

/// How long `confirm` waits for the lock, which a dead-man rollback may
/// hold for a moment.
const LOCK_WAIT: Duration = Duration::from_secs(10);

/// How long `apply` keeps waiting after the deadline for the timer's
/// rollback to finish.
const GRACE: Duration = Duration::from_secs(60);

/// `confirm`, or with `extend` `confirm --extend`.
pub(in crate::cli) fn confirm(
    host: &Host,
    txn: Option<&str>,
    extend: Option<Duration>,
    out: &mut dyn Write,
) -> anyhow::Result<u8> {
    require_root(host, "confirm")?;
    if !host.sys.fs.exists(host.state_dir) {
        return Err(EngineError::from(Refusal::NothingPending).into());
    }
    let state = StateDir::open(host.sys.fs, host.state_dir, host.state_uid)?;
    let engine = Engine::lock_timeout(&state, host.sys, LOCK_WAIT)?;
    if let Some(by) = extend {
        let done = engine.extend(txn, by, &host.binary)?;
        let limit = if done.capped {
            ", the latest allowed: 2 hours after the changes went live"
        } else {
            ""
        };
        writeln!(
            out,
            "Transaction {} now reverts at {} ({} left{limit}). Confirm before then from a \
             new SSH login.",
            done.txn,
            clock(done.deadline.wall),
            countdown(done.left)
        )?;
        return Ok(0);
    }
    let id = engine.waiting(txn)?;
    let facts = (host.facts)(host.sys)?;
    let ports = sshd_ports(&facts, host.sys.runner);
    let session = match (host.session)(host.sys) {
        Ok(session) => session,
        Err(NoSession::NotSsh) => bail!(
            "this is not an SSH login (the console, tmux, screen or mosh), so it proves \
             nothing about the changes. {}",
            again(host, None, &ports)
        ),
        Err(NoSession::Unknown(why)) => bail!(
            "cannot find the SSH login this runs in: {why}. {}",
            again(host, None, &ports)
        ),
    };
    match engine.confirm(Some(&id), &session, &ports) {
        Ok(txn) => {
            writeln!(
                out,
                "Confirmed transaction {txn} from a new SSH login ({} from {}). The changes \
                 stay; undo them with `sudo vps-ready rollback --last`.",
                login_user(host, Some(&session)),
                session.client.ip()
            )?;
            Ok(0)
        }
        Err(EngineError::Refused(r @ (Refusal::SameSession | Refusal::OldSession))) => bail!(
            "{r}. This is not a new SSH login: tmux, screen and mosh sessions, the console, \
             and ssh connections shared through ControlMaster all count as old. {}",
            again(host, Some(&session), &ports)
        ),
        Err(EngineError::Refused(r @ Refusal::OtherSshd { .. })) => {
            bail!("{r}. {}", again(host, Some(&session), &ports))
        }
        Err(e) => Err(e.into()),
    }
}

/// What `apply` prints once its changes wait for a confirm: the command to
/// run from a new terminal, with real values, and the deadline.
pub(super) fn print_pending(
    host: &Host,
    facts: &Facts,
    deadline: Deadline,
    left: Duration,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    let ports = sshd_ports(facts, host.sys.runner);
    let session = facts.session.as_ref();
    writeln!(out, "Changes are live. Open a NEW terminal and run:\n")?;
    writeln!(out, "    {}", ssh_line(host, session, &ports))?;
    if let Some(ip) = session.map(|s| s.server.ip())
        && !public(ip)
    {
        writeln!(out, "    (or the address you connected to instead of {ip})")?;
    }
    writeln!(
        out,
        "\nIf no new session confirms by {} ({} left), every change is rolled back.\n\
         More time: sudo vps-ready confirm --extend\n\
         Do not edit files vps-ready manages until you confirm: an unconfirmed change \
         reverts them.\n\
         Ctrl-C stops waiting here, not the timer.",
        clock(deadline.wall),
        countdown(left)
    )
}

/// Waits with a countdown until transaction `txn`, pending until
/// `deadline`, is no longer pending: confirmed exits 0 (after an audit of
/// what `plan` fixed), rolled back 1. Ctrl-C, or a deadline passed a
/// minute ago without the rollback finishing, stops waiting and exits
/// [`EXIT_PENDING`]; neither touches the timer.
pub(super) fn wait(
    host: &Host,
    state: &StateDir,
    txn: &str,
    deadline: Deadline,
    plan: &Plan,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<u8> {
    if host.catch_sigint {
        signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&host.stop))?;
    }
    let fs = host.sys.fs;
    let mut minute = None;
    let mut last = deadline.boottime;
    let mut said_rolling = false;
    let mut on_line = false;
    loop {
        let overdue = engine::deadman::boottime(fs)?.saturating_sub(last) >= GRACE.as_secs();
        if host.stop.load(Ordering::Relaxed) || overdue {
            end_line(err, &mut on_line)?;
            let why = if overdue {
                "The deadline passed, but the dead-man rollback has not finished yet. Stopped \
                 waiting"
            } else {
                "Stopped waiting"
            };
            writeln!(
                out,
                "{why}; transaction {txn} is still pending. Unless a new SSH login confirms \
                 it, it reverts at its deadline: see `sudo vps-ready history`."
            )?;
            return Ok(EXIT_PENDING);
        }
        match engine::watch(state, fs, txn)? {
            Watch::Pending { deadline, left } => {
                last = deadline.boottime;
                if host.tty {
                    write!(
                        err,
                        "\r\x1b[KWaiting for a confirm: {} left",
                        countdown(left)
                    )?;
                    err.flush()?;
                    on_line = true;
                } else if minute != Some(left.as_secs() / 60) {
                    minute = Some(left.as_secs() / 60);
                    print_progress(err, &Progress::Waiting { left });
                }
            }
            Watch::RollingBack => {
                if !said_rolling {
                    end_line(err, &mut on_line)?;
                    writeln!(err, "The changes are being rolled back.")?;
                    said_rolling = true;
                }
            }
            Watch::Done(TxnState::Confirmed) => {
                end_line(err, &mut on_line)?;
                writeln!(
                    out,
                    "Confirmed: the changes of transaction {txn} stay. Undo them with \
                     `sudo vps-ready rollback --last`."
                )?;
                if let Err(e) = audit_fixed(host, plan, out) {
                    writeln!(err, "vps-ready: could not audit after apply: {e:#}")?;
                }
                return Ok(0);
            }
            Watch::Done(state @ TxnState::RolledBack { .. }) => {
                end_line(err, &mut on_line)?;
                writeln!(
                    err,
                    "error: no new SSH login confirmed the changes, so every change was \
                     restored; transaction {txn} is {state}."
                )?;
                return Ok(EXIT_ROLLED_BACK);
            }
            Watch::Done(state) => bail!("transaction {txn} is {state}, not pending"),
        }
        std::thread::sleep(host.poll);
    }
}

/// Ends the countdown line, if one is shown.
fn end_line(err: &mut dyn Write, on_line: &mut bool) -> std::io::Result<()> {
    if std::mem::take(on_line) {
        writeln!(err)?;
    }
    Ok(())
}

/// The ports the host's sshd listens on: each `port` of `sshd -T` and,
/// with socket activation, each stream `Listen` of `ssh.socket`, which
/// `sshd -T` does not show.
pub(super) fn sshd_ports(facts: &Facts, runner: &dyn Runner) -> Vec<u16> {
    let mut ports: Vec<u16> = facts
        .ssh
        .effective
        .iter()
        .flat_map(|c| c.get_all("port"))
        .filter_map(|p| p.parse().ok())
        .collect();
    if facts.ssh.activation == SshActivation::Socket {
        let cmd = Cmd::new("systemctl")
            .args(["show", "--property=Listen", "ssh.socket"])
            .timeout(Duration::from_secs(10));
        match runner.run(&cmd) {
            Ok(out) if out.ok() => {
                ports.extend(listen_ports(&String::from_utf8_lossy(&out.stdout)))
            }
            Ok(out) => tracing::warn!(
                "`systemctl show ssh.socket` failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            Err(e) => tracing::warn!("`systemctl show ssh.socket`: {e}"),
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// The ports of `Listen=[::]:22 (Stream)` lines.
fn listen_ports(text: &str) -> Vec<u16> {
    text.lines()
        .filter_map(|line| {
            let addr = line.strip_prefix("Listen=")?.strip_suffix(" (Stream)")?;
            addr.rsplit(':').next()?.parse().ok()
        })
        .collect()
}

/// "Open a new terminal and run: `ssh ...`".
fn again(host: &Host, session: Option<&Session>, ports: &[u16]) -> String {
    format!(
        "Open a new terminal and run: `{}`",
        ssh_line(host, session, ports)
    )
}

/// `ssh -t -o ControlPath=none -p <port> <user>@<address> sudo vps-ready
/// confirm`, with the server address and port of `session`. `-o
/// ControlPath=none` keeps a `ControlMaster` from reusing an old connection;
/// `-t` gives sudo a terminal to ask for a password on.
fn ssh_line(host: &Host, session: Option<&Session>, ports: &[u16]) -> String {
    let port = session
        .map(|s| s.server.port())
        .or_else(|| ports.first().copied())
        .unwrap_or(22);
    let address = session.map_or_else(
        || "<server address>".to_owned(),
        |s| s.server.ip().to_string(),
    );
    format!(
        "ssh -t -o ControlPath=none -p {port} {}@{address} sudo vps-ready confirm",
        login_user(host, session)
    )
}

/// Who logs in to confirm: whoever ran sudo, else the session's user.
fn login_user(host: &Host, session: Option<&Session>) -> String {
    host.sudo_user
        .clone()
        .or_else(|| session.and_then(|s| s.user.clone()))
        .unwrap_or_else(|| "<user>".to_owned())
}

/// Whether `ip` is reachable as it is from elsewhere: not private, shared
/// (CGNAT), loopback, link-local or unique local, as behind a cloud's NAT.
fn public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            let shared = a == 100 && b & 0xc0 == 64;
            !(v4.is_private() || v4.is_loopback() || v4.is_link_local() || shared)
        }
        IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unicast_link_local() || v6.is_unique_local()),
    }
}

/// `4:59`.
pub(super) fn countdown(left: Duration) -> String {
    let secs = left.as_secs();
    format!("{}:{:02}", secs / 60, secs % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_stream_ports_of_ssh_socket() {
        let text = "Listen=[::]:22 (Stream)\nListen=0.0.0.0:2222 (Stream)\n\
                    Listen=[::]:53 (Datagram)\nListen=/run/x.sock (Stream)\n";
        assert_eq!(listen_ports(text), [22, 2222]);
        assert_eq!(listen_ports(""), Vec::<u16>::new());
    }

    #[test]
    fn private_addresses_are_not_public() {
        for ip in [
            "10.0.2.15",
            "172.16.0.1",
            "192.168.1.2",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["203.0.113.10", "100.128.0.1", "2001:db8::1"] {
            assert!(public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn counts_down_in_minutes_and_seconds() {
        assert_eq!(countdown(Duration::from_secs(299)), "4:59");
        assert_eq!(countdown(Duration::from_secs(7)), "0:07");
        assert_eq!(countdown(Duration::from_secs(7200)), "120:00");
    }
}
