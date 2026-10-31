//! Listening sockets, from `ss -tulnpH`.
//!
//! The kernel's view of what listens is the real attack surface; a service's
//! config file only says what it intended.

use std::fmt;
use std::path::Path;

use serde::Serialize;

use super::{Probe, probe};
use crate::sys::{Cmd, Fs, Runner};

/// The executable of the system's sshd listener.
const SSHD: &str = "/usr/sbin/sshd";

/// Transport protocol of a listening socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

/// One listening socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Listener {
    /// Protocol.
    pub proto: Proto,
    /// Local address without brackets, e.g. `0.0.0.0`, `::`,
    /// `127.0.0.53%lo`, or `*` for all addresses.
    pub addr: String,
    /// Local port.
    pub port: u16,
    /// Names of the owning processes, when `ss` can see them (needs root).
    /// Under socket activation this includes `systemd`, and before the first
    /// connection it is *only* `systemd`, so do not expect `sshd` on the SSH port.
    /// Any user can name a process `sshd`: see [`crate::facts::Ssh::listening`].
    pub processes: Vec<String>,
}

/// The listening sockets, and the TCP ports the system's sshd listens on
/// (see [`sshd_ports`]).
pub(super) fn detect(
    fs: &dyn Fs,
    runner: &dyn Runner,
    notices: &mut Vec<String>,
) -> (Vec<Listener>, Vec<u16>) {
    match probe(runner, &Cmd::new("ss").arg("-tulnpH"), notices) {
        Probe::Ran(out) if out.ok() => {
            let lines = parse_lines(&String::from_utf8_lossy(&out.stdout));
            let sshd = sshd_ports(fs, &lines);
            (lines.into_iter().map(|(l, _)| l).collect(), sshd)
        }
        Probe::Ran(out) => {
            notices.push(format!(
                "`ss -tulnpH` exited with {}; listening sockets are unknown",
                out.status
            ));
            (Vec::new(), Vec::new())
        }
        Probe::Missing => {
            notices.push("ss not found (iproute2); listening sockets are unknown".to_owned());
            (Vec::new(), Vec::new())
        }
        Probe::Failed => (Vec::new(), Vec::new()),
    }
}

/// The TCP ports of `lines` held by a process that runs [`SSHD`] as root. A
/// process name proves nothing: any user can start a listener named `sshd`,
/// or run `/usr/sbin/sshd` with a config of their own.
fn sshd_ports(fs: &dyn Fs, lines: &[(Listener, Vec<u32>)]) -> Vec<u16> {
    let mut ports: Vec<u16> = lines
        .iter()
        .filter(|(l, pids)| l.proto == Proto::Tcp && pids.iter().any(|p| is_sshd(fs, *p)))
        .map(|(l, _)| l.port)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Whether process `pid` runs [`SSHD`] with every uid of its `Uid:` line 0.
/// Reading `/proc/<pid>/exe` needs root.
fn is_sshd(fs: &dyn Fs, pid: u32) -> bool {
    let status = fs
        .read(Path::new(&format!("/proc/{pid}/status")))
        .unwrap_or_default();
    let root = String::from_utf8_lossy(&status)
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .is_some_and(|uids| {
            let uids: Vec<&str> = uids.split_whitespace().collect();
            !uids.is_empty() && uids.iter().all(|u| *u == "0")
        });
    root && fs
        .read_link(Path::new(&format!("/proc/{pid}/exe")))
        .is_ok_and(|exe| exe == Path::new(SSHD))
}

/// Parses `ss -tulnpH` output. Columns: netid, state, recv-q, send-q, local
/// address:port, peer address:port, then the optional process column.
/// Lines that do not fit are skipped.
#[must_use]
pub fn parse(text: &str) -> Vec<Listener> {
    parse_lines(text).into_iter().map(|(l, _)| l).collect()
}

/// [`parse`], with the PIDs of each socket's processes.
fn parse_lines(text: &str) -> Vec<(Listener, Vec<u32>)> {
    text.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<(Listener, Vec<u32>)> {
    let mut fields = line.split_whitespace();
    let proto = match fields.next()? {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        _ => return None,
    };
    let local = fields.nth(3)?;
    let _peer = fields.next()?;
    let process = fields.collect::<Vec<_>>().join(" ");

    let (addr, port) = local.rsplit_once(':')?;
    let addr = addr.trim_start_matches('[').replacen(']', "", 1);
    let (processes, pids) = processes(&process);
    let listener = Listener {
        proto,
        addr,
        port: port.parse().ok()?,
        processes,
    };
    Some((listener, pids))
}

/// `users:(("sshd",pid=131,fd=3),("systemd",pid=1,fd=41))` -> `[sshd, systemd]`
/// and `[131, 1]`, without duplicates.
fn processes(column: &str) -> (Vec<String>, Vec<u32>) {
    let mut names: Vec<String> = Vec::new();
    let mut pids: Vec<u32> = Vec::new();
    let mut rest = column;
    while let Some(start) = rest.find("(\"") {
        let Some(after) = rest.get(start + 2..) else {
            break;
        };
        let Some(end) = after.find('"') else {
            break;
        };
        if let Some(name) = after.get(..end).filter(|n| !n.is_empty())
            && !names.iter().any(|n| n == name)
        {
            names.push(name.to_owned());
        }
        rest = after.get(end + 1..).unwrap_or("");
        let pid = rest
            .strip_prefix(",pid=")
            .and_then(|r| r.split([',', ')']).next()?.parse().ok());
        if let Some(pid) = pid.filter(|p| !pids.contains(p)) {
            pids.push(pid);
        }
    }
    (names, pids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::fake::FakeFs;

    fn listener(proto: Proto, addr: &str, port: u16, processes: &[&str]) -> Listener {
        Listener {
            proto,
            addr: addr.to_owned(),
            port,
            processes: processes.iter().map(|p| (*p).to_owned()).collect(),
        }
    }

    #[test]
    fn parses_ss_output() {
        let text = "\
tcp LISTEN 0      4096   0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=131,fd=3),(\"systemd\",pid=1,fd=41))
tcp LISTEN 0      4096      [::]:22    [::]:* users:((\"systemd\",pid=1,fd=47))
udp UNCONN 0      0      127.0.0.53%lo:53 0.0.0.0:* users:((\"systemd-resolve\",pid=300,fd=13))
udp UNCONN 0      0            *:68       *:*
udp UNCONN 0      0      [fe80::1%eth0]:546 [::]:* users:((\"dhclient\",pid=9,fd=6),(\"dhclient\",pid=9,fd=7))
tcp LISTEN 0      511    [::ffff:127.0.0.1]:8080 *:*
garbage line
tcp LISTEN 0 1 noport *:*
";
        assert_eq!(
            parse(text),
            vec![
                listener(Proto::Tcp, "0.0.0.0", 22, &["sshd", "systemd"]),
                listener(Proto::Tcp, "::", 22, &["systemd"]),
                listener(Proto::Udp, "127.0.0.53%lo", 53, &["systemd-resolve"]),
                listener(Proto::Udp, "*", 68, &[]),
                listener(Proto::Udp, "fe80::1%eth0", 546, &["dhclient"]),
                listener(Proto::Tcp, "::ffff:127.0.0.1", 8080, &[]),
            ]
        );
        let pids: Vec<Vec<u32>> = parse_lines(text).into_iter().map(|(_, p)| p).collect();
        assert_eq!(
            pids,
            [vec![131, 1], vec![1], vec![300], vec![], vec![9], vec![]]
        );
    }

    /// `/proc/<pid>` of a process with uids `uids` running `exe`.
    fn process(fs: FakeFs, pid: u32, uids: &str, exe: &str) -> FakeFs {
        fs.with_file(
            format!("/proc/{pid}/status"),
            format!("Name:\tsshd\nUid:\t{uids}\nGid:\t0\t0\t0\t0\n"),
        )
        .with_symlink(format!("/proc/{pid}/exe"), exe)
    }

    #[test]
    fn sshd_ports_need_root_and_the_system_sshd() {
        let text = "\
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=59,fd=3))
tcp LISTEN 0 128 [::]:22 [::]:* users:((\"sshd\",pid=59,fd=4))
tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:((\"sshd\",pid=700,fd=3))
tcp LISTEN 0 128 0.0.0.0:2200 0.0.0.0:* users:((\"sshd\",pid=701,fd=3))
tcp LISTEN 0 128 0.0.0.0:2022 0.0.0.0:* users:((\"sshd\",pid=702,fd=3))
tcp LISTEN 0 128 0.0.0.0:2023 0.0.0.0:* users:((\"sshd\",pid=703,fd=3))
udp UNCONN 0 0 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=59,fd=5))
";
        let fs = process(FakeFs::new(), 59, "0\t0\t0\t0", SSHD);
        // A user's own binary named sshd, a user's copy of the real one, a
        // root process of another binary, and one with a non-root saved uid.
        let fs = process(fs, 700, "1000\t1000\t1000\t1000", "/home/eve/sshd");
        let fs = process(fs, 701, "1000\t1000\t1000\t1000", SSHD);
        let fs = process(fs, 702, "0\t0\t0\t0", "/usr/bin/python3");
        let fs = process(fs, 703, "0\t0\t1000\t0", SSHD);
        assert_eq!(sshd_ports(&fs, &parse_lines(text)), [22]);
        // Without /proc (or root), none.
        assert!(sshd_ports(&FakeFs::new(), &parse_lines(text)).is_empty());
    }

    proptest::proptest! {
        #[test]
        fn parse_never_panics(s in "\\PC*") {
            let _ = parse(&s);
        }
    }
}
