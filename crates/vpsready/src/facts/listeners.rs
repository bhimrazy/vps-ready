//! Listening sockets, from `ss -tulnpH`.
//!
//! The kernel's view of what listens is the real attack surface; a service's
//! config file only says what it intended.

use std::fmt;

use serde::Serialize;

use super::{Probe, probe};
use crate::sys::{Cmd, Runner};

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
    pub processes: Vec<String>,
}

pub(super) fn detect(runner: &dyn Runner, notices: &mut Vec<String>) -> Vec<Listener> {
    match probe(runner, &Cmd::new("ss").arg("-tulnpH"), notices) {
        Probe::Ran(out) if out.ok() => parse(&String::from_utf8_lossy(&out.stdout)),
        Probe::Ran(out) => {
            notices.push(format!(
                "`ss -tulnpH` exited with {}; listening sockets are unknown",
                out.status
            ));
            Vec::new()
        }
        Probe::Missing => {
            notices.push("ss not found (iproute2); listening sockets are unknown".to_owned());
            Vec::new()
        }
        Probe::Failed => Vec::new(),
    }
}

/// Parses `ss -tulnpH` output. Columns: netid, state, recv-q, send-q, local
/// address:port, peer address:port, then the optional process column.
/// Lines that do not fit are skipped.
#[must_use]
pub fn parse(text: &str) -> Vec<Listener> {
    text.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<Listener> {
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
    Some(Listener {
        proto,
        addr,
        port: port.parse().ok()?,
        processes: process_names(&process),
    })
}

/// `users:(("sshd",pid=131,fd=3),("systemd",pid=1,fd=41))` -> `[sshd, systemd]`,
/// without duplicates.
fn process_names(column: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
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
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    proptest::proptest! {
        #[test]
        fn parse_never_panics(s in "\\PC*") {
            let _ = parse(&s);
        }
    }
}
