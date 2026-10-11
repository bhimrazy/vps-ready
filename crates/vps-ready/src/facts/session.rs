//! The SSH session `vps-ready` was started from.
//!
//! Knowing the admin's address and the port they connected to is what lets
//! later milestones keep that path open: the firewall must allow it, and a
//! confirmation must arrive on a *different* connection.

use std::net::{IpAddr, SocketAddr};

use serde::Serialize;

/// Inputs taken from the process environment, passed in explicitly so tests
/// can supply their own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Env {
    /// `SSH_CONNECTION`: `client_ip client_port server_ip server_port`.
    pub ssh_connection: Option<String>,
}

impl Env {
    /// Reads the variables from this process's environment.
    #[must_use]
    pub fn from_process() -> Self {
        Self {
            ssh_connection: std::env::var("SSH_CONNECTION").ok(),
        }
    }
}

/// Both ends of the SSH connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SshSession {
    /// The admin's address and source port.
    pub client: SocketAddr,
    /// The server address and port they connected to.
    pub server: SocketAddr,
}

impl SshSession {
    /// Parses `SSH_CONNECTION`. IPv6 addresses appear without brackets; a
    /// zone such as `%eth0` is dropped.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let mut fields = value.split_whitespace();
        let mut addr = || -> Option<SocketAddr> {
            let ip = fields.next()?;
            let ip: IpAddr = ip.split('%').next()?.parse().ok()?;
            Some(SocketAddr::new(ip, fields.next()?.parse().ok()?))
        };
        let session = Self {
            client: addr()?,
            server: addr()?,
        };
        fields.next().is_none().then_some(session)
    }
}

pub(super) fn detect(env: &Env, notices: &mut Vec<String>) -> Option<SshSession> {
    let Some(value) = env.ssh_connection.as_deref() else {
        notices.push(
            "SSH_CONNECTION is not set: not an SSH session, or sudo removed it \
             (use `sudo --preserve-env=SSH_CONNECTION`)"
                .to_owned(),
        );
        return None;
    };
    let session = SshSession::parse(value);
    if session.is_none() {
        notices.push(format!("could not parse SSH_CONNECTION={value:?}"));
    }
    session
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ssh_connection() {
        let s = SshSession::parse("198.51.100.7 51234 203.0.113.10 22").unwrap();
        assert_eq!(s.client.to_string(), "198.51.100.7:51234");
        assert_eq!(s.server.port(), 22);

        let v6 = SshSession::parse("2001:db8::7 51234 fe80::1%eth0 2222").unwrap();
        assert_eq!(v6.client.to_string(), "[2001:db8::7]:51234");
        assert_eq!(v6.server.port(), 2222);

        for bad in [
            "",
            "192.0.2.1 1 192.0.2.2",
            "192.0.2.1 x 192.0.2.2 22",
            "a b c d",
            "192.0.2.1 1 192.0.2.2 22 extra",
        ] {
            assert_eq!(SshSession::parse(bad), None, "{bad:?}");
        }
    }

    proptest::proptest! {
        #[test]
        fn parse_never_panics(s in "\\PC*") {
            let _ = SshSession::parse(&s);
        }
    }
}
