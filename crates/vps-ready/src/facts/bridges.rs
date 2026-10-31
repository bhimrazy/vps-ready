//! `docker0` and the interfaces named `br-*`, from `/sys/class/net`.
//!
//! Docker names its bridges `docker0` and `br-<first 12 hex digits of the
//! network ID>`. Other tools name bridges `br-*` too (netplan, LXD, libvirt),
//! and a firewall rule for `br-*` would match them as well.

use std::path::Path;

use serde::Serialize;

use crate::sys::{Fs, SysError};

/// `docker0` or an interface named `br-*`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Bridge {
    /// Interface name.
    pub name: String,
    /// Whether it is named as Docker names its bridges.
    pub docker: bool,
}

pub(super) fn detect(fs: &dyn Fs, notices: &mut Vec<String>) -> Vec<Bridge> {
    let paths = match fs.read_dir(Path::new("/sys/class/net")) {
        Ok(paths) => paths,
        Err(SysError::NotFound(_)) => return Vec::new(),
        Err(err) => {
            notices.push(format!(
                "reading /sys/class/net: {err}; bridges are unknown"
            ));
            return Vec::new();
        }
    };
    paths
        .iter()
        .filter_map(|p| p.file_name()?.to_str())
        // A name that cannot be quoted in a ruleset is left out. Only root
        // creates interfaces in the host's network namespace.
        .filter(|n| (*n == "docker0" || n.starts_with("br-")) && is_plain(n))
        .map(|name| Bridge {
            name: name.to_owned(),
            docker: is_docker(name),
        })
        .collect()
}

/// `docker0`, or `br-` and 12 lowercase hex digits.
fn is_docker(name: &str) -> bool {
    name == "docker0"
        || name.strip_prefix("br-").is_some_and(|id| {
            id.len() == 12 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

fn is_plain(name: &str) -> bool {
    name.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::fake::FakeFs;

    #[test]
    fn finds_docker0_and_br_interfaces() {
        let fs = [
            "lo",
            "eth0",
            "docker0",
            "br-0123456789ab",
            "br-lan",
            "br-x\"y",
        ]
        .iter()
        .fold(FakeFs::new(), |fs, n| {
            fs.with_file(format!("/sys/class/net/{n}/type"), "1\n")
        });
        let mut notices = Vec::new();
        let got: Vec<(String, bool)> = detect(&fs, &mut notices)
            .into_iter()
            .map(|b| (b.name, b.docker))
            .collect();
        assert!(notices.is_empty(), "{notices:?}");
        assert_eq!(
            got,
            [
                ("br-0123456789ab".to_owned(), true),
                ("br-lan".to_owned(), false),
                ("docker0".to_owned(), true),
            ]
        );
        assert!(detect(&FakeFs::new(), &mut notices).is_empty());
        assert!(notices.is_empty());
    }

    #[test]
    fn docker_names() {
        for name in ["docker0", "br-0123456789ab"] {
            assert!(is_docker(name), "{name}");
        }
        for name in [
            "br-lan",
            "br0",
            "br-0123456789AB",
            "br-0123456789abc",
            "docker1",
        ] {
            assert!(!is_docker(name), "{name}");
        }
    }
}
