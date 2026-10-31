//! `docker0` and the interfaces named `br-*`, from `/sys/class/net`, with
//! the networks routed through them (`/proc/net/route`,
//! `/proc/net/ipv6_route`).
//!
//! Docker names its bridges `docker0` and `br-<first 12 hex digits of the
//! network ID>`. Other tools name bridges `br-*` too (netplan, LXD, libvirt),
//! and a firewall rule for `br-*` would match them as well.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::{Serialize, Serializer};

use crate::sys::{Fs, SysError};

/// `docker0` or an interface named `br-*`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Bridge {
    /// Interface name.
    pub name: String,
    /// Whether it is named as Docker names its bridges.
    pub docker: bool,
    /// Networks routed through it, without link-local and multicast ones.
    pub networks: Vec<Network>,
}

/// An IP network, such as `172.17.0.0/16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    /// Its address.
    pub addr: IpAddr,
    /// Prefix length: at most 32 for IPv4, 128 for IPv6.
    pub prefix: u8,
}

impl Network {
    /// Whether `ip` is in this network. An IPv4-mapped IPv6 address
    /// (`::ffff:172.17.0.2`) counts as its IPv4 address.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                (u32::from(net) ^ u32::from(ip)) & mask == 0
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                (u128::from(net) ^ u128::from(ip)) & mask == 0
            }
            _ => false,
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl Serialize for Network {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

pub(super) fn detect(fs: &dyn Fs, notices: &mut Vec<String>) -> Vec<Bridge> {
    let names = match fs.read_dir(Path::new("/sys/class/net")) {
        Ok(paths) => paths,
        Err(SysError::NotFound(_)) => return Vec::new(),
        Err(err) => {
            notices.push(format!(
                "reading /sys/class/net: {err}; bridges are unknown"
            ));
            return Vec::new();
        }
    };
    let routes = routes(fs);
    names
        .iter()
        .filter_map(|p| p.file_name()?.to_str())
        // A name that cannot be quoted in a ruleset is left out. Only root
        // creates interfaces in the host's network namespace.
        .filter(|n| (*n == "docker0" || n.starts_with("br-")) && is_plain(n))
        .map(|name| Bridge {
            name: name.to_owned(),
            docker: is_docker(name),
            networks: routes
                .iter()
                .filter(|(dev, _)| dev == name)
                .map(|(_, net)| *net)
                .collect(),
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

/// `(interface, network)` of each route in `/proc/net/route` and
/// `/proc/net/ipv6_route`, except default, link-local and multicast ones.
/// Missing or unreadable files give none.
fn routes(fs: &dyn Fs) -> Vec<(String, Network)> {
    let read = |path: &str| {
        fs.read(Path::new(path))
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    };
    let mut routes: Vec<(String, Network)> = read("/proc/net/route")
        .lines()
        .skip(1)
        .filter_map(route_v4)
        .chain(read("/proc/net/ipv6_route").lines().filter_map(route_v6))
        .filter(|(_, net)| net.prefix > 0)
        .collect();
    routes.dedup();
    routes
}

/// A line of `/proc/net/route`: `Iface Destination Gateway Flags RefCnt Use
/// Metric Mask ...`, with addresses as hex in the host's byte order.
fn route_v4(line: &str) -> Option<(String, Network)> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let hex = |i: usize| u32::from_str_radix(fields.get(i)?, 16).ok();
    let (dest, mask) = (hex(1)?, hex(7)?);
    let network = Network {
        addr: IpAddr::V4(Ipv4Addr::from(dest.to_ne_bytes())),
        prefix: u8::try_from(mask.count_ones()).ok()?,
    };
    Some(((*fields.first()?).to_owned(), network))
}

/// A line of `/proc/net/ipv6_route`: destination, its prefix length (hex),
/// source, its prefix length, next hop, metric, refcount, use, flags and the
/// interface.
fn route_v6(line: &str) -> Option<(String, Network)> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let addr = Ipv6Addr::from(u128::from_str_radix(fields.first()?, 16).ok()?);
    let prefix = u8::from_str_radix(fields.get(1)?, 16)
        .ok()
        .filter(|p| *p <= 128)?;
    let link_local = (addr.segments()[0] & 0xffc0) == 0xfe80;
    if link_local || addr.is_multicast() {
        return None;
    }
    let network = Network {
        addr: IpAddr::V6(addr),
        prefix,
    };
    Some(((*fields.get(9)?).to_owned(), network))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::fake::FakeFs;

    fn net(s: &str) -> Network {
        let (addr, prefix) = s.split_once('/').unwrap();
        Network {
            addr: addr.parse().unwrap(),
            prefix: prefix.parse().unwrap(),
        }
    }

    #[test]
    fn finds_docker_bridges_and_their_networks() {
        // 172.17.0.0/16 and 172.18.0.0/16 in a little-endian host's order.
        let v4 = if cfg!(target_endian = "little") {
            ["000011AC", "0000FFFF", "000012AC"]
        } else {
            ["AC110000", "FFFF0000", "AC120000"]
        };
        let route = format!(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
             eth0\t00000000\t010200C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
             docker0\t{}\t00000000\t0001\t0\t0\t0\t{}\t0\t0\t0\n\
             br-0123456789ab\t{}\t00000000\t0001\t0\t0\t0\t{}\t0\t0\t0\n",
            v4[0], v4[1], v4[2], v4[1]
        );
        let ipv6_route = "\
fd000000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001  docker0
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001  docker0
ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001  docker0
";
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
        })
        .with_file("/proc/net/route", route)
        .with_file("/proc/net/ipv6_route", ipv6_route);
        let mut notices = Vec::new();
        let bridges = detect(&fs, &mut notices);
        assert!(notices.is_empty(), "{notices:?}");
        let got: Vec<(&str, bool, Vec<String>)> = bridges
            .iter()
            .map(|b| {
                let nets = b.networks.iter().map(ToString::to_string).collect();
                (b.name.as_str(), b.docker, nets)
            })
            .collect();
        assert_eq!(
            got,
            [
                ("br-0123456789ab", true, vec!["172.18.0.0/16".to_owned()]),
                ("br-lan", false, vec![]),
                (
                    "docker0",
                    true,
                    vec!["172.17.0.0/16".to_owned(), "fd00::/64".to_owned()]
                ),
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

    #[test]
    fn network_contains() {
        let v4 = net("172.17.0.0/16");
        assert!(v4.contains("172.17.0.2".parse().unwrap()));
        assert!(v4.contains("::ffff:172.17.0.2".parse().unwrap()));
        assert!(!v4.contains("172.18.0.2".parse().unwrap()));
        assert!(!v4.contains("fd00::2".parse().unwrap()));
        assert!(net("0.0.0.0/0").contains("192.0.2.1".parse().unwrap()));
        let v6 = net("fd00::/64");
        assert!(v6.contains("fd00::2".parse().unwrap()));
        assert!(!v6.contains("fd00:0:0:1::2".parse().unwrap()));
        assert!(net("2001:db8::1/128").contains("2001:db8::1".parse().unwrap()));
    }

    proptest::proptest! {
        #[test]
        fn route_parsers_never_panic(s in "\\PC*") {
            let _ = route_v4(&s);
            let _ = route_v6(&s);
        }
    }
}
