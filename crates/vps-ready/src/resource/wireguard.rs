//! The [`WireguardKey`] and [`WireguardSync`] resources.
//!
//! The private key never passes through vps-ready: `wg genkey` writes it
//! straight to its file and `wg pubkey` reads it from there. Only `wg show
//! <if> listen-port`, `allowed-ips` and `public-key` are read, never `wg
//! showconf` or `wg show <if> dump`, which print the private key.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{Backup, ResourceError, failed};
use crate::sys::{Cmd, FileKind, Sys, SysError};

/// Kill timeout of each `wg` command.
pub(crate) const WG_TIMEOUT: Duration = Duration::from_secs(10);

/// `wg`, with [`WG_TIMEOUT`].
pub(crate) fn wg<'a>(args: impl IntoIterator<Item = &'a str>) -> Cmd {
    Cmd::new("wg").args(args).timeout(WG_TIMEOUT)
}

/// Whether `text` is a WireGuard key as `wg` prints it: base64 of 32 bytes.
#[must_use]
pub fn is_key(text: &str) -> bool {
    decode_key(text).is_some()
}

/// The 32 bytes of a base64 WireGuard key; `None` unless it is exactly 44
/// characters of the standard alphabet ending in one `=`, with the unused
/// low bits zero, as `wg` writes it.
fn decode_key(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 44 || bytes[43] != b'=' {
        return None;
    }
    let value = |c: u8| -> Option<u32> {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        Some(u32::from(v))
    };
    // 10 groups of 4 characters for 30 bytes, then 3 for the last 2.
    let mut out = [0u8; 32];
    let mut n = 0;
    for chunk in bytes[..40].chunks(4) {
        let mut v = 0u32;
        for &c in chunk {
            v = (v << 6) | value(c)?;
        }
        out[n] = (v >> 16) as u8;
        out[n + 1] = (v >> 8) as u8;
        out[n + 2] = v as u8;
        n += 3;
    }
    let mut v = 0u32;
    for &c in &bytes[40..43] {
        v = (v << 6) | value(c)?;
    }
    // 18 bits for the last 2 bytes: the low 2 must be zero.
    if v & 0b11 != 0 {
        return None;
    }
    out[30] = (v >> 10) as u8;
    out[31] = (v >> 2) as u8;
    Some(out)
}

/// The public key of the private key in `path`, from `wg pubkey` reading the
/// file itself.
fn public_key(sys: Sys, path: &Path) -> Result<String, ResourceError> {
    let out = sys.runner.run(&wg(["pubkey"]).stdin_from(path))?;
    if !out.ok() {
        return Err(failed("wg", &out));
    }
    let key = out.stdout_str()?.trim();
    if !is_key(key) {
        return Err(ResourceError::Unexpected {
            program: "wg pubkey".to_owned(),
            output: key.to_owned(),
        });
    }
    Ok(key.to_owned())
}

/// The server's private key, generated on the host: `wg genkey` writes it to
/// [`WireguardKey::path`], which it creates with mode 0600. An existing key
/// is kept, so a rollback and a later apply keep the same public key.
/// Rollback keeps a key it generated: client configs made since go on
/// working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireguardKey {
    /// E.g. `/etc/wireguard/wg0.key`.
    pub path: PathBuf,
}

impl WireguardKey {
    /// The summary, or `None` when a usable key is there. A key file that
    /// is not one is refused, not replaced: other configs may use it.
    pub(super) fn diff(&self, sys: Sys) -> Result<Option<(String, Option<String>)>, ResourceError> {
        if self.check(sys, false)? {
            return Ok(None);
        }
        Ok(Some((
            format!(
                "generate a private key in {} (mode 0600, root:root) with `wg genkey`; it \
                 never leaves this server",
                self.path.display()
            ),
            None,
        )))
    }

    pub(super) fn snapshot(&self, sys: Sys) -> Result<Backup, ResourceError> {
        let exists = self.check(sys, true)?;
        Ok(Backup::WireguardKey {
            path: self.path.clone(),
            created: !exists,
            public_key: exists.then(|| public_key(sys, &self.path)).transpose()?,
        })
    }

    /// `wg genkey` straight into a new file, then `wg pubkey` on it; a key
    /// it rejects is removed and fails the apply.
    pub(super) fn apply(&self, sys: Sys) -> Result<(), ResourceError> {
        if self.check(sys, true)? {
            return Ok(());
        }
        let generated = sys
            .runner
            .run(&wg(["genkey"]).stdout_to(&self.path, 0o600))
            .map_err(ResourceError::from)
            .and_then(|out| {
                if out.ok() {
                    Ok(())
                } else {
                    Err(failed("wg", &out))
                }
            })
            .and_then(|()| public_key(sys, &self.path).map(drop));
        if let Err(e) = generated {
            match sys.fs.remove(&self.path) {
                Ok(()) | Err(SysError::NotFound(_)) => {}
                Err(rm) => tracing::error!("removing {}: {rm}", self.path.display()),
            }
            return Err(e);
        }
        if let Some(dir) = self.path.parent() {
            sys.fs.sync_dir(dir)?;
        }
        Ok(())
    }

    /// Whether a usable key is at the path: a regular file owned by root,
    /// with no group or other permission bits, not a symlink, that `wg
    /// pubkey` accepts. `false` when there is none; anything else there is
    /// [`ResourceError::Unsafe`]. Without `wg` (installed later in the same
    /// apply) only the metadata is checked, unless `need_wg`.
    fn check(&self, sys: Sys, need_wg: bool) -> Result<bool, ResourceError> {
        let unsafe_key = |reason: String| ResourceError::Unsafe {
            path: self.path.clone(),
            reason: format!(
                "{reason}; fix it, or remove it to have a new key generated (every client then \
                 needs the new public key)"
            ),
        };
        let meta = match sys.fs.metadata(&self.path) {
            Ok(meta) => meta,
            Err(SysError::NotFound(_)) => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        match meta.kind {
            FileKind::File => {}
            FileKind::Symlink => return Err(unsafe_key("it is a symlink".to_owned())),
            kind => return Err(unsafe_key(format!("it is not a regular file ({kind:?})"))),
        }
        if meta.uid != 0 {
            return Err(unsafe_key(format!(
                "it is owned by uid {}, not root",
                meta.uid
            )));
        }
        if meta.mode & 0o077 != 0 {
            return Err(unsafe_key(format!(
                "its mode {:04o} lets other users read it",
                meta.mode
            )));
        }
        match public_key(sys, &self.path) {
            Ok(_) => Ok(true),
            Err(ResourceError::Sys(SysError::NotFound(p))) if p == "wg" && !need_wg => Ok(true),
            Err(ResourceError::Command { .. } | ResourceError::Unexpected { .. }) => Err(
                unsafe_key("`wg pubkey` does not accept it as a private key".to_owned()),
            ),
            Err(e) => Err(e),
        }
    }
}

/// A peer of [`WireguardSync`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncPeer {
    /// The profile's name for it, for the plan.
    pub name: String,
    /// Its public key.
    pub public_key: String,
    /// Its tunnel address, e.g. `10.86.12.2/32`.
    pub allowed_ip: String,
}

/// The running interface's listen port and peers, as the file has them.
/// Changed with `wg set` only, never `wg syncconf` or `setconf`: those
/// would clear the private key that `PostUp` loaded, since the file has
/// none. Nothing to do while the interface is down; bringing it up reads
/// the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireguardSync {
    /// E.g. `wg0`.
    pub interface: String,
    /// `ListenPort`.
    pub port: u16,
    /// Each `[Peer]`.
    pub peers: Vec<SyncPeer>,
}

/// A WireGuard interface's listen port and peers' allowed IPs, keyed by
/// public key. Holds no private key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgState {
    /// Listen port.
    pub port: u16,
    /// Allowed IPs per peer public key, as `wg` prints them.
    pub peers: BTreeMap<String, Vec<String>>,
}

impl WireguardSync {
    fn desired(&self) -> WgState {
        WgState {
            port: self.port,
            peers: self
                .peers
                .iter()
                .map(|p| (p.public_key.clone(), vec![p.allowed_ip.clone()]))
                .collect(),
        }
    }

    /// The differences, or `None` when the interface is down or matches.
    pub(super) fn diff(&self, sys: Sys) -> Result<Option<(String, Option<String>)>, ResourceError> {
        let Some(now) = runtime(sys, &self.interface)? else {
            return Ok(None);
        };
        let want = self.desired();
        if now == want {
            return Ok(None);
        }
        let name = |key: &str| {
            self.peers
                .iter()
                .find(|p| p.public_key == key)
                .map_or_else(|| key.to_owned(), |p| p.name.clone())
        };
        let mut parts = Vec::new();
        for key in now.peers.keys().filter(|k| !want.peers.contains_key(*k)) {
            parts.push(format!("remove peer {key}"));
        }
        for (key, ips) in &want.peers {
            match now.peers.get(key) {
                None => parts.push(format!("add peer {} ({})", name(key), ips.join(", "))),
                Some(old) if old != ips => parts.push(format!(
                    "set peer {} to {} (was {})",
                    name(key),
                    ips.join(", "),
                    if old.is_empty() {
                        "none".to_owned()
                    } else {
                        old.join(", ")
                    }
                )),
                Some(_) => {}
            }
        }
        if now.port != want.port {
            parts.push(format!("listen port {} -> {}", now.port, want.port));
        }
        Ok(Some((
            format!(
                "update the running {} with `wg set`: {}",
                self.interface,
                parts.join(", ")
            ),
            None,
        )))
    }

    pub(super) fn snapshot(&self, sys: Sys) -> Result<Backup, ResourceError> {
        Ok(Backup::WireguardSync {
            interface: self.interface.clone(),
            before: runtime(sys, &self.interface)?,
            after: self.desired(),
        })
    }

    pub(super) fn apply(&self, sys: Sys) -> Result<(), ResourceError> {
        converge(sys, &self.interface, &self.desired())
    }

    /// The longest snapshot and apply may run: two reads in each, then a
    /// `wg set` per peer, one per peer removed, and one for the port.
    pub(super) fn timeout(&self) -> Duration {
        WG_TIMEOUT * (6 + 2 * u32::try_from(self.peers.len()).unwrap_or(u32::MAX / 4))
    }
}

/// The interface's state from `wg show`; `None` when it does not exist
/// or `wg` is not installed.
pub(crate) fn runtime(sys: Sys, interface: &str) -> Result<Option<WgState>, ResourceError> {
    let show = |what: &str| -> Result<Option<String>, ResourceError> {
        let out = match sys.runner.run(&wg(["show", interface, what])) {
            Ok(out) => out,
            // Not installed yet, so no interface either.
            Err(SysError::NotFound(p)) if p == "wg" => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if out.ok() {
            return Ok(Some(out.stdout_str()?.to_owned()));
        }
        if String::from_utf8_lossy(&out.stderr).contains("No such device") {
            return Ok(None);
        }
        Err(failed("wg", &out))
    };
    let Some(port) = show("listen-port")? else {
        return Ok(None);
    };
    let Some(ips) = show("allowed-ips")? else {
        return Ok(None);
    };
    let port = port.trim().parse().map_err(|_| ResourceError::Unexpected {
        program: "wg show listen-port".to_owned(),
        output: port.clone(),
    })?;
    let peers = ips
        .lines()
        .filter_map(|line| {
            let (key, ips) = line.split_once('\t')?;
            let ips = ips
                .split_whitespace()
                .filter(|ip| *ip != "(none)")
                .map(str::to_owned)
                .collect();
            Some((key.to_owned(), ips))
        })
        .collect();
    Ok(Some(WgState { port, peers }))
}

/// The `wg set` commands that take `now` to `want`: removals, then peers,
/// then the port. Never a `private-key` argument.
pub(crate) fn set_commands(interface: &str, now: &WgState, want: &WgState) -> Vec<Cmd> {
    let mut cmds = Vec::new();
    for key in now.peers.keys().filter(|k| !want.peers.contains_key(*k)) {
        cmds.push(wg(["set", interface, "peer", key, "remove"]));
    }
    for (key, ips) in &want.peers {
        if now.peers.get(key) != Some(ips) {
            let ips = ips.join(",");
            cmds.push(wg(["set", interface, "peer", key, "allowed-ips", &ips]));
        }
    }
    if now.port != want.port {
        let port = want.port.to_string();
        cmds.push(wg(["set", interface, "listen-port", &port]));
    }
    cmds
}

/// Brings the running interface to `want`, if it exists.
fn converge(sys: Sys, interface: &str, want: &WgState) -> Result<(), ResourceError> {
    let Some(now) = runtime(sys, interface)? else {
        return Ok(());
    };
    for cmd in set_commands(interface, &now, want) {
        super::run(sys, &cmd)?;
    }
    Ok(())
}

/// Puts the running interface back to `before`; nothing when it was down
/// then or is now.
pub(super) fn restore(
    sys: Sys,
    interface: &str,
    before: Option<&WgState>,
) -> Result<(), ResourceError> {
    match before {
        Some(before) => converge(sys, interface, before),
        None => Ok(()),
    }
}

/// The safety check: the running interface is as apply left it or as it
/// was, or it is down.
pub(crate) fn unchanged(
    sys: Sys,
    interface: &str,
    before: Option<&WgState>,
    after: &WgState,
) -> Result<bool, ResourceError> {
    Ok(match runtime(sys, interface)? {
        None => true,
        Some(now) => &now == after || Some(&now) == before,
    })
}

/// How to restore the running interface by hand; `None` if apply changed
/// nothing there.
pub(crate) fn by_hand(
    interface: &str,
    before: Option<&WgState>,
    after: &WgState,
) -> Option<String> {
    let before = before?;
    let mut line = String::new();
    for cmd in set_commands(interface, after, before) {
        if !line.is_empty() {
            line.push_str("; ");
        }
        let _ = write!(line, "wg {}", cmd.args.join(" "));
    }
    (!line.is_empty()).then_some(line)
}
