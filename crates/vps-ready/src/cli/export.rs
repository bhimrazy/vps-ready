//! `export cloud-init`: `#cloud-config` user-data that installs this
//! version and applies a profile at a new server's first boot, before
//! anyone logs in. It makes no network call: the tarball hashes come from
//! the release's `checksums.txt`, which the user downloaded and verified.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, bail};

use super::change::Host;
use crate::VERSION_INFO;
use crate::config::{Profile, STAGED_VIA};

/// The release tarballs, by `uname -m`.
const TARGETS: [(&str, &str); 2] = [
    ("x86_64", "x86_64-unknown-linux-musl"),
    ("aarch64", "aarch64-unknown-linux-musl"),
];

/// Where the exported profile is written on the new server.
pub(super) const PROFILE_PATH: &str = "/etc/vps-ready/profile.toml";

/// Prints the user-data for profile `spec` (a built-in name or a file),
/// with the hashes from the file `checksums` and the tarballs downloaded
/// from `base_url`, by default this version's GitHub release. Warnings go
/// to `err`.
pub(super) fn cloud_init(
    host: &Host,
    spec: &str,
    checksums: &Path,
    base_url: Option<&str>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<u8> {
    let (text, profile) = load(host, spec)?;
    if let Some(why) = refusal(&profile) {
        bail!("profile {spec}: {}", why.reason());
    }
    let address = profile
        .params("net.wireguard")
        .and_then(|w| w.get("address"))
        .and_then(toml::Value::as_str);
    if address.is_some_and(|a| !a.is_empty()) {
        writeln!(
            err,
            "warning: net.wireguard has an explicit `address`, so every server made from this \
             export gets the same WireGuard subnet, and one laptop cannot reach two of them; \
             drop `address` to derive one per server"
        )?;
    }

    // YAML 1.1 parsers break lines at these; TOML allows them in strings.
    if let Some(c) = text
        .chars()
        .find(|c| matches!(c, '\u{85}' | '\u{2028}' | '\u{2029}' | '\u{feff}'))
    {
        bail!(
            "profile {spec} contains U+{:04X}, which YAML would change; remove it",
            u32::from(c)
        );
    }
    let version = VERSION_INFO.version;
    let sums = read(host, checksums)?;
    let mut cases = String::new();
    for (arch, target) in TARGETS {
        let tarball = format!("vps-ready-{version}-{target}.tar.gz");
        let sum = sha256(&sums, &tarball).with_context(|| {
            format!(
                "{} has no SHA-256 for {tarball}; use the checksums.txt of the v{version} release",
                checksums.display()
            )
        })?;
        cases.push_str(&format!("        {arch}) t={target}; sum={sum} ;;\n"));
    }
    let base = match base_url {
        Some(url) => checked_url(url)?,
        None => format!("https://github.com/bhimrazy/vps-ready/releases/download/v{version}"),
    };
    let curl_https = if base.starts_with("https://") {
        " --proto '=https' --tlsv1.2"
    } else {
        ""
    };
    write!(
        out,
        "#cloud-config
# vps-ready {version} (export cloud-init): hardens this server at first boot.
write_files:
  - path: {PROFILE_PATH}
    permissions: \"0600\"
    content: |2
{content}runcmd:
  - - sh
    - -c
    - |
      set -eu
      case \"$(uname -m)\" in
{cases}        *) echo \"vps-ready: unsupported architecture\" >&2; exit 1 ;;
      esac
      d=$(mktemp -d)
      f=\"$d/vps-ready-{version}-$t.tar.gz\"
      u=\"{base}/vps-ready-{version}-$t.tar.gz\"
      if command -v curl >/dev/null; then
        curl{curl_https} -fsSL --retry 5 --retry-connrefused -o \"$f\" \"$u\"
      else
        wget -q --tries=5 --retry-connrefused -O \"$f\" \"$u\"
      fi
      echo \"$sum  $f\" | sha256sum -c -
      tar -xzf \"$f\" -C \"$d\"
      install -m 0755 \"$d/vps-ready-{version}-$t/vps-ready\" /usr/local/bin/vps-ready
      rm -rf \"$d\"
      # `sshd -T` needs it; with ssh.socket it appears only at the first login.
      [ -d /run/sshd ] || mkdir -m 0755 /run/sshd
      /usr/local/bin/vps-ready apply --profile {PROFILE_PATH} --yes --deadman=off
",
        content = indent(&text, 6),
    )?;
    Ok(0)
}

/// Why `export` refuses a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
    /// At first boot there is no SSH session to copy keys from, and root's
    /// keys on cloud images carry a `command=` that `user.admin` skips.
    NoAdminKeys,
    /// User-data is readable by any process on the host through the
    /// metadata service, so it must not lead to an auth key.
    TailscaleAuthKey,
    /// The same for a tunnel token.
    TunnelToken,
    /// At first boot no SSH session can come through the VPN.
    SshVia,
}

impl Refusal {
    pub(super) const fn reason(self) -> &'static str {
        match self {
            Self::NoAdminKeys => {
                "user.admin needs `authorized_keys`: at first boot there is no SSH session to \
                 copy keys from"
            }
            Self::TailscaleAuthKey => {
                "net.tailscale has `auth_key_file`, and nothing at first boot puts a key there \
                 safely: user-data is readable through the metadata service. Leave it out, and \
                 log in with `sudo tailscale up --accept-dns=false` after the first boot"
            }
            Self::TunnelToken => {
                "net.tunnel has `token_file`, and nothing at first boot puts a token there \
                 safely: user-data is readable through the metadata service. Leave it out, and \
                 after the first boot save the token to a root-only file, set `token_file` and \
                 apply again"
            }
            Self::SshVia => {
                "firewall.inbound has `ssh_via`: at first boot no SSH session can come through \
                 the VPN, so apply it later from one that does"
            }
        }
    }
}

/// Why `export` refuses `profile`, if it does.
pub(super) fn refusal(profile: &Profile) -> Option<Refusal> {
    let via = profile
        .params("firewall.inbound")
        .and_then(|p| p.get("ssh_via"))
        .and_then(toml::Value::as_str);
    // The private profile's `"vpn"` stays in step 1 at first boot: SSH public.
    if via.is_some_and(|v| !v.is_empty() && !v.starts_with(STAGED_VIA)) {
        return Some(Refusal::SshVia);
    }
    if let Some(admin) = profile.params("user.admin") {
        let keys = admin.get("authorized_keys").and_then(toml::Value::as_array);
        if keys.is_none_or(Vec::is_empty) {
            return Some(Refusal::NoAdminKeys);
        }
    }
    let set = |module: &str, key: &str| {
        profile
            .params(module)
            .and_then(|t| t.get(key))
            .and_then(toml::Value::as_str)
            .is_some_and(|path| !path.is_empty())
    };
    if set("net.tailscale", "auth_key_file") {
        return Some(Refusal::TailscaleAuthKey);
    }
    set("net.tunnel", "token_file").then_some(Refusal::TunnelToken)
}

/// The profile's text as written to the server, and the profile. A
/// built-in profile is written as a file that extends it.
fn load(host: &Host, spec: &str) -> anyhow::Result<(String, Profile)> {
    if let Some(profile) = Profile::built_in(spec, host.modules)? {
        return Ok((format!("schema = 1\nextends = \"{spec}\"\n"), profile));
    }
    let text = read(host, Path::new(spec))
        .map_err(|e| anyhow::anyhow!("{spec} is not a built-in profile ({e:#})"))?;
    let profile =
        Profile::parse(&text, host.modules).map_err(|e| anyhow::anyhow!("profile {spec}: {e}"))?;
    Ok((text, profile))
}

fn read(host: &Host, path: &Path) -> anyhow::Result<String> {
    let bytes = host.sys.fs.read(&std::path::absolute(path)?)?;
    String::from_utf8(bytes).with_context(|| format!("{} is not valid UTF-8", path.display()))
}

/// The SHA-256 of `file` in `sha256sum` output, in text (`hash  file`) or
/// binary (`hash *file`) mode.
fn sha256<'a>(sums: &'a str, file: &str) -> Option<&'a str> {
    sums.lines().find_map(|line| {
        let (hash, rest) = line.split_once(' ')?;
        let name = rest.strip_prefix([' ', '*'])?;
        (name == file && hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            .then_some(hash)
    })
}

/// `url` without a trailing `/`, if it is an `http` or `https` URL that is
/// safe inside the script's double quotes. The tarball's hash is checked on
/// the server, so the URL cannot change what runs.
fn checked_url(url: &str) -> anyhow::Result<String> {
    let safe = |c: char| c.is_ascii_alphanumeric() || "-._~:/?#[]@!&'()*+,;=%".contains(c);
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    let host_part = rest.map(|r| r.trim_end_matches('/'));
    if !host_part.is_some_and(|r| !r.is_empty() && !r.starts_with('/')) || !url.chars().all(safe) {
        bail!("--base-url {url:?} is not an http or https URL without spaces, quotes or `$`");
    }
    Ok(url.trim_end_matches('/').to_owned())
}

/// Each line of `text` after `n` spaces; empty lines stay empty.
fn indent(text: &str, n: usize) -> String {
    let pad = " ".repeat(n);
    text.lines()
        .map(|l| {
            if l.is_empty() {
                "\n".to_owned()
            } else {
                format!("{pad}{l}\n")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests;
