//! `export cloud-init`: `#cloud-config` user-data that installs this
//! version and applies a profile at a new server's first boot, before
//! anyone logs in. It makes no network call: the tarball hashes come from
//! the release's `checksums.txt`, which the user downloaded and verified.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, bail};

use super::change::Host;
use crate::VERSION_INFO;
use crate::config::Profile;

/// The release tarballs, by `uname -m`.
const TARGETS: [(&str, &str); 2] = [
    ("x86_64", "x86_64-unknown-linux-musl"),
    ("aarch64", "aarch64-unknown-linux-musl"),
];

/// Where the exported profile is written on the new server.
pub(super) const PROFILE_PATH: &str = "/etc/vps-ready/profile.toml";

/// Prints the user-data for profile `spec` (a built-in name or a file),
/// with the hashes from the file `checksums` and the tarballs downloaded
/// from `base_url`, by default this version's GitHub release.
pub(super) fn cloud_init(
    host: &Host,
    spec: &str,
    checksums: &Path,
    base_url: Option<&str>,
    out: &mut dyn Write,
) -> anyhow::Result<u8> {
    let (text, profile) = load(host, spec)?;
    if let Some(why) = refusal(&profile) {
        bail!("profile {spec}: {why}");
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
    write!(
        out,
        "#cloud-config
# vps-ready {version} (export cloud-init): hardens this server at first boot.
write_files:
  - path: {PROFILE_PATH}
    permissions: \"0600\"
    content: {block}
{content}runcmd:
  - - sh
    - -c
    - |
      set -eu
      case \"$(uname -m)\" in
{cases}        *) echo \"vps-ready: unsupported architecture\" >&2; exit 1 ;;
      esac
      f=/root/vps-ready-{version}-$t.tar.gz
      curl -fsSL --retry 5 --retry-connrefused -o \"$f\" \\
        \"{base}/vps-ready-{version}-$t.tar.gz\"
      echo \"$sum  $f\" | sha256sum -c -
      tar -xzf \"$f\" -C /root
      install -m 0755 \"/root/vps-ready-{version}-$t/vps-ready\" /usr/local/bin/vps-ready
      vps-ready apply --profile {PROFILE_PATH} --yes --deadman=off
",
        block = block_indicator(&text),
        content = indent(&text, 6),
    )?;
    Ok(0)
}

/// Why `export` refuses `profile`, if it does: at first boot there is no
/// SSH session to copy keys from, and root's keys on cloud images carry a
/// `command=` that `user.admin` skips.
pub(super) fn refusal(profile: &Profile) -> Option<&'static str> {
    let admin = profile.params("user.admin")?;
    let keys = admin.get("authorized_keys").and_then(toml::Value::as_array);
    match keys {
        Some(keys) if !keys.is_empty() => None,
        _ => Some(
            "user.admin needs `authorized_keys`: at first boot there is no SSH session to \
             copy keys from",
        ),
    }
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
    if !rest.is_some_and(|r| !r.is_empty()) || !url.chars().all(safe) {
        bail!("--base-url {url:?} is not an http or https URL without spaces, quotes or `$`");
    }
    Ok(url.trim_end_matches('/').to_owned())
}

/// `|`, or `|2` when the first line with text is indented: YAML takes the
/// block's indentation from that line otherwise.
fn block_indicator(text: &str) -> &'static str {
    match text.lines().find(|l| !l.trim().is_empty()) {
        Some(line) if line.starts_with([' ', '\t']) => "|2",
        _ => "|",
    }
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
