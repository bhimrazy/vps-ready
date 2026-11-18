//! Vendor apt repositories, as ordinary [`Directory`] and [`File`]
//! resources: a public key and a deb822 source that names it.
//!
//! The keys are embedded in the binary and never downloaded at apply time,
//! so a key is reviewed in a PR and covered by the release signature. The
//! `apt-keys` workflow checks them weekly against the vendors' published
//! keys.

use std::path::{Path, PathBuf};

use super::{Directory, File, Resource, ResourceError, run};
use crate::sys::{Cmd, FileOwner, Sys, SysError};

/// Where the keys go. apt 2.4 and later ship it; it is planned anyway.
pub const KEYRINGS: &str = "/etc/apt/keyrings";

/// Where the sources go.
pub const SOURCES: &str = "/etc/apt/sources.list.d";

/// Docker's armored public key, from <https://download.docker.com/linux/debian/gpg>
/// (the same key as `.../linux/ubuntu/gpg`).
pub const DOCKER_KEY: &str = include_str!("../../keys/docker.asc");

/// The fingerprint of [`DOCKER_KEY`]'s primary key, as Docker's install docs
/// gave it.
pub const DOCKER_FINGERPRINT: &str = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88";

/// Caddy's armored public key, from <https://dl.cloudsmith.io/public/caddy/stable/gpg.key>.
pub const CADDY_KEY: &str = include_str!("../../keys/caddy.asc");

/// The fingerprint of [`CADDY_KEY`]'s primary key, as Cloudsmith's API
/// gives it for the `caddy/stable` repository.
pub const CADDY_FINGERPRINT: &str = "65760C51EDEA2017CEA2CA15155B6D79CA56EA34";

/// A vendor's apt repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AptSource {
    /// File stem of the key and the source, e.g. `docker`.
    pub name: &'static str,
    /// Armored public key that signs the repository.
    pub key: &'static str,
    /// Repository URI.
    pub uri: &'static str,
    /// Suite, e.g. the host's codename.
    pub suite: String,
    /// Component, e.g. `stable`.
    pub component: &'static str,
}

impl AptSource {
    /// Docker's repository for the distribution `id` (`debian` or `ubuntu`,
    /// from `os-release`) and its `codename`, e.g. `bookworm`; `None` for
    /// another distribution or a codename that is not a plain word.
    #[must_use]
    pub fn docker(id: &str, codename: &str) -> Option<Self> {
        let uri = match id {
            "debian" => "https://download.docker.com/linux/debian",
            "ubuntu" => "https://download.docker.com/linux/ubuntu",
            _ => return None,
        };
        plain_word(codename).then(|| Self {
            name: "docker",
            key: DOCKER_KEY,
            uri,
            suite: codename.to_owned(),
            component: "stable",
        })
    }

    /// Caddy's repository, one suite for every distribution and release.
    #[must_use]
    pub fn caddy() -> Self {
        Self {
            name: "caddy",
            key: CADDY_KEY,
            uri: "https://dl.cloudsmith.io/public/caddy/stable/deb/debian",
            suite: "any-version".to_owned(),
            component: "main",
        }
    }

    /// Where [`apt_source`] writes this source.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        sources_path(self.name)
    }

    /// Whether another apt source already names this repository by its
    /// URI; see [`configured_elsewhere`].
    ///
    /// # Errors
    ///
    /// Any [`crate::sys::SysError`] from reading the sources.
    pub fn configured_elsewhere(&self, sys: Sys) -> Result<bool, ResourceError> {
        let repo = self
            .uri
            .split_once("://")
            .map_or(self.uri, |(_, rest)| rest);
        configured_elsewhere(sys, self.name, repo)
    }
}

fn sources_path(name: &str) -> PathBuf {
    Path::new(SOURCES).join(format!("{name}.sources"))
}

/// Whether an apt source other than the one [`apt_source`] writes for
/// `name` already contains `repo`, e.g. `docker.list` from Docker's older
/// install docs. A second source with another `Signed-By` makes `apt-get
/// update` fail, so the vendor source is then left out.
///
/// # Errors
///
/// Any [`crate::sys::SysError`] from reading the sources.
pub fn configured_elsewhere(sys: Sys, name: &str, repo: &str) -> Result<bool, ResourceError> {
    let own = sources_path(name);
    let mut files = vec![PathBuf::from("/etc/apt/sources.list")];
    match sys.fs.read_dir(Path::new(SOURCES)) {
        Ok(paths) => files.extend(paths),
        Err(SysError::NotFound(_)) => {}
        Err(e) => return Err(e.into()),
    }
    for path in files.iter().filter(|p| **p != own) {
        match sys.fs.read(path) {
            Ok(bytes) if String::from_utf8_lossy(&bytes).contains(repo) => return Ok(true),
            Ok(_) | Err(SysError::NotFound(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(false)
}

/// The resources that add `source` for the dpkg architecture `arch`, e.g.
/// `amd64` (see [`architecture`]): the keyrings directory, the key at
/// `/etc/apt/keyrings/<name>.asc` and the deb822 source at
/// `/etc/apt/sources.list.d/<name>.sources`. Rollback removes all three, the
/// directory only if it is empty.
#[must_use]
pub fn apt_source(source: &AptSource, arch: &str) -> Vec<Resource> {
    let key = Path::new(KEYRINGS).join(format!("{}.asc", source.name));
    let list = format!(
        "# Written by vps-ready. `vps-ready rollback --last` removes it.\n\
         Types: deb\n\
         URIs: {}\n\
         Suites: {}\n\
         Components: {}\n\
         Architectures: {arch}\n\
         Signed-By: {}\n",
        source.uri,
        source.suite,
        source.component,
        key.display(),
    );
    vec![
        Resource::Directory(Directory {
            path: KEYRINGS.into(),
            owner: root(0o755),
        }),
        Resource::File(File {
            path: key,
            content: source.key.as_bytes().to_vec(),
            owner: root(0o644),
            validate: None,
        }),
        Resource::File(File {
            path: source.path(),
            content: list.into_bytes(),
            owner: root(0o644),
            validate: None,
        }),
    ]
}

/// The host's dpkg architecture, from `dpkg --print-architecture`.
///
/// # Errors
///
/// [`ResourceError::Command`] if dpkg fails, [`ResourceError::Unexpected`]
/// if it prints something other than one plain word; any
/// [`crate::sys::SysError`].
pub fn architecture(sys: Sys) -> Result<String, ResourceError> {
    let out = run(sys, &Cmd::new("dpkg").arg("--print-architecture"))?;
    let arch = out.stdout_str()?.trim();
    if plain_word(arch) {
        Ok(arch.to_owned())
    } else {
        Err(ResourceError::Unexpected {
            program: "dpkg".to_owned(),
            output: arch.to_owned(),
        })
    }
}

/// Lowercase letters, digits, `-` and `.`, so it cannot break a deb822 line.
fn plain_word(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
}

fn root(mode: u32) -> FileOwner {
    FileOwner {
        mode,
        uid: 0,
        gid: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Backup, restore};
    use super::*;
    use crate::sys::fake::{FakeFs, FakeRunner};
    use crate::sys::{Fs, Output};

    const TXN: &str = "/var/lib/vps-ready/txn/20261031T120000Z";

    fn files(resources: &[Resource]) -> Vec<(String, String)> {
        resources
            .iter()
            .filter_map(|r| match r {
                Resource::File(f) => Some((
                    f.path.display().to_string(),
                    String::from_utf8(f.content.clone()).unwrap(),
                )),
                _ => None,
            })
            .collect()
    }

    fn source_file(source: &AptSource, arch: &str) -> String {
        let resources = apt_source(source, arch);
        files(&resources).remove(1).1
    }

    #[test]
    fn docker_sources_for_each_codename_and_architecture() {
        let hosts = [
            ("debian", "bookworm", "debian"),
            ("debian", "trixie", "debian"),
            ("ubuntu", "jammy", "ubuntu"),
            ("ubuntu", "noble", "ubuntu"),
        ];
        for (id, codename, path) in hosts {
            for arch in ["amd64", "arm64"] {
                let source = AptSource::docker(id, codename).unwrap();
                let resources = apt_source(&source, arch);
                let ids: Vec<String> = resources.iter().map(Resource::id).collect();
                assert_eq!(
                    ids,
                    [
                        "directory:/etc/apt/keyrings",
                        "file:/etc/apt/keyrings/docker.asc",
                        "file:/etc/apt/sources.list.d/docker.sources",
                    ]
                );
                let files = files(&resources);
                assert_eq!(files[0].1, DOCKER_KEY);
                assert_eq!(
                    files[1].1,
                    format!(
                        "# Written by vps-ready. `vps-ready rollback --last` removes it.\n\
                         Types: deb\n\
                         URIs: https://download.docker.com/linux/{path}\n\
                         Suites: {codename}\n\
                         Components: stable\n\
                         Architectures: {arch}\n\
                         Signed-By: /etc/apt/keyrings/docker.asc\n"
                    ),
                    "{id} {codename} {arch}"
                );
            }
        }
    }

    #[test]
    fn caddy_uses_its_fixed_suite() {
        for arch in ["amd64", "arm64"] {
            assert_eq!(
                source_file(&AptSource::caddy(), arch),
                format!(
                    "# Written by vps-ready. `vps-ready rollback --last` removes it.\n\
                     Types: deb\n\
                     URIs: https://dl.cloudsmith.io/public/caddy/stable/deb/debian\n\
                     Suites: any-version\n\
                     Components: main\n\
                     Architectures: {arch}\n\
                     Signed-By: /etc/apt/keyrings/caddy.asc\n"
                )
            );
        }
        let resources = apt_source(&AptSource::caddy(), "amd64");
        assert_eq!(files(&resources)[0].1, CADDY_KEY);
    }

    #[test]
    fn files_are_root_owned_and_world_readable() {
        for resource in apt_source(&AptSource::caddy(), "amd64") {
            let owner = match resource {
                Resource::Directory(d) => d.owner,
                Resource::File(f) => f.owner,
                other => panic!("{other:?}"),
            };
            assert_eq!((owner.uid, owner.gid), (0, 0));
            assert!(matches!(owner.mode, 0o644 | 0o755), "{:o}", owner.mode);
        }
    }

    #[test]
    fn docker_refuses_other_distributions_and_odd_codenames() {
        assert_eq!(AptSource::docker("fedora", "bookworm"), None);
        assert_eq!(AptSource::docker("raspbian", "bookworm"), None);
        for codename in ["", "noble\nTrusted: yes", "Noble", "a b"] {
            assert_eq!(AptSource::docker("ubuntu", codename), None, "{codename:?}");
        }
    }

    #[test]
    fn architecture_from_dpkg() {
        let runner =
            FakeRunner::new().on("dpkg", ["--print-architecture"], Output::success("arm64\n"));
        let fs = FakeFs::new();
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        assert_eq!(architecture(sys).unwrap(), "arm64");

        let runner = FakeRunner::new().on(
            "dpkg",
            ["--print-architecture"],
            Output::success("amd64\nTrusted: yes\n"),
        );
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let err = architecture(sys).unwrap_err();
        assert!(matches!(err, ResourceError::Unexpected { .. }), "{err:?}");
    }

    /// Snapshots and applies each resource in order, as the engine does,
    /// then restores in reverse.
    #[test]
    fn rollback_removes_the_key_the_source_and_the_directory() {
        let fs = FakeFs::new()
            .with_dir("/etc/apt", root(0o755))
            .with_dir(SOURCES, root(0o755))
            .with_file("/etc/apt/sources.list.d/debian.sources", "Types: deb\n");
        let sys = super::super::test_sys(&fs);
        let txn = Path::new(TXN);
        let source = AptSource::docker("debian", "trixie").unwrap();
        let resources = apt_source(&source, "amd64");

        let mut backups: Vec<Backup> = Vec::new();
        for (n, resource) in (1..).zip(&resources) {
            backups.push(resource.snapshot(sys, txn, n).unwrap());
            resource.apply(sys).unwrap();
        }
        for resource in &resources {
            assert_eq!(resource.diff(sys).unwrap(), None);
        }
        assert_eq!(
            fs.read(Path::new("/etc/apt/keyrings/docker.asc")).unwrap(),
            DOCKER_KEY.as_bytes()
        );

        for backup in backups.iter().rev() {
            restore(sys, txn, backup).unwrap();
        }
        assert!(!fs.exists(Path::new("/etc/apt/keyrings/docker.asc")));
        assert!(!fs.exists(Path::new("/etc/apt/sources.list.d/docker.sources")));
        assert!(!fs.exists(Path::new(KEYRINGS)));
        assert!(fs.exists(Path::new("/etc/apt/sources.list.d/debian.sources")));
    }

    #[test]
    fn rollback_keeps_an_existing_keyrings_directory() {
        let fs = FakeFs::new()
            .with_dir("/etc/apt", root(0o755))
            .with_dir(KEYRINGS, root(0o755))
            .with_dir(SOURCES, root(0o755));
        let sys = super::super::test_sys(&fs);
        let txn = Path::new(TXN);
        let resources = apt_source(&AptSource::caddy(), "arm64");
        assert_eq!(resources[0].diff(sys).unwrap(), None);
        let mut backups: Vec<Backup> = Vec::new();
        for (n, resource) in (1..).zip(&resources) {
            backups.push(resource.snapshot(sys, txn, n).unwrap());
            resource.apply(sys).unwrap();
        }
        for backup in backups.iter().rev() {
            restore(sys, txn, backup).unwrap();
        }
        assert!(!fs.exists(Path::new("/etc/apt/keyrings/caddy.asc")));
        assert!(!fs.exists(Path::new("/etc/apt/sources.list.d/caddy.sources")));
        assert!(fs.exists(Path::new(KEYRINGS)));
    }

    /// The primary key fingerprints `gpg --show-keys` reads from `key`;
    /// `None` when gpg is not installed, except in CI.
    fn gpg_fingerprints(key: &str) -> Option<Vec<String>> {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        let home = tempfile::tempdir().unwrap();
        let child = Command::new("gpg")
            .arg("--homedir")
            .arg(home.path())
            .args(["--batch", "--show-keys", "--with-colons"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let mut child = match child {
            Ok(child) => child,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                assert!(
                    std::env::var_os("CI").is_none(),
                    "gpg is needed in CI to check the embedded keys"
                );
                eprintln!("skipped: gpg is not installed");
                return None;
            }
            Err(e) => panic!("running gpg: {e}"),
        };
        child
            .stdin
            .take()
            .unwrap()
            .write_all(key.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "gpg failed: {out:?}");
        // Each `pub` record is followed by its `fpr` record, whose 10th
        // field is the fingerprint.
        let listing = String::from_utf8(out.stdout).unwrap();
        let mut lines = listing.lines();
        let mut fingerprints = Vec::new();
        while let Some(line) = lines.next() {
            if line.starts_with("pub:") {
                let fpr = lines.next().unwrap();
                assert!(fpr.starts_with("fpr:"), "{fpr}");
                fingerprints.push(fpr.split(':').nth(9).unwrap().to_owned());
            }
        }
        Some(fingerprints)
    }

    #[test]
    fn embedded_keys_match_their_fingerprints() {
        for (key, fingerprint) in [
            (DOCKER_KEY, DOCKER_FINGERPRINT),
            (CADDY_KEY, CADDY_FINGERPRINT),
        ] {
            let Some(found) = gpg_fingerprints(key) else {
                return;
            };
            // One primary key per file, so nothing else is trusted.
            assert_eq!(found, [fingerprint]);
        }
    }
}
