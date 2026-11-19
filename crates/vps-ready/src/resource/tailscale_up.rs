//! The [`TailscaleUp`] resource.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{Backup, ResourceError, run};
use crate::facts::network::{parse_tailscale, tailscale_status};
use crate::sys::{Cmd, FileKind, Sys, SysError};

/// How long `tailscale up` waits for the node to come up (`--timeout`).
const UP_TIMEOUT: &str = "60s";

/// Kill timeout of `tailscale up` and `tailscale down`: longer than
/// [`UP_TIMEOUT`].
const COMMAND_TIMEOUT: Duration = Duration::from_secs(90);

/// The longest snapshot and apply may run: `tailscale status`, then
/// `tailscale up`.
pub(super) const TIMEOUT: Duration = Duration::from_secs(10 + 90);

/// This node logged in to a tailnet with an auth key that `tailscale up`
/// reads from a file itself (`--auth-key=file:<path>`), so the key never
/// passes through vps-ready. Tailscale's DNS settings are not accepted, and
/// Tailscale SSH stays off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleUp {
    /// A root-only file holding the auth key; see [`check_key_file`].
    pub auth_key_file: PathBuf,
    /// Coordination server, e.g. Headscale's URL; Tailscale's when `None`.
    pub login_server: Option<String>,
    /// This node's name in the tailnet; the host name when `None`.
    pub hostname: Option<String>,
}

impl TailscaleUp {
    /// The summary of the change, or `None` when the node is `Running`.
    pub(super) fn diff(&self, sys: Sys) -> Result<Option<(String, Option<String>)>, ResourceError> {
        Ok((!running(sys)?).then(|| {
            (
                format!(
                    "log in to the tailnet with the auth key in {}",
                    self.auth_key_file.display()
                ),
                None,
            )
        }))
    }

    pub(super) fn snapshot(&self, sys: Sys) -> Result<Backup, ResourceError> {
        Ok(Backup::TailscaleUp {
            was_running: running(sys)?,
        })
    }

    /// Checks the key file again, since it may have changed since the plan.
    pub(super) fn apply(&self, sys: Sys) -> Result<(), ResourceError> {
        if running(sys)? {
            return Ok(());
        }
        check_key_file(sys, &self.auth_key_file).map_err(|reason| ResourceError::Unsafe {
            path: self.auth_key_file.clone(),
            reason,
        })?;
        run(sys, &self.command())?;
        Ok(())
    }

    /// `tailscale up`, with no `--ssh` and no routes or exit node.
    pub(crate) fn command(&self) -> Cmd {
        let mut cmd = Cmd::new("tailscale")
            .arg("up")
            .arg(format!("--auth-key=file:{}", self.auth_key_file.display()))
            .arg("--accept-dns=false");
        if let Some(url) = &self.login_server {
            cmd = cmd.arg(format!("--login-server={url}"));
        }
        if let Some(name) = &self.hostname {
            cmd = cmd.arg(format!("--hostname={name}"));
        }
        cmd.arg(format!("--timeout={UP_TIMEOUT}"))
            .timeout(COMMAND_TIMEOUT)
    }
}

/// Why `path` cannot hold an auth key, if it cannot: it must be a regular
/// file, not a symlink, owned by root, with no group or other permissions.
/// Only its metadata is read, never its content.
///
/// # Errors
///
/// What is wrong, for the message.
pub fn check_key_file(sys: Sys, path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("it is not an absolute path".to_owned());
    }
    let meta = match sys.fs.metadata(path) {
        Ok(meta) => meta,
        Err(SysError::NotFound(_)) => return Err("it does not exist".to_owned()),
        Err(e) => return Err(e.to_string()),
    };
    match meta.kind {
        FileKind::File => {}
        FileKind::Symlink => return Err("it is a symlink".to_owned()),
        _ => return Err("it is not a regular file".to_owned()),
    }
    if meta.uid != 0 {
        return Err(format!("it is owned by uid {}, not root", meta.uid));
    }
    if meta.mode & 0o077 != 0 {
        return Err(format!(
            "its mode {:04o} lets other users read it; `chmod 600` it",
            meta.mode
        ));
    }
    Ok(())
}

/// `tailscale down` if the node was not `Running` before apply. It
/// disconnects but keeps the login, never `logout`: that expires the node
/// key, and applying again would need a new auth key.
pub(super) fn restore(sys: Sys, was_running: bool) -> Result<(), ResourceError> {
    if was_running {
        return Ok(());
    }
    run(sys, &down())?;
    Ok(())
}

/// How to restore by hand; `None` if the node was `Running` before.
pub(crate) fn by_hand(was_running: bool) -> Option<String> {
    (!was_running).then(|| "tailscale down".to_owned())
}

fn down() -> Cmd {
    Cmd::new("tailscale").arg("down").timeout(COMMAND_TIMEOUT)
}

/// Whether `tailscale status` says `Running`. Without `tailscale`, or when
/// its daemon does not answer, the node is not.
fn running(sys: Sys) -> Result<bool, ResourceError> {
    let out = match sys.runner.run(&tailscale_status()) {
        Ok(out) if out.ok() => out,
        Ok(_) | Err(SysError::NotFound(_)) => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let status = parse_tailscale(&out.stdout).map_err(|_| ResourceError::Unexpected {
        program: "tailscale".to_owned(),
        output: String::from_utf8_lossy(&out.stdout).into_owned(),
    })?;
    Ok(status.backend_state == "Running")
}

#[cfg(test)]
mod tests {
    use super::super::{Resource, restore as restore_backup};
    use super::*;
    use crate::sys::fake::{FakeFs, FakeRunner};
    use crate::sys::{FileOwner, Fs, Output};

    const KEY: &str = "/root/tailscale-auth-key";
    const TXN: &str = "/var/lib/vps-ready/txn/20261119T120000Z";

    fn up() -> TailscaleUp {
        TailscaleUp {
            auth_key_file: KEY.into(),
            login_server: None,
            hostname: None,
        }
    }

    fn status(state: &str) -> Output {
        Output::success(format!(
            r#"{{"BackendState":"{state}","Self":{{"TailscaleIPs":[]}}}}"#
        ))
    }

    fn key_fs(mode: u32, uid: u32) -> FakeFs {
        let fs = FakeFs::new().with_dir(
            "/root",
            FileOwner {
                mode: 0o700,
                uid: 0,
                gid: 0,
            },
        );
        fs.write_atomic(
            Path::new(KEY),
            b"tskey-auth-secret",
            FileOwner { mode, uid, gid: 0 },
        )
        .unwrap();
        fs
    }

    #[test]
    fn command_reads_the_key_from_the_file() {
        let full = TailscaleUp {
            login_server: Some("https://headscale.example.com".into()),
            hostname: Some("web-1".into()),
            ..up()
        };
        for (r, argv) in [
            (
                up(),
                vec![
                    "up",
                    "--auth-key=file:/root/tailscale-auth-key",
                    "--accept-dns=false",
                    "--timeout=60s",
                ],
            ),
            (
                full,
                vec![
                    "up",
                    "--auth-key=file:/root/tailscale-auth-key",
                    "--accept-dns=false",
                    "--login-server=https://headscale.example.com",
                    "--hostname=web-1",
                    "--timeout=60s",
                ],
            ),
        ] {
            let cmd = r.command();
            assert_eq!(cmd.program, "tailscale");
            assert_eq!(cmd.args, argv);
            assert!(cmd.env.is_empty());
            assert!(!cmd.args.iter().any(|a| a.contains("tskey") || a == "--ssh"));
        }
    }

    #[test]
    fn key_file_checks() {
        let runner = FakeRunner::new();
        let sys = |fs: &FakeFs| {
            check_key_file(
                Sys {
                    fs,
                    runner: &runner,
                },
                Path::new(KEY),
            )
        };
        assert_eq!(sys(&key_fs(0o600, 0)), Ok(()));
        assert_eq!(sys(&key_fs(0o400, 0)), Ok(()));
        for (fs, why) in [
            (
                key_fs(0o640, 0),
                "its mode 0640 lets other users read it; `chmod 600` it",
            ),
            (
                key_fs(0o604, 0),
                "its mode 0604 lets other users read it; `chmod 600` it",
            ),
            (key_fs(0o600, 1000), "it is owned by uid 1000, not root"),
            (FakeFs::new(), "it does not exist"),
            (
                FakeFs::new().with_symlink(KEY, "/root/real-key"),
                "it is a symlink",
            ),
            (FakeFs::new().with_fifo(KEY), "it is not a regular file"),
        ] {
            assert_eq!(sys(&fs), Err(why.to_owned()));
        }
        let fs = FakeFs::new();
        assert_eq!(
            check_key_file(
                Sys {
                    fs: &fs,
                    runner: &runner
                },
                Path::new("tailscale-auth-key")
            ),
            Err("it is not an absolute path".to_owned())
        );
    }

    #[test]
    fn diff_joins_unless_running() {
        let fs = key_fs(0o600, 0);
        let resource = Resource::TailscaleUp(up());
        for (runner, change) in [
            (FakeRunner::new(), true),
            (
                FakeRunner::new().on("tailscale", ["status"], status("NeedsLogin")),
                true,
            ),
            (
                FakeRunner::new().on("tailscale", ["status"], status("Stopped")),
                true,
            ),
            (
                FakeRunner::new().on("tailscale", ["status"], status("Running")),
                false,
            ),
        ] {
            let sys = Sys {
                fs: &fs,
                runner: &runner,
            };
            let diff = resource.diff(sys).unwrap();
            assert_eq!(diff.is_some(), change, "{diff:?}");
            if let Some(diff) = diff {
                assert_eq!(
                    diff.summary,
                    "log in to the tailnet with the auth key in /root/tailscale-auth-key"
                );
            }
        }
    }

    #[test]
    fn apply_refuses_a_key_file_that_became_unsafe() {
        let fs = key_fs(0o644, 0);
        let runner = FakeRunner::new()
            .on("tailscale", ["status"], status("NeedsLogin"))
            .on("tailscale", ["up"], Output::success(""));
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let err = Resource::TailscaleUp(up()).apply(sys).unwrap_err();
        assert!(matches!(err, ResourceError::Unsafe { .. }), "{err:?}");
        assert!(
            !runner
                .calls()
                .iter()
                .any(|c| c.args.first().is_some_and(|a| a == "up"))
        );
    }

    #[test]
    fn rollback_runs_down_only_if_it_was_not_running() {
        let fs = key_fs(0o600, 0);
        for (state, downs) in [("NeedsLogin", 1), ("Running", 0)] {
            let runner = FakeRunner::new()
                .on("tailscale", ["status"], status(state))
                .on("tailscale", ["up"], Output::success(""))
                .on("tailscale", ["down"], Output::success(""));
            let sys = Sys {
                fs: &fs,
                runner: &runner,
            };
            let resource = Resource::TailscaleUp(up());
            let backup = resource.snapshot(sys, Path::new(TXN), 1).unwrap();
            assert_eq!(
                backup,
                Backup::TailscaleUp {
                    was_running: state == "Running"
                }
            );
            resource.apply(sys).unwrap();
            restore_backup(sys, Path::new(TXN), &backup).unwrap();
            let calls = runner.calls();
            let count = |verb: &str| {
                calls
                    .iter()
                    .filter(|c| c.args.first().is_some_and(|a| a == verb))
                    .count()
            };
            assert_eq!((count("up"), count("down")), (downs, downs), "{state}");
            assert_eq!(by_hand(state == "Running").is_none(), downs == 0);
        }
    }
}
