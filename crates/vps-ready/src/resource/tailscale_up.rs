//! The [`TailscaleUp`] resource.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{Backup, ResourceError, failed};
use crate::facts::network::{parse_tailscale, tailscale_status};
use crate::sys::{Cmd, FileKind, Output, Sys, SysError};

/// How long `tailscale up` waits for the node to come up (`--timeout`).
const UP_TIMEOUT: &str = "60s";

/// Kill timeout of `tailscale up` and `tailscale down`: longer than
/// [`UP_TIMEOUT`].
const COMMAND_TIMEOUT: Duration = Duration::from_secs(90);

/// The longest snapshot and apply may run: `tailscale status` in each, then
/// `tailscale up`.
pub(super) const TIMEOUT: Duration = Duration::from_secs(2 * 10 + 90);

/// This node up in a tailnet. With an auth key file, `tailscale up` reads
/// the key itself (`--auth-key=file:<path>`), so the key never passes
/// through vps-ready; without one, the node logs in with the node key it
/// has. Tailscale's DNS settings are not accepted, and Tailscale SSH stays
/// off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleUp {
    /// A root-only file holding the auth key, see [`check_key_file`];
    /// `None` for a node that has a node key.
    pub auth_key_file: Option<PathBuf>,
    /// Coordination server, e.g. Headscale's URL; Tailscale's when `None`.
    pub login_server: Option<String>,
    /// This node's name in the tailnet; the host name when `None`.
    pub hostname: Option<String>,
}

impl TailscaleUp {
    /// The summary of the change, or `None` when the node is `Running`.
    pub(super) fn diff(&self, sys: Sys) -> Result<Option<(String, Option<String>)>, ResourceError> {
        let summary = match &self.auth_key_file {
            Some(path) => format!(
                "log in to the tailnet with the auth key in {}",
                path.display()
            ),
            None => "bring the node up in the tailnet, with the login it has".to_owned(),
        };
        Ok((!running(sys)?).then_some((summary, None)))
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
        if let Some(path) = &self.auth_key_file {
            check_key_file(sys, path).map_err(|reason| ResourceError::Unsafe {
                path: path.clone(),
                reason,
            })?;
        }
        let out = sys.runner.run(&self.command())?;
        if out.ok() {
            return Ok(());
        }
        // Tailscale's own messages may quote the key.
        match failed("tailscale", &out) {
            ResourceError::Command {
                program,
                status,
                stderr,
            } => {
                let mut stderr = redact(&stderr);
                if self.auth_key_file.is_none() {
                    stderr.push_str(
                        "; the node's login may have expired or been removed: put a new auth \
                         key in auth_key_file and apply again",
                    );
                }
                Err(ResourceError::Command {
                    program,
                    status,
                    stderr,
                })
            }
            other => Err(other),
        }
    }

    /// `tailscale up`, with no `--ssh` and no routes or exit node.
    pub(crate) fn command(&self) -> Cmd {
        let mut cmd = Cmd::new("tailscale").arg("up");
        if let Some(path) = &self.auth_key_file {
            cmd = cmd.arg(format!("--auth-key=file:{}", path.display()));
        }
        cmd = cmd.arg("--accept-dns=false");
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

/// `text` with every `tskey-...` auth key cut to `tskey-…`.
fn redact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("tskey-") {
        out.push_str(&rest[..i]);
        out.push_str("tskey-…");
        let after = &rest[i + "tskey-".len()..];
        let end = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            .unwrap_or(after.len());
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

/// Why `path` cannot hold an auth key, if it cannot: it must be a regular
/// file owned by root with no group or other permissions, and it and every
/// parent directory must not be a symlink, and the directories must be
/// owned by root and not writable by group or others (unless sticky), so
/// nobody else can swap the file. Only metadata is read, never the content.
///
/// # Errors
///
/// What is wrong, for the message.
pub fn check_key_file(sys: Sys, path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("it is not an absolute path".to_owned());
    }
    // `Path::components` drops a `.` inside the path, so split the text.
    if path
        .to_str()
        .is_none_or(|s| s.split('/').any(|c| c == "." || c == ".."))
    {
        return Err("it has a `.` or `..` component".to_owned());
    }
    for dir in path.ancestors().skip(1) {
        let meta = sys
            .fs
            .metadata(dir)
            .map_err(|e| format!("cannot check {}: {e}", dir.display()))?;
        let shown = dir.display();
        if meta.kind != FileKind::Dir {
            return Err(format!("{shown} is a {:?}, not a directory", meta.kind));
        }
        if meta.uid != 0 {
            return Err(format!("{shown} is owned by uid {}, not root", meta.uid));
        }
        if meta.mode & 0o022 != 0 && meta.mode & 0o1000 == 0 {
            return Err(format!(
                "{shown} is writable by group or others (mode {:04o})",
                meta.mode
            ));
        }
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
/// key, and applying again would need a new auth key. Also from `Starting`
/// or `NeedsMachineAuth`, where the node would still join once approved. A
/// `Stopped` node, a daemon that does not answer, or a `tailscale` that is
/// gone needs nothing.
pub(super) fn restore(sys: Sys, was_running: bool) -> Result<(), ResourceError> {
    if was_running || backend_state(sys)?.is_none_or(|s| s == "Stopped") {
        return Ok(());
    }
    let out = sys.runner.run(&down())?;
    if out.ok() {
        return Ok(());
    }
    // `tailscale down` asks before cutting an SSH session that came in over
    // Tailscale, and without a terminal the answer is no. Its
    // `--accept-risk=lose-ssh` would cut the session doing the rollback.
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if said.contains("connected over Tailscale") || said.contains("aborted, no changes made") {
        return Err(ResourceError::Refused(
            "this session comes through Tailscale, and `tailscale down` would cut it; run \
             the rollback from another path (the provider's console or a public SSH login), \
             or run `sudo tailscale down` yourself, which cuts this session (Tailscale 1.82 \
             and older need `--accept-risk=lose-ssh`), and roll back again"
                .to_owned(),
        ));
    }
    Err(failed("tailscale", &out))
}

/// How to restore by hand; `None` if the node was `Running` before.
pub(crate) fn by_hand(was_running: bool) -> Option<String> {
    (!was_running).then(|| "tailscale down".to_owned())
}

fn down() -> Cmd {
    Cmd::new("tailscale").arg("down").timeout(COMMAND_TIMEOUT)
}

/// Whether `tailscale status` says `Running`.
fn running(sys: Sys) -> Result<bool, ResourceError> {
    Ok(backend_state(sys)?.is_some_and(|s| s == "Running"))
}

/// `BackendState` from `tailscale status`; `None` without `tailscale`, or
/// when its daemon does not answer.
fn backend_state(sys: Sys) -> Result<Option<String>, ResourceError> {
    let out: Output = match sys.runner.run(&tailscale_status()) {
        Ok(out) if out.ok() => out,
        Ok(_) | Err(SysError::NotFound(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let status = parse_tailscale(&out.stdout).map_err(|_| ResourceError::Unexpected {
        program: "tailscale".to_owned(),
        output: String::from_utf8_lossy(&out.stdout).into_owned(),
    })?;
    Ok(Some(status.backend_state))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::super::{Resource, restore as restore_backup};
    use super::*;
    use crate::sys::fake::{FakeFs, FakeRunner};
    use crate::sys::{FileOwner, Fs, Runner};

    const KEY: &str = "/root/tailscale-auth-key";
    const TXN: &str = "/var/lib/vps-ready/txn/20261119T120000Z";

    fn up() -> TailscaleUp {
        TailscaleUp {
            auth_key_file: Some(KEY.into()),
            login_server: None,
            hostname: None,
        }
    }

    fn status(state: &str) -> Output {
        Output::success(format!(
            r#"{{"BackendState":"{state}","Self":{{"TailscaleIPs":[]}}}}"#
        ))
    }

    fn fail(stdout: &str, stderr: &str) -> Output {
        Output {
            status: 1,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    const fn root(mode: u32) -> FileOwner {
        FileOwner {
            mode,
            uid: 0,
            gid: 0,
        }
    }

    fn key_fs(mode: u32, uid: u32) -> FakeFs {
        let fs = FakeFs::new()
            .with_dir("/", root(0o755))
            .with_dir("/root", root(0o700));
        fs.write_atomic(
            Path::new(KEY),
            b"tskey-auth-secret",
            FileOwner { mode, uid, gid: 0 },
        )
        .unwrap();
        fs
    }

    /// `tailscale` whose state `up` and `down` change; `down` answers
    /// with `down` and, when it fails, leaves the state.
    struct Tailscale {
        state: Mutex<String>,
        down: Output,
        calls: Mutex<Vec<String>>,
    }

    impl Tailscale {
        fn new(state: &str, down: Output) -> Self {
            Self {
                state: Mutex::new(state.into()),
                down,
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl Runner for Tailscale {
        fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
            let verb = cmd.args[0].clone();
            self.calls.lock().unwrap().push(verb.clone());
            let mut state = self.state.lock().unwrap();
            Ok(match verb.as_str() {
                "status" => status(&state),
                "up" => {
                    *state = "Running".into();
                    Output::success("")
                }
                "down" => {
                    if self.down.ok() {
                        *state = "Stopped".into();
                    }
                    self.down.clone()
                }
                other => panic!("tailscale {other}"),
            })
        }
    }

    #[test]
    fn command_reads_the_key_from_the_file() {
        let full = TailscaleUp {
            login_server: Some("https://headscale.example.com".into()),
            hostname: Some("web-1".into()),
            ..up()
        };
        let node_key = TailscaleUp {
            auth_key_file: None,
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
            (node_key, vec!["up", "--accept-dns=false", "--timeout=60s"]),
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
        let check = |fs: &FakeFs, path: &str| {
            check_key_file(
                Sys {
                    fs,
                    runner: &runner,
                },
                Path::new(path),
            )
        };
        assert_eq!(check(&key_fs(0o600, 0), KEY), Ok(()));
        assert_eq!(check(&key_fs(0o400, 0), KEY), Ok(()));
        let bare = || {
            FakeFs::new()
                .with_dir("/", root(0o755))
                .with_dir("/root", root(0o700))
        };
        let cases = [
            (
                key_fs(0o640, 0),
                "its mode 0640 lets other users read it; `chmod 600` it",
            ),
            (
                key_fs(0o604, 0),
                "its mode 0604 lets other users read it; `chmod 600` it",
            ),
            (key_fs(0o600, 1000), "it is owned by uid 1000, not root"),
            (bare(), "it does not exist"),
            (
                bare().with_symlink(KEY, "/root/real-key"),
                "it is a symlink",
            ),
            (bare().with_fifo(KEY), "it is not a regular file"),
        ];
        for (fs, why) in cases {
            assert_eq!(check(&fs, KEY), Err(why.to_owned()));
        }
        for path in ["tailscale-auth-key", "/root/./key", "/root/../root/key"] {
            assert!(check(&FakeFs::new(), path).is_err(), "{path}");
        }
    }

    #[test]
    fn key_file_parents_are_checked() {
        let runner = FakeRunner::new();
        let with_dir = |dir: &str, owner: FileOwner| {
            let fs = FakeFs::new()
                .with_dir("/", root(0o755))
                .with_dir(dir, owner);
            let path = Path::new(dir).join("key");
            fs.write_atomic(&path, b"k", root(0o600)).unwrap();
            (fs, path)
        };
        let check = |(fs, path): (FakeFs, PathBuf)| {
            check_key_file(
                Sys {
                    fs: &fs,
                    runner: &runner,
                },
                &path,
            )
        };
        assert_eq!(check(with_dir("/root", root(0o700))), Ok(()));
        // A sticky directory: nobody else can remove or rename the file.
        assert_eq!(check(with_dir("/tmp", root(0o1777))), Ok(()));
        assert_eq!(
            check(with_dir("/keys", root(0o777))),
            Err("/keys is writable by group or others (mode 0777)".to_owned())
        );
        assert_eq!(
            check(with_dir(
                "/home",
                FileOwner {
                    mode: 0o755,
                    uid: 1000,
                    gid: 1000
                }
            )),
            Err("/home is owned by uid 1000, not root".to_owned())
        );
        let fs = FakeFs::new()
            .with_dir("/", root(0o755))
            .with_dir("/real", root(0o700))
            .with_symlink("/keys", "/real");
        assert_eq!(
            check((fs, PathBuf::from("/keys/key"))),
            Err("/keys is a Symlink, not a directory".to_owned())
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
    fn a_failed_up_hides_the_key() {
        let fs = key_fs(0o600, 0);
        let runner = FakeRunner::new()
            .on("tailscale", ["status"], status("NeedsLogin"))
            .on(
                "tailscale",
                ["up"],
                fail(
                    "",
                    "backend error: invalid key: tskey-auth-kAB12_cd-EF34 not valid\n",
                ),
            );
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        let err = Resource::TailscaleUp(up()).apply(sys).unwrap_err();
        assert_eq!(
            err.to_string(),
            "`tailscale` exited with status 1: backend error: invalid key: tskey-… not valid"
        );
    }

    #[test]
    fn redacts_every_key() {
        assert_eq!(
            redact("a tskey-auth-x1_Y-2, tskey-client-z. tskey-"),
            "a tskey-…, tskey-…. tskey-…"
        );
        assert_eq!(redact("no key"), "no key");
    }

    #[test]
    fn rollback_runs_down_only_if_it_was_not_running() {
        let fs = key_fs(0o600, 0);
        for (state, downs) in [("NeedsLogin", 1), ("Running", 0)] {
            let runner = Tailscale::new(state, Output::success(""));
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
            let calls = runner.calls.lock().unwrap();
            let count = |verb: &str| calls.iter().filter(|c| *c == verb).count();
            assert_eq!((count("up"), count("down")), (downs, downs), "{state}");
            assert_eq!(by_hand(state == "Running").is_none(), downs == 0);
        }
    }

    /// A rollback that cannot run `tailscale down` finishes when there is
    /// nothing to bring down: the node is down already, `tailscaled` does
    /// not answer, or `tailscale` is gone.
    #[test]
    fn restore_needs_nothing_from_a_stopped_or_unreachable_node() {
        let fs = FakeFs::new();
        let backup = Backup::TailscaleUp { was_running: false };
        let stopped = Tailscale::new("Stopped", fail("", "should not run"));
        let no_daemon = FakeRunner::new().on(
            "tailscale",
            ["status"],
            fail("", "failed to connect to local tailscaled"),
        );
        let gone = FakeRunner::new();
        for runner in [&stopped as &dyn Runner, &no_daemon, &gone] {
            restore_backup(Sys { fs: &fs, runner }, Path::new(TXN), &backup).unwrap();
        }
        assert_eq!(*stopped.calls.lock().unwrap(), ["status"]);

        // A node awaiting approval, or still starting, would join later.
        for state in ["NeedsMachineAuth", "Starting", "NeedsLogin"] {
            let pending = Tailscale::new(state, Output::success(""));
            restore_backup(
                Sys {
                    fs: &fs,
                    runner: &pending,
                },
                Path::new(TXN),
                &backup,
            )
            .unwrap();
            assert_eq!(
                *pending.calls.lock().unwrap(),
                ["status", "down"],
                "{state}"
            );
        }
    }

    #[test]
    fn a_failed_keyless_up_says_to_use_a_new_key() {
        let fs = FakeFs::new();
        let runner = FakeRunner::new()
            .on("tailscale", ["status"], status("Stopped"))
            .on("tailscale", ["up"], fail("", "timeout waiting for Running"));
        let keyless = TailscaleUp {
            auth_key_file: None,
            ..up()
        };
        let err = Resource::TailscaleUp(keyless)
            .apply(Sys {
                fs: &fs,
                runner: &runner,
            })
            .unwrap_err();
        assert!(
            err.to_string().ends_with(
                "timeout waiting for Running; the node's login may have expired or been \
                 removed: put a new auth key in auth_key_file and apply again"
            ),
            "{err}"
        );
    }

    #[test]
    fn restore_refuses_to_cut_a_session_over_tailscale() {
        let fs = FakeFs::new();
        let backup = Backup::TailscaleUp { was_running: false };
        let runner = Tailscale::new(
            "Running",
            fail(
                "You are connected over Tailscale; this action will disable Tailscale and \
                 result in your session disconnecting.\nTo skip this warning, use \
                 --accept-risk=lose-ssh\n",
                "aborted, no changes made\n",
            ),
        );
        let err = restore_backup(
            Sys {
                fs: &fs,
                runner: &runner,
            },
            Path::new(TXN),
            &backup,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .starts_with("this session comes through Tailscale"),
            "{err}"
        );

        let runner = Tailscale::new("Running", fail("", "permission denied\n"));
        let err = restore_backup(
            Sys {
                fs: &fs,
                runner: &runner,
            },
            Path::new(TXN),
            &backup,
        )
        .unwrap_err();
        assert!(matches!(err, ResourceError::Command { .. }), "{err:?}");
    }
}
