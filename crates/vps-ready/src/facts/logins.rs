//! Who is logged in to this host, for `apply --deadman=off`.
//!
//! Without the timer nobody can confirm, so that is accepted only on
//! positive evidence that nobody could: no per-session sshd process in
//! `/proc` and no logind session of class `user`. A tmux, screen or mosh
//! session has no sshd ancestor, so the applying process's own session is
//! not enough.

use std::path::Path;

use super::session::is_session_title;
use crate::sys::{Cmd, Fs, Runner, SysError};

/// The logins on this host, e.g. `sshd: admin@pts/0` and `logind session 3
/// of admin`; empty when nobody is logged in.
///
/// # Errors
///
/// Why it could not tell: `/proc` or a process could not be read, or
/// `loginctl` did not answer.
pub fn detect(fs: &dyn Fs, runner: &dyn Runner) -> Result<Vec<String>, String> {
    let mut logins = sshd_sessions(fs)?;
    logins.extend(logind_sessions(runner)?);
    Ok(logins)
}

/// The titles of the per-session sshd processes.
fn sshd_sessions(fs: &dyn Fs) -> Result<Vec<String>, String> {
    let mut titles = Vec::new();
    let entries = fs.read_dir(Path::new("/proc")).map_err(|e| e.to_string())?;
    for path in entries {
        if !path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        let cmdline = match fs.read(&path.join("cmdline")) {
            Ok(bytes) => bytes,
            // It exited during the scan.
            Err(SysError::NotFound(_)) => continue,
            Err(e) => return Err(e.to_string()),
        };
        let title = String::from_utf8_lossy(cmdline.split(|&b| b == 0).next().unwrap_or_default());
        let title = title.trim_end();
        // A title is easy to fake, but a fake one only refuses.
        if is_session_title("sshd", title) || is_session_title("sshd-session", title) {
            titles.push(title.to_owned());
        }
    }
    Ok(titles)
}

/// The logind sessions of class `user` (also `user-early` and the other
/// `user-*` classes of newer systemd), as `logind session <id> of <name>`.
fn logind_sessions(runner: &dyn Runner) -> Result<Vec<String>, String> {
    let list = loginctl(runner, &["list-sessions", "--no-legend", "--no-pager"])?;
    let mut sessions = Vec::new();
    for id in list.lines().filter_map(|l| l.split_whitespace().next()) {
        let props = loginctl(runner, &["show-session", id, "-p", "Name", "-p", "Class"])?;
        let prop = |key: &str| {
            props
                .lines()
                .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
                .unwrap_or_default()
        };
        if prop("Class").starts_with("user") {
            sessions.push(format!("logind session {id} of {}", prop("Name")));
        }
    }
    Ok(sessions)
}

fn loginctl(runner: &dyn Runner, args: &[&str]) -> Result<String, String> {
    let command = format!("`loginctl {}`", args.join(" "));
    let out = runner
        .run(&Cmd::new("loginctl").args(args.iter().copied()))
        .map_err(|e| format!("{command}: {e}"))?;
    if !out.ok() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "{command} exited {}: {}",
            out.status,
            stderr.trim()
        ));
    }
    out.stdout_str()
        .map(str::to_owned)
        .map_err(|e| format!("{command}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::Output;
    use crate::sys::fake::{FakeFs, FakeRunner};

    /// `/proc` with these command lines, NUL-separated as the kernel writes
    /// them, and a file that is not a process.
    fn procs(cmdlines: &[(u32, &str)]) -> FakeFs {
        cmdlines.iter().fold(
            FakeFs::new().with_file("/proc/uptime", "1000.00 1.00\n"),
            |fs, (pid, cmdline)| fs.with_file(format!("/proc/{pid}/cmdline"), *cmdline),
        )
    }

    /// The processes of a host where someone is in tmux: the tmux server has
    /// no sshd ancestor.
    const TMUX: [(u32, &str); 4] = [
        (1, "/sbin/init\0"),
        (
            640,
            "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups\0",
        ),
        (900, "tmux\0new\0"),
        (901, "-bash\0"),
    ];

    fn no_logind() -> FakeRunner {
        FakeRunner::new().on("loginctl", ["list-sessions"], Output::success(""))
    }

    #[test]
    fn nobody_without_session_processes_or_user_sessions() {
        // A cron job's session is of class background.
        let runner = FakeRunner::new()
            .on(
                "loginctl",
                ["list-sessions"],
                Output::success("c1 0 root - -\n"),
            )
            .on(
                "loginctl",
                ["show-session", "c1"],
                Output::success("Name=root\nClass=background\n"),
            );
        assert_eq!(detect(&procs(&TMUX), &runner), Ok(Vec::new()));
    }

    #[test]
    fn finds_sshd_session_processes() {
        let mut procs_ = TMUX.to_vec();
        procs_.extend([
            (812, "sshd: admin@pts/0\0\0\0"),
            (813, "sshd-session: deploy@notty\0"),
            // Before authentication; not a login.
            (814, "sshd-session: root [priv]\0"),
        ]);
        assert_eq!(
            detect(&procs(&procs_), &no_logind()),
            Ok(vec![
                "sshd: admin@pts/0".to_owned(),
                "sshd-session: deploy@notty".to_owned()
            ])
        );
    }

    #[test]
    fn finds_logind_user_sessions() {
        // A console login: no sshd process.
        let runner = FakeRunner::new()
            .on(
                "loginctl",
                ["list-sessions"],
                Output::success("3 1000 admin seat0 tty1\n"),
            )
            .on(
                "loginctl",
                ["show-session", "3"],
                Output::success("Name=admin\nClass=user\n"),
            );
        assert_eq!(
            detect(&procs(&TMUX), &runner),
            Ok(vec!["logind session 3 of admin".to_owned()])
        );
    }

    #[test]
    fn without_loginctl_it_cannot_tell() {
        let err = detect(&procs(&TMUX), &FakeRunner::new()).unwrap_err();
        assert!(err.contains("loginctl list-sessions"), "{err}");
        let failed = FakeRunner::new().on(
            "loginctl",
            ["list-sessions"],
            Output {
                status: 1,
                stderr: b"Failed to connect to bus\n".to_vec(),
                ..Output::default()
            },
        );
        let err = detect(&procs(&TMUX), &failed).unwrap_err();
        assert!(err.ends_with("exited 1: Failed to connect to bus"), "{err}");
    }
}
