//! Session detection on a fake `/proc`, built from process trees seen on
//! real hosts.

use super::*;
use crate::sys::fake::FakeFs;

const CONNECTION: &str = "198.51.100.7 51234 203.0.113.10 22";
const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash\n";

/// One process: what `/proc/<pid>` shows.
#[derive(Clone, Copy)]
struct P {
    pid: u32,
    ppid: u32,
    name: &'static str,
    title: &'static str,
    /// Real and effective uid.
    uid: (u32, u32),
    start: u64,
    /// Whether `SSH_CONNECTION` is in its `environ`.
    ssh: bool,
}

const fn p(pid: u32, ppid: u32, name: &'static str, title: &'static str, uid: u32) -> P {
    P {
        pid,
        ppid,
        name,
        title,
        uid: (uid, uid),
        start: pid as u64 * 100,
        ssh: false,
    }
}

impl P {
    const fn ssh(mut self) -> Self {
        self.ssh = true;
        self
    }

    /// A setuid program such as `sudo`: effective uid 0.
    const fn setuid(mut self) -> Self {
        self.uid.1 = 0;
        self
    }
}

fn tree(procs: &[P]) -> FakeFs {
    procs
        .iter()
        .fold(FakeFs::new().with_file("/etc/passwd", PASSWD), |fs, p| {
            let (ruid, euid) = p.uid;
            let dir = format!("/proc/{}", p.pid);
            let mut environ = b"LANG=C.UTF-8\0".to_vec();
            if p.ssh {
                environ.extend(format!("SSH_CONNECTION={CONNECTION}\0").bytes());
            }
            let zeros = "0 ".repeat(17);
            fs.with_file(
                format!("{dir}/status"),
                format!(
                    "Name:\t{}\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t{pid}\nPid:\t{pid}\n\
                     PPid:\t{}\nUid:\t{ruid}\t{euid}\t{euid}\t{euid}\n",
                    p.name,
                    p.ppid,
                    pid = p.pid
                ),
            )
            .with_file(
                format!("{dir}/stat"),
                format!(
                    "{} ({}) S {} {zeros}{} 0 0\n",
                    p.pid, p.name, p.ppid, p.start
                ),
            )
            .with_file(format!("{dir}/cmdline"), format!("{}\0\0\0", p.title))
            .with_file(format!("{dir}/environ"), environ)
        })
}

const SYSTEMD: P = p(1, 0, "systemd", "/sbin/init", 0);

/// Debian 13 (OpenSSH 10.0): `[priv]` has PPID 1.
const DEBIAN_13: [P; 4] = [
    SYSTEMD,
    p(
        640,
        1,
        "sshd",
        "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups",
        0,
    ),
    p(811, 1, "sshd-session", "sshd-session: admin [priv]", 0),
    p(812, 811, "sshd-session", "sshd-session: admin@pts/0", 1000),
];

/// Ubuntu 24.04, Ubuntu 22.04 and Debian 12: `[priv]` under the listener.
const UBUNTU: [P; 4] = [
    SYSTEMD,
    p(
        640,
        1,
        "sshd",
        "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups",
        0,
    ),
    p(811, 640, "sshd", "sshd: admin [priv]", 0),
    p(812, 811, "sshd", "sshd: admin@pts/0", 1000),
];

/// A shell under `sshd`, then `sudo vps-ready` with a terminal: `use_pty`
/// adds a second `sudo`.
const SUDO_PTY: [P; 4] = [
    p(813, 812, "bash", "-bash", 1000).ssh(),
    p(900, 813, "sudo", "sudo vps-ready detect", 1000).setuid(),
    p(901, 900, "sudo", "sudo vps-ready detect", 1000).setuid(),
    p(902, 901, "vps-ready", "vps-ready detect", 0),
];

fn session(procs: &[&[P]], pid: u32) -> Result<Session, NoSession> {
    let all: Vec<P> = procs.iter().flat_map(|p| p.iter().copied()).collect();
    detect(&tree(&all), pid)
}

fn admin_session() -> Session {
    Session {
        id: SessionId {
            pid: 812,
            start: 81200,
        },
        client: "198.51.100.7:51234".parse().unwrap(),
        server: "203.0.113.10:22".parse().unwrap(),
        uid: 1000,
        user: Some("admin".to_owned()),
    }
}

#[test]
fn sudo_with_a_terminal() {
    assert_eq!(session(&[&DEBIAN_13, &SUDO_PTY], 902), Ok(admin_session()));
    assert_eq!(session(&[&UBUNTU, &SUDO_PTY], 902), Ok(admin_session()));
}

/// `ssh host sudo vps-ready`: no terminal, no shell left, one `sudo`. Its
/// effective uid is 0; the login user is its real uid.
#[test]
fn sudo_without_a_terminal() {
    for (name, title) in [
        ("sshd-session", "sshd-session: admin@notty"),
        ("sshd", "sshd: admin@notty"),
    ] {
        let procs = [
            SYSTEMD,
            p(812, 1, name, title, 1000),
            p(900, 812, "sudo", "sudo vps-ready detect", 1000)
                .setuid()
                .ssh(),
            p(901, 900, "vps-ready", "vps-ready detect", 0),
        ];
        assert_eq!(session(&[&procs], 901), Ok(admin_session()), "{title}");
    }
}

/// Nothing above the per-session process is read.
#[test]
fn does_not_need_the_listener_or_priv() {
    assert_eq!(
        session(&[&DEBIAN_13[3..], &SUDO_PTY], 902),
        Ok(admin_session())
    );
}

/// Without sudo, the process itself can be the child of `sshd`
/// (`ssh host vps-ready detect`).
#[test]
fn directly_under_sshd() {
    let procs = [p(902, 812, "vps-ready", "vps-ready detect", 1000).ssh()];
    assert_eq!(session(&[&DEBIAN_13, &procs], 902), Ok(admin_session()));
}

/// Channels shared through `ControlMaster` list several ttys in one title:
/// one session, so a confirm through it counts as the old one.
#[test]
fn control_master_is_one_session() {
    let mut debian = DEBIAN_13;
    debian[3].title = "sshd-session: admin@pts/0,pts/1";
    assert_eq!(session(&[&debian, &SUDO_PTY], 902), Ok(admin_session()));
}

#[test]
fn no_sshd_ancestor() {
    let shell = |ppid| {
        [
            p(813, ppid, "bash", "-bash", 1000).ssh(),
            p(900, 813, "sudo", "sudo vps-ready detect", 1000).setuid(),
            p(901, 900, "vps-ready", "vps-ready detect", 0),
        ]
    };
    // The tmux server forks away from the client, which ran under sshd.
    let tmux = [p(700, 1, "tmux: server", "tmux new -s main", 1000)];
    let mosh = [p(700, 1, "mosh-server", "mosh-server new -s", 1000)];
    let screen = [p(700, 1, "screen", "SCREEN", 1000)];
    let console = [p(700, 1, "login", "/bin/login -p --", 0)];
    for parent in [&tmux, &mosh, &screen, &console] {
        assert_eq!(
            session(&[&DEBIAN_13, parent, &shell(700)], 901),
            Err(NoSession::NotSsh),
            "{}",
            parent[0].name
        );
    }
}

/// The nearest sshd process must be a login session, not `[priv]` or the
/// listener.
#[test]
fn refuses_other_sshd_processes() {
    for parent in [811, 640] {
        let procs = [
            p(813, parent, "bash", "-bash", 1000).ssh(),
            p(902, 813, "vps-ready", "vps-ready detect", 1000),
        ];
        let err = session(&[&UBUNTU, &procs], 902).unwrap_err();
        assert!(
            matches!(&err, NoSession::Unknown(r) if r.contains("not a login session")),
            "{err}"
        );
    }
    for title in [
        "sshd: admin@",
        "sshd: @pts/0",
        "sshd: admin@pts/",
        "sshd: admin@tty1",
        "sshd-session: admin@pts/0",
        "sshd: admin@pts/0 extra",
    ] {
        assert!(!is_session_title("sshd", title), "{title}");
    }
}

#[test]
fn unreadable_trees_are_unknown() {
    let unknown = |procs: &[P], pid| match detect(&tree(procs), pid) {
        Err(NoSession::Unknown(reason)) => reason,
        other => panic!("{other:?}"),
    };
    // No `/proc` at all.
    assert!(unknown(&[], 902).contains("/proc/902/status"));
    // The shell has no SSH_CONNECTION.
    let mut procs = SUDO_PTY;
    procs[0].ssh = false;
    let all: Vec<P> = DEBIAN_13.iter().chain(&procs).copied().collect();
    assert!(unknown(&all, 902).contains("no SSH_CONNECTION in /proc/813/environ"));
    // A loop in the PPids ends at the depth limit.
    let looped = [p(5, 6, "a", "a", 0), p(6, 5, "b", "b", 0)];
    assert!(unknown(&looped, 5).contains("within 64 parents"));
}

#[test]
fn user_not_in_passwd() {
    let mut procs = SUDO_PTY;
    procs[0].uid = (1001, 1001);
    procs[1].uid = (1001, 0);
    let s = session(&[&DEBIAN_13, &procs], 902).unwrap();
    assert_eq!((s.uid, s.user), (1001, None));
}

#[test]
fn start_time_counts_from_the_last_parenthesis() {
    let zeros = "0 ".repeat(17);
    assert_eq!(
        start_time(&format!("7 (a) b) S 1 {zeros}4242 0")),
        Some(4242)
    );
    assert_eq!(start_time("7 (sshd) S 1"), None);
    assert_eq!(start_time(""), None);
}

/// A new session is a different sshd process that started after the change
/// went live.
#[test]
fn new_session_rule() {
    let applied = SessionId {
        pid: 812,
        start: 10_433,
    };
    let at = |pid, start| Session {
        id: SessionId { pid, start },
        ..admin_session()
    };
    // live_since is 1275 s after boot.
    assert!(at(951, 127_600).is_new(Some(applied), 1275));
    // The applying session itself.
    assert!(!at(812, 10_433).is_new(Some(applied), 1275));
    // PID reuse: the same PID with a later start is another process.
    assert!(at(812, 127_600).is_new(Some(applied), 1275));
    // Opened before the change went live, or within that same second.
    assert!(!at(951, 12_000).is_new(Some(applied), 1275));
    assert!(!at(951, 127_550).is_new(Some(applied), 1275));
    // No session recorded at apply: any session after live_since.
    assert!(at(812, 127_600).is_new(None, 1275));
    assert!(!at(812, 10_433).is_new(None, 1275));
}

#[test]
fn parses_ssh_connection() {
    let (client, server) = parse_connection("198.51.100.7 51234 203.0.113.10 22").unwrap();
    assert_eq!(client.to_string(), "198.51.100.7:51234");
    assert_eq!(server.port(), 22);

    let (client, server) = parse_connection("2001:db8::7 51234 fe80::1%eth0 2222").unwrap();
    assert_eq!(client.to_string(), "[2001:db8::7]:51234");
    assert_eq!(server.port(), 2222);

    for bad in [
        "",
        "192.0.2.1 1 192.0.2.2",
        "192.0.2.1 x 192.0.2.2 22",
        "a b c d",
        "192.0.2.1 1 192.0.2.2 22 extra",
        // Lima's vsock shell.
        "UNKNOWN 65535 UNKNOWN 65535",
    ] {
        assert_eq!(parse_connection(bad), None, "{bad:?}");
    }
}

proptest::proptest! {
    #[test]
    fn parsers_never_panic(s in "\\PC*") {
        let _ = parse_connection(&s);
        let _ = start_time(&s);
        let _ = is_session_title("sshd", &s);
    }
}
