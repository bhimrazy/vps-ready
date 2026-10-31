//! The wizard on a [`FakeFs`] VM, answered by a [`Script`]: each scenario
//! is a transcript snapshot, and its answers saved and parsed again give
//! the same plan.

use std::io::{BufReader, Cursor, Read};

use super::*;
use crate::cli::change::exit_code;
use crate::cli::change::tests::{BINARY, STATE, container, fixture, host, vm};
use crate::config::Profile;
use crate::engine::{Event, Record};
use crate::facts::{Listener, Session, SessionId};
use crate::sys::fake::{FakeFs, FakeRunner};
use crate::sys::{Fs, Output, Sys};
use crate::tui::script::{Answer, Script, Transcript};

use Answer::{Check, CtrlC, Enter, Pick, Say, Type};

const CWD: &str = "/root";
const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGlaptop me@laptop";

/// [`fixture`] with this binary, `/etc/shells` and the current directory.
fn fs() -> FakeFs {
    let fs = fixture()
        .with_file(BINARY, "\x7fELF")
        .with_file("/etc/shells", "/bin/sh\n/bin/bash\n");
    fs.create_dir_all(Path::new(CWD), 0o700).unwrap();
    fs
}

/// `rules` first, then the answers of [`host`]'s runner: root and no other
/// account or group.
fn runner(rules: impl FnOnce(FakeRunner) -> FakeRunner) -> FakeRunner {
    let missing = Output {
        status: 2,
        ..Output::default()
    };
    rules(FakeRunner::new())
        .on("dpkg-query", ["-W"], Output::success("installed"))
        .on("apt-config", ["-c"], Output::success(""))
        .on(
            "getent",
            ["passwd", "root"],
            Output::success("root:x:0:0:root:/root:/bin/bash\n"),
        )
        .on("getent", Vec::<String>::new(), missing)
        .on(
            "systemctl",
            ["show"],
            Output::success("LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n"),
        )
}

fn on<'a>(fs: &'a FakeFs, runner: &'a FakeRunner) -> Host<'a> {
    Host {
        sys: Sys { fs, runner },
        ..host(fs)
    }
}

fn listener(proto: Proto, addr: &str, port: u16, process: &str) -> Listener {
    Listener {
        proto,
        addr: addr.to_owned(),
        port,
        processes: vec![process.to_owned()],
    }
}

/// Copies what is read to the transcript, as a terminal echoes it.
struct Echo(Cursor<Vec<u8>>, Transcript);

impl Read for Echo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.0.read(buf)?;
        self.1.write_all(&buf[..n])?;
        Ok(n)
    }
}

/// Runs the wizard with `answers`, then `typed` for apply's question.
/// Returns the exit code and the transcript, with an error printed as
/// `main` does and the version as `<version>`.
fn wizard(host: &Host, answers: Vec<Answer>, typed: &str) -> (u8, String) {
    let log = Transcript::default();
    let mut script = Script::new(answers, &log);
    let (mut out, mut err) = (log.clone(), log.clone());
    let stdin = || BufReader::new(Echo(Cursor::new(typed.as_bytes().to_vec()), log.clone()));
    let code = match run(host, &mut script, Path::new(CWD), stdin, &mut out, &mut err) {
        Ok(code) => code,
        Err(e) => {
            writeln!(out, "error: {e:#}").unwrap();
            exit_code(&e)
        }
    };
    assert!(script.done(), "answers left:\n{}", log.text());
    let text = log.text().replace(VERSION_INFO.version, "<version>");
    (code, text)
}

/// The profile `questions` build. Saved and parsed again, it is the same
/// profile and gives the same plan.
fn round_trip(host: &Host, questions: Vec<Answer>) -> ProfileBuilder {
    let facts = (host.facts)(host.sys).unwrap();
    let log = Transcript::default();
    let mut script = Script::new(questions, &log);
    let builder = ask(host, &facts, &mut script, &mut log.clone()).unwrap();
    assert!(script.done());
    let built = builder.build(host.modules).unwrap();
    let parsed = Profile::parse(&builder.to_toml(), host.modules).unwrap();
    assert_eq!(parsed, built);
    let plan = |profile| {
        let mut json = Vec::new();
        change::plan_profile(host, Some(profile), &Selection::default(), true, &mut json).unwrap();
        String::from_utf8(json).unwrap()
    };
    assert_eq!(plan(parsed), plan(built));
    builder
}

/// Runs `questions`, `n` at apply's question, then `after`; snapshots the
/// transcript as `name` and checks the round trip. Returns the transcript.
fn scenario(name: &str, host: &Host, questions: Vec<Answer>, after: Vec<Answer>) -> String {
    let answers = questions.iter().cloned().chain(after).collect();
    let (code, text) = wizard(host, answers, "n\n");
    assert_eq!(code, 0, "{text}");
    insta::assert_snapshot!(name, text);
    round_trip(host, questions);
    text
}

fn saved(fs: &FakeFs) -> String {
    String::from_utf8(fs.read(&Path::new(CWD).join(SAVE_AS)).unwrap()).unwrap()
}

/// The registry indexes of `ids`, for the module list.
fn modules(host: &Host, ids: &[&str]) -> Answer {
    Check(
        (0..host.modules.len())
            .filter(|&i| ids.contains(&host.modules[i].id()))
            .collect(),
    )
}

#[test]
fn a_docker_host_gets_web_without_its_published_ports() {
    let fs = fs();
    let runner = runner(|r| r);
    let host = Host {
        facts: |sys| {
            let mut facts = vm(sys)?;
            facts.docker = true;
            facts
                .listeners
                .push(listener(Proto::Tcp, "0.0.0.0", 3000, "docker-proxy"));
            Ok(facts)
        },
        ..on(&fs, &runner)
    };
    let text = scenario(
        "docker",
        &host,
        vec![Enter, Enter, Enter, Enter, Enter],
        vec![],
    );
    assert!(
        text.contains("(recommended: Docker is installed)"),
        "{text}"
    );
    assert!(!text.contains("3000"), "{text}");
    assert!(
        text.ends_with("Next time, without questions:\n  sudo vps-ready apply --profile web\n"),
        "{text}"
    );
}

#[test]
fn a_host_with_nothing_listening_gets_minimal() {
    let fs = fs();
    let runner = runner(|r| r);
    let host = on(&fs, &runner);
    let text = scenario(
        "nothing-listening",
        &host,
        vec![Enter, Enter, Enter, Enter],
        vec![],
    );
    assert!(text.contains("SSH only (recommended: "), "{text}");
    assert!(text.ends_with("apply --profile minimal\n"), "{text}");
}

/// The SSH login the wizard runs in, as alice.
fn alice() -> Session {
    Session {
        id: SessionId {
            pid: 812,
            start: 90_000,
        },
        client: "198.51.100.7:50022".parse().unwrap(),
        server: "10.0.2.15:22".parse().unwrap(),
        uid: 1000,
        user: Some("alice".into()),
    }
}

#[test]
fn the_session_user_is_the_default_admin() {
    let alice_owns = |mode| FileOwner {
        mode,
        uid: 1000,
        gid: 1000,
    };
    let fs = fs()
        .with_dir("/home/alice", alice_owns(0o755))
        .with_dir("/home/alice/.ssh", alice_owns(0o700));
    let keys = Path::new("/home/alice/.ssh/authorized_keys");
    fs.write_atomic(keys, format!("{KEY}\n").as_bytes(), alice_owns(0o600))
        .unwrap();
    let runner = runner(|r| {
        r.on(
            "getent",
            ["passwd", "alice"],
            Output::success("alice:x:1000:1000::/home/alice:/bin/bash\n"),
        )
        .on(
            "sudo",
            ["-n", "-l", "-U", "alice"],
            Output::success("User alice is not allowed to run sudo on vm.\n"),
        )
        .on("id", ["-Gn", "alice"], Output::success("alice\n"))
    });
    let host = Host {
        facts: |sys| {
            let mut facts = vm(sys)?;
            facts.session = Some(alice());
            Ok(facts)
        },
        ..on(&fs, &runner)
    };
    let text = scenario(
        "session-user",
        &host,
        vec![Enter, Enter, Enter, Enter],
        vec![Enter],
    );
    assert!(
        text.contains(
            "  existing account (the one you logged in as): gets sudo and 1 key from \
             /home/alice/.ssh/authorized_keys\n"
        ),
        "{text}"
    );
    // alice has the key: only the sudo rule is new.
    assert!(!text.contains("create user"), "{text}");
    assert!(!text.contains(".ssh/authorized_keys (mode"), "{text}");
    assert!(
        text.contains("+alice ALL=(ALL:ALL) NOPASSWD: ALL"),
        "{text}"
    );
    assert_eq!(
        saved(&fs),
        "schema = 1\nextends = \"minimal\"\n\n[modules.\"user.admin\"]\nname = \"alice\"\n"
    );
    assert!(
        text.ends_with("apply --profile /root/vps-ready.toml\n"),
        "{text}"
    );
}

#[test]
fn an_existing_admin_account_is_named() {
    let home = FileOwner {
        mode: 0o755,
        uid: 1001,
        gid: 1001,
    };
    let fs = fs().with_dir("/home/admin", home);
    let runner = runner(|r| {
        r.on(
            "getent",
            ["passwd", "admin"],
            Output::success("admin:x:1001:1001::/home/admin:/bin/bash\n"),
        )
        .on(
            "sudo",
            ["-n", "-l", "-U", "admin"],
            Output::success("User admin is not allowed to run sudo on vm.\n"),
        )
        .on("id", ["-Gn", "admin"], Output::success("admin\n"))
    });
    let host = on(&fs, &runner);
    let text = scenario(
        "existing-admin",
        &host,
        vec![Enter, Enter, Enter, Enter],
        vec![],
    );
    assert!(
        text.contains("  existing account: gets sudo and 1 key from /root/.ssh/authorized_keys\n"),
        "{text}"
    );
}

#[test]
fn a_group_without_a_user_is_refused_and_asked_again() {
    let fs = fs();
    let runner = runner(|r| {
        r.on(
            "getent",
            ["group", "admin"],
            Output::success("admin:x:118:\n"),
        )
    });
    let host = on(&fs, &runner);
    let text = scenario(
        "group-admin",
        &host,
        vec![Enter, Enter, Type("deploy".into()), Enter, Enter],
        vec![Say(false)],
    );
    assert!(
        text.contains("  a group named admin exists, but no user"),
        "{text}"
    );
    assert!(text.contains("  created, with 1 key from /root/.ssh/authorized_keys\n"));
    assert!(text.contains("Not saved."), "{text}");
    assert!(!fs.exists(&Path::new(CWD).join(SAVE_AS)));
}

#[test]
fn without_a_key_to_copy_one_is_pasted() {
    let fs = fs();
    fs.remove(Path::new("/root/.ssh/authorized_keys")).unwrap();
    let runner = runner(|r| r);
    let host = on(&fs, &runner);
    let text = scenario(
        "paste-key",
        &host,
        vec![
            Enter,
            Enter,
            Type("my key".into()),
            Type(format!("  {KEY}  ")),
            Enter,
            Enter,
        ],
        vec![Enter],
    );
    assert!(text.contains("  created, with the public key you paste next\n"));
    assert!(text.contains("  That is not a public key"), "{text}");
    assert!(text.contains(&format!("+{KEY}\n")), "{text}");
    assert!(saved(&fs).contains(&format!("authorized_keys = [\"{KEY}\"]")));
}

#[test]
fn public_listeners_are_offered_unchecked_and_ports_can_be_typed() {
    let fs = fs();
    let runner = runner(|r| r);
    let host = Host {
        facts: |sys| {
            let mut facts = vm(sys)?;
            facts.listeners.extend([
                listener(Proto::Tcp, "0.0.0.0", 80, "nginx"),
                listener(Proto::Tcp, "0.0.0.0", 5432, "postgres"),
                listener(Proto::Tcp, "::", 5432, "postgres"),
                listener(Proto::Tcp, "127.0.0.1", 6379, "redis-server"),
                listener(Proto::Tcp, "::1", 6379, "redis-server"),
                listener(Proto::Tcp, "::ffff:127.0.0.1", 7000, "app"),
                listener(Proto::Udp, "127.0.0.53%lo", 53, "systemd-resolve"),
                listener(Proto::Tcp, "fe80::1%eth0", 9090, "cockpit"),
                listener(Proto::Tcp, "*", 2049, "systemd"),
            ]);
            Ok(facts)
        },
        ..on(&fs, &runner)
    };
    let text = scenario(
        "listeners",
        &host,
        vec![
            Enter,
            Enter,
            Enter,
            Type("8080".into()),
            Type("8080/tcp, 51820/udp".into()),
            Enter,
        ],
        vec![Enter],
    );
    assert!(text.contains("(recommended: something listens on port 80)"));
    assert!(text.contains("  [ ] 5432/tcp (postgres)\n"), "{text}");
    assert!(text.contains("  [ ] 9090/tcp (cockpit)\n"), "{text}");
    assert!(text.contains("  [ ] 2049/tcp (systemd)\n"), "{text}");
    for hidden in ["6379", "7000", "53/udp", "80/tcp (nginx)"] {
        assert!(!text.contains(hidden), "{hidden}: {text}");
    }
    assert!(text.contains("  \"8080\" is not `<port>/tcp` or `<port>/udp`\n"));
    assert!(saved(&fs).contains(
        "allow = [\"22/tcp\", \"80/tcp\", \"443/tcp\", \"443/udp\", \"8080/tcp\", \"51820/udp\"]"
    ));
}

#[test]
fn a_customized_module_list_is_saved() {
    let fs = fs().with_file(Path::new(CWD).join(SAVE_AS), "old\n");
    let runner = runner(|r| r);
    let host = on(&fs, &runner);
    let all = [
        "user.admin",
        "ssh.server",
        "firewall.inbound",
        "kernel.sysctl",
    ];
    let questions = vec![
        Enter,
        Enter,
        Enter,
        Say(true),
        // ssh.server without user.admin: refused, asked again.
        modules(&host, &all[1..]),
        modules(&host, &[&all[..], &["ssh.bruteforce"]].concat()),
    ];
    let text = scenario("customized", &host, questions, vec![Enter, Say(true)]);
    assert!(
        text.contains("  ssh.server: refusing to turn off"),
        "{text}"
    );
    assert!(text.contains("updates.auto: Install security updates"));
    assert_eq!(
        saved(&fs),
        "schema = 1\nextends = \"minimal\"\n\n\
         [modules.\"ssh.bruteforce\"]\n\n\
         [modules.\"updates.auto\"]\nenabled = false\n"
    );
    assert!(
        text.ends_with(
            "Saved /root/vps-ready.toml.\n\nNext time, without questions:\n  \
             sudo vps-ready apply --profile /root/vps-ready.toml\n"
        ),
        "{text}"
    );
}

#[test]
fn an_existing_file_is_kept_unless_replaced() {
    let fs = fs().with_file(Path::new(CWD).join(SAVE_AS), "old\n");
    let runner = runner(|r| r);
    let host = on(&fs, &runner);
    let answers = vec![Enter, Type("deploy".into()), Enter, Enter, Enter, Enter];
    let (code, text) = wizard(&host, answers, "n\n");
    assert_eq!(code, 0);
    assert!(text.contains("? /root/vps-ready.toml exists. Replace it? (y/N) no\nNot saved."));
    assert_eq!(saved(&fs), "old\n");
}

#[test]
fn an_empty_plan_says_the_server_matches() {
    let fs = fs();
    let runner = runner(|r| r);
    let host = Host {
        facts: container,
        ..on(&fs, &runner)
    };
    let text = scenario(
        "empty-plan",
        &host,
        vec![
            Enter,
            Enter,
            Enter,
            Say(true),
            modules(&host, &["kernel.sysctl"]),
        ],
        vec![Say(false)],
    );
    assert!(
        text.contains("\nNothing to do: this server already matches.\n"),
        "{text}"
    );
    assert!(!text.contains("Apply "), "{text}");
}

#[test]
fn the_ports_question_is_skipped_without_the_firewall() {
    let fs = fs();
    let runner = runner(|r| r);
    let host = Host {
        facts: |sys| {
            let mut facts = vm(sys)?;
            facts.firewall_tools.ufw = Some(true);
            Ok(facts)
        },
        ..on(&fs, &runner)
    };
    let text = scenario("no-firewall", &host, vec![Enter, Enter, Enter], vec![]);
    assert!(
        text.contains(
            "Open ports: skipped, ufw is enabled; vps-ready leaves the firewall to it.\n"
        ),
        "{text}"
    );
}

#[test]
fn the_other_profile_can_be_picked() {
    let fs = fs();
    let runner = runner(|r| r);
    let host = on(&fs, &runner);
    let questions = vec![Pick(1), Enter, Enter, Enter, Enter];
    let (code, text) = wizard(&host, questions.clone(), "n\n");
    assert_eq!(code, 0);
    assert!(text.ends_with("apply --profile web\n"), "{text}");
    assert_eq!(round_trip(&host, questions).base(), "web");
}

#[test]
fn ctrl_c_at_a_question_changes_nothing() {
    let fs = fs();
    let runner = runner(|r| r);
    let host = on(&fs, &runner);
    let (code, text) = wizard(&host, vec![Enter, CtrlC], "");
    assert_eq!(code, EXIT_INTERRUPTED);
    assert!(
        text.ends_with(
            "? Admin user (logs in with an SSH key, uses sudo) ^C\nNothing was changed.\n"
        ),
        "{text}"
    );
    assert!(txns(&fs).is_empty());
}

fn txns(fs: &FakeFs) -> Vec<String> {
    StateDir::open(fs, STATE, 0)
        .unwrap()
        .txns(fs)
        .unwrap()
        .iter()
        .map(|t| t.id().to_owned())
        .collect()
}

/// `y` at apply's question applies; a failed apply exits with its code
/// and skips "Next time".
#[test]
fn yes_applies_the_answers() {
    let fs = fs();
    let runner = runner(|r| r);
    let host = on(&fs, &runner);
    let safe = modules(&host, &["kernel.sysctl", "updates.auto"]);
    let answers = vec![Enter, Enter, Enter, Say(true), safe, Enter];
    let (code, text) = wizard(&host, answers, "y\n");
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("Apply 8 changes? [y/N] y\n"), "{text}");
    assert!(text.contains("\nApplied 8 changes (transaction "), "{text}");
    assert!(
        text.ends_with("apply --profile /root/vps-ready.toml\n"),
        "{text}"
    );
    assert_eq!(txns(&fs).len(), 1);

    // The dead-man switch cannot be armed: /proc/uptime is missing.
    let fs = self::fs();
    let host = on(&fs, &runner);
    let (code, text) = wizard(&host, vec![Enter, Enter, Enter, Enter], "y\n");
    assert_eq!(code, 2, "{text}");
    assert!(
        text.contains("error: dead-man switch: reading /proc/uptime"),
        "{text}"
    );
    assert!(!text.contains("Next time"), "{text}");
}

#[test]
fn start_checks_stop_before_the_first_question() {
    let fs = fs();
    let runner = runner(|r| r);
    let not_root = Host {
        root: false,
        ..on(&fs, &runner)
    };
    assert_eq!(
        wizard(&not_root, vec![], ""),
        (
            2,
            "error: setting up this server needs root. Run it with sudo: sudo vps-ready\n"
                .to_owned()
        )
    );

    let untrusted = Host {
        binary: "/home/admin/vps-ready".into(),
        ..on(&fs, &runner)
    };
    let (code, text) = wizard(&untrusted, vec![], "");
    assert_eq!(code, 2);
    assert!(
        text.starts_with("error: refusing to arm the dead-man switch with /home/admin/vps-ready"),
        "{text}"
    );

    let state = StateDir::create(&fs, STATE, 0).unwrap();
    let txn = state.create_txn(&fs, 1_792_755_766).unwrap();
    let begin = Event::Begin {
        version: "0.3.0".into(),
        modules: vec!["kernel.sysctl".into()],
    };
    txn.append(
        &fs,
        &Record {
            at: 0,
            event: begin,
        },
    )
    .unwrap();
    assert_eq!(
        wizard(&on(&fs, &runner), vec![], ""),
        (
            2,
            "error: transaction 20261023T114246Z did not finish; \
             run `vps-ready rollback --txn 20261023T114246Z`\n"
                .to_owned()
        )
    );
}

#[test]
fn public_addresses() {
    for addr in [
        "*",
        "0.0.0.0",
        "::",
        "203.0.113.4",
        "fe80::1%eth0",
        "2001:db8::1",
    ] {
        assert!(public(addr), "{addr}");
    }
    for addr in ["127.0.0.1", "127.0.0.53%lo", "::1", "::ffff:127.0.0.1"] {
        assert!(!public(addr), "{addr}");
    }
}
