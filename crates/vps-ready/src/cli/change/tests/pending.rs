//! A dead-man apply: the printed `ssh` line, the wait and how it ends,
//! `confirm`, `confirm --extend`, `history` and `rollback --last`.

use std::time::Duration;

use super::*;
use crate::facts::{NoSession, Session, SessionId};

/// The SSH login apply runs in, through a cloud's NAT.
fn applying() -> Session {
    Session {
        id: SessionId {
            pid: 812,
            start: 90_000,
        },
        client: "198.51.100.7:50022".parse().unwrap(),
        server: "10.0.2.15:22".parse().unwrap(),
        uid: 1000,
        user: Some("admin".into()),
    }
}

/// A login after the changes went live, 1000 s or later after boot.
fn new_login(_: Sys) -> Result<Session, NoSession> {
    Ok(Session {
        id: SessionId {
            pid: 951,
            start: 105_000,
        },
        ..applying()
    })
}

fn vm_in_session(sys: Sys) -> anyhow::Result<Facts> {
    let mut facts = vm(sys)?;
    facts.session = Some(applying());
    Ok(facts)
}

/// A VM that can arm the dead-man switch, 1000 s after boot.
fn armable() -> FakeFs {
    let fs = fixture()
        .with_file("/proc/sys/kernel/random/boot_id", "a\n")
        .with_file("/proc/uptime", "1000.00 1.00\n")
        .with_file(BINARY, "\x7fELF");
    fs.create_dir_all(Path::new("/etc/systemd/system"), 0o755)
        .unwrap();
    fs
}

fn dm_runner() -> FakeRunner {
    FakeRunner::new()
        .on("systemd-run", Vec::<String>::new(), Output::success(""))
        .on("systemctl", Vec::<String>::new(), Output::success(""))
}

/// [`host`] with only [`Lockout`], applied from [`applying`]. Its apply
/// stops waiting at once, as after Ctrl-C.
fn lockout_host<'a>(fs: &'a FakeFs, runner: &'a FakeRunner) -> Host<'a> {
    Host {
        modules: &[&Lockout],
        sys: Sys { fs, runner },
        facts: vm_in_session,
        stop: Arc::new(AtomicBool::new(true)),
        ..host(fs)
    }
}

fn apply_lockout(host: &Host) -> (u8, String, String) {
    let ids = only(&["test.lockout"]);
    run(|out, err| apply(host, &ids, true, WINDOW, None, out, err))
}

fn confirm_cmd(host: &Host, extend: Option<Duration>) -> (u8, String, String) {
    run(|out, _| confirm(host, None, extend, out))
}

fn set_uptime(fs: &FakeFs, secs: u64) {
    fs.write(
        Path::new("/proc/uptime"),
        format!("{secs}.00 1.00\n").as_bytes(),
    )
    .unwrap();
}

fn calls(runner: &FakeRunner) -> Vec<String> {
    runner
        .calls()
        .iter()
        .map(|c| format!("{} {}", c.program, c.args.join(" ")))
        .collect()
}

/// What follows the `Applied` line, with the deadline's time of day
/// replaced by `<time>`.
fn pending_text(out: &str) -> String {
    let text = &out[out.find("Changes are live").unwrap()..];
    let at = text.find(" UTC").unwrap();
    format!("{}<time>{}", &text[..at - 8], &text[at + 4..])
}

#[test]
fn apply_prints_the_confirm_command_and_ctrl_c_only_stops_waiting() {
    let fs = armable();
    let runner = dm_runner();
    // As the wizard runs it: Ctrl-C ends the process until the wait catches
    // it. This installs a SIGINT handler in the test process, which sets
    // `stop`, already set.
    let ends = Arc::new(AtomicBool::new(true));
    let host = Host {
        catch_sigint: true,
        sigint_ends: Some(Arc::clone(&ends)),
        ..lockout_host(&fs, &runner)
    };
    let (code, out, err) = apply_lockout(&host);
    assert_eq!(code, EXIT_PENDING, "{err}");
    assert!(!ends.load(Ordering::SeqCst));
    let txn = txn_ids(&fs).pop().unwrap();
    assert!(
        out.contains(&format!(
            "Applied 1 change (transaction {txn}). Undo them now with `sudo vps-ready \
             rollback --last`.\n"
        )),
        "{out}"
    );
    assert_eq!(
        pending_text(&out),
        format!(
            "Changes are live. To keep them, open a NEW terminal on your computer and run
this to show you can still log in:

    ssh -t -o ControlPath=none -p 22 admin@10.0.2.15 sudo vps-ready confirm
    (or the address you connected to instead of 10.0.2.15)

If no new session confirms by <time> (5:00 left), every change is rolled back.
More time: sudo vps-ready confirm --extend
Do not edit files vps-ready manages until you confirm: an unconfirmed change reverts them.
Ctrl-C stops waiting here, not the timer.
Stopped waiting; transaction {txn} is still pending. Unless a new SSH login confirms it, \
it reverts at its deadline: see `sudo vps-ready history`.
"
        )
    );
    // Stopping the wait left the timer and the hook alone: the last call
    // is the re-arm's stop of the first timer.
    let unit = format!("vps-ready-deadman-{txn}-1");
    assert_eq!(
        calls(&runner).last().unwrap(),
        &format!("systemctl stop {unit}.timer {unit}.service")
    );
    assert!(fs.exists(Path::new(LOCKOUT)));

    set_uptime(&fs, 1108);
    let history = redact(&fs, &history_text(&host), true);
    assert_eq!(
        history,
        "<txn-1>               pending-confirm (reverts in 3m12s)  test.lockout  1 change\n"
    );
    set_uptime(&fs, 1300);
    assert!(history_text(&host).contains("pending-confirm (deadline passed)  test.lockout"));
}

#[test]
fn confirm_needs_a_new_ssh_login() {
    let fs = armable();
    let runner = dm_runner();
    let host = lockout_host(&fs, &runner);

    let (code, _, err) = confirm_cmd(&host, None);
    assert_eq!(
        (code, err.as_str()),
        (2, "error: nothing is waiting for a confirm\n")
    );
    let not_root = Host {
        root: false,
        ..lockout_host(&fs, &runner)
    };
    let (code, _, err) = confirm_cmd(&not_root, None);
    assert_eq!(
        (code, err.as_str()),
        (2, "error: confirm needs root; run it with sudo\n")
    );

    apply_lockout(&host);
    let txn = txn_ids(&fs).pop().unwrap();
    set_uptime(&fs, 1100);
    let (code, _, err) = confirm_cmd(&host, None);
    assert_eq!(code, 2);
    assert_eq!(
        err,
        "error: this is not an SSH login (the console, tmux, screen or mosh), so it proves \
         nothing about the changes. Open a new terminal and run: `ssh -t -o ControlPath=none \
         -p 22 admin@<server address> sudo vps-ready confirm`\n"
    );
    let same = Host {
        session: |_| Ok(applying()),
        ..lockout_host(&fs, &runner)
    };
    let (code, _, err) = confirm_cmd(&same, None);
    assert_eq!(code, 2);
    assert_eq!(
        err,
        "error: this is the SSH session that applied the changes. This is not a new SSH \
         login: tmux, screen and mosh sessions, the console, and ssh connections shared \
         through ControlMaster all count as old. Open a new terminal and run: `ssh -t -o \
         ControlPath=none -p 22 admin@10.0.2.15 sudo vps-ready confirm`\n"
    );
    let rescue = Host {
        session: |_| {
            Ok(Session {
                server: "10.0.2.15:2222".parse().unwrap(),
                ..new_login(Sys {
                    fs: &FakeFs::new(),
                    runner: &FakeRunner::new(),
                })?
            })
        },
        ..lockout_host(&fs, &runner)
    };
    let (code, _, err) = confirm_cmd(&rescue, None);
    assert_eq!(code, 2);
    assert!(
        err.starts_with(
            "error: this SSH login came in on port 2222, which the host's sshd does not \
             listen on (it listens on 22). Open a new terminal and run: `ssh -t -o \
             ControlPath=none -p 2222 admin@10.0.2.15"
        ),
        "{err}"
    );
    assert!(history_text(&host).contains("pending-confirm"));

    let new = Host {
        session: new_login,
        ..lockout_host(&fs, &runner)
    };
    let (code, out, err) = confirm_cmd(&new, None);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        out,
        format!(
            "Confirmed transaction {txn} from a new SSH login (admin from 198.51.100.7). The \
             changes stay; undo them with `sudo vps-ready rollback --last`.\n"
        )
    );
    assert!(history_text(&host).contains("confirmed  "));
    assert!(fs.exists(Path::new(LOCKOUT)));
    let (code, _, err) = confirm_cmd(&new, None);
    assert_eq!(
        (code, err.as_str()),
        (2, "error: nothing is waiting for a confirm\n")
    );
}

#[test]
fn confirm_extend_moves_the_deadline() {
    let fs = armable();
    let runner = dm_runner();
    let host = lockout_host(&fs, &runner);
    apply_lockout(&host);
    let txn = txn_ids(&fs).pop().unwrap();
    set_uptime(&fs, 1100);
    // From any session, the applying one too.
    let (code, out, err) = confirm_cmd(&host, Some(Duration::from_secs(600)));
    assert_eq!(code, 0, "{err}");
    assert!(
        out.starts_with(&format!("Transaction {txn} now reverts at ")),
        "{out}"
    );
    assert!(
        out.ends_with(" UTC (10:00 left). Confirm before then from a new SSH login.\n"),
        "{out}"
    );
    assert!(history_text(&host).contains("pending-confirm (reverts in 10m00s)"));
    set_uptime(&fs, 1700);
    let (code, _, err) = confirm_cmd(&host, Some(Duration::from_secs(600)));
    assert_eq!(code, 2);
    assert_eq!(
        err,
        format!(
            "error: the deadline of transaction {txn} passed; its changes are being rolled \
             back\n"
        )
    );
}

fn deadline_of(fs: &FakeFs, txn: &str) -> engine::Deadline {
    let state = StateDir::open(fs, STATE, 0).unwrap();
    match engine::watch(&state, fs, txn).unwrap() {
        engine::Watch::Pending { deadline, .. } => deadline,
        other => panic!("{other:?}"),
    }
}

fn wait_for(
    host: &Host,
    fs: &FakeFs,
    txn: &str,
    at: engine::Deadline,
    plan: &Plan,
) -> (u8, String, String) {
    let state = StateDir::open(fs, STATE, 0).unwrap();
    run(|out, err| super::super::confirm::wait(host, &state, txn, at, plan, out, err))
}

#[test]
fn the_wait_ends_with_the_confirm_or_the_rollback() {
    let fs = armable();
    let runner = dm_runner();
    let host = lockout_host(&fs, &runner);
    let facts = vm_in_session(host.sys).unwrap();
    let selected = [Selected::new(&Lockout)];
    let plan = engine::plan(&selected, &facts, host.sys).unwrap();
    let waiting = Host {
        stop: Arc::new(AtomicBool::new(false)),
        ..lockout_host(&fs, &runner)
    };
    // Confirmed while waiting: exit 0.
    apply_lockout(&host);
    let txn = txn_ids(&fs).pop().unwrap();
    let at = deadline_of(&fs, &txn);
    set_uptime(&fs, 1100);
    let new = Host {
        session: new_login,
        ..lockout_host(&fs, &runner)
    };
    assert_eq!(confirm_cmd(&new, None).0, 0);
    let (code, out, _) = wait_for(&waiting, &fs, &txn, at, &plan);
    assert_eq!(code, 0);
    assert!(
        out.starts_with(&format!(
            "Confirmed: the changes of transaction {txn} stay. Undo them with `sudo \
             vps-ready rollback --last`.\n"
        )),
        "{out}"
    );
    let (code, _, err) = rollback_last(&host);
    assert_eq!(code, 0, "{err}");

    // Rolled back by the timer while waiting: exit 1.
    set_uptime(&fs, 2000);
    apply_lockout(&host);
    let txn = txn_ids(&fs).pop().unwrap();
    let at = deadline_of(&fs, &txn);
    set_uptime(&fs, 2300);
    assert_eq!(
        run(|out, err| rollback_deadman(&host, &txn, 0, out, err)).0,
        0
    );
    let (code, _, err) = wait_for(&waiting, &fs, &txn, at, &plan);
    assert_eq!(code, EXIT_ROLLED_BACK);
    assert_eq!(
        err,
        format!(
            "error: no new SSH login confirmed the changes, so every change was restored; \
             transaction {txn} is rolled-back (deadman-timeout).\n"
        )
    );

    // A minute past the deadline and still pending: stop waiting, exit 4.
    set_uptime(&fs, 3000);
    apply_lockout(&host);
    let txn = txn_ids(&fs).pop().unwrap();
    let at = deadline_of(&fs, &txn);
    set_uptime(&fs, 3360);
    let (code, out, _) = wait_for(&waiting, &fs, &txn, at, &plan);
    assert_eq!(code, EXIT_PENDING);
    assert!(
        out.starts_with("The deadline passed, but the dead-man rollback has not finished yet."),
        "{out}"
    );

    // One countdown line without a terminal, then Ctrl-C.
    set_uptime(&fs, 3200);
    let stop = Arc::new(AtomicBool::new(false));
    let counting = Host {
        stop: Arc::clone(&stop),
        poll: Duration::from_millis(1),
        ..lockout_host(&fs, &runner)
    };
    let ctrl_c = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        stop.store(true, Ordering::Relaxed);
    });
    let (code, out, err) = wait_for(&counting, &fs, &txn, at, &plan);
    ctrl_c.join().unwrap();
    assert_eq!(code, EXIT_PENDING);
    assert_eq!(err, "waiting for a confirm: 1:40 left\n");
    assert!(out.starts_with("Stopped waiting; "), "{out}");
}

#[test]
fn rollback_last_undoes_a_pending_apply_and_disarms() {
    let fs = armable();
    let runner = dm_runner();
    let host = lockout_host(&fs, &runner);
    apply_lockout(&host);
    let txn = txn_ids(&fs).pop().unwrap();
    let (code, out, err) = rollback_last(&host);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        out,
        format!("Rolled back transaction {txn}: restored 1 change.\n")
    );
    assert!(!fs.exists(Path::new(LOCKOUT)));
    let calls = calls(&runner);
    let unit = format!("vps-ready-deadman-{txn}-2");
    assert_eq!(
        calls[calls.len() - 2..],
        [
            format!("systemctl stop {unit}.timer {unit}.service"),
            "systemctl disable vps-ready-deadman.service".to_owned(),
        ]
    );
    assert!(history_text(&host).contains("rolled-back (manual)"));
}

/// The printed line logs in as the plan's admin, not as root who ran it.
#[test]
fn the_ssh_line_names_the_planned_admin() {
    let fs = armable();
    let runner = dm_runner();
    let host = Host {
        sudo_user: Some("root".into()),
        ..lockout_host(&fs, &runner)
    };
    let facts = vm_in_session(host.sys).unwrap();
    let deadline = engine::Deadline {
        boottime: 1300,
        wall: 0,
    };
    let line = |admins: &[String]| {
        let mut out = Vec::new();
        super::super::confirm::print_pending(
            &host,
            &facts,
            admins,
            deadline,
            Duration::from_secs(300),
            &mut out,
        )
        .unwrap();
        String::from_utf8(out)
            .unwrap()
            .lines()
            .nth(3)
            .unwrap()
            .to_owned()
    };
    assert_eq!(
        line(&["admin".into(), "deploy".into()]),
        "    ssh -t -o ControlPath=none -p 22 admin@10.0.2.15 sudo vps-ready confirm"
    );
    assert_eq!(
        line(&[]),
        "    ssh -t -o ControlPath=none -p 22 root@10.0.2.15 sudo vps-ready confirm"
    );
}

/// With an admin in the plan, a login as anyone else is refused and told
/// whom to log in as.
#[test]
fn confirm_refuses_a_login_other_than_the_admin() {
    let fs = armable();
    let runner = dm_runner();
    let host = lockout_host(&fs, &runner);
    apply_lockout(&host);
    let txn = txn_ids(&fs).pop().unwrap();
    let path = PathBuf::from(format!("{STATE}/txn/{txn}/journal.jsonl"));
    // Journaled as the applying user, `admin`; as if the plan gave keys to
    // `deploy` instead.
    let text = String::from_utf8(fs.read(&path).unwrap())
        .unwrap()
        .replace(r#""admins":["admin"]"#, r#""admins":["deploy"]"#);
    fs.write(&path, text.as_bytes()).unwrap();
    set_uptime(&fs, 1100);
    let new = Host {
        session: new_login,
        ..lockout_host(&fs, &runner)
    };
    let (code, _, err) = confirm_cmd(&new, None);
    assert_eq!(code, 2);
    assert_eq!(
        err,
        "error: this SSH login is admin, but the changes give SSH keys to deploy: log in as \
         deploy to confirm. Open a new terminal and run: `ssh -t -o ControlPath=none -p 22 \
         deploy@10.0.2.15 sudo vps-ready confirm`\n"
    );
    assert!(history_text(&host).contains("pending-confirm"));
}
