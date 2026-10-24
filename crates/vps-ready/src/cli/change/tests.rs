//! The change commands on a [`FakeFs`] VM with the registry's modules.

use std::collections::BTreeMap;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use crate::engine::{Event, Record};
use crate::facts::{AptUpdates, Virt, sysctl};
use crate::sys::fake::{FakeFs, FakeRunner, Op};
use crate::sys::{Cmd, FileKind, Fs, Output, Runner, SysError};

const STATE: &str = "/var/lib/vps-ready";
const DROP_IN: &str = crate::modules::kernel_sysctl::DROP_IN;
const APT_DROP_IN: &str = "/etc/apt/apt.conf.d/52vps-ready";

/// Kernel defaults of a Debian 13 VM, without Yama; six keys fail, which
/// with the drop-in makes seven changes.
const START: [(&str, &str); 13] = [
    ("kernel.kptr_restrict", "0"),
    ("kernel.dmesg_restrict", "0"),
    ("kernel.unprivileged_bpf_disabled", "0"),
    ("kernel.randomize_va_space", "2"),
    ("kernel.perf_event_paranoid", "4"),
    ("fs.protected_symlinks", "1"),
    ("fs.protected_hardlinks", "1"),
    ("fs.protected_fifos", "0"),
    ("fs.protected_regular", "0"),
    ("fs.suid_dumpable", "2"),
    ("net.ipv4.tcp_syncookies", "1"),
    ("net.ipv4.conf.all.accept_source_route", "1"),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
];

/// Kernel defaults as `/proc/sys`, and apt with `unattended-upgrades`
/// installed but without vps-ready's drop-in.
fn fixture() -> FakeFs {
    START.iter().fold(
        FakeFs::new()
            .with_file("/etc/sysctl.d/README.sysctl", "distro\n")
            .with_file("/etc/apt/apt.conf.d/20auto-upgrades", "distro\n"),
        |fs, (key, value)| fs.with_file(format!("/proc/sys/{}", key.replace('.', "/")), *value),
    )
}

/// A captured Debian 13 host as a VM, with the sysctl values of the tree
/// and, as `apt-config dump` would report it, the `APT::Periodic` settings
/// of the apt drop-in.
fn vm(sys: Sys) -> anyhow::Result<Facts> {
    let mut facts = crate::facts::fixtures::host("debian-13", &[]);
    facts.virtualization.container = Virt::None;
    facts.sysctl = Some(sysctl::detect(sys.fs, &mut Vec::new()));
    let drop_in = sys.fs.read(Path::new(APT_DROP_IN)).unwrap_or_default();
    let periodic = String::from_utf8(drop_in)?
        .lines()
        .filter_map(|l| l.strip_prefix("APT::Periodic::")?.split_once(' '))
        .map(|(k, v)| (k.to_owned(), v.trim_matches(['"', ';']).to_owned()))
        .collect();
    // The captured state of apt's systemd units.
    let units = facts.updates.take().and_then(|u| u.units);
    facts.updates = Some(AptUpdates {
        unattended_upgrades: true,
        periodic,
        units,
    });
    Ok(facts)
}

/// The captured Debian 13 container.
fn container(_: Sys) -> anyhow::Result<Facts> {
    Ok(crate::facts::fixtures::host("debian-13", &[]))
}

fn host(fs: &FakeFs) -> Host<'_> {
    // `apt-config -c` validates a path on the fake fs, so it is answered
    // here rather than run.
    static RUNNER: std::sync::LazyLock<FakeRunner> = std::sync::LazyLock::new(|| {
        FakeRunner::new()
            .on("dpkg-query", ["-W"], Output::success("installed"))
            .on("apt-config", ["-c"], Output::success(""))
    });
    Host {
        sys: Sys {
            fs,
            runner: &*RUNNER,
        },
        modules: crate::modules::all(),
        state_dir: Path::new(STATE),
        state_uid: 0,
        root: true,
        facts: vm,
        color: false,
    }
}

/// Exit code, stdout and stderr, with an error printed as `main` does.
fn run(
    f: impl FnOnce(&mut dyn Write, &mut dyn Write) -> anyhow::Result<u8>,
) -> (u8, String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = match f(&mut out, &mut err) {
        Ok(code) => code,
        Err(e) => {
            writeln!(err, "error: {e:#}").unwrap();
            exit_code(&e)
        }
    };
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn plan_cmd(host: &Host, ids: &[&str]) -> (u8, String, String) {
    let ids: Vec<String> = ids.iter().map(|s| (*s).to_owned()).collect();
    run(|out, _| plan(host, &ids, false, out))
}

fn apply_yes(host: &Host) -> (u8, String, String) {
    run(|out, err| apply(host, &[], true, None, out, err))
}

fn apply_answer(host: &Host, input: &mut dyn BufRead) -> (u8, String, String) {
    run(|out, err| apply(host, &[], false, Some(input), out, err))
}

fn rollback_last(host: &Host) -> (u8, String, String) {
    run(|out, err| rollback(host, Target::Last, out, err))
}

fn history_text(host: &Host) -> String {
    run(|out, _| history(host, false, out)).1
}

fn txn_ids(fs: &FakeFs) -> Vec<String> {
    match StateDir::open(fs, STATE, 0) {
        Ok(state) => state
            .txns(fs)
            .unwrap()
            .iter()
            .map(|t| t.id().to_owned())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Replaces each transaction ID, which is the current time, with `<txn-N>`,
/// padded to the ID's width if `align`.
fn redact(fs: &FakeFs, text: &str, align: bool) -> String {
    let mut ids = txn_ids(fs);
    // Longest first, so `X-2` is not replaced as `X` plus `-2`.
    ids.sort_by_key(|id| std::cmp::Reverse(id.len()));
    let mut text = text.to_owned();
    for id in ids {
        let n = txn_ids(fs).iter().position(|i| *i == id).unwrap() + 1;
        let width = if align { id.len() } else { 0 };
        text = text.replace(&id, &format!("{:<width$}", format!("<txn-{n}>")));
    }
    text
}

/// Every file outside the state directory, with its bytes and mode.
fn tree(fs: &dyn Fs) -> BTreeMap<PathBuf, (Vec<u8>, u32)> {
    fn walk(fs: &dyn Fs, dir: &Path, out: &mut BTreeMap<PathBuf, (Vec<u8>, u32)>) {
        for path in fs.read_dir(dir).unwrap() {
            let meta = fs.metadata(&path).unwrap();
            match meta.kind {
                FileKind::Dir => walk(fs, &path, out),
                _ => {
                    out.insert(path.clone(), (fs.read(&path).unwrap(), meta.mode));
                }
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(fs, Path::new("/"), &mut out);
    out.retain(|p, _| !p.starts_with(STATE));
    out
}

#[test]
fn plan_text_snapshot() {
    let fs = fixture();
    let (code, out, err) = plan_cmd(&host(&fs), &[]);
    assert_eq!((code, err.as_str()), (0, ""));
    insta::assert_snapshot!(out);
}

#[test]
fn plan_with_a_module_lists_it_as_not_applicable() {
    let fs = fixture();
    let host = Host {
        facts: container,
        ..host(&fs)
    };
    let (code, out, _) = plan_cmd(&host, &["kernel.sysctl"]);
    assert_eq!(code, 0);
    assert_eq!(
        out,
        "kernel.sysctl: not applicable (kernel settings belong to the host inside a container)\n\
         \nNothing to do.\n"
    );
}

#[test]
fn plan_json_is_the_plan() {
    let fs = fixture();
    let (code, out, _) = run(|out, _| plan(&host(&fs), &[], true, out));
    assert_eq!(code, 0);
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    let module = &json["modules"][0];
    assert_eq!(module["id"], "kernel.sysctl");
    assert_eq!(module["status"], "applicable");
    assert_eq!(module["changes"].as_array().unwrap().len(), 7);
    assert_eq!(module["changes"][0]["id"], format!("file:{DROP_IN}"));
    assert_eq!(module["changes"][0]["reversibility"], "reversible");
}

/// apply, plan, apply again, history, rollback, history: the cycle a user
/// runs, ending with the tree as it started.
#[test]
fn apply_history_rollback_cycle() {
    let fs = fixture();
    let host = host(&fs);
    let original = tree(&fs);

    let (code, out, err) = apply_yes(&host);
    assert_eq!(code, 0);
    let applied = redact(&fs, &out, false);
    insta::assert_snapshot!("apply", applied);
    insta::assert_snapshot!("apply-progress", err);
    assert_ne!(tree(&fs), original);

    let (code, out, _) = plan_cmd(&host, &[]);
    assert_eq!(code, 0);
    assert!(out.ends_with("no changes\n\nNothing to do.\n"), "{out}");
    let (code, out, _) = apply_yes(&host);
    assert_eq!(code, 0);
    assert!(out.ends_with("Nothing to do.\n"), "{out}");
    assert_eq!(txn_ids(&fs).len(), 1);

    let (code, out, err) = rollback_last(&host);
    assert_eq!(code, 0);
    assert_eq!(
        redact(&fs, &out, false),
        "Rolled back transaction <txn-1>: restored 8 changes.\n"
    );
    insta::assert_snapshot!("rollback-progress", err);
    assert_eq!(tree(&fs), original);

    // A second transaction, so history has an applied and a rolled-back one.
    assert_eq!(apply_yes(&host).0, 0);
    insta::assert_snapshot!("history", redact(&fs, &history_text(&host), true));

    let (code, out, _) = run(|out, _| history(&host, true, out));
    assert_eq!(code, 0);
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json[0]["state"], "applied");
    assert_eq!(json[1]["state"], "rolled-back");
    assert_eq!(json[1]["reason"], "manual");
    assert_eq!(json[1]["changes"], 8);
}

#[test]
fn history_without_a_state_dir_is_empty() {
    let fs = fixture();
    assert_eq!(history_text(&host(&fs)), "No transactions.\n");
    assert!(!fs.exists(Path::new(STATE)));
}

#[test]
fn apply_rollback_and_history_need_root() {
    let fs = fixture();
    let host = Host {
        root: false,
        ..host(&fs)
    };
    let original = tree(&fs);
    let (code, out, err) = apply_yes(&host);
    assert_eq!((code, out.as_str()), (2, ""));
    assert_eq!(err, "error: apply needs root; run it with sudo\n");
    let (code, _, err) = rollback_last(&host);
    assert_eq!(code, 2);
    assert_eq!(err, "error: rollback needs root; run it with sudo\n");
    let (code, _, err) = run(|out, _| history(&host, false, out));
    assert_eq!(code, 2);
    assert_eq!(err, "error: history needs root; run it with sudo\n");
    assert_eq!(tree(&fs), original);
    assert!(!fs.exists(Path::new(STATE)));
}

#[test]
fn apply_asks_first() {
    let fs = fixture();
    let host = host(&fs);
    let original = tree(&fs);

    for answer in ["n\n", "\n", ""] {
        let (code, out, _) = apply_answer(&host, &mut answer.as_bytes());
        assert_eq!(code, 0);
        assert!(
            out.ends_with("Apply 8 changes? [y/N] Nothing was changed.\n"),
            "{out}"
        );
    }
    assert_eq!(tree(&fs), original);
    assert!(txn_ids(&fs).is_empty());

    let (code, _, err) = run(|out, err| apply(&host, &[], false, None, out, err));
    assert_eq!(code, 2);
    assert_eq!(
        err,
        "error: stdin is not a terminal; pass --yes to apply without asking\n"
    );
    assert_eq!(tree(&fs), original);

    let (code, out, _) = apply_answer(&host, &mut "Y\n".as_bytes());
    assert_eq!(code, 0);
    assert!(out.contains("Applied 8 changes"), "{out}");
}

/// The summary counts steps by kind, with singular and plural forms; the
/// footnote appears with a package, which rollback does not remove.
#[test]
fn plan_summary_counts_kinds() {
    let fs = fixture();
    let (_, out, _) = plan_cmd(&host(&fs), &[]);
    assert!(
        out.contains("\n8 changes in 2 modules: 2 files, 6 kernel settings.\n"),
        "{out}"
    );
    assert!(out.contains("(mode 0644, root:root)"), "{out}");
    assert!(!out.contains("partial:"), "{out}");

    let apt = Apt {
        installed: AtomicBool::new(false),
        install: Output::success(""),
    };
    let (_, out, _) = plan_cmd(&apt_host(&fs, &apt), &[]);
    assert!(
        out.contains("\n9 changes in 2 modules: 2 files, 6 kernel settings, 1 package.\n"),
        "{out}"
    );
    assert!(
        out.ends_with(
            "partial: rollback restores the files but leaves installed packages in place.\n\
             Run `sudo vps-ready apply` to make them.\n"
        ),
        "{out}"
    );

    let host = Host {
        facts: container,
        ..host(&fs)
    };
    let (_, out, _) = plan_cmd(&host, &[]);
    assert!(out.contains("\n1 change in 1 module: 1 file.\n"), "{out}");
    assert!(out.ends_with("to make it.\n"), "{out}");
}

#[test]
fn owner_is_spelled_out() {
    assert_eq!(
        show_owner("/etc/a (0644 0:0)"),
        "/etc/a (mode 0644, root:root)"
    );
    assert_eq!(
        show_owner("/etc/a (0644 0:0 -> 0600 1000:100)"),
        "/etc/a (mode 0644, root:root -> mode 0600, 1000:100)"
    );
    assert_eq!(show_owner("/etc/a"), "/etc/a");
}

/// The success line names the journal, under the state directory.
#[test]
fn applied_line_names_the_journal() {
    let fs = fixture();
    let (_, out, _) = apply_yes(&host(&fs));
    let id = &txn_ids(&fs)[0];
    assert!(
        out.contains(&format!(
            "Applied 8 changes (transaction {id}, journal {STATE}/txn/{id}). \
             Undo with `sudo vps-ready rollback --last`.\n"
        )),
        "{out}"
    );
}

/// Answers `y`, after changing a sysctl the plan shows.
struct Meddler<'a>(&'a FakeFs, bool);

impl Read for Meddler<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.1 {
            return Ok(0);
        }
        self.1 = true;
        self.0
            .write(Path::new("/proc/sys/kernel/kptr_restrict"), b"2")
            .unwrap();
        buf[..2].copy_from_slice(b"y\n");
        Ok(2)
    }
}

#[test]
fn a_plan_changed_during_the_prompt_is_an_error() {
    let fs = fixture();
    let host = host(&fs);
    let mut input = BufReader::new(Meddler(&fs, false));
    let (code, _, err) = apply_answer(&host, &mut input);
    assert_eq!(code, 2);
    assert!(err.contains("the plan changed after it was shown"), "{err}");
    assert!(!fs.exists(Path::new(DROP_IN)));
}

#[test]
fn apply_errors_exit_2() {
    // The lock is busy.
    let fs = fixture();
    let state = StateDir::create(&fs, STATE, 0).unwrap();
    let held = state.lock(&fs).unwrap();
    let (code, _, err) = apply_yes(&host(&fs));
    assert_eq!(
        (code, err.as_str()),
        (2, "error: another vps-ready is running\n")
    );
    drop(held);

    // A transaction is unfinished.
    let txn = state.create_txn(&fs, 1_792_755_766).unwrap();
    let begin = Event::Begin {
        version: "0.2.0".into(),
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
    let (code, _, err) = apply_yes(&host(&fs));
    assert_eq!(code, 2);
    assert_eq!(
        err,
        "error: transaction 20261023T114246Z did not finish; \
         run `vps-ready rollback --txn 20261023T114246Z`\n"
    );

    // A module named with --module does not apply.
    let fs = fixture();
    let host = Host {
        facts: container,
        ..host(&fs)
    };
    let ids = ["kernel.sysctl".to_owned()];
    let (code, _, err) = run(|out, err| apply(&host, &ids, true, None, out, err));
    assert_eq!(code, 2);
    assert_eq!(
        err,
        "error: kernel.sysctl does not apply to this host: \
         kernel settings belong to the host inside a container\n"
    );
    // Without --module, it is skipped and updates.auto is applied.
    let (code, out, _) = apply_yes(&host);
    assert_eq!(code, 0);
    assert!(out.contains("Applied 1 change "), "{out}");
    assert!(!fs.exists(Path::new(DROP_IN)));
}

/// After a reboot, rollback leaves the kernel settings as the boot set them
/// and names them.
#[test]
fn rollback_after_a_reboot() {
    let boot_id = Path::new(crate::resource::sysctl::BOOT_ID);
    let fs = fixture().with_file(boot_id, "boot-1\n");
    let host = host(&fs);
    assert_eq!(apply_yes(&host).0, 0);
    fs.write(boot_id, b"boot-2\n").unwrap();
    // As on Ubuntu, a later sysctl.d file set `fs.protected_regular` after the drop-in.
    fs.write(Path::new("/proc/sys/fs/protected_regular"), b"2")
        .unwrap();

    let (code, out, err) = rollback_last(&host);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        redact(&fs, &out, false),
        "Rolled back transaction <txn-1>: restored 2 changes.\n\
         6 kernel settings keep their running value until the next boot: \
         net.ipv4.conf.all.accept_source_route, fs.protected_regular, fs.protected_fifos, \
         kernel.unprivileged_bpf_disabled, kernel.dmesg_restrict, kernel.kptr_restrict\n"
    );
    insta::assert_snapshot!("rollback-after-reboot-progress", err);
    assert!(!fs.exists(Path::new(DROP_IN)));
    assert_eq!(
        fs.read(Path::new("/proc/sys/fs/protected_regular"))
            .unwrap(),
        b"2"
    );
}

#[test]
fn rollback_refused_by_the_safety_check_exits_2() {
    let fs = fixture().with_file(crate::resource::sysctl::BOOT_ID, "boot-1\n");
    let host = host(&fs);
    assert_eq!(apply_yes(&host).0, 0);
    fs.write(Path::new("/proc/sys/kernel/kptr_restrict"), b"2")
        .unwrap();
    let (code, _, err) = rollback_last(&host);
    assert_eq!(code, 2);
    assert!(err.contains("refusing to roll back transaction"), "{err}");
    assert!(
        err.contains("sysctl:kernel.kptr_restrict: sysctl -w 'kernel.kptr_restrict=0'"),
        "{err}"
    );
    assert!(fs.exists(Path::new(DROP_IN)));

    let (code, _, err) = run(|out, err| rollback(&host, Target::Txn("nope"), out, err));
    assert_eq!((code, err.as_str()), (2, "error: no transaction nope\n"));
}

#[test]
fn nothing_to_roll_back_exits_2() {
    let fs = fixture();
    let (code, _, err) = rollback_last(&host(&fs));
    assert_eq!((code, err.as_str()), (2, "error: nothing to roll back\n"));
}

/// A failed write during apply: exit 1 when the rollback after it completes,
/// 3 when it does not; then `rollback --last` finishes the job.
#[test]
fn failed_applies_exit_1_or_3() {
    let original = tree(&fixture());
    let mut seen = (0, 0);
    for n in 1..100 {
        let fs = fixture().fail(Op::Write, n);
        let (code, out, err) = apply_yes(&host(&fs));
        if code == 0 {
            assert!(out.contains("Applied"), "{out}");
            break;
        }
        assert_eq!(code, 1, "{n}: {err}");
        assert!(err.contains("\nerror: apply failed: "), "{err}");
        assert!(err.ends_with("is rolled-back (apply-failed).\n"), "{err}");
        assert_eq!(tree(&fs), original);
        seen.0 += 1;

        // The first remove of the rollback is the newest drop-in it created.
        let fs = fixture().fail(Op::Write, n).fail(Op::Remove, 1);
        let (code, _, err) = apply_yes(&host(&fs));
        if code == 3 {
            let dir = format!("{STATE}/txn/{}", txn_ids(&fs)[0]);
            assert!(err.contains(&format!("({dir}) did not complete")), "{err}");
            assert!(err.contains(&format!("remove {DROP_IN}")), "{err}");
            assert_eq!(rollback_last(&host(&fs)).0, 0);
            seen.1 += 1;
        } else {
            assert_eq!(code, 1, "{n}: {err}");
        }
        assert_eq!(tree(&fs), original);
    }
    assert!(seen.0 > 0 && seen.1 > 0, "{seen:?}");
}

/// A rollback that stops part way exits 3; running it again finishes. The
/// first restore removes the apt drop-in, the last change applied.
#[test]
fn an_incomplete_rollback_exits_3() {
    let fs = fixture().fail(Op::Remove, 1);
    let host = host(&fs);
    let original = tree(&fs);
    assert_eq!(apply_yes(&host).0, 0);
    let (code, _, err) = rollback_last(&host);
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("did not complete"), "{err}");
    assert!(err.contains(&format!("remove {APT_DROP_IN}")), "{err}");
    // The failed remove was the first restore, so the rerun does them all.
    let (code, out, _) = rollback_last(&host);
    assert_eq!(code, 0);
    assert!(out.ends_with("restored 8 changes.\n"), "{out}");
    assert_eq!(tree(&fs), original);
}

/// apt without `unattended-upgrades`: `apt-get install` answers `install`,
/// and once it succeeds `dpkg-query` reports the package installed.
struct Apt {
    installed: AtomicBool,
    install: Output,
}

impl Runner for Apt {
    fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
        let installed = self.installed.load(Ordering::SeqCst);
        Ok(match cmd.program.as_str() {
            "dpkg-query" if installed => Output::success("installed"),
            "dpkg-query" => Output::success("not-installed"),
            "apt-get" if cmd.args.iter().any(|a| a == "install") => {
                self.installed.store(self.install.ok(), Ordering::SeqCst);
                self.install.clone()
            }
            _ => Output::success(""),
        })
    }
}

fn apt_host<'a>(fs: &'a FakeFs, apt: &'a Apt) -> Host<'a> {
    Host {
        sys: Sys { fs, runner: apt },
        ..host(fs)
    }
}

/// The package step says it can take a while; rollback leaves the package.
#[test]
fn progress_of_a_package() {
    let fs = fixture();
    let apt = Apt {
        installed: AtomicBool::new(false),
        install: Output::success(""),
    };
    let host = apt_host(&fs, &apt);
    let (code, _, err) = apply_yes(&host);
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains(
            "[8/9] install unattended-upgrades \
             (apt-get update, then install; can take a few minutes)\n\
             [9/9] create /etc/apt/apt.conf.d/52vps-ready (mode 0644, root:root)\n\
             verify: ok\n"
        ),
        "{err}"
    );
    let (code, _, err) = rollback_last(&host);
    assert_eq!(code, 0, "{err}");
    assert!(
        err.starts_with(
            "remove /etc/apt/apt.conf.d/52vps-ready\n\
             leave unattended-upgrades as it is (rollback does not remove packages)\n"
        ),
        "{err}"
    );
}

/// A failed install: each change made so far is restored, newest first,
/// and the error ends with apt's stderr.
#[test]
fn progress_of_a_failed_apply() {
    let fs = fixture();
    let original = tree(&fs);
    let apt = Apt {
        installed: AtomicBool::new(false),
        install: Output {
            status: 100,
            stdout: Vec::new(),
            stderr: b"E: Unable to locate package unattended-upgrades\n".to_vec(),
        },
    };
    let (code, _, err) = apply_yes(&apt_host(&fs, &apt));
    assert_eq!(code, 1, "{err}");
    insta::assert_snapshot!("failed-apply-progress", redact(&fs, &err, false));
    assert_eq!(tree(&fs), original);
}

#[test]
fn colors_only_when_asked() {
    let fs = fixture();
    let plain = plan_cmd(&host(&fs), &[]).1;
    assert!(!plain.contains('\x1b'));
    let colored = plan_cmd(
        &Host {
            color: true,
            ..host(&fs)
        },
        &[],
    )
    .1;
    assert!(colored.contains('\x1b'));
}

/// A second module that does not apply here.
struct NoApt;

impl Module for NoApt {
    fn id(&self) -> &'static str {
        "test.noapt"
    }
    fn title(&self) -> &'static str {
        "Needs apt"
    }
    fn why(&self) -> &'static str {
        "For tests."
    }
    fn applicable(&self, _: &Facts) -> crate::modules::Applicability {
        crate::modules::Applicability::NotApplicable {
            reason: "apt not found".into(),
        }
    }
    fn plan(
        &self,
        _: &crate::modules::PlanCx,
        _: Sys,
    ) -> Result<crate::modules::ModuleSteps, crate::modules::ModuleError> {
        Ok(crate::modules::ModuleSteps::default())
    }
}

/// Without `--module` every module is listed and only those that apply are
/// applied; `--module` selects in registry order.
#[test]
fn several_modules() {
    let fs = fixture();
    let modules: &[&dyn Module] = &[crate::modules::all()[0], &NoApt];
    let host = Host {
        modules,
        ..host(&fs)
    };
    let (code, out, _) = plan_cmd(&host, &[]);
    assert_eq!(code, 0);
    assert!(
        out.contains("test.noapt: not applicable (apt not found)\n\n7 changes in 1 module: 1 file, 6 kernel settings."),
        "{out}"
    );
    let (code, out, _) = plan_cmd(&host, &["test.noapt"]);
    assert_eq!(code, 0);
    assert!(!out.contains("kernel.sysctl"), "{out}");

    let ids = ["test.noapt".to_owned(), "kernel.sysctl".to_owned()];
    let (code, _, err) = run(|out, err| apply(&host, &ids, true, None, out, err));
    assert_eq!(code, 2);
    assert_eq!(
        err,
        "error: test.noapt does not apply to this host: apt not found\n"
    );
    let (code, out, _) = apply_yes(&host);
    assert_eq!(code, 0);
    assert!(out.contains("Applied 7 changes"), "{out}");
}

#[test]
fn restore_progress_of_users() {
    let line = |created, groups: &[&str]| {
        let backup = Backup::User {
            name: "admin".into(),
            created,
            added_groups: groups.iter().map(|&g| g.to_owned()).collect(),
        };
        let mut err = Vec::new();
        print_progress(&mut err, &Progress::Restore(&backup));
        String::from_utf8(err).unwrap()
    };
    assert_eq!(
        line(true, &["sudo"]),
        "remove user admin (its home directory stays)\n"
    );
    assert_eq!(
        line(false, &["sudo", "adm"]),
        "remove admin from groups sudo,adm\n"
    );
    assert_eq!(line(false, &[]), "leave user admin as it is\n");
}
