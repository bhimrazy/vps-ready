//! `kernel.sysctl` on [`RealFs`] over a tempdir, with `/proc/sys/...` as
//! plain files and [`Facts`] built by hand.

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use proptest::prelude::*;

use super::*;
use crate::audit::Outcome;
use crate::engine::{self, ApplyOutcome, Engine, Plan, Selected, StateDir, Target};
use crate::facts::{Virt, sysctl};
use crate::resource::sysctl::BOOT_ID;
use crate::sys::fake::FakeRunner;
use crate::sys::{Fs, RealFs};

const STATE: &str = "/var/lib/vps-ready";

/// Values the kernel will not take back at runtime.
const STICKY: [(&str, &str); 2] = [
    ("kernel.unprivileged_bpf_disabled", "1"),
    ("kernel.yama.ptrace_scope", "3"),
];

/// Keys from the baseline's "Never set" list, and `rp_filter`.
const NEVER: [&str; 3] = ["ip_forward", "accept_ra", "rp_filter"];

/// A host tree in a tempdir: `/etc/sysctl.d`, a boot ID and the given
/// `/proc/sys` values, plus an optional drop-in.
struct Host {
    dir: tempfile::TempDir,
    fs: RealFs,
    module: KernelSysctl,
}

impl Host {
    fn new(values: &[(&str, &str)], drop_in: Option<&str>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("etc/sysctl.d")).unwrap();
        // Also lets facts collection find `/proc/sys` with no values.
        let boot_id = dir.path().join(BOOT_ID.trim_start_matches('/'));
        std::fs::create_dir_all(boot_id.parent().unwrap()).unwrap();
        std::fs::write(boot_id, "boot-1\n").unwrap();
        for (key, value) in values {
            let path = dir.path().join("proc/sys").join(key.replace('.', "/"));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            // Without the newline the kernel adds, as `Sysctl::apply` writes them.
            std::fs::write(path, value).unwrap();
        }
        if let Some(text) = drop_in {
            let path = dir.path().join(DROP_IN.trim_start_matches('/'));
            std::fs::write(&path, text).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let meta = std::fs::metadata(dir.path()).unwrap();
        let fs = RealFs::new(dir.path());
        Self {
            dir,
            fs,
            module: KernelSysctl::owned_by(meta.uid(), meta.gid()),
        }
    }

    fn sys(&self) -> Sys<'_> {
        static RUNNER: std::sync::LazyLock<FakeRunner> = std::sync::LazyLock::new(FakeRunner::new);
        Sys {
            fs: &self.fs,
            runner: &*RUNNER,
        }
    }

    /// Facts with the sysctl values read from the tree, as on a VM.
    fn facts(&self) -> Facts {
        let mut notices = Vec::new();
        facts_with(sysctl::detect(&self.fs, &mut notices))
    }

    fn plan<'a>(&'a self, facts: &'a Facts) -> Plan<'a> {
        engine::plan(&[Selected::new(&self.module)], facts, self.sys()).unwrap()
    }

    fn state(&self) -> StateDir {
        let uid = std::fs::metadata(self.dir.path()).unwrap().uid();
        StateDir::create(&self.fs, STATE, uid).unwrap()
    }

    fn apply(&self, plan: &Plan) {
        let state = self.state();
        let outcome = Engine::lock(&state, self.sys())
            .unwrap()
            .apply(plan, &crate::engine::Deadman::default(), &mut |_| {})
            .unwrap();
        assert!(
            matches!(
                outcome,
                ApplyOutcome::Applied { .. } | ApplyOutcome::NothingToDo
            ),
            "{outcome:?}"
        );
    }

    fn rollback(&self) {
        let state = self.state();
        Engine::lock(&state, self.sys())
            .unwrap()
            .rollback(Target::Last, &mut |_| {})
            .unwrap();
    }

    /// Every file outside the state directory, with its bytes and mode.
    fn tree(&self) -> BTreeMap<PathBuf, (Vec<u8>, u32)> {
        fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, (Vec<u8>, u32)>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                let meta = std::fs::symlink_metadata(&path).unwrap();
                if meta.is_dir() {
                    walk(root, &path, out);
                } else {
                    let rel = path.strip_prefix(root).unwrap().to_path_buf();
                    out.insert(rel, (std::fs::read(&path).unwrap(), meta.mode() & 0o7777));
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(self.dir.path(), self.dir.path(), &mut out);
        out.retain(|p, _| !Path::new("/").join(p).starts_with(STATE));
        out
    }

    fn drop_in(&self) -> Option<String> {
        self.fs
            .read(Path::new(DROP_IN))
            .ok()
            .map(|b| String::from_utf8(b).unwrap())
    }
}

/// A debian-13 host outside a container, with these kernel settings.
fn facts_with(sysctl: crate::facts::Sysctl) -> Facts {
    let mut facts = crate::facts::fixtures::host("debian-13", &[]);
    facts.virtualization.container = Virt::None;
    facts.sysctl = Some(sysctl);
    facts
}

fn resources(host: &Host, facts: &Facts) -> Vec<Resource> {
    let params = toml::Table::new();
    host.module
        .plan(
            &PlanCx {
                facts,
                params: &params,
            },
            host.sys(),
        )
        .unwrap()
        .resources
}

fn sysctl_keys(resources: &[Resource]) -> Vec<&str> {
    resources
        .iter()
        .filter_map(|r| match r {
            Resource::Sysctl(s) => Some(s.key.as_str()),
            _ => None,
        })
        .collect()
}

/// Every `key = value` the module would set, at runtime or in the drop-in.
fn emitted(resources: &[Resource]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for r in resources {
        match r {
            Resource::Sysctl(s) => out.push((s.key.clone(), s.value.clone())),
            Resource::File(f) => {
                for line in String::from_utf8_lossy(&f.content).lines() {
                    if let Some((k, v)) = line.split_once('=')
                        && !line.starts_with('#')
                    {
                        out.push((k.trim().to_owned(), v.trim().to_owned()));
                    }
                }
            }
            other => panic!("kernel.sysctl planned {}", other.id()),
        }
    }
    out
}

fn assert_safe(resources: &[Resource]) {
    for (key, value) in emitted(resources) {
        assert!(!NEVER.iter().any(|n| key.contains(n)), "{key}");
        assert!(
            !STICKY.contains(&(key.as_str(), value.as_str())),
            "{key}={value}"
        );
    }
}

/// A plain kernel: most settings fail, some pass, Yama is absent, and
/// `perf_event_paranoid` is stricter than the module's value.
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

/// Every key failing its control.
const FAILING: [(&str, &str); 14] = [
    ("kernel.kptr_restrict", "0"),
    ("kernel.dmesg_restrict", "0"),
    ("kernel.unprivileged_bpf_disabled", "0"),
    ("kernel.yama.ptrace_scope", "0"),
    ("kernel.randomize_va_space", "0"),
    ("kernel.perf_event_paranoid", "1"),
    ("fs.protected_symlinks", "0"),
    ("fs.protected_hardlinks", "0"),
    ("fs.protected_fifos", "0"),
    ("fs.protected_regular", "0"),
    ("fs.suid_dumpable", "1"),
    ("net.ipv4.tcp_syncookies", "0"),
    ("net.ipv4.conf.all.accept_source_route", "1"),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "0"),
];

/// The first plan as the CLI would list it: summaries, diffs and notes.
fn render(plan: &Plan) -> String {
    let mut out = String::new();
    for m in &plan.modules {
        out.push_str(&format!("{}: {}\n", m.id, m.title));
        for note in &m.notes {
            out.push_str(&format!("  note: {note}\n"));
        }
    }
    for step in plan.steps() {
        out.push_str(&format!(
            "  {} ({:?})\n",
            step.change.summary, step.change.reversibility
        ));
        for line in step.change.diff.iter().flat_map(|d| d.lines()) {
            out.push_str(&format!("      {line}\n"));
        }
    }
    out
}

#[test]
fn first_plan_snapshot() {
    let host = Host::new(&START, None);
    // The registry's instance: root:root, which a plan only reads.
    let facts = host.facts();
    let plan = engine::plan(&[Selected::new(&KernelSysctl::ROOT)], &facts, host.sys()).unwrap();
    insta::assert_snapshot!(render(&plan));
}

#[test]
fn apply_then_plan_is_empty() {
    let host = Host::new(&START, None);
    host.apply(&host.plan(&host.facts()));
    assert_eq!(host.plan(&host.facts()).steps().count(), 0);
    // Only failing keys were written; the stricter value stays.
    assert_eq!(
        host.fs
            .read(Path::new("/proc/sys/kernel/perf_event_paranoid"))
            .unwrap(),
        b"4"
    );
    assert!(!host.drop_in().unwrap().contains("perf_event_paranoid"));
}

#[test]
fn apply_then_rollback_restores_the_tree() {
    let host = Host::new(&START, None);
    let before = host.tree();
    host.apply(&host.plan(&host.facts()));
    assert_ne!(host.tree(), before);
    host.rollback();
    assert_eq!(host.tree(), before);
}

fn proc_path(key: &str) -> PathBuf {
    PathBuf::from(format!("/proc/sys/{}", key.replace('.', "/")))
}

/// After a reboot, rollback removes the drop-in and leaves each running
/// value as the boot set it, even one that is neither the original nor the
/// applied value.
#[test]
fn rollback_after_a_reboot_does_not_lower_any_key() {
    let weak = [
        ("kernel.kptr_restrict", "0"),
        ("kernel.dmesg_restrict", "0"),
        ("fs.protected_fifos", "0"),
        ("fs.protected_regular", "0"),
        ("net.ipv4.conf.all.accept_source_route", "1"),
        ("kernel.perf_event_paranoid", "1"),
    ];
    let host = Host::new(&weak, None);
    host.apply(&host.plan(&host.facts()));

    // As Ubuntu boots: the drop-in, then `99-protect-links.conf`.
    host.fs.write(Path::new(BOOT_ID), b"boot-2\n").unwrap();
    let booted: Vec<(&str, &str)> = weak
        .iter()
        .map(|(key, _)| match *key {
            "fs.protected_regular" => (*key, "2"),
            _ => *VALUES.iter().find(|(k, _)| k == key).unwrap(),
        })
        .collect();
    for (key, value) in &booted {
        host.fs.write(&proc_path(key), value.as_bytes()).unwrap();
    }

    host.rollback();
    assert_eq!(host.drop_in(), None);
    for (key, value) in booted {
        assert_eq!(
            host.fs.read(&proc_path(key)).unwrap(),
            value.as_bytes(),
            "{key}"
        );
    }
}

/// A key lowered at runtime below the kernel's compiled-in default passes
/// at the module's value, so the drop-in persists that value.
#[test]
fn a_key_lowered_at_runtime_is_persisted_at_the_module_value() {
    let host = Host::new(&[("kernel.perf_event_paranoid", "1")], None);
    host.apply(&host.plan(&host.facts()));
    assert!(
        host.drop_in()
            .unwrap()
            .contains("\nkernel.perf_event_paranoid = 2\n")
    );
    host.rollback();
    assert!(
        host.drop_in()
            .is_none_or(|text| !text.contains("perf_event_paranoid"))
    );
}

/// After apply, the facts collected again pass every control the module
/// fixes.
#[test]
fn audit_and_fix_agree() {
    let host = Host::new(&FAILING, None);
    host.apply(&host.plan(&host.facts()));
    let report = audit::run(audit::catalog().unwrap(), &host.facts());
    let fixed: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.control.fix.as_deref() == Some("kernel.sysctl"))
        .collect();
    assert_eq!(fixed.len(), VALUES.len());
    for f in fixed {
        assert_eq!(f.outcome, Outcome::Pass, "{}", f.control.id);
    }
}

/// The module's keys are exactly those of the controls it fixes, and each
/// value passes its control.
#[test]
fn values_match_the_catalog() {
    let mut keys = Vec::new();
    for c in audit::catalog().unwrap() {
        if c.fix.as_deref() != Some("kernel.sysctl") {
            continue;
        }
        let Check::Sysctl { key, one_of } = &c.check else {
            panic!("{}: fix = kernel.sysctl on a check of another kind", c.id);
        };
        let (_, value) = VALUES
            .iter()
            .find(|(k, _)| k == key)
            .unwrap_or_else(|| panic!("{}: {key} has no value", c.id));
        assert!(one_of.iter().any(|o| o == value), "{}: {key}={value}", c.id);
        keys.push(key.clone());
    }
    keys.sort();
    let mut values: Vec<_> = VALUES.iter().map(|(k, _)| (*k).to_owned()).collect();
    values.sort();
    assert_eq!(keys, values);
    let mut read = sysctl::KEYS.to_vec();
    read.sort_unstable();
    assert_eq!(values, read);
}

#[test]
fn never_emits_forwarding_ra_rp_filter_or_sticky_values() {
    for (key, value) in VALUES {
        assert!(!NEVER.iter().any(|n| key.contains(n)), "{key}");
        assert!(!STICKY.contains(&(key, value)), "{key}={value}");
    }
    let host = Host::new(&FAILING, None);
    let resources = resources(&host, &host.facts());
    assert_eq!(sysctl_keys(&resources).len(), VALUES.len());
    assert_safe(&resources);
}

/// Running values the kernel will not lower again pass their controls, so
/// they are left alone.
#[test]
fn sticky_running_values_are_kept() {
    let host = Host::new(
        &[
            ("kernel.unprivileged_bpf_disabled", "1"),
            ("kernel.yama.ptrace_scope", "3"),
        ],
        None,
    );
    assert!(resources(&host, &host.facts()).is_empty());
}

#[test]
fn absent_and_unreadable_keys_are_skipped() {
    let host = Host::new(&[], None);
    let mut running = crate::facts::Sysctl::default();
    running
        .values
        .insert("kernel.kptr_restrict".into(), "0".into());
    running.unreadable.push("fs.protected_symlinks".into());
    let facts = facts_with(running);
    let resources = resources(&host, &facts);
    assert_eq!(sysctl_keys(&resources), ["kernel.kptr_restrict"]);
    assert_eq!(
        emitted(&resources)
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>(),
        ["kernel.kptr_restrict", "kernel.kptr_restrict"]
    );
    assert_eq!(
        host.module.notes(&facts),
        ["1 kernel setting is readable only by root on this kernel \
          (fs.protected_symlinks), so the plan skips it; run with sudo to plan it"]
    );
}

/// A key the drop-in lists stays there, even when only root can read it or
/// its running value passes; one the kernel lacks is dropped.
#[test]
fn listed_keys_stay_in_the_drop_in() {
    // A `;` comment, a `-` prefix (ignore errors) and a `/` key, as sysctl.d allows.
    let drop_in = "; kernel.dmesg_restrict = 1\n-kernel.kptr_restrict = 1\n\
                   fs/protected_symlinks = 1\nkernel.yama.ptrace_scope = 1\n";
    let host = Host::new(&[("kernel.kptr_restrict", "2")], Some(drop_in));
    let mut running = crate::facts::Sysctl::default();
    running
        .values
        .insert("kernel.kptr_restrict".into(), "2".into());
    running
        .values
        .insert("kernel.dmesg_restrict".into(), "1".into());
    running.unreadable.push("fs.protected_symlinks".into());
    let resources = resources(&host, &facts_with(running));
    assert_eq!(
        emitted(&resources),
        [
            ("kernel.kptr_restrict".to_owned(), "1".to_owned()),
            ("fs.protected_symlinks".to_owned(), "1".to_owned()),
        ]
    );
}

#[test]
fn nothing_to_do_without_a_failing_or_listed_key() {
    for drop_in in [None, Some("# none of ours\nvm.swappiness = 10\n")] {
        let host = Host::new(&[("kernel.kptr_restrict", "1")], drop_in);
        assert!(resources(&host, &host.facts()).is_empty(), "{drop_in:?}");
    }
}

#[test]
fn not_applicable_in_a_container() {
    let mut facts = facts_with(crate::facts::Sysctl::default());
    facts.sysctl = None;
    assert!(matches!(
        KernelSysctl::ROOT.applicable(&facts),
        Applicability::NotApplicable { .. }
    ));
}

/// A running value: absent, or one of the values the controls see in practice.
fn running_value() -> impl Strategy<Value = Option<&'static str>> {
    proptest::option::of(proptest::sample::select(vec!["0", "1", "2", "3", "4"]))
}

/// A pre-existing drop-in: absent, or some of the keys with any value.
fn drop_in() -> impl Strategy<Value = Option<Vec<(usize, &'static str)>>> {
    proptest::option::of(proptest::collection::vec(
        (
            0..VALUES.len(),
            proptest::sample::select(vec!["0", "1", "2"]),
        ),
        0..6,
    ))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn apply_is_idempotent_and_rolls_back(
        values in proptest::collection::vec(running_value(), VALUES.len()),
        listed in drop_in(),
    ) {
        let start: Vec<(&str, &str)> = VALUES
            .iter()
            .zip(&values)
            .filter_map(|((key, _), v)| v.map(|v| (*key, v)))
            .collect();
        let text = listed.map(|lines| {
            lines
                .iter()
                .map(|(i, v)| format!("{} = {v}\n", VALUES[*i].0))
                .collect::<String>()
        });
        let host = Host::new(&start, text.as_deref());
        let before = host.tree();
        let facts = host.facts();
        assert_safe(&resources(&host, &facts));

        host.apply(&host.plan(&facts));
        prop_assert_eq!(host.plan(&host.facts()).steps().count(), 0);
        host.rollback_if_applied();
        prop_assert_eq!(host.tree(), before);
    }
}

impl Host {
    /// Rolls back the last transaction, if apply made one.
    fn rollback_if_applied(&self) {
        let state = self.state();
        if !state.txns(&self.fs).unwrap().is_empty() {
            self.rollback();
        }
    }
}
