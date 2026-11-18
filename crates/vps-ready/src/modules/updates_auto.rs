//! The `updates.auto` module: security updates through `unattended-upgrades`.

use crate::facts::{Facts, OsFamily};
use crate::modules::{Applicability, Module, ModuleError, ModuleSteps, NoParams, PlanCx};
use crate::resource::{File, Package, Resource, Validate};
use crate::sys::{FileOwner, Sys};

/// The drop-in this module owns. apt reads `apt.conf.d` in name order, so
/// it overrides the package's `20auto-upgrades`.
const DROP_IN: &str = "/etc/apt/apt.conf.d/52vps-ready";

/// `Enable` defaults to on; it is set so that an earlier file cannot turn
/// every job off. `Unattended-Upgrade::Automatic-Reboot` is left to the admin.
const DROP_IN_CONTENT: &str = "\
APT::Periodic::Enable \"1\";
APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Unattended-Upgrade \"1\";
";

/// Installs `unattended-upgrades` and turns on apt's daily update and
/// upgrade jobs. Debian family only. It does not touch apt's systemd units.
#[derive(Debug, Clone, Copy)]
pub struct UpdatesAuto {
    uid: u32,
    gid: u32,
}

impl UpdatesAuto {
    /// The drop-in owned by root:root.
    pub const ROOT: Self = Self { uid: 0, gid: 0 };

    /// The drop-in owned by `uid:gid`, for tests that cannot `chown` to root.
    #[cfg(test)]
    const fn owned_by(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }
}

impl Module for UpdatesAuto {
    fn id(&self) -> &'static str {
        "updates.auto"
    }

    fn title(&self) -> &'static str {
        "Install security updates automatically"
    }

    fn why(&self) -> &'static str {
        "Attackers scan for a flaw soon after its fix is published. Unattended \
         upgrades install security fixes on their own, so a server nobody logs \
         into still gets them."
    }

    fn applicable(&self, facts: &Facts) -> Applicability {
        let reason = if facts.os.family != OsFamily::Debian {
            "apt is supported only on Debian and Ubuntu"
        } else if facts.updates.is_none() {
            "apt not found, or `apt-config` failed"
        } else {
            return Applicability::Applicable;
        };
        Applicability::NotApplicable {
            reason: reason.to_owned(),
        }
    }

    fn notes(&self, facts: &Facts) -> Vec<String> {
        let off: Vec<String> = facts
            .updates
            .iter()
            .filter_map(|apt| apt.units.as_ref())
            .flatten()
            .filter(|(_, state)| *state != "ok")
            .map(|(unit, state)| format!("{unit} is {state}"))
            .collect();
        if off.is_empty() {
            return Vec::new();
        }
        vec![format!(
            "{}; apt's systemd units are left as they are, so the daily jobs stay off",
            off.join(", ")
        )]
    }

    fn plan(&self, cx: &PlanCx, _: Sys) -> Result<ModuleSteps, ModuleError> {
        let NoParams {} = cx.params()?;
        Ok(ModuleSteps::from(vec![
            Resource::Package(Package {
                names: vec!["unattended-upgrades".to_owned()],
            }),
            Resource::File(File {
                path: DROP_IN.into(),
                content: DROP_IN_CONTENT.into(),
                owner: FileOwner {
                    mode: 0o644,
                    uid: self.uid,
                    gid: self.gid,
                },
                validate: Some(Validate::new("apt-config", ["-c", Validate::PATH, "dump"])),
                describe: None,
            }),
        ]))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::engine::{self, ApplyOutcome, Engine, Plan, Selected, StateDir, Target};
    use crate::facts::AptUpdates;
    use crate::facts::fixtures::host;
    use crate::sys::fake::FakeRunner;
    use crate::sys::{Cmd, Fs, Output, RealFs, Runner, SysError};

    const STATE: &str = "/var/lib/vps-ready";

    fn facts() -> Facts {
        let mut facts = host("debian-13", &[]);
        facts.updates = Some(AptUpdates::default());
        facts
    }

    fn dpkg_query(status: &str) -> FakeRunner {
        FakeRunner::new().on("dpkg-query", ["-W"], Output::success(status))
    }

    /// A tempdir with an empty `/etc/apt/apt.conf.d`, or one holding the
    /// drop-in with `existing` content.
    fn root(existing: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let conf_d = dir.path().join("etc/apt/apt.conf.d");
        std::fs::create_dir_all(&conf_d).unwrap();
        if let Some(content) = existing {
            let path = conf_d.join("52vps-ready");
            std::fs::write(&path, content).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        dir
    }

    /// apt on a host without `unattended-upgrades`: `dpkg-query` reports it
    /// installed once `apt-get install` has run. Other commands go to a
    /// [`FakeRunner`] that accepts `apt-get` and `apt-config`.
    struct Apt {
        installed: AtomicBool,
        runner: FakeRunner,
    }

    impl Apt {
        fn new() -> Self {
            Self {
                installed: AtomicBool::new(false),
                runner: FakeRunner::new()
                    .on("apt-get", ["-o"], Output::success(""))
                    .on("apt-config", ["-c"], Output::success("")),
            }
        }
    }

    impl Runner for Apt {
        fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
            if cmd.program == "dpkg-query" {
                let installed = self.installed.load(Ordering::SeqCst);
                return Ok(Output::success(if installed {
                    "installed"
                } else {
                    "not-installed"
                }));
            }
            if cmd.program == "apt-get" && cmd.args.iter().any(|a| a == "install") {
                self.installed.store(true, Ordering::SeqCst);
            }
            self.runner.run(cmd)
        }
    }

    fn plan<'a>(
        module: &'a UpdatesAuto,
        fs: &dyn Fs,
        runner: &dyn Runner,
        facts: &'a Facts,
    ) -> Plan<'a> {
        engine::plan(&[Selected::new(module)], facts, Sys { fs, runner }).unwrap()
    }

    fn change_ids(plan: &Plan) -> Vec<String> {
        plan.steps().map(|s| s.change.id.clone()).collect()
    }

    /// Path, content and mode of every file under `dir/etc`.
    fn etc_tree(dir: &Path) -> BTreeMap<PathBuf, (Vec<u8>, u32)> {
        fn walk(path: &Path, out: &mut BTreeMap<PathBuf, (Vec<u8>, u32)>) {
            for entry in std::fs::read_dir(path).unwrap() {
                let path = entry.unwrap().path();
                let meta = std::fs::symlink_metadata(&path).unwrap();
                if meta.is_dir() {
                    walk(&path, out);
                } else {
                    let content = std::fs::read(&path).unwrap();
                    out.insert(path, (content, meta.mode() & 0o7777));
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(&dir.join("etc"), &mut out);
        out
    }

    #[test]
    fn applies_only_with_apt() {
        let mut facts = facts();
        assert_eq!(
            UpdatesAuto::ROOT.applicable(&facts),
            Applicability::Applicable
        );
        facts.updates = None;
        assert_eq!(
            UpdatesAuto::ROOT.applicable(&facts),
            Applicability::NotApplicable {
                reason: "apt not found, or `apt-config` failed".into()
            }
        );
        facts.os.family = OsFamily::Rhel;
        assert_eq!(
            UpdatesAuto::ROOT.applicable(&facts),
            Applicability::NotApplicable {
                reason: "apt is supported only on Debian and Ubuntu".into()
            }
        );
    }

    #[test]
    fn plans_the_package_then_the_drop_in() {
        let dir = root(None);
        let facts = facts();
        let plan = plan(
            &UpdatesAuto::ROOT,
            &RealFs::new(dir.path()),
            &dpkg_query("not-installed"),
            &facts,
        );
        insta::assert_yaml_snapshot!(plan);
    }

    #[test]
    fn plans_only_the_drop_in_when_the_package_is_installed() {
        let dir = root(None);
        let facts = facts();
        let plan = plan(
            &UpdatesAuto::ROOT,
            &RealFs::new(dir.path()),
            &dpkg_query("installed"),
            &facts,
        );
        assert_eq!(change_ids(&plan), [format!("file:{DROP_IN}")]);
    }

    #[test]
    fn validates_the_drop_in_with_apt_config() {
        let dir = root(None);
        let fs = RealFs::new(dir.path());
        let runner = FakeRunner::new();
        let steps = UpdatesAuto::ROOT.plan(
            &PlanCx {
                facts: &facts(),
                params: &toml::Table::new(),
                planned: &[],
            },
            Sys {
                fs: &fs,
                runner: &runner,
            },
        );
        let Some(Resource::File(file)) = steps.unwrap().resources.pop() else {
            panic!("the drop-in comes last");
        };
        assert_eq!(
            file.validate,
            Some(Validate {
                program: "apt-config".into(),
                args: vec!["-c".into(), "{}".into(), "dump".into()],
            })
        );
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn notes_apt_units_it_leaves_off() {
        let mut facts = facts();
        let units = |timer: &str| {
            BTreeMap::from([
                ("apt-daily.timer".to_owned(), "ok".to_owned()),
                ("apt-daily-upgrade.timer".to_owned(), timer.to_owned()),
            ])
        };
        facts.updates.as_mut().unwrap().units = Some(units("ok"));
        assert!(UpdatesAuto::ROOT.notes(&facts).is_empty());

        facts.updates.as_mut().unwrap().units = Some(units("masked"));
        let dir = root(None);
        let plan = plan(
            &UpdatesAuto::ROOT,
            &RealFs::new(dir.path()),
            &dpkg_query("installed"),
            &facts,
        );
        assert_eq!(
            plan.modules[0].notes,
            [
                "apt-daily-upgrade.timer is masked; apt's systemd units are left as they \
                 are, so the daily jobs stay off"
            ]
        );
        assert_eq!(change_ids(&plan), [format!("file:{DROP_IN}")]);
    }

    /// Apply, then plan again; then roll back. Rollback leaves the package
    /// installed and restores the files.
    #[test]
    fn apply_is_idempotent_and_rolls_back() {
        for existing in [None, Some("APT::Periodic::Enable \"0\";\n")] {
            let dir = root(existing);
            let fs = RealFs::new(dir.path());
            let meta = std::fs::metadata(dir.path()).unwrap();
            let module = UpdatesAuto::owned_by(meta.uid(), meta.gid());
            let apt = Apt::new();
            let sys = Sys {
                fs: &fs,
                runner: &apt,
            };
            let facts = facts();
            let before = etc_tree(dir.path());

            let first = plan(&module, &fs, &apt, &facts);
            assert_eq!(
                change_ids(&first),
                [
                    "package:unattended-upgrades".to_owned(),
                    format!("file:{DROP_IN}")
                ],
                "{existing:?}"
            );
            let state = StateDir::create(&fs, STATE, meta.uid()).unwrap();
            let engine = Engine::lock(&state, sys).unwrap();
            let outcome = engine
                .apply(&first, &crate::engine::Deadman::default(), &mut |_| {})
                .unwrap();
            let ApplyOutcome::Applied { txn } = outcome else {
                panic!("{existing:?}: {outcome:?}");
            };
            let drop_in = String::from_utf8(fs.read(Path::new(DROP_IN)).unwrap()).unwrap();
            insta::assert_snapshot!("drop-in", drop_in);
            let after = format!("{STATE}/txn/{txn}/files/2.after");
            let validate = Cmd::new("apt-config").args(["-c", after.as_str(), "dump"]);
            assert!(
                apt.runner.calls().contains(&validate),
                "{existing:?}: {:?}",
                apt.runner.calls()
            );

            let next = plan(&module, &fs, &apt, &facts);
            assert!(change_ids(&next).is_empty(), "{existing:?}");

            engine.rollback(Target::Last, &mut |_| {}).unwrap();
            assert_eq!(etc_tree(dir.path()), before, "{existing:?}");
            assert!(apt.installed.load(Ordering::SeqCst), "{existing:?}");
        }
    }
}
