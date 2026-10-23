//! The `updates.auto` module: security updates through `unattended-upgrades`.

use crate::facts::{Facts, OsFamily};
use crate::modules::{Applicability, Module, ModuleError};
use crate::resource::{File, Package, Resource, Validate};
use crate::sys::{FileOwner, Sys};

/// The drop-in this module owns. apt reads `apt.conf.d` in order, so it
/// overrides the package's `20auto-upgrades`.
const DROP_IN: &str = "/etc/apt/apt.conf.d/52vps-ready";

/// `Enable` is needed because some images (Ubuntu 24.04) set it to `0`.
/// `Unattended-Upgrade::Automatic-Reboot` is left to the admin.
const DROP_IN_CONTENT: &str = "\
APT::Periodic::Enable \"1\";
APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Unattended-Upgrade \"1\";
";

/// Installs `unattended-upgrades` and turns on apt's daily update and
/// upgrade jobs. Debian family only. It does not touch apt's systemd units.
#[derive(Debug, Clone, Copy, Default)]
pub struct UpdatesAuto;

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
            "{}; vps-ready leaves apt's systemd units as they are, so the daily \
             jobs stay off until they are turned back on",
            off.join(", ")
        )]
    }

    fn plan(&self, _: &Facts, _: Sys) -> Result<Vec<Resource>, ModuleError> {
        Ok(vec![
            Resource::Package(Package {
                name: "unattended-upgrades".to_owned(),
            }),
            Resource::File(File {
                path: DROP_IN.into(),
                content: DROP_IN_CONTENT.into(),
                owner: FileOwner {
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                },
                validate: Some(Validate::new("apt-config", ["-c", Validate::PATH, "dump"])),
            }),
        ])
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::engine::{self, ApplyOutcome, Engine, Plan, StateDir, Target};
    use crate::facts::AptUpdates;
    use crate::facts::fixtures::host;
    use crate::sys::fake::FakeRunner;
    use crate::sys::{Cmd, FileMeta, Fs, FsLock, Output, RealFs, Runner, SysError};

    const STATE: &str = "/var/lib/vps-ready";

    fn facts() -> Facts {
        let mut facts = host("debian-13", &[]);
        facts.updates = Some(AptUpdates::default());
        facts
    }

    fn dpkg_query(status: &str) -> FakeRunner {
        FakeRunner::new().on("dpkg-query", ["-W"], Output::success(status))
    }

    /// A tempdir with `/etc/apt/apt.conf.d`, holding the package's own
    /// `20auto-upgrades` and, if given, an existing drop-in.
    fn root(drop_in: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let conf_d = dir.path().join("etc/apt/apt.conf.d");
        std::fs::create_dir_all(&conf_d).unwrap();
        std::fs::write(
            conf_d.join("20auto-upgrades"),
            "APT::Periodic::Unattended-Upgrade \"0\";\n",
        )
        .unwrap();
        if let Some(content) = drop_in {
            let path = conf_d.join("52vps-ready");
            std::fs::write(&path, content).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        dir
    }

    /// [`RealFs`] that shows the test user's files as root's and writes
    /// root's files as the test user's, since tests cannot `chown`.
    struct AsRoot {
        fs: RealFs,
        uid: u32,
        gid: u32,
    }

    impl AsRoot {
        fn new(dir: &Path) -> Self {
            let meta = std::fs::metadata(dir).unwrap();
            Self {
                fs: RealFs::new(dir),
                uid: meta.uid(),
                gid: meta.gid(),
            }
        }
    }

    impl Fs for AsRoot {
        fn read(&self, path: &Path) -> Result<Vec<u8>, SysError> {
            self.fs.read(path)
        }
        fn exists(&self, path: &Path) -> bool {
            self.fs.exists(path)
        }
        fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>, SysError> {
            self.fs.read_dir(path)
        }
        fn metadata(&self, path: &Path) -> Result<FileMeta, SysError> {
            let mut meta = self.fs.metadata(path)?;
            if meta.uid == self.uid {
                meta.uid = 0;
            }
            if meta.gid == self.gid {
                meta.gid = 0;
            }
            Ok(meta)
        }
        fn write_atomic(
            &self,
            path: &Path,
            bytes: &[u8],
            owner: FileOwner,
        ) -> Result<(), SysError> {
            assert_eq!((owner.uid, owner.gid), (0, 0), "{}", path.display());
            let owner = FileOwner {
                uid: self.uid,
                gid: self.gid,
                ..owner
            };
            self.fs.write_atomic(path, bytes, owner)
        }
        fn write(&self, path: &Path, bytes: &[u8]) -> Result<(), SysError> {
            self.fs.write(path, bytes)
        }
        fn append_sync(&self, path: &Path, bytes: &[u8]) -> Result<(), SysError> {
            self.fs.append_sync(path, bytes)
        }
        fn remove(&self, path: &Path) -> Result<(), SysError> {
            self.fs.remove(path)
        }
        fn create_dir_all(&self, path: &Path, mode: u32) -> Result<(), SysError> {
            self.fs.create_dir_all(path, mode)
        }
        fn sync_dir(&self, path: &Path) -> Result<(), SysError> {
            self.fs.sync_dir(path)
        }
        fn try_lock(&self, path: &Path) -> Result<FsLock, SysError> {
            self.fs.try_lock(path)
        }
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

    fn plan(fs: &dyn Fs, runner: &dyn Runner, facts: &Facts) -> Plan {
        engine::plan(&[&UpdatesAuto], facts, Sys { fs, runner }).unwrap()
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
        assert_eq!(UpdatesAuto.applicable(&facts), Applicability::Applicable);
        facts.updates = None;
        assert_eq!(
            UpdatesAuto.applicable(&facts),
            Applicability::NotApplicable {
                reason: "apt not found, or `apt-config` failed".into()
            }
        );
        facts.os.family = OsFamily::Rhel;
        assert_eq!(
            UpdatesAuto.applicable(&facts),
            Applicability::NotApplicable {
                reason: "apt is supported only on Debian and Ubuntu".into()
            }
        );
    }

    #[test]
    fn plans_the_package_then_the_drop_in() {
        let dir = root(None);
        let plan = plan(
            &AsRoot::new(dir.path()),
            &dpkg_query("not-installed"),
            &facts(),
        );
        insta::assert_yaml_snapshot!(plan);
    }

    #[test]
    fn plans_only_the_drop_in_when_the_package_is_installed() {
        let dir = root(None);
        let plan = plan(&AsRoot::new(dir.path()), &dpkg_query("installed"), &facts());
        assert_eq!(change_ids(&plan), [format!("file:{DROP_IN}")]);
    }

    #[test]
    fn validates_the_drop_in_with_apt_config() {
        let dir = root(None);
        let fs = AsRoot::new(dir.path());
        let runner = FakeRunner::new();
        let resources = UpdatesAuto.plan(
            &facts(),
            Sys {
                fs: &fs,
                runner: &runner,
            },
        );
        let Some(Resource::File(file)) = resources.unwrap().pop() else {
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
        assert!(UpdatesAuto.notes(&facts).is_empty());

        facts.updates.as_mut().unwrap().units = Some(units("masked"));
        let dir = root(None);
        let plan = plan(&AsRoot::new(dir.path()), &dpkg_query("installed"), &facts);
        assert_eq!(
            plan.modules[0].notes,
            [
                "apt-daily-upgrade.timer is masked; vps-ready leaves apt's systemd units as \
                 they are, so the daily jobs stay off until they are turned back on"
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
            let fs = AsRoot::new(dir.path());
            let apt = Apt::new();
            let sys = Sys {
                fs: &fs,
                runner: &apt,
            };
            let facts = facts();
            let before = etc_tree(dir.path());

            let first = plan(&fs, &apt, &facts);
            assert_eq!(
                change_ids(&first),
                [
                    "package:unattended-upgrades".to_owned(),
                    format!("file:{DROP_IN}")
                ]
            );
            let state = StateDir::create(&fs, STATE, 0).unwrap();
            let engine = Engine::lock(&state, sys).unwrap();
            let outcome = engine.apply(&first).unwrap();
            let ApplyOutcome::Applied { txn } = outcome else {
                panic!("{outcome:?}");
            };
            let drop_in = String::from_utf8(fs.read(Path::new(DROP_IN)).unwrap()).unwrap();
            insta::assert_snapshot!("drop-in", drop_in);
            let after = format!("{STATE}/txn/{txn}/files/2.after");
            let validate = Cmd::new("apt-config").args(["-c", after.as_str(), "dump"]);
            assert!(
                apt.runner.calls().contains(&validate),
                "{:?}",
                apt.runner.calls()
            );

            assert!(change_ids(&plan(&fs, &apt, &facts)).is_empty());

            engine.rollback(Target::Last).unwrap();
            assert_eq!(etc_tree(dir.path()), before, "{existing:?}");
            assert!(apt.installed.load(Ordering::SeqCst));
        }
    }
}
