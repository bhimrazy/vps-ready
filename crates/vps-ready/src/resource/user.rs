//! The [`User`] resource.

use std::path::PathBuf;

use super::{Backup, ResourceError, failed, plain_name, run};
use crate::sys::{Cmd, Sys};

/// A login account that must exist and be in `groups`. A missing one is
/// created with `useradd --create-home --user-group --shell /bin/bash`; an
/// existing one only gains the groups it lacks, and its password field is
/// never touched.
///
/// Rollback removes a created account with `userdel`, which keeps its home
/// directory. Locking an account is not used anywhere: with `UsePAM yes`, a
/// locked account still accepts SSH key logins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// User name.
    pub name: String,
    /// Supplementary groups, which must exist.
    pub groups: Vec<String>,
    /// Password field of a created account.
    pub password: Password,
}

/// The password field `useradd` gives a created account. Neither allows a
/// password login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Password {
    /// `!`, `useradd`'s default: locked.
    Locked,
    /// `*`: not locked, for an sshd with `UsePAM no`, which refuses key
    /// logins to a locked account.
    Star,
}

/// An entry of the user database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) home: PathBuf,
    /// Login shell; empty when the entry has none.
    pub(crate) shell: String,
}

impl User {
    /// The summary of the change, or `None`.
    pub(super) fn diff(&self, sys: Sys) -> Result<Option<(String, Option<String>)>, ResourceError> {
        self.check_names()?;
        if lookup(sys, &self.name)?.is_none() {
            let mut extra = Vec::new();
            if !self.groups.is_empty() {
                extra.push(format!("groups {}", self.groups.join(",")));
            }
            if self.password == Password::Star {
                extra.push("password *".to_owned());
            }
            let extra = if extra.is_empty() {
                String::new()
            } else {
                format!(" ({})", extra.join("; "))
            };
            return Ok(Some((format!("create user {}{extra}", self.name), None)));
        }
        let missing = self.missing_groups(sys)?;
        Ok((!missing.is_empty()).then(|| {
            (
                format!("add {} to groups {}", self.name, missing.join(",")),
                None,
            )
        }))
    }

    pub(super) fn snapshot(&self, sys: Sys) -> Result<Backup, ResourceError> {
        self.check_names()?;
        let created = lookup(sys, &self.name)?.is_none();
        let added_groups = if created {
            self.groups.clone()
        } else {
            self.missing_groups(sys)?
        };
        Ok(Backup::User {
            name: self.name.clone(),
            created,
            added_groups,
        })
    }

    /// Creates the account or adds the groups; returns the uid of a created
    /// account.
    pub(super) fn apply(&self, sys: Sys) -> Result<Option<u32>, ResourceError> {
        self.check_names()?;
        if lookup(sys, &self.name)?.is_none() {
            let mut cmd =
                Cmd::new("useradd").args(["--create-home", "--user-group", "--shell", "/bin/bash"]);
            if !self.groups.is_empty() {
                cmd = cmd.args(["--groups", &self.groups.join(",")]);
            }
            if self.password == Password::Star {
                cmd = cmd.args(["--password", "*"]);
            }
            run(sys, &cmd.arg(&self.name))?;
            return Ok(lookup(sys, &self.name)?.map(|e| e.uid));
        }
        let missing = self.missing_groups(sys)?;
        if !missing.is_empty() {
            let cmd = Cmd::new("usermod").args(["--append", "--groups", &missing.join(",")]);
            run(sys, &cmd.arg(&self.name))?;
        }
        Ok(None)
    }

    fn check_names(&self) -> Result<(), ResourceError> {
        check_name("user", &self.name)?;
        self.groups.iter().try_for_each(|g| check_name("group", g))
    }

    /// `groups` the existing account is not in, in order.
    fn missing_groups(&self, sys: Sys) -> Result<Vec<String>, ResourceError> {
        let current = groups(sys, &self.name)?;
        let mut missing: Vec<String> = Vec::new();
        for g in &self.groups {
            if !current.contains(g) && !missing.contains(g) {
                missing.push(g.clone());
            }
        }
        Ok(missing)
    }
}

/// Removes a created account (already gone is fine), or takes an existing
/// one out of the groups apply added it to.
pub(super) fn restore(
    sys: Sys,
    name: &str,
    created: bool,
    added_groups: &[String],
) -> Result<(), ResourceError> {
    check_name("user", name)?;
    if lookup(sys, name)?.is_none() {
        return Ok(());
    }
    if created {
        run(sys, &Cmd::new("userdel").arg(name))?;
        return Ok(());
    }
    let current = groups(sys, name)?;
    for g in added_groups.iter().filter(|g| current.contains(g)) {
        check_name("group", g)?;
        run(sys, &Cmd::new("gpasswd").args(["--delete", name, g]))?;
    }
    Ok(())
}

/// The safety check. A created account is unchanged if it is already gone,
/// or still has `uid`, the uid apply journaled for it; without one (a crash
/// before the `applied` line), any account of that name counts. An existing
/// one is unchanged if it is in all of the added groups or in none of them.
pub(crate) fn unchanged(
    sys: Sys,
    backup: &Backup,
    uid: Option<u32>,
) -> Result<bool, ResourceError> {
    let Backup::User {
        name,
        created,
        added_groups,
    } = backup
    else {
        return Ok(false);
    };
    check_name("user", name)?;
    let Some(entry) = lookup(sys, name)? else {
        return Ok(true);
    };
    if *created {
        // No uid (a journal from before 0.3, or a crash between `useradd`
        // and the `applied` line): the name is all there is to go by.
        return Ok(uid.is_none_or(|uid| uid == entry.uid));
    }
    let current = groups(sys, name)?;
    let in_group = |g: &String| current.contains(g);
    Ok(added_groups.iter().all(in_group) || !added_groups.iter().any(in_group))
}

/// How to restore `backup` by hand; `None` if apply changed nothing.
pub(crate) fn by_hand(backup: &Backup) -> Option<String> {
    let Backup::User {
        name,
        created,
        added_groups,
    } = backup
    else {
        return None;
    };
    if *created {
        return Some(format!("pkill -u {name}; userdel {name}"));
    }
    let steps: Vec<String> = added_groups
        .iter()
        .map(|g| format!("gpasswd -d {name} {g}"))
        .collect();
    (!steps.is_empty()).then(|| steps.join("; "))
}

/// The account's entry from `getent passwd`; `None` if there is none.
pub(crate) fn lookup(sys: Sys, name: &str) -> Result<Option<Entry>, ResourceError> {
    check_name("user", name)?;
    let out = sys.runner.run(&Cmd::new("getent").args(["passwd", name]))?;
    match out.status {
        0 => {}
        // The key was not found.
        2 => return Ok(None),
        _ => return Err(failed("getent", &out)),
    }
    let text = out.stdout_str()?;
    let fields: Vec<&str> = text.trim_end().split(':').collect();
    let entry = match fields[..] {
        [n, _, uid, gid, _, home, shell] if n == name && home.starts_with('/') => uid
            .parse()
            .ok()
            .zip(gid.parse().ok())
            .map(|(uid, gid)| Entry {
                uid,
                gid,
                home: PathBuf::from(home),
                shell: shell.to_owned(),
            }),
        _ => None,
    };
    entry.map(Some).ok_or_else(|| ResourceError::Unexpected {
        program: "getent".to_owned(),
        output: text.to_owned(),
    })
}

/// The names of the groups `name` is in, primary group included.
fn groups(sys: Sys, name: &str) -> Result<Vec<String>, ResourceError> {
    let out = run(sys, &Cmd::new("id").args(["-Gn", name]))?;
    Ok(out
        .stdout_str()?
        .split_whitespace()
        .map(str::to_owned)
        .collect())
}

fn check_name(kind: &'static str, name: &str) -> Result<(), ResourceError> {
    if plain_name(name) {
        Ok(())
    } else {
        Err(ResourceError::InvalidName {
            kind,
            name: name.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::super::{Change, Resource, Reversibility, restore};
    use super::*;
    use crate::sys::Output;
    use crate::sys::fake::{FakeFs, FakeRunner};

    const TXN: &str = "/var/lib/vps-ready/txn/20261023T114246Z";
    const ENTRY: &str = "admin:x:1001:1001::/home/admin:/bin/bash\n";

    fn user(groups: &[&str], password: Password) -> Resource {
        Resource::User(User {
            name: "admin".into(),
            groups: groups.iter().map(|&g| g.to_owned()).collect(),
            password,
        })
    }

    fn exit(status: i32) -> Output {
        Output {
            status,
            ..Output::default()
        }
    }

    /// A runner for a host where `admin` is missing.
    fn missing() -> FakeRunner {
        FakeRunner::new().on("getent", ["passwd"], exit(2)).on(
            "useradd",
            Vec::<String>::new(),
            Output::success(""),
        )
    }

    /// A runner for a host where `admin` exists in `groups`.
    fn existing(groups: &str) -> FakeRunner {
        FakeRunner::new()
            .on("getent", ["passwd"], Output::success(ENTRY))
            .on("id", ["-Gn"], Output::success(format!("{groups}\n")))
            .on("usermod", Vec::<String>::new(), Output::success(""))
            .on("gpasswd", Vec::<String>::new(), Output::success(""))
            .on("userdel", Vec::<String>::new(), Output::success(""))
    }

    fn sys<'a>(fs: &'a FakeFs, runner: &'a FakeRunner) -> Sys<'a> {
        Sys { fs, runner }
    }

    fn getent() -> Cmd {
        Cmd::new("getent").args(["passwd", "admin"])
    }

    fn id() -> Cmd {
        Cmd::new("id").args(["-Gn", "admin"])
    }

    #[test]
    fn diff_creates_a_missing_user() {
        let fs = FakeFs::new();
        let runner = missing();
        let change = user(&["sudo"], Password::Locked)
            .diff(sys(&fs, &runner))
            .unwrap();
        assert_eq!(
            change,
            Some(Change {
                id: "user:admin".into(),
                summary: "create user admin (groups sudo)".into(),
                diff: None,
                reversibility: Reversibility::Partial,
            })
        );
        let summary = user(&[], Password::Star)
            .diff(sys(&fs, &runner))
            .unwrap()
            .unwrap()
            .summary;
        assert_eq!(summary, "create user admin (password *)");
        assert_eq!(runner.calls(), [getent(), getent()]);
    }

    #[test]
    fn diff_adds_missing_groups_only() {
        let fs = FakeFs::new();
        let runner = existing("admin users");
        let summary = user(&["sudo", "users", "adm"], Password::Locked)
            .diff(sys(&fs, &runner))
            .unwrap()
            .map(|c| c.summary);
        assert_eq!(summary.as_deref(), Some("add admin to groups sudo,adm"));
        assert_eq!(runner.calls(), [getent(), id()]);

        let runner = existing("admin sudo");
        let diff = user(&["sudo"], Password::Star)
            .diff(sys(&fs, &runner))
            .unwrap();
        assert_eq!(diff, None);
    }

    #[test]
    fn apply_creates_with_a_locked_password_by_default() {
        let fs = FakeFs::new();
        let runner = missing();
        user(&["sudo", "adm"], Password::Locked)
            .apply(sys(&fs, &runner))
            .unwrap();
        assert_eq!(
            runner.calls(),
            [
                getent(),
                Cmd::new("useradd").args([
                    "--create-home",
                    "--user-group",
                    "--shell",
                    "/bin/bash",
                    "--groups",
                    "sudo,adm",
                    "admin",
                ]),
                getent(),
            ]
        );
    }

    #[test]
    fn apply_returns_the_uid_of_a_created_account() {
        /// `getent` finds `admin` once `useradd` ran.
        struct Created(std::sync::Mutex<bool>);
        impl crate::sys::Runner for Created {
            fn run(&self, cmd: &Cmd) -> Result<Output, crate::sys::SysError> {
                let mut created = self.0.lock().unwrap();
                match cmd.program.as_str() {
                    "useradd" => *created = true,
                    "getent" if *created => return Ok(Output::success(ENTRY)),
                    _ => return Ok(exit(2)),
                }
                Ok(Output::success(""))
            }
        }
        let fs = FakeFs::new();
        let created = Created(std::sync::Mutex::new(false));
        let applied = user(&[], Password::Locked)
            .apply(Sys {
                fs: &fs,
                runner: &created,
            })
            .unwrap();
        assert_eq!(applied.uid, Some(1001));
        // An existing account was not created: no uid.
        let runner = existing("admin");
        let applied = user(&[], Password::Locked)
            .apply(sys(&fs, &runner))
            .unwrap();
        assert_eq!(applied.uid, None);
    }

    #[test]
    fn apply_creates_with_star_when_asked() {
        let fs = FakeFs::new();
        let runner = missing();
        user(&[], Password::Star).apply(sys(&fs, &runner)).unwrap();
        assert_eq!(
            runner.calls()[1],
            Cmd::new("useradd").args([
                "--create-home",
                "--user-group",
                "--shell",
                "/bin/bash",
                "--password",
                "*",
                "admin",
            ])
        );
    }

    #[test]
    fn apply_never_touches_an_existing_password() {
        let fs = FakeFs::new();
        let runner = existing("admin");
        user(&["sudo"], Password::Star)
            .apply(sys(&fs, &runner))
            .unwrap();
        assert_eq!(
            runner.calls(),
            [
                getent(),
                id(),
                Cmd::new("usermod").args(["--append", "--groups", "sudo", "admin"]),
            ]
        );
    }

    #[test]
    fn names_that_could_be_options_are_refused() {
        let fs = FakeFs::new();
        let runner = FakeRunner::new();
        for (name, group) in [("-r", "sudo"), ("Admin", "sudo"), ("admin", "--help")] {
            let resource = Resource::User(User {
                name: name.into(),
                groups: vec![group.into()],
                password: Password::Locked,
            });
            let err = resource.diff(sys(&fs, &runner)).unwrap_err();
            assert!(matches!(err, ResourceError::InvalidName { .. }), "{err:?}");
            assert!(resource.apply(sys(&fs, &runner)).is_err());
        }
        assert_eq!(runner.calls(), []);
    }

    #[test]
    fn snapshot_records_what_apply_adds() {
        let fs = FakeFs::new();
        let txn = Path::new(TXN);
        let created = user(&["sudo"], Password::Locked)
            .snapshot(sys(&fs, &missing()), txn, 1)
            .unwrap();
        assert_eq!(
            created,
            Backup::User {
                name: "admin".into(),
                created: true,
                added_groups: vec!["sudo".into()],
            }
        );
        let existing = user(&["sudo", "admin"], Password::Locked)
            .snapshot(sys(&fs, &existing("admin")), txn, 1)
            .unwrap();
        assert_eq!(
            existing,
            Backup::User {
                name: "admin".into(),
                created: false,
                added_groups: vec!["sudo".into()],
            }
        );
    }

    #[test]
    fn restore_removes_a_created_user_but_not_its_home() {
        let fs = FakeFs::new();
        let runner = existing("admin sudo");
        let backup = Backup::User {
            name: "admin".into(),
            created: true,
            added_groups: vec!["sudo".into()],
        };
        restore(sys(&fs, &runner), Path::new(TXN), &backup).unwrap();
        assert_eq!(runner.calls(), [getent(), Cmd::new("userdel").arg("admin")]);

        // Already gone, e.g. on a resumed rollback.
        let runner = missing();
        restore(sys(&fs, &runner), Path::new(TXN), &backup).unwrap();
        assert_eq!(runner.calls(), [getent()]);
    }

    #[test]
    fn restore_reports_a_userdel_that_fails() {
        let fs = FakeFs::new();
        let runner = FakeRunner::new()
            .on("getent", ["passwd"], Output::success(ENTRY))
            .on(
                "userdel",
                Vec::<String>::new(),
                Output {
                    status: 8,
                    stdout: Vec::new(),
                    stderr: b"userdel: user admin is currently used by process 4242\n".to_vec(),
                },
            );
        let backup = Backup::User {
            name: "admin".into(),
            created: true,
            added_groups: Vec::new(),
        };
        let err = restore(sys(&fs, &runner), Path::new(TXN), &backup).unwrap_err();
        assert_eq!(
            err.to_string(),
            "`userdel` exited with status 8: userdel: user admin is currently used by process 4242"
        );
        assert_eq!(
            by_hand(&backup).as_deref(),
            Some("pkill -u admin; userdel admin")
        );
    }

    #[test]
    fn restore_removes_only_the_added_groups_still_held() {
        let fs = FakeFs::new();
        let runner = existing("admin sudo");
        let backup = Backup::User {
            name: "admin".into(),
            created: false,
            added_groups: vec!["sudo".into(), "adm".into()],
        };
        restore(sys(&fs, &runner), Path::new(TXN), &backup).unwrap();
        assert_eq!(
            runner.calls(),
            [
                getent(),
                id(),
                Cmd::new("gpasswd").args(["--delete", "admin", "sudo"]),
            ]
        );
        assert_eq!(
            by_hand(&backup).as_deref(),
            Some("gpasswd -d admin sudo; gpasswd -d admin adm")
        );
    }

    #[test]
    fn unchanged_rules() {
        let fs = FakeFs::new();
        let added = Backup::User {
            name: "admin".into(),
            created: false,
            added_groups: vec!["sudo".into(), "adm".into()],
        };
        let check = |runner: FakeRunner, backup: &Backup| {
            unchanged(sys(&fs, &runner), backup, None).unwrap()
        };
        assert!(check(existing("admin sudo adm"), &added));
        assert!(check(existing("admin"), &added));
        assert!(!check(existing("admin sudo"), &added));
        assert!(check(missing(), &added));
        let created = Backup::User {
            name: "admin".into(),
            created: true,
            added_groups: Vec::new(),
        };
        assert!(check(existing("admin"), &created));
        assert!(check(missing(), &created));
        // With the uid apply journaled, another account of that name is a
        // change: its rollback must not `userdel` it.
        let with_uid =
            |runner: FakeRunner, uid| unchanged(sys(&fs, &runner), &created, Some(uid)).unwrap();
        assert!(with_uid(existing("admin"), 1001));
        assert!(!with_uid(existing("admin"), 1002));
        assert!(with_uid(missing(), 1002));
    }

    #[test]
    fn lookup_parses_an_entry() {
        let fs = FakeFs::new();
        let runner = existing("admin");
        assert_eq!(
            lookup(sys(&fs, &runner), "admin").unwrap(),
            Some(Entry {
                uid: 1001,
                gid: 1001,
                home: "/home/admin".into(),
                shell: "/bin/bash".into(),
            })
        );
        let runner = FakeRunner::new().on("getent", ["passwd"], Output::success("admin:x:1001\n"));
        assert!(lookup(sys(&fs, &runner), "admin").is_err());
    }
}
