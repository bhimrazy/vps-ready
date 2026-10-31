//! `deploy.user` on [`FakeFs`], with the account tools and sudo simulated by
//! [`Debian`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Mutex;

use super::*;
use crate::engine::{self, ApplyOutcome, Deadman, Engine, Plan, Selected, StateDir, Target};
use crate::facts::SshdConfig;
use crate::facts::fixtures::host;
use crate::modules::UserAdmin;
use crate::resource::Package;
use crate::sys::fake::FakeFs;
use crate::sys::{Cmd, Fs, Output, Runner, SysError};

const STATE: &str = "/var/lib/vps-ready";
const BIN: &str = "/usr/local/bin/vps-ready";
const COMMAND: &str = "/usr/local/bin/deploy-app";
const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGdeploy ci@example.com";
const ADMIN_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGadmin me@example.com";

fn root(mode: u32) -> FileOwner {
    FileOwner {
        mode,
        uid: 0,
        gid: 0,
    }
}

/// The accounts on the simulated host, besides root.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Accounts {
    /// Name to uid, GECOS and supplementary groups.
    users: BTreeMap<String, (u32, String, Vec<String>)>,
    groups: BTreeSet<String>,
}

impl Accounts {
    fn with_user(mut self, name: &str, comment: &str) -> Self {
        let uid = 1001 + u32::try_from(self.users.len()).unwrap();
        self.users
            .insert(name.to_owned(), (uid, comment.to_owned(), Vec::new()));
        self.groups.insert(name.to_owned());
        self
    }

    fn with_group(mut self, name: &str) -> Self {
        self.groups.insert(name.to_owned());
        self
    }
}

/// `getent`, `id`, `useradd`, `usermod`, `gpasswd`, `userdel`, `sudo -l`
/// and `visudo` on a [`FakeFs`]. `useradd` creates the home directory;
/// `userdel` keeps it.
struct Debian<'a> {
    fs: &'a FakeFs,
    accounts: Mutex<Accounts>,
    calls: Mutex<Vec<Cmd>>,
}

impl<'a> Debian<'a> {
    fn new(fs: &'a FakeFs, accounts: Accounts) -> Self {
        Self {
            fs,
            accounts: Mutex::new(accounts),
            calls: Mutex::default(),
        }
    }

    fn accounts(&self) -> Accounts {
        self.accounts.lock().unwrap().clone()
    }

    fn calls(&self, program: &str) -> Vec<Vec<String>> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.program == program)
            .map(|c| c.args.clone())
            .collect()
    }
}

fn exit(status: i32) -> Output {
    Output {
        status,
        ..Output::default()
    }
}

/// The value after `flag` in `args`.
fn flag<'a>(args: &[&'a str], flag: &str) -> Option<&'a str> {
    args.iter().position(|a| *a == flag).map(|i| args[i + 1])
}

impl Runner for Debian<'_> {
    fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
        self.calls.lock().unwrap().push(cmd.clone());
        let mut acc = self.accounts.lock().unwrap();
        let args: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        let last = args.last().copied().unwrap_or_default();
        let out = match (cmd.program.as_str(), &args[..]) {
            ("getent", ["passwd", name]) => match acc.users.get(*name) {
                Some((uid, comment, _)) => Output::success(format!(
                    "{name}:x:{uid}:{uid}:{comment}:/home/{name}:/bin/bash\n"
                )),
                None => exit(2),
            },
            ("getent", ["group", name]) if acc.groups.contains(*name) => {
                Output::success(format!("{name}:x:1500:\n"))
            }
            ("getent", ["group", _]) => exit(2),
            ("id", ["-Gn", name]) => {
                let (_, _, groups) = &acc.users[*name];
                Output::success(format!("{name} {}\n", groups.join(" ")))
            }
            ("useradd", _) => {
                let uid = 1001 + u32::try_from(acc.users.len()).unwrap();
                let groups = flag(&args, "--groups")
                    .map(|g| g.split(',').map(str::to_owned).collect())
                    .unwrap_or_default();
                let comment = flag(&args, "--comment").unwrap_or_default().to_owned();
                acc.users.insert(last.to_owned(), (uid, comment, groups));
                acc.groups.insert(last.to_owned());
                let owner = FileOwner {
                    mode: 0o750,
                    uid,
                    gid: uid,
                };
                self.fs
                    .create_dir(&Path::new("/home").join(last), owner)
                    .unwrap();
                Output::success("")
            }
            ("usermod", ["--append", "--groups", group, name]) => {
                let groups = &mut acc.users.get_mut(*name).unwrap().2;
                groups.extend(group.split(',').map(str::to_owned));
                Output::success("")
            }
            ("gpasswd", ["--delete", name, group]) => {
                acc.users.get_mut(*name).unwrap().2.retain(|g| g != group);
                Output::success("")
            }
            ("userdel", [name]) => {
                acc.users.remove(*name);
                acc.groups.remove(*name);
                Output::success("")
            }
            ("sudo", ["-n", "-l", "-U", name]) => {
                let rules = self
                    .fs
                    .read(Path::new(SUDOERS))
                    .is_ok_and(|b| String::from_utf8_lossy(&b).contains(&format!("\n{name} ALL")));
                Output::success(if rules {
                    format!(
                        "User {name} may run the following commands on vps:\n    (root) NOPASSWD: {COMMAND} \"\"\n"
                    )
                } else {
                    format!("User {name} is not allowed to run sudo on vps.\n")
                })
            }
            ("visudo", _) => Output::success(""),
            (other, _) => return Err(SysError::NotFound(other.to_owned())),
        };
        Ok(out)
    }
}

/// A Debian host with sudo and a root-owned deploy command.
fn fs() -> FakeFs {
    let fs = FakeFs::new()
        .with_dir("/home", root(0o755))
        .with_dir(SUDOERS_DIR, root(0o755))
        .with_file(BIN, "\x7fELF")
        .with_file(COMMAND, "#!/bin/sh\n");
    fs.write_atomic(Path::new(COMMAND), b"#!/bin/sh\n", root(0o755))
        .unwrap();
    fs
}

fn facts() -> Facts {
    host("debian-13", &[])
}

fn table(text: &str) -> toml::Table {
    toml::from_str(text).unwrap()
}

/// The params with [`KEY`] and `extra` lines.
fn params(extra: &str) -> toml::Table {
    table(&format!("keys = [\"{KEY}\"]\n{extra}"))
}

fn plan_steps(
    fs: &FakeFs,
    runner: &Debian,
    planned: &[Resource],
    params: &toml::Table,
) -> Result<ModuleSteps, ModuleError> {
    DeployUser.plan(
        &PlanCx {
            facts: &facts(),
            params,
            planned,
        },
        Sys { fs, runner },
    )
}

fn refusal(result: Result<ModuleSteps, ModuleError>) -> String {
    match result {
        Err(ModuleError::Refused(reason)) => reason,
        Ok(_) => panic!("planned instead of refusing"),
        Err(e) => panic!("failed with another error: {e}"),
    }
}

fn plan<'a>(fs: &FakeFs, runner: &Debian, facts: &'a Facts, params: &'a toml::Table) -> Plan<'a> {
    let selected = Selected {
        module: &DeployUser,
        params,
    };
    engine::plan(&[selected], facts, Sys { fs, runner }).unwrap()
}

fn change_ids(plan: &Plan) -> Vec<String> {
    plan.steps().map(|s| s.change.id.clone()).collect()
}

/// Every file under `/etc` and `/home`, with its bytes.
fn tree(fs: &FakeFs) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(fs: &FakeFs, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for path in fs.read_dir(dir).unwrap() {
            match fs.read(&path) {
                Ok(bytes) => {
                    out.insert(path, bytes);
                }
                Err(_) => walk(fs, &path, out),
            }
        }
    }
    let mut out = BTreeMap::new();
    for dir in ["/etc", "/home"] {
        walk(fs, Path::new(dir), &mut out);
    }
    out
}

#[test]
fn applies_on_debian_without_the_dead_man() {
    let mut facts = facts();
    assert_eq!(DeployUser.applicable(&facts), Applicability::Applicable);
    assert!(!DeployUser.needs_deadman());
    assert!(!DeployUser.keys_admins());
    facts.os.family = OsFamily::Alpine;
    assert_eq!(
        DeployUser.applicable(&facts),
        Applicability::NotApplicable {
            reason: "the deploy account is set up only on Debian and Ubuntu so far".into()
        }
    );
}

#[test]
fn the_sudoers_file_is_read_by_sudo() {
    let name = Path::new(SUDOERS).file_name().unwrap().to_str().unwrap();
    assert!(!name.contains('.') && !name.ends_with('~'), "{name}");
    assert_eq!(Path::new(SUDOERS).parent(), Some(Path::new(SUDOERS_DIR)));
}

#[test]
fn params_are_checked() {
    let full = params(&format!(
        "name = \"ci\"\ncommand = \"{COMMAND}\"\ndocker = true\n"
    ));
    DeployUser.check_params(&full).unwrap();
    let typo = DeployUser
        .check_params(&params("dockr = true"))
        .unwrap_err();
    assert!(typo.to_string().contains("unknown field `dockr`"), "{typo}");
    // A key that already has options, which would be doubled.
    let restricted = table(&format!("keys = [\"no-pty {KEY}\"]"));
    let err = DeployUser.check_params(&restricted).unwrap_err();
    assert!(
        err.to_string()
            .contains("is not a public key line without options"),
        "{err}"
    );
    let err = DeployUser
        .check_params(&table("keys = [\"not a key\"]"))
        .unwrap_err();
    assert!(err.to_string().contains("without options"), "{err}");
}

#[test]
fn keys_are_required() {
    let fs = fs();
    let runner = Debian::new(&fs, Accounts::default());
    for params in [toml::Table::new(), table("keys = []")] {
        assert_eq!(
            refusal(plan_steps(&fs, &runner, &[], &params)),
            "`keys` is empty; set the public keys CI logs in with for deploy.user in a profile"
        );
    }
}

#[test]
fn without_command_keys_are_restricted_and_there_is_no_sudo() {
    let fs = fs();
    let runner = Debian::new(&fs, Accounts::default());
    // `command = ""`, its documented default, is the same as none.
    for params in [params(""), params("command = \"\"")] {
        let steps = plan_steps(&fs, &runner, &[], &params).unwrap();
        assert_eq!(
            steps.resources,
            [
                Resource::User(User {
                    name: "deploy".into(),
                    groups: Vec::new(),
                    password: Password::Locked,
                    comment: Some(COMMENT.into()),
                }),
                Resource::AuthorizedKeys(AuthorizedKeys {
                    user: "deploy".into(),
                    keys: vec![format!("restrict {KEY}")],
                }),
            ]
        );
        assert!(steps.notes.is_empty(), "{:?}", steps.notes);
    }
}

#[test]
fn with_command_keys_are_forced_and_sudo_allows_only_it() {
    let fs = fs();
    let runner = Debian::new(&fs, Accounts::default());
    let params = params(&format!("command = \"{COMMAND}\""));
    let steps = plan_steps(&fs, &runner, &[], &params).unwrap();
    let [_, Resource::AuthorizedKeys(keys), Resource::File(drop_in)] = &steps.resources[..] else {
        panic!("{:?}", steps.resources);
    };
    assert_eq!(keys.keys, [format!("restrict,command=\"{COMMAND}\" {KEY}")]);
    assert_eq!(drop_in.path, Path::new(SUDOERS));
    assert_eq!(drop_in.owner, root(0o440));
    assert_eq!(
        drop_in.validate,
        Some(Validate::new("visudo", ["-cf", Validate::PATH]))
    );
    insta::assert_snapshot!(
        "sudoers",
        String::from_utf8(drop_in.content.clone()).unwrap()
    );
}

#[test]
fn docker_adds_the_group_and_says_it_is_root() {
    let fs = fs();
    let runner = Debian::new(&fs, Accounts::default().with_group("docker"));
    let steps = plan_steps(&fs, &runner, &[], &params("docker = true")).unwrap();
    let Resource::User(user) = &steps.resources[0] else {
        panic!("{:?}", steps.resources);
    };
    assert_eq!(user.groups, ["docker"]);
    assert_eq!(
        steps.notes,
        [
            "docker = true: deploy joins the docker group, which is root access: it can start \
          a container that mounts / and change anything on this host"
        ]
    );

    // No docker group, and no Docker planned before this module.
    let runner = Debian::new(&fs, Accounts::default());
    assert_eq!(
        refusal(plan_steps(&fs, &runner, &[], &params("docker = true"))),
        "`docker = true`, but there is no docker group; install Docker first"
    );
    // Docker installed by the same plan creates the group first.
    let docker = [Resource::Package(Package {
        name: "docker-ce".into(),
    })];
    plan_steps(&fs, &runner, &docker, &params("docker = true")).unwrap();
}

#[test]
fn a_command_root_does_not_own_alone_is_refused() {
    let fs = fs();
    let runner = Debian::new(&fs, Accounts::default());
    let with = |command: &str| params(&format!("command = \"{command}\""));

    fs.write_atomic(Path::new(COMMAND), b"#!/bin/sh\n", root(0o775))
        .unwrap();
    assert_eq!(
        refusal(plan_steps(&fs, &runner, &[], &with(COMMAND))),
        "`command` /usr/local/bin/deploy-app cannot be used: /usr/local/bin/deploy-app is \
         writable by group or others (mode 0775). It must be an absolute path to a file that \
         root owns and only root can write, since deploy may run it as root"
    );
    let owner = FileOwner {
        mode: 0o755,
        uid: 1000,
        gid: 1000,
    };
    fs.write_atomic(Path::new(COMMAND), b"#!/bin/sh\n", owner)
        .unwrap();
    assert!(
        refusal(plan_steps(&fs, &runner, &[], &with(COMMAND)))
            .contains("is owned by uid 1000, not root")
    );
    for (command, why) in [
        ("deploy-app", "not an absolute path"),
        ("/usr/local/bin/deploy app", "not an absolute path"),
        ("/home/ci/deploy-app", "it is under /home"),
        (
            "/usr/local/bin/missing",
            "cannot check /usr/local/bin/missing",
        ),
    ] {
        let reason = refusal(plan_steps(&fs, &runner, &[], &with(command)));
        assert!(reason.contains(why), "{command}: {reason}");
    }
}

#[test]
fn the_admins_name_is_refused() {
    let fs = fs();
    let runner = Debian::new(&fs, Accounts::default());
    let admin_params = table(&format!("authorized_keys = [\"{ADMIN_KEY}\"]"));
    let admin = UserAdmin
        .plan(
            &PlanCx {
                facts: &facts(),
                params: &admin_params,
                planned: &[],
            },
            Sys {
                fs: &fs,
                runner: &runner,
            },
        )
        .unwrap();
    assert_eq!(
        refusal(plan_steps(
            &fs,
            &runner,
            &admin.resources,
            &params("name = \"admin\"")
        )),
        "user.admin in this profile sets up admin as the admin; give deploy.user another `name`"
    );
    plan_steps(&fs, &runner, &admin.resources, &params("")).unwrap();
}

/// With `user.admin` in the same plan, only the admin may confirm.
#[test]
fn the_deploy_user_does_not_confirm() {
    let fs = fs();
    let runner = Debian::new(&fs, Accounts::default());
    let facts = facts();
    let admin = table(&format!("authorized_keys = [\"{ADMIN_KEY}\"]"));
    let deploy = params("");
    let selected = [
        Selected {
            module: &UserAdmin,
            params: &admin,
        },
        Selected {
            module: &DeployUser,
            params: &deploy,
        },
    ];
    let plan = engine::plan(
        &selected,
        &facts,
        Sys {
            fs: &fs,
            runner: &runner,
        },
    )
    .unwrap();
    assert!(change_ids(&plan).contains(&"authorized-keys:deploy".to_owned()));
    assert_eq!(plan.admins(), ["admin"]);
}

#[test]
fn an_existing_account_it_did_not_create_is_refused() {
    let fs = fs();
    let runner = Debian::new(&fs, Accounts::default().with_user("deploy", "Deploy,,,"));
    assert_eq!(
        refusal(plan_steps(&fs, &runner, &[], &params(""))),
        "deploy already exists, and deploy.user did not create it, so it does not get \
         restricted keys or the docker group; set `name` to a new account"
    );
    // Its own account, from an earlier apply, is kept up to date.
    let runner = Debian::new(&fs, Accounts::default().with_user("deploy", COMMENT));
    plan_steps(&fs, &runner, &[], &params("")).unwrap();

    let runner = Debian::new(&fs, Accounts::default().with_group("deploy"));
    assert!(
        refusal(plan_steps(&fs, &runner, &[], &params("")))
            .starts_with("a group named deploy exists, but no user")
    );
    assert_eq!(
        refusal(plan_steps(&fs, &runner, &[], &params("name = \"root\""))),
        "`name` is root; the deploy user must be another account"
    );
}

#[test]
fn star_password_only_when_usepam_is_off() {
    let fs = fs();
    let runner = Debian::new(&fs, Accounts::default());
    let mut facts = facts();
    facts.ssh.effective = Some(SshdConfig::parse("usepam no\n"));
    let params = params("");
    let steps = DeployUser
        .plan(
            &PlanCx {
                facts: &facts,
                params: &params,
                planned: &[],
            },
            Sys {
                fs: &fs,
                runner: &runner,
            },
        )
        .unwrap();
    let Resource::User(user) = &steps.resources[0] else {
        panic!("{:?}", steps.resources);
    };
    assert_eq!(user.password, Password::Star);
}

#[test]
fn first_plan_snapshot() {
    let fs = fs();
    let runner = Debian::new(&fs, Accounts::default().with_group("docker"));
    let facts = facts();
    let params = params(&format!("command = \"{COMMAND}\"\ndocker = true"));
    insta::assert_yaml_snapshot!(plan(&fs, &runner, &facts, &params));
}

/// Apply creates the account with its marker, the restricted keys and the
/// drop-in, without the dead-man switch; the next plan is empty; a rollback
/// removes all but the home directory. The deploy user is not an admin who
/// may confirm.
#[test]
fn creates_the_deploy_user_and_rolls_back() {
    let fs = fs();
    let runner = Debian::new(&fs, Accounts::default());
    let facts = facts();
    let params = params(&format!("command = \"{COMMAND}\""));
    let before = tree(&fs);

    let first = plan(&fs, &runner, &facts, &params);
    assert_eq!(
        change_ids(&first),
        [
            "user:deploy",
            "authorized-keys:deploy",
            &format!("file:{SUDOERS}")
        ]
    );
    assert!(!first.needs_deadman());
    assert!(first.admins().is_empty(), "{:?}", first.admins());

    let state = StateDir::create(&fs, STATE, 0).unwrap();
    let engine = Engine::lock(
        &state,
        Sys {
            fs: &fs,
            runner: &runner,
        },
    )
    .unwrap();
    let deadman = Deadman {
        window: crate::engine::deadman::DEFAULT_WINDOW,
        binary: BIN.into(),
    };
    let outcome = engine.apply(&first, &deadman, &mut |_| {}).unwrap();
    assert!(
        matches!(outcome, ApplyOutcome::Applied { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        runner.calls("useradd"),
        [[
            "--create-home",
            "--user-group",
            "--shell",
            "/bin/bash",
            "--comment",
            COMMENT,
            "deploy"
        ]]
    );
    let visudo = runner.calls("visudo");
    assert_eq!(visudo.len(), 1, "{visudo:?}");
    assert!(visudo[0][1].ends_with(".after"), "{visudo:?}");
    assert_eq!(
        fs.read(Path::new("/home/deploy/.ssh/authorized_keys"))
            .unwrap(),
        format!("restrict,command=\"{COMMAND}\" {KEY}\n").as_bytes()
    );
    // Verify asked sudo for the rule.
    assert_eq!(runner.calls("sudo"), [["-n", "-l", "-U", "deploy"]]);

    let next = plan(&fs, &runner, &facts, &params);
    assert!(change_ids(&next).is_empty(), "{:?}", change_ids(&next));

    engine.rollback(Target::Last, &mut |_| {}).unwrap();
    assert!(runner.accounts().users.is_empty());
    let mut after = tree(&fs);
    after.retain(|p, _| !p.starts_with("/home/deploy"));
    assert!(!fs.exists(Path::new("/home/deploy/.ssh")));
    assert_eq!(after, before);
}

#[test]
fn verify_fails_without_the_sudo_rule() {
    let fs = fs();
    let runner = Debian::new(&fs, Accounts::default().with_user("deploy", COMMENT));
    let params = params(&format!("command = \"{COMMAND}\""));
    let facts = facts();
    let cx = PlanCx {
        facts: &facts,
        params: &params,
        planned: &[],
    };
    let sys = Sys {
        fs: &fs,
        runner: &runner,
    };
    assert_eq!(
        DeployUser.verify(&cx, sys),
        Err("`sudo -l -U deploy` lists no rules for deploy".into())
    );
    // Without `command` there is no rule to look for.
    let params = super::tests::params("");
    let cx = PlanCx {
        params: &params,
        ..cx
    };
    assert_eq!(DeployUser.verify(&cx, sys), Ok(()));
}
