//! `user.admin` on [`FakeFs`], with the account tools and sudo simulated by
//! [`Debian`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Mutex;

use super::*;
use crate::engine::{
    self, ApplyOutcome, Deadman, DeadmanOutcome, Engine, Event, Plan, RollbackReason, Selected,
    StateDir, Target,
};
use crate::facts::fixtures::host;
use crate::facts::{Session, SessionId, SshdConfig};
use crate::resource::sysctl::BOOT_ID;
use crate::sys::fake::FakeFs;
use crate::sys::{Fs, Output, Runner};

const STATE: &str = "/var/lib/vps-ready";
const BIN: &str = "/usr/local/bin/vps-ready";
const UPTIME: &str = "/proc/uptime";
const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtest me@laptop";
const ROOT_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGroot root@laptop";
/// What Ubuntu and AWS images put on root's key.
const RESTRICTED: &str = "no-port-forwarding,command=\"echo 'Please login as the user \
                          \\\"ubuntu\\\" rather than the user \\\"root\\\".';sleep 10\" \
                          ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGcloud cloud";
const HASH: &str = "$y$j9T$abc$def";

fn root_dir(mode: u32) -> FileOwner {
    FileOwner {
        mode,
        uid: 0,
        gid: 0,
    }
}

/// The accounts on the simulated host, besides root.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Accounts {
    /// Name to uid and supplementary groups.
    users: BTreeMap<String, (u32, Vec<String>)>,
    groups: BTreeSet<String>,
    /// Users with sudo rules from somewhere other than [`SUDOERS`] or the
    /// `sudo` group.
    sudoers: BTreeSet<String>,
    /// `sudo -l` lists no rules for anyone.
    broken_sudo: bool,
}

impl Accounts {
    fn with_user(mut self, name: &str, uid: u32) -> Self {
        self.users.insert(name.to_owned(), (uid, Vec::new()));
        self.groups.insert(name.to_owned());
        self
    }
}

/// `getent`, `id`, `useradd`, `usermod`, `gpasswd`, `userdel`, `sudo -l`,
/// `visudo`, `systemd-run` and `systemctl` on a [`FakeFs`]. `useradd`
/// creates the home directory; `userdel` keeps it.
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

fn exit(status: i32, stderr: &str) -> Output {
    Output {
        status,
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

impl Runner for Debian<'_> {
    fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
        self.calls.lock().unwrap().push(cmd.clone());
        let mut acc = self.accounts.lock().unwrap();
        let args: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        let last = args.last().copied().unwrap_or_default();
        let out = match (cmd.program.as_str(), &args[..]) {
            ("getent", ["passwd", "root"]) => Output::success("root:x:0:0:root:/root:/bin/bash\n"),
            ("getent", ["passwd", name]) => match acc.users.get(*name) {
                Some((uid, _)) => {
                    Output::success(format!("{name}:x:{uid}:{uid}::/home/{name}:/bin/bash\n"))
                }
                None => exit(2, ""),
            },
            ("getent", ["group", name]) if acc.groups.contains(*name) => {
                Output::success(format!("{name}:x:1500:\n"))
            }
            ("getent", ["group", _]) => exit(2, ""),
            ("id", ["-Gn", name]) => {
                let (_, groups) = &acc.users[*name];
                Output::success(format!("{name} {}\n", groups.join(" ")))
            }
            ("useradd", _) if acc.groups.contains(last) => exit(
                9,
                "useradd: group admin exists - if you want to add this user to that group, use -g.",
            ),
            ("useradd", _) => {
                let uid = 1001 + u32::try_from(acc.users.len()).unwrap();
                let groups = args
                    .iter()
                    .position(|a| *a == "--groups")
                    .map(|i| args[i + 1].split(',').map(str::to_owned).collect())
                    .unwrap_or_default();
                acc.users.insert(last.to_owned(), (uid, groups));
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
                let groups = &mut acc.users.get_mut(*name).unwrap().1;
                groups.extend(group.split(',').map(str::to_owned));
                Output::success("")
            }
            ("gpasswd", ["--delete", name, group]) => {
                acc.users.get_mut(*name).unwrap().1.retain(|g| g != group);
                Output::success("")
            }
            ("userdel", [name]) => {
                acc.users.remove(*name);
                acc.groups.remove(*name);
                Output::success("")
            }
            ("sudo", ["-n", "-l", "-U", name]) => {
                let Some((_, groups)) = acc.users.get(*name) else {
                    return Ok(exit(1, &format!("sudo: unknown user {name}")));
                };
                let drop_in = self
                    .fs
                    .read(Path::new(SUDOERS))
                    .is_ok_and(|b| String::from_utf8_lossy(&b).contains(&format!("\n{name} ALL")));
                let rules = !acc.broken_sudo
                    && (drop_in
                        || acc.sudoers.contains(*name)
                        || groups.iter().any(|g| g == "sudo"));
                Output::success(if rules {
                    format!(
                        "User {name} may run the following commands on vps:\n    (ALL : ALL) ALL\n"
                    )
                } else {
                    format!("User {name} is not allowed to run sudo on vps.\n")
                })
            }
            ("visudo" | "systemd-run" | "systemctl", _) => Output::success(""),
            (other, _) => return Err(SysError::NotFound(other.to_owned())),
        };
        Ok(out)
    }
}

/// A Debian host where root logs in with a cloud key it may not use and
/// one it may, and the dead-man switch can arm.
fn fs() -> FakeFs {
    let fs = FakeFs::new()
        .with_dir("/root", root_dir(0o700))
        .with_dir("/root/.ssh", root_dir(0o700))
        .with_file(
            "/root/.ssh/authorized_keys",
            format!("# keys\n{RESTRICTED}\n{ROOT_KEY}\n"),
        )
        .with_dir("/home", root_dir(0o755))
        .with_dir(SUDOERS_DIR, root_dir(0o755))
        .with_file(SHADOW, "root:*:20000:0:99999:7:::\n")
        .with_file(BOOT_ID, "a\n")
        .with_file(UPTIME, "1000.25 900.00\n")
        .with_file(BIN, "\x7fELF");
    fs.create_dir_all(Path::new("/etc/systemd/system"), 0o755)
        .unwrap();
    fs
}

/// The captured Debian 13 host (`UsePAM yes`), applied from root's session.
fn facts() -> Facts {
    let mut facts = host("debian-13", &[]);
    facts.session = Some(Session {
        id: SessionId {
            pid: 902,
            start: 4200,
        },
        client: "192.0.2.10:51234".parse().unwrap(),
        server: "198.51.100.5:22".parse().unwrap(),
        uid: 0,
        user: Some("root".into()),
    });
    facts
}

fn table(text: &str) -> toml::Table {
    toml::from_str(text).unwrap()
}

fn plan_steps(
    fs: &FakeFs,
    runner: &Debian,
    facts: &Facts,
    params: &str,
) -> Result<ModuleSteps, ModuleError> {
    let params = table(params);
    UserAdmin.plan(
        &PlanCx {
            facts,
            params: &params,
        },
        Sys { fs, runner },
    )
}

fn refusal(result: Result<ModuleSteps, ModuleError>) -> String {
    match result {
        Err(ModuleError::Refused(reason)) => reason,
        other => panic!("{other:?}"),
    }
}

fn plan<'a>(fs: &FakeFs, runner: &Debian, facts: &'a Facts, params: &'a toml::Table) -> Plan<'a> {
    let selected = Selected {
        module: &UserAdmin,
        params,
    };
    engine::plan(&[selected], facts, Sys { fs, runner }).unwrap()
}

fn change_ids(plan: &Plan) -> Vec<String> {
    plan.steps().map(|s| s.change.id.clone()).collect()
}

fn engine_on<'a>(fs: &'a FakeFs, runner: &'a Debian, state: &'a StateDir) -> Engine<'a> {
    Engine::lock(state, Sys { fs, runner }).unwrap()
}

fn deadman() -> Deadman {
    Deadman {
        window: crate::engine::deadman::DEFAULT_WINDOW,
        binary: BIN.into(),
    }
}

fn events(fs: &FakeFs, state: &StateDir, txn: &str) -> Vec<Event> {
    let txn = state
        .txns(fs)
        .unwrap()
        .into_iter()
        .find(|t| t.id() == txn)
        .unwrap();
    txn.read(fs).unwrap().into_iter().map(|r| r.event).collect()
}

/// Every file under `/etc`, `/root` and `/home`, with its bytes.
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
    for dir in ["/etc", "/root", "/home"] {
        walk(fs, Path::new(dir), &mut out);
    }
    out
}

#[test]
fn applies_only_on_debian_with_systemd() {
    let mut facts = facts();
    let module = UserAdmin;
    assert_eq!(module.applicable(&facts), Applicability::Applicable);
    assert!(module.needs_deadman());
    assert!(!module.force_restore());
    let reason = |facts: &Facts| match module.applicable(facts) {
        Applicability::NotApplicable { reason } => reason,
        Applicability::Applicable => panic!("applies"),
    };
    facts.init = Init::OpenRc;
    assert_eq!(
        reason(&facts),
        "the dead-man switch needs systemd, and systemd is not running"
    );
    facts.os.family = OsFamily::Alpine;
    assert_eq!(
        reason(&facts),
        "the admin account is set up only on Debian and Ubuntu so far"
    );
}

#[test]
fn params_are_checked() {
    let module = UserAdmin;
    let full = table(&format!(
        "name = \"deploy\"\nauthorized_keys = [\"{KEY}\"]\nsudo = \"password\"\n"
    ));
    module.check_params(&full).unwrap();
    module.check_params(&toml::Table::new()).unwrap();
    let typo = module
        .check_params(&table("sudo_mode = \"password\""))
        .unwrap_err();
    assert!(
        typo.to_string().contains("unknown field `sudo_mode`"),
        "{typo}"
    );
    let bad = module
        .check_params(&table("sudo = \"always\""))
        .unwrap_err();
    assert!(
        bad.to_string().contains("unknown variant `always`"),
        "{bad}"
    );
}

#[test]
fn the_sudoers_file_is_read_by_sudo() {
    let name = Path::new(SUDOERS).file_name().unwrap().to_str().unwrap();
    assert!(!name.contains('.') && !name.ends_with('~'), "{name}");
    assert_eq!(Path::new(SUDOERS).parent(), Some(Path::new(SUDOERS_DIR)));
}

#[test]
fn copies_root_keys_without_options() {
    let fs = fs();
    let runner = Debian::new(&fs, Accounts::default());
    let steps = plan_steps(&fs, &runner, &facts(), "").unwrap();
    let Resource::AuthorizedKeys(keys) = &steps.resources[1] else {
        panic!("{:?}", steps.resources);
    };
    assert_eq!(keys.keys, [ROOT_KEY]);
    assert_eq!(
        steps.notes,
        [
            "no `authorized_keys` given: copies 1 key from /root/.ssh/authorized_keys",
            "skipped 1 line of /root/.ssh/authorized_keys with options (command=, no-pty, ...), \
             which would restrict the admin too",
        ]
    );

    // Keys given in the profile are used as they are.
    let given = steps_with_keys(&fs, &runner);
    let Resource::AuthorizedKeys(keys) = &given.resources[1] else {
        panic!("{:?}", given.resources);
    };
    assert_eq!(keys.keys, [KEY]);
    assert!(
        !given.notes.iter().any(|n| n.contains("copies")),
        "{:?}",
        given.notes
    );

    // Nothing to copy.
    fs.write(
        Path::new("/root/.ssh/authorized_keys"),
        format!("{RESTRICTED}\n").as_bytes(),
    )
    .unwrap();
    assert_eq!(
        refusal(plan_steps(&fs, &runner, &facts(), "")),
        "no `authorized_keys` given, and /root/.ssh/authorized_keys has no key to copy \
         (1 line with options skipped); set `authorized_keys` for user.admin in a profile"
    );
}

fn steps_with_keys(fs: &FakeFs, runner: &Debian) -> ModuleSteps {
    plan_steps(
        fs,
        runner,
        &facts(),
        &format!("authorized_keys = [\"{KEY}\"]"),
    )
    .unwrap()
}

#[test]
fn copies_the_keys_of_the_session_user() {
    let fs = fs()
        .with_dir(
            "/home/ubuntu",
            FileOwner {
                mode: 0o750,
                uid: 1000,
                gid: 1000,
            },
        )
        .with_dir(
            "/home/ubuntu/.ssh",
            FileOwner {
                mode: 0o700,
                uid: 1000,
                gid: 1000,
            },
        )
        .with_file("/home/ubuntu/.ssh/authorized_keys", format!("{KEY}\n"));
    let runner = Debian::new(&fs, Accounts::default().with_user("ubuntu", 1000));
    let mut facts = facts();
    if let Some(session) = &mut facts.session {
        session.uid = 1000;
        session.user = Some("ubuntu".into());
    }
    let steps = plan_steps(&fs, &runner, &facts, "").unwrap();
    let Resource::AuthorizedKeys(keys) = &steps.resources[1] else {
        panic!("{:?}", steps.resources);
    };
    assert_eq!(keys.keys, [KEY]);
    assert_eq!(
        steps.notes[0],
        "no `authorized_keys` given: copies 1 key from /home/ubuntu/.ssh/authorized_keys"
    );
}

#[test]
fn star_password_only_when_usepam_is_off() {
    let fs = fs();
    let runner = Debian::new(&fs, Accounts::default());
    let password = |facts: &Facts| {
        let steps = plan_steps(&fs, &runner, facts, "").unwrap();
        let Resource::User(user) = &steps.resources[0] else {
            panic!("{:?}", steps.resources);
        };
        let noted = steps.notes.iter().any(|n| n.starts_with("UsePAM is off"));
        (user.password, noted)
    };
    let mut facts = facts();
    assert_eq!(password(&facts), (Password::Locked, false));
    facts.ssh.effective = Some(SshdConfig::parse("usepam no\n"));
    assert_eq!(password(&facts), (Password::Star, true));
    facts.ssh.effective = None;
    assert_eq!(password(&facts), (Password::Locked, false));

    // An existing account's password is never touched, so there is no note.
    let runner = Debian::new(&fs, Accounts::default().with_user("admin", 1001));
    facts.ssh.effective = Some(SshdConfig::parse("usepam no\n"));
    let steps = plan_steps(&fs, &runner, &facts, "").unwrap();
    assert!(
        !steps.notes.iter().any(|n| n.starts_with("UsePAM")),
        "{:?}",
        steps.notes
    );
}

#[test]
fn an_existing_user_keeps_its_sudo() {
    let fs = fs();
    let mut accounts = Accounts::default().with_user("admin", 1001);
    accounts.sudoers.insert("admin".into());
    let runner = Debian::new(&fs, accounts);
    for sudo in ["nopasswd", "password"] {
        let steps = plan_steps(&fs, &runner, &facts(), &format!("sudo = \"{sudo}\"")).unwrap();
        let ids: Vec<String> = steps.resources.iter().map(Resource::id).collect();
        assert_eq!(ids, ["user:admin", "authorized-keys:admin"], "{sudo}");
        let Resource::User(user) = &steps.resources[0] else {
            panic!();
        };
        assert!(user.groups.is_empty(), "{sudo}");
        assert!(
            steps.notes.contains(
                &"admin already has sudo rules (`sudo -l -U admin`); they stay as they are, \
                  and no sudoers file is written"
                    .to_owned()
            ),
            "{sudo}: {:?}",
            steps.notes
        );
    }
}

#[test]
fn password_sudo_needs_a_password() {
    let fs = fs();
    let params = "sudo = \"password\"";
    let created = Debian::new(&fs, Accounts::default());
    assert_eq!(
        refusal(plan_steps(&fs, &created, &facts(), params)),
        "`sudo = \"password\"` needs an account with a password, and admin does not exist \
         yet; create it and set one with `passwd admin` first, or use `sudo = \"nopasswd\"`"
    );

    let runner = Debian::new(&fs, Accounts::default().with_user("admin", 1001));
    for field in ["", "!", "*", &format!("!{HASH}")] {
        fs.write(
            Path::new(SHADOW),
            format!("root:*:20000::::::\nadmin:{field}:20000::::::\n").as_bytes(),
        )
        .unwrap();
        assert_eq!(
            refusal(plan_steps(&fs, &runner, &facts(), params)),
            "`sudo = \"password\"` needs a password, and admin has none; set one with \
             `passwd admin` first, or use `sudo = \"nopasswd\"`",
            "{field:?}"
        );
    }

    fs.write(
        Path::new(SHADOW),
        format!("admin:{HASH}:20000::::::\n").as_bytes(),
    )
    .unwrap();
    let steps = plan_steps(&fs, &runner, &facts(), params).unwrap();
    let ids: Vec<String> = steps.resources.iter().map(Resource::id).collect();
    assert_eq!(ids, ["user:admin", "authorized-keys:admin"]);
    let Resource::User(user) = &steps.resources[0] else {
        panic!();
    };
    assert_eq!(user.groups, ["sudo"]);
}

#[test]
fn refuses_what_it_cannot_set_up() {
    let fs = fs();
    let runner = Debian::new(&fs, Accounts::default());
    assert_eq!(
        refusal(plan_steps(&fs, &runner, &facts(), "name = \"root\"")),
        "`name` is root; the admin must be another account"
    );

    let mut accounts = Accounts::default();
    accounts.groups.insert("admin".into());
    let runner = Debian::new(&fs, accounts);
    assert_eq!(
        refusal(plan_steps(&fs, &runner, &facts(), "")),
        "a group named admin exists, but no user, so `useradd --user-group` cannot create \
         admin; set `name` to another user"
    );

    let bare = FakeFs::new()
        .with_dir("/root/.ssh", root_dir(0o700))
        .with_file("/root/.ssh/authorized_keys", format!("{ROOT_KEY}\n"));
    let runner = Debian::new(&bare, Accounts::default());
    assert_eq!(
        refusal(plan_steps(&bare, &runner, &facts(), "")),
        "sudo is not installed (/etc/sudoers.d is missing); install it with \
         `apt-get install sudo` first"
    );

    let err = plan_steps(&fs, &runner, &facts(), "name = \"-o\"").unwrap_err();
    assert!(err.to_string().contains("not a plain name"), "{err}");
}

#[test]
fn first_plan_snapshot() {
    let fs = fs();
    let runner = Debian::new(&fs, Accounts::default());
    let facts = facts();
    let params = toml::Table::new();
    let plan = plan(&fs, &runner, &facts, &params);
    insta::assert_yaml_snapshot!(plan);
}

/// Apply arms the dead-man switch and creates the account, its keys and
/// the drop-in; the next plan is empty; a manual rollback removes all but
/// the home directory.
#[test]
fn creates_the_admin_and_rolls_back() {
    let fs = fs();
    let runner = Debian::new(&fs, Accounts::default());
    let facts = facts();
    let params = toml::Table::new();
    let before = tree(&fs);

    let first = plan(&fs, &runner, &facts, &params);
    assert_eq!(
        change_ids(&first),
        [
            "user:admin",
            "authorized-keys:admin",
            &format!("file:{SUDOERS}")
        ]
    );
    assert!(first.needs_deadman());
    // The planned admin, not root of the applying session, must confirm.
    assert_eq!(first.admins(), ["admin"]);
    let state = StateDir::create(&fs, STATE, 0).unwrap();
    let engine = engine_on(&fs, &runner, &state);
    let outcome = engine.apply(&first, &deadman(), &mut |_| {}).unwrap();
    let ApplyOutcome::Pending { txn, .. } = outcome else {
        panic!("{outcome:?}");
    };

    assert_eq!(
        runner.calls("useradd"),
        [[
            "--create-home",
            "--user-group",
            "--shell",
            "/bin/bash",
            "admin"
        ]]
    );
    let visudo = runner.calls("visudo");
    assert_eq!(visudo.len(), 1, "{visudo:?}");
    assert_eq!(visudo[0][0], "-cf");
    assert!(visudo[0][1].ends_with(".after"), "{visudo:?}");
    assert_eq!(
        fs.read(Path::new("/home/admin/.ssh/authorized_keys"))
            .unwrap(),
        format!("{ROOT_KEY}\n").as_bytes()
    );
    let drop_in = fs.metadata(Path::new(SUDOERS)).unwrap();
    assert_eq!((drop_in.mode, drop_in.uid, drop_in.gid), (0o440, 0, 0));
    insta::assert_snapshot!(
        "sudoers",
        String::from_utf8(fs.read(Path::new(SUDOERS)).unwrap()).unwrap()
    );
    // Only verify asks sudo: a created account has no rules to keep.
    assert_eq!(runner.calls("sudo"), [["-n", "-l", "-U", "admin"]]);

    let events = events(&fs, &state, &txn);
    let forced: Vec<bool> = events
        .iter()
        .filter_map(|e| match e {
            Event::Backup { force_restore, .. } => Some(*force_restore),
            _ => None,
        })
        .collect();
    assert_eq!(forced, [false, false, false]);
    assert!(events.contains(&Event::Applied {
        resource: "user:admin".into(),
        uid: Some(1001),
    }));
    let Some(Event::State { admins, .. }) = events.last() else {
        panic!("{:?}", events.last());
    };
    assert_eq!(admins, &["admin"]);

    let next = plan(&fs, &runner, &facts, &params);
    assert!(change_ids(&next).is_empty(), "{:?}", change_ids(&next));
    assert!(
        next.modules[0]
            .notes
            .iter()
            .all(|n| !n.contains("sudo rules"))
    );
    // An edited drop-in is replaced, not taken for rules of the admin's own.
    let drop_in = fs.read(Path::new(SUDOERS)).unwrap();
    fs.write(Path::new(SUDOERS), b"admin ALL=(ALL:ALL) ALL\n")
        .unwrap();
    let edited = plan(&fs, &runner, &facts, &params);
    assert_eq!(change_ids(&edited), [format!("file:{SUDOERS}")]);
    fs.write(Path::new(SUDOERS), &drop_in).unwrap();

    engine.rollback(Target::Last, &mut |_| {}).unwrap();
    assert!(runner.accounts().users.is_empty());
    assert_eq!(runner.calls("userdel"), [["admin"]]);
    let mut after = tree(&fs);
    // `userdel` keeps the home directory with what was in it.
    assert!(fs.metadata(Path::new("/home/admin")).is_ok());
    assert!(!fs.exists(Path::new("/home/admin/.ssh")));
    after.retain(|p, _| !p.starts_with("/home/admin"));
    // The boot hook stays, disabled.
    after.remove(Path::new(crate::engine::deadman::HOOK));
    assert_eq!(after, before);
}

/// The timer rolls back an unconfirmed apply. A key the admin added during
/// the window keeps its file in place; the rest is restored.
#[test]
fn the_dead_man_skips_an_edited_key_file() {
    let fs = fs();
    let runner = Debian::new(&fs, Accounts::default());
    let facts = facts();
    let params = toml::Table::new();
    let first = plan(&fs, &runner, &facts, &params);
    let state = StateDir::create(&fs, STATE, 0).unwrap();
    let engine = engine_on(&fs, &runner, &state);
    let ApplyOutcome::Pending { txn, deadline } =
        engine.apply(&first, &deadman(), &mut |_| {}).unwrap()
    else {
        panic!("not pending");
    };
    let keys = Path::new("/home/admin/.ssh/authorized_keys");
    let edited = format!("{ROOT_KEY}\n{KEY}\n");
    fs.write(keys, edited.as_bytes()).unwrap();
    fs.write(
        Path::new(UPTIME),
        format!("{}.00 0.00\n", deadline.boottime + 1).as_bytes(),
    )
    .unwrap();

    let outcome = engine
        .deadman(&txn, Path::new(BIN), 0, &mut |_| {})
        .unwrap();
    let DeadmanOutcome::RolledBack(done) = outcome else {
        panic!("{outcome:?}");
    };
    let skipped: Vec<&str> = done.skipped.iter().map(|s| s.resource.as_str()).collect();
    assert_eq!(skipped, ["authorized-keys:admin"]);
    assert!(done.during.is_empty());
    assert!(!fs.exists(Path::new(SUDOERS)));
    assert!(runner.accounts().users.is_empty());
    assert_eq!(fs.read(keys).unwrap(), edited.as_bytes());
    assert!(events(&fs, &state, &txn).iter().any(|e| matches!(
        e,
        Event::State {
            state: crate::engine::TxnState::RolledBack {
                reason: RollbackReason::DeadmanTimeout
            },
            ..
        }
    )));
}

#[test]
fn verify_fails_without_sudo_rules() {
    let fs = fs();
    let accounts = Accounts {
        broken_sudo: true,
        ..Accounts::default()
    };
    let runner = Debian::new(&fs, accounts);
    let facts = facts();
    let params = toml::Table::new();
    let first = plan(&fs, &runner, &facts, &params);
    let state = StateDir::create(&fs, STATE, 0).unwrap();
    let engine = engine_on(&fs, &runner, &state);
    let outcome = engine.apply(&first, &deadman(), &mut |_| {}).unwrap();
    let ApplyOutcome::RolledBack { reason, cause, .. } = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(reason, RollbackReason::VerifyFailed);
    assert!(
        cause
            .to_string()
            .contains("`sudo -l -U admin` lists no rules for admin"),
        "{cause}"
    );
    assert!(runner.accounts().users.is_empty());
}
