//! `ssh.server` on [`FakeFs`], with sshd, sudo and systemd simulated by
//! [`Host`].

use std::collections::BTreeMap;
use std::sync::Mutex;

use super::*;
use crate::engine::{self, ApplyOutcome, Deadman, Engine, Plan, Selected, StateDir, Target};
use crate::facts::fixtures::host;
use crate::facts::{Session, SessionId};
use crate::resource::AuthorizedKeys;
use crate::sys::fake::FakeFs;
use crate::sys::{Fs, Output, Runner};

const STATE: &str = "/var/lib/vps-ready";
const BIN: &str = "/usr/local/bin/vps-ready";
const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDxkdGVzdGtleWZvcnRlc3RzMDEyMzQ1Njc4OTA admin@laptop";

/// sshd, `sudo -l`, `getent`, `systemd-run` and `systemctl` on a
/// [`FakeFs`]. `sshd -T -C` prints the captured `sshd -T` with the
/// drop-in's settings first, as sshd reads it first.
struct Host<'a> {
    fs: &'a FakeFs,
    effective: String,
    /// Users with sudo rules.
    sudoers: Vec<&'static str>,
    calls: Mutex<Vec<Cmd>>,
}

impl<'a> Host<'a> {
    fn new(fs: &'a FakeFs, facts: &Facts) -> Self {
        let effective = std::fs::read_to_string(crate::facts::fixtures::testdata(
            "hosts/debian-13/cmd/sshd-T.stdout",
        ))
        .unwrap();
        assert!(facts.ssh.effective.is_some());
        Self {
            fs,
            effective,
            sudoers: vec!["admin"],
            calls: Mutex::default(),
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|c| format!("{} {}", c.program, c.args.join(" ")))
            .collect()
    }
}

impl Runner for Host<'_> {
    fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
        self.calls.lock().unwrap().push(cmd.clone());
        let args: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        Ok(match (cmd.program.as_str(), args.as_slice()) {
            ("sshd", ["-T", "-C", _]) => {
                let drop_in = self.fs.read(Path::new(DROP_IN)).unwrap_or_default();
                let mut text = String::from_utf8(drop_in)
                    .unwrap()
                    .lines()
                    .filter(|l| !l.starts_with('#'))
                    .map(|l| format!("{}\n", l.to_ascii_lowercase()))
                    .collect::<String>();
                text.push_str(&self.effective);
                Output::success(text)
            }
            ("sshd", ["-t"] | ["-t", "-f", _]) => Output::success(""),
            ("getent", ["passwd", name]) => {
                Output::success(format!("{name}:x:1000:1000::/home/{name}:/bin/bash\n"))
            }
            ("sudo", ["-n", "-l", "-U", name]) if self.sudoers.contains(name) => {
                Output::success(format!(
                    "User {name} may run the following commands on vps:\n    (ALL) NOPASSWD: ALL\n"
                ))
            }
            ("sudo", ["-n", "-l", "-U", name]) => {
                Output::success(format!("User {name} is not allowed to run sudo on vps.\n"))
            }
            ("systemd-run" | "systemctl", _) => Output::success(""),
            _ => return Err(SysError::NotFound(cmd.program.clone())),
        })
    }
}

fn session(user: &str, uid: u32) -> Session {
    Session {
        id: SessionId {
            pid: 902,
            start: 4200,
        },
        client: "192.0.2.10:51234".parse().unwrap(),
        server: "198.51.100.5:22".parse().unwrap(),
        uid,
        user: Some(user.into()),
    }
}

/// The captured Debian 13 host, applied from `admin`'s SSH session.
fn facts() -> Facts {
    let mut facts = host("debian-13", &[]);
    facts.session = Some(session("admin", 1000));
    facts
}

/// A host that can arm the dead-man, with `admin`'s key in place.
fn fs() -> FakeFs {
    let fs = FakeFs::new()
        .with_file(crate::resource::sysctl::BOOT_ID, "a\n")
        .with_file("/proc/uptime", "1000.25 900.00\n")
        .with_file(BIN, "\x7fELF")
        .with_file(SSHD_CONFIG, "Include /etc/ssh/sshd_config.d/*.conf\n")
        .with_file("/home/admin/.ssh/authorized_keys", format!("{KEY}\n"));
    for dir in ["/etc/systemd/system", "/etc/ssh/sshd_config.d"] {
        fs.create_dir_all(Path::new(dir), 0o755).unwrap();
    }
    fs
}

fn sys<'a>(fs: &'a FakeFs, runner: &'a dyn Runner) -> Sys<'a> {
    Sys { fs, runner }
}

fn steps(
    facts: &Facts,
    planned: &[Resource],
    fs: &FakeFs,
    runner: &dyn Runner,
) -> Result<ModuleSteps, ModuleError> {
    SshServer.plan(
        &PlanCx {
            facts,
            params: &toml::Table::new(),
            planned,
        },
        sys(fs, runner),
    )
}

fn drop_in_of(steps: &ModuleSteps) -> String {
    match steps.resources.as_slice() {
        [Resource::File(f)] => String::from_utf8(f.content.clone()).unwrap(),
        other => panic!("{other:?}"),
    }
}

/// The keywords of a drop-in, in order.
fn keywords(text: &str) -> Vec<String> {
    let fs = FakeFs::new().with_file(DROP_IN, text);
    Config::read(&FsSource(&fs), Path::new(DROP_IN))
        .unwrap()
        .directives()
        .iter()
        .map(|d| d.keyword.clone())
        .collect()
}

fn reason(facts: &Facts) -> String {
    match SshServer.applicable(facts) {
        Applicability::NotApplicable { reason } => reason,
        Applicability::Applicable => panic!("applies"),
    }
}

/// Facts whose `sshd_config` is `main`, with `files` in `sshd_config.d`.
fn with_config(main: &str, files: &[(&str, &str)]) -> Facts {
    let mut facts = facts();
    let fs = files
        .iter()
        .fold(FakeFs::new().with_file(SSHD_CONFIG, main), |fs, (p, c)| {
            fs.with_file(*p, *c)
        });
    facts.ssh.files = Some(Config::read(&FsSource(&fs), Path::new(SSHD_CONFIG)).unwrap());
    facts
}

#[test]
fn applies_only_where_the_drop_in_wins() {
    let module = SshServer;
    for name in crate::facts::fixtures::HOSTS {
        assert_eq!(
            module.applicable(&host(name, &[])),
            Applicability::Applicable,
            "{name}"
        );
    }

    assert_eq!(
        reason(&with_config("UsePAM yes\n", &[])),
        "/etc/ssh/sshd_config does not Include /etc/ssh/sshd_config.d/00-vps-ready.conf, \
         and vps-ready does not edit it"
    );
    assert_eq!(
        reason(&with_config(
            "Match Address 192.0.2.0/24\nInclude /etc/ssh/sshd_config.d/*.conf\n",
            &[]
        )),
        "the Include that reads /etc/ssh/sshd_config.d/00-vps-ready.conf is inside the Match \
         block at /etc/ssh/sshd_config:1, so it would apply to some connections only"
    );
    assert_eq!(
        reason(&with_config(
            "Include /etc/ssh/sshd_config.d/*.conf\n",
            &[(
                "/etc/ssh/sshd_config.d/0-custom.conf",
                "PasswordAuthentication yes\n"
            )]
        )),
        "/etc/ssh/sshd_config.d/0-custom.conf:1 sets PasswordAuthentication before \
         /etc/ssh/sshd_config.d/00-vps-ready.conf is read, so it wins over the drop-in"
    );
    // A keyword set to `no` first agrees with the drop-in; cloud-init's 50- comes later.
    let facts = with_config(
        "PermitEmptyPasswords no\nInclude /etc/ssh/sshd_config.d/*.conf\n",
        &[(
            "/etc/ssh/sshd_config.d/50-cloud-init.conf",
            "PasswordAuthentication yes\n",
        )],
    );
    assert_eq!(module.applicable(&facts), Applicability::Applicable);

    let mut facts = facts;
    facts.ssh.files = None;
    assert_eq!(reason(&facts), "/etc/ssh/sshd_config could not be read");
    facts.ssh.effective = None;
    assert_eq!(
        reason(&facts),
        "the effective sshd config is unknown (`sshd -T` failed)"
    );
    facts.init = Init::OpenRc;
    assert_eq!(
        reason(&facts),
        "the dead-man switch needs systemd, and systemd is not running"
    );
    facts.os.family = OsFamily::Alpine;
    assert_eq!(
        reason(&facts),
        "sshd is set up only on Debian and Ubuntu so far"
    );
}

#[test]
fn manages_exactly_the_keys_of_ssh_001_to_ssh_007() {
    let catalog = crate::audit::catalog().unwrap();
    let fixed: Vec<String> = catalog
        .iter()
        .filter(|c| c.fix.as_deref() == Some("ssh.server"))
        .map(|c| c.id.clone())
        .collect();
    assert_eq!(
        fixed,
        (1..=7).map(|n| format!("SSH-00{n}")).collect::<Vec<_>>()
    );
    let managed: Vec<&str> = MANAGED.iter().map(|&(key, _)| key).collect();
    for (control, (key, written)) in fixed.iter().zip(MANAGED) {
        let check = catalog.iter().find(|c| c.id == *control).unwrap();
        let text = format!("{:?}", check.check);
        assert!(text.contains(&format!("{key:?}")), "{control}: {text}");
        assert!(text.contains("\"no\""), "{control}: {text}");
        assert_eq!(written.to_ascii_lowercase(), key);
    }
    assert_eq!(managed.len(), 7);
}

/// The drop-in never sets what could cut the admin off or break clients.
#[test]
fn never_writes_ports_listeners_groups_methods_or_crypto() {
    const NEVER: [&str; 11] = [
        "port",
        "listenaddress",
        "allowgroups",
        "allowusers",
        "authenticationmethods",
        "ciphers",
        "macs",
        "kexalgorithms",
        "hostkeyalgorithms",
        "pubkeyacceptedalgorithms",
        "match",
    ];
    let all: Vec<Setting> = MANAGED
        .iter()
        .map(|&(_, keyword)| Setting {
            keyword,
            value: VALUE,
        })
        .collect();
    let written = keywords(&DropIn { settings: &all }.render().unwrap());
    assert_eq!(
        written,
        MANAGED.map(|(key, _)| key.to_owned()),
        "every managed keyword, in order, and nothing else"
    );
    assert!(written.iter().all(|k| !NEVER.contains(&k.as_str())));
}

#[test]
fn writes_failing_keywords_and_those_the_drop_in_lists() {
    let facts = facts();
    let fs = fs();
    let host = Host::new(&fs, &facts);
    let first = steps(&facts, &[], &fs, &host).unwrap();
    assert_eq!(
        keywords(&drop_in_of(&first)),
        ["permitrootlogin", "passwordauthentication", "x11forwarding"]
    );
    assert_eq!(first.reloads, [Reload::SshdReload]);
    let Resource::File(file) = &first.resources[0] else {
        unreachable!()
    };
    assert_eq!(
        file.validate,
        Some(Validate::new("sshd", ["-t", "-f", "{}"]))
    );

    // A keyword the drop-in already lists stays, though it passes now.
    let listed = self::fs().with_file(DROP_IN, "PermitEmptyPasswords no\nX11Forwarding no\n");
    let again = steps(&facts, &[], &listed, &Host::new(&listed, &facts)).unwrap();
    assert_eq!(
        keywords(&drop_in_of(&again)),
        [
            "permitrootlogin",
            "passwordauthentication",
            "permitemptypasswords",
            "x11forwarding"
        ]
    );

    // Nothing fails and there is no drop-in: nothing to do.
    let mut hardened = facts.clone();
    let text = host
        .effective
        .lines()
        .map(|l| {
            let key = l.split_whitespace().next().unwrap_or_default();
            if MANAGED.iter().any(|(k, _)| *k == key) {
                format!("{key} no\n")
            } else {
                format!("{l}\n")
            }
        })
        .collect::<String>();
    hardened.ssh.effective = Some(SshdConfig::parse(&text));
    let fs = self::fs();
    assert_eq!(
        steps(&hardened, &[], &fs, &host).unwrap(),
        ModuleSteps::default()
    );
}

#[test]
fn takes_no_params() {
    assert!(SshServer.check_params(&toml::Table::new()).is_ok());
    let typo: toml::Table = toml::from_str("port = 2222").unwrap();
    let err = SshServer.check_params(&typo).unwrap_err();
    assert!(err.to_string().contains("unknown field `port`"), "{err}");
}

/// Turning off root or password logins needs a user other than root with
/// a key and sudo: the admin this plan sets up, or the session's user.
#[test]
fn refuses_to_lock_out_without_a_keyed_sudo_user() {
    let refused = |facts: &Facts, planned: &[Resource], fs: &FakeFs, sudoers: Vec<&'static str>| {
        let mut host = Host::new(fs, facts);
        host.sudoers = sudoers;
        match steps(facts, planned, fs, &host) {
            Err(ModuleError::Refused(why)) => Some(why),
            Err(e) => panic!("{e}"),
            Ok(_) => None,
        }
    };
    let fs = fs();
    let mut facts = facts();
    assert_eq!(refused(&facts, &[], &fs, vec!["admin"]), None);

    let why = refused(&facts, &[], &fs, vec![]).unwrap();
    assert_eq!(
        why,
        "refusing to turn off root login and password login: no user other than root has \
         an SSH key and sudo to log in with afterwards (admin has no sudo rights). Set one up \
         with the user.admin module, or log in as such a user and run vps-ready with sudo"
    );
    let no_key = FakeFs::new()
        .with_file(SSHD_CONFIG, "Include /etc/ssh/sshd_config.d/*.conf\n")
        .with_file("/home/admin/.ssh/authorized_keys", "# no keys yet\n\n");
    assert!(
        refused(&facts, &[], &no_key, vec!["admin"])
            .unwrap()
            .contains("(admin has no SSH key in authorized_keys)")
    );
    // `authorized_keys2` counts: it is in sshd's AuthorizedKeysFile.
    let second = no_key.with_file("/home/admin/.ssh/authorized_keys2", format!("{KEY}\n"));
    assert_eq!(refused(&facts, &[], &second, vec!["admin"]), None);

    facts.session = Some(session("root", 0));
    assert!(
        refused(&facts, &[], &fs, vec!["root"])
            .unwrap()
            .contains("(this SSH session is root's)")
    );
    facts.session = None;
    assert!(
        refused(&facts, &[], &fs, vec![])
            .unwrap()
            .contains("(there is no SSH session to take the user from)")
    );

    // The admin of this plan, before user.admin has created it.
    let keys = Resource::AuthorizedKeys(AuthorizedKeys {
        user: "deploy".into(),
        exact: false,
        keys: vec![KEY.into()],
    });
    let sudoers = Resource::File(File {
        path: "/etc/sudoers.d/90-vps-ready-admin".into(),
        content: b"deploy ALL=(ALL:ALL) NOPASSWD: ALL\n".to_vec(),
        owner: FileOwner {
            mode: 0o440,
            uid: 0,
            gid: 0,
        },
        validate: None,
    });
    assert_eq!(refused(&facts, &[keys.clone(), sudoers], &fs, vec![]), None);
    assert_eq!(
        refused(&facts, std::slice::from_ref(&keys), &fs, vec!["deploy"]),
        None
    );
    assert!(
        refused(&facts, &[keys], &fs, vec![])
            .unwrap()
            .ends_with("(deploy gets SSH keys from this plan but no sudo). Set one up with the user.admin module, or log in as such a user and run vps-ready with sudo")
    );

    // `deploy.user` planned first, from root's session: keys that all have
    // options and a sudo rule for one command do not make an admin.
    let restricted = Resource::AuthorizedKeys(AuthorizedKeys {
        user: "deploy".into(),
        exact: true,
        keys: vec![format!(
            "restrict,command=\"/usr/local/bin/deploy-app\" {KEY}"
        )],
    });
    let one_command = Resource::File(File {
        path: "/etc/sudoers.d/90-vps-ready-deploy".into(),
        content: b"deploy ALL=(root) NOPASSWD: /usr/local/bin/deploy-app \"\"\n".to_vec(),
        owner: FileOwner {
            mode: 0o440,
            uid: 0,
            gid: 0,
        },
        validate: None,
    });
    facts.session = Some(session("root", 0));
    assert!(
        refused(&facts, &[restricted, one_command], &fs, vec!["deploy"])
            .unwrap()
            .contains("(this SSH session is root's)")
    );
    // An admin whose only key is limited to some addresses is still one.
    let from = Resource::AuthorizedKeys(AuthorizedKeys {
        user: "admin".into(),
        exact: false,
        keys: vec![format!("from=\"203.0.113.0/24\" {KEY}")],
    });
    let admin_sudo = Resource::File(File {
        path: "/etc/sudoers.d/90-vps-ready-admin".into(),
        content: b"admin ALL=(ALL:ALL) NOPASSWD: ALL\n".to_vec(),
        owner: FileOwner {
            mode: 0o440,
            uid: 0,
            gid: 0,
        },
        validate: None,
    });
    assert_eq!(refused(&facts, &[from, admin_sudo], &fs, vec![]), None);
    facts.session = None;

    // X11 forwarding alone needs no admin.
    let mut only_x11 = self::facts();
    only_x11.session = None;
    let text = Host::new(&fs, &only_x11)
        .effective
        .replace("permitrootlogin without-password", "permitrootlogin no")
        .replace("passwordauthentication yes", "passwordauthentication no");
    only_x11.ssh.effective = Some(SshdConfig::parse(&text));
    assert_eq!(refused(&only_x11, &[], &fs, vec![]), None);
}

#[test]
fn keys_paths_expand_like_sshd() {
    let home = Path::new("/home/admin");
    for (pattern, want) in [
        (".ssh/authorized_keys", "/home/admin/.ssh/authorized_keys"),
        ("%h/.ssh/keys", "/home/admin/.ssh/keys"),
        ("/etc/ssh/keys/%u", "/etc/ssh/keys/admin"),
        ("/etc/%%/%x", "/etc/%/%x"),
    ] {
        assert_eq!(
            keys_path(pattern, home, "admin"),
            Path::new(want),
            "{pattern}"
        );
    }
}

fn plan<'a>(fs: &FakeFs, runner: &dyn Runner, facts: &'a Facts) -> Plan<'a> {
    engine::plan(&[Selected::new(&SshServer)], facts, sys(fs, runner)).unwrap()
}

#[test]
fn first_plan_snapshot() {
    let facts = facts();
    let fs = fs();
    let host = Host::new(&fs, &facts);
    insta::assert_yaml_snapshot!(plan(&fs, &host, &facts));
}

/// Every file with its bytes, outside the state directory and the dead-man
/// hook, which nothing removes.
fn files(fs: &FakeFs) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(fs: &FakeFs, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for path in fs.read_dir(dir).unwrap() {
            if fs.metadata(&path).unwrap().kind == crate::sys::FileKind::Dir {
                walk(fs, &path, out);
            } else {
                out.insert(path.clone(), fs.read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(fs, Path::new("/"), &mut out);
    out.retain(|p, _| !p.starts_with(STATE) && p != Path::new(engine::deadman::HOOK));
    out
}

/// Apply arms the dead-man and waits; the drop-in is checked on its own,
/// then sshd reloads and verify asks for the admin's connection. The next
/// plan is empty, and rollback brings back the tree.
#[test]
fn apply_is_idempotent_and_rolls_back() {
    let facts = facts();
    let fs = fs();
    let host = Host::new(&fs, &facts);
    let before = files(&fs);

    let first = plan(&fs, &host, &facts);
    assert!(first.needs_deadman());
    assert!(first.modules[0].force_restore());
    let state = StateDir::create(&fs, STATE, 0).unwrap();
    let engine = Engine::lock(&state, sys(&fs, &host)).unwrap();
    let deadman = Deadman {
        binary: BIN.into(),
        ..Deadman::default()
    };
    let outcome = engine.apply(&first, &deadman, &mut |_| {}).unwrap();
    assert!(
        matches!(outcome, ApplyOutcome::Pending { .. }),
        "{outcome:?}"
    );
    let drop_in = String::from_utf8(fs.read(Path::new(DROP_IN)).unwrap()).unwrap();
    insta::assert_snapshot!("drop-in", drop_in);
    assert_eq!(
        fs.metadata(Path::new(DROP_IN)).unwrap().owner(),
        FileOwner {
            mode: 0o644,
            uid: 0,
            gid: 0
        }
    );

    let calls = host.calls();
    let sshd: Vec<&String> = calls
        .iter()
        .filter(|c| c.starts_with("sshd") || c.contains("ssh.service"))
        .collect();
    assert_eq!(sshd.len(), 4, "{sshd:?}");
    assert!(
        sshd[0].starts_with("sshd -t -f /var/lib/vps-ready/txn/") && sshd[0].ends_with(".after"),
        "{sshd:?}"
    );
    assert_eq!(sshd[1], "sshd -t");
    assert_eq!(sshd[2], "systemctl try-reload-or-restart ssh.service");
    assert_eq!(
        sshd[3],
        "sshd -T -C user=admin,host=192.0.2.10,addr=192.0.2.10"
    );

    let next = plan(&fs, &host, &facts);
    assert_eq!(next.steps().count(), 0);
    assert!(next.modules[0].reloads().is_empty());

    engine.rollback(Target::Last, &mut |_| {}).unwrap();
    assert_eq!(files(&fs), before);
}

/// A `Match` block for the admin that turns passwords back on fails verify,
/// and apply rolls back.
#[test]
fn verify_checks_the_admins_own_connection() {
    let facts = facts();
    let cx = PlanCx {
        facts: &facts,
        params: &toml::Table::new(),
        planned: &[],
    };
    // No drop-in, nothing to check.
    let none = fs();
    assert_eq!(
        SshServer.verify(&cx, sys(&none, &Host::new(&none, &facts))),
        Ok(())
    );

    let fs = fs().with_file(DROP_IN, "PasswordAuthentication no\n");
    let mut matched = Host::new(&fs, &facts);
    matched.effective = String::new();
    assert_eq!(
        SshServer.verify(&cx, sys(&fs, &matched)),
        Ok(()),
        "the drop-in alone shows passwordauthentication no"
    );

    /// `sshd -T -C` as with `Match User admin` / `PasswordAuthentication yes`
    /// in a file read before the drop-in.
    struct Matched;
    impl Runner for Matched {
        fn run(&self, _: &Cmd) -> Result<Output, SysError> {
            Ok(Output::success("passwordauthentication yes\n"))
        }
    }
    assert_eq!(
        SshServer.verify(&cx, sys(&fs, &Matched)),
        Err(
            "`sshd -T -C user=admin,host=192.0.2.10,addr=192.0.2.10` shows \
             passwordauthentication yes, not no"
                .to_owned()
        )
    );
    assert_eq!(SshServer.verify_timeout(), Duration::from_secs(10));
}

/// Any user the plan gives keys may confirm, so verify asks for each of
/// them: a `Match User bob` that turns passwords back on fails it.
#[test]
fn verify_checks_every_admin() {
    struct MatchBob;
    impl Runner for MatchBob {
        fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
            let value = if cmd.args.iter().any(|a| a.starts_with("user=bob,")) {
                "yes"
            } else {
                "no"
            };
            Ok(Output::success(format!("passwordauthentication {value}\n")))
        }
    }
    let facts = facts();
    let fs = fs().with_file(DROP_IN, "PasswordAuthentication no\n");
    let keys = |user: &str| {
        Resource::AuthorizedKeys(AuthorizedKeys {
            user: user.into(),
            exact: false,
            keys: vec![KEY.into()],
        })
    };
    let verify = |facts: &Facts, planned: &[Resource]| {
        let cx = PlanCx {
            facts,
            params: &toml::Table::new(),
            planned,
        };
        SshServer.verify(&cx, sys(&fs, &MatchBob))
    };
    assert_eq!(verify(&facts, &[keys("alice")]), Ok(()));
    assert_eq!(
        verify(&facts, &[keys("alice"), keys("bob")]),
        Err(
            "`sshd -T -C user=bob,host=192.0.2.10,addr=192.0.2.10` shows \
             passwordauthentication yes, not no"
                .to_owned()
        )
    );
    // No admin in the plan: the session's user.
    assert_eq!(verify(&facts, &[]), Ok(()));
    let mut bob = facts.clone();
    bob.session = Some(session("bob", 1001));
    assert!(verify(&bob, &[]).is_err());
}

/// vps-ready reads only `authorized_keys`; the refusal says so when sshd
/// also takes keys from a command or certificates from a CA.
#[test]
fn a_refusal_names_keys_it_cannot_check() {
    let mut facts = facts();
    let text = Host::new(&fs(), &facts)
        .effective
        .replace(
            "authorizedkeyscommand none",
            "authorizedkeyscommand /usr/bin/get-keys",
        )
        .replace(
            "trustedusercakeys none",
            "trustedusercakeys /etc/ssh/user_ca.pub",
        );
    facts.ssh.effective = Some(SshdConfig::parse(&text));
    let no_key = FakeFs::new().with_file(SSHD_CONFIG, "Include /etc/ssh/sshd_config.d/*.conf\n");
    let host = Host::new(&no_key, &facts);
    let Err(ModuleError::Refused(why)) = steps(&facts, &[], &no_key, &host) else {
        panic!("not refused");
    };
    assert!(
        why.contains(
            "(admin has no SSH key in authorized_keys, and vps-ready cannot check the keys \
             sshd also takes through AuthorizedKeysCommand and TrustedUserCAKeys)"
        ),
        "{why}"
    );
}

#[test]
fn a_missing_sudo_is_a_refusal() {
    struct NoSudo<'a>(Host<'a>);
    impl Runner for NoSudo<'_> {
        fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
            if cmd.program == "sudo" {
                return Err(SysError::NotFound("sudo".into()));
            }
            self.0.run(cmd)
        }
    }
    let facts = facts();
    let fs = fs();
    let runner = NoSudo(Host::new(&fs, &facts));
    match steps(&facts, &[], &fs, &runner) {
        Err(ModuleError::Refused(why)) => assert_eq!(
            why,
            "sudo is not installed; install it with `apt-get install sudo` first"
        ),
        other => panic!("{other:?}"),
    }
}
