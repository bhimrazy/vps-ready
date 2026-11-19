//! Private access for SSH: the VPN question, the hidden auth key, and
//! step 2 from a login through the VPN.

use super::*;
use crate::facts::{Address, Interface, Tailscale};
use crate::modules::{ModuleSteps, PlanCx, parse_params};

/// A fake auth key, built here so that no key-shaped text is in the source.
fn auth_key() -> String {
    ["tskey", "auth", "kFAKE", "0123456789"].join("-")
}

/// [`fs`] with `/run`, where the auth key goes.
fn fs_with_run() -> FakeFs {
    fs().with_dir(
        "/run",
        FileOwner {
            mode: 0o755,
            uid: 0,
            gid: 0,
        },
    )
}

#[test]
fn tailscale_without_a_key_builds_on_the_private_profile() {
    let fs = fs();
    let runner = runner(|r| r);
    let host = on(&fs, &runner);
    let questions = vec![Enter, Enter, Pick(1), Enter, Enter, Enter];
    let (text, profile) = scenario("tailscale", &host, questions);
    assert!(text.contains("? Auth key (hidden; Enter to log in yourself after): \n"));
    assert!(
        text.contains("note: no auth_key_file: unless this node is logged in already"),
        "{text}"
    );
    assert!(
        text.contains("note: step 1 of 2: SSH stays public until you apply this profile again"),
        "{text}"
    );
    assert_eq!(
        profile,
        "schema = 1\nextends = \"private\"\n\n[modules.\"net.tailscale\"]\n"
    );
}

/// A pasted key is used for this apply as `auth_key_file` and never shown
/// or saved; the file goes whether the apply is declined or fails.
#[test]
fn a_pasted_auth_key_is_used_once_and_removed() {
    let key = auth_key();
    let questions = vec![
        Enter,
        Enter,
        Pick(1),
        // Not an auth key: asked again.
        Type("my-password".into()),
        Type(format!(" {key} ")),
        Enter,
        Enter,
    ];
    let runner = runner(|r| r);
    for typed in ["n\n", "y\n"] {
        let fs = fs_with_run();
        let host = on(&fs, &runner);
        let (code, text) = wizard(&host, questions.clone(), typed);
        assert!(!text.contains(&key), "{text}");
        assert!(text.contains("  That is not an auth key: it starts with tskey-\n"));
        assert!(text.contains("? Auth key (hidden; Enter to log in yourself after): [hidden]\n"));
        assert!(
            text.contains("+ log in to the tailnet with the auth key in /run/vps-ready/"),
            "{text}"
        );
        // The wizard removes it, so the module does not ask the user to.
        assert!(!text.contains("delete /run/vps-ready"), "{text}");
        assert!(!fs.exists(Path::new(AUTH_KEY_FILE)), "{typed:?}");
        if typed == "y\n" {
            // The dead-man switch cannot be armed: /proc/uptime is missing.
            assert_eq!(code, 2, "{text}");
            assert!(text.contains("error: dead-man switch"), "{text}");
        } else {
            assert_eq!(code, 0, "{text}");
            snapshot("tailscale-key", &text);
        }
    }
    let fs = fs_with_run();
    let host = on(&fs, &runner);
    let saved = round_trip(&host, questions).to_toml();
    assert!(!saved.contains("auth_key_file"), "{saved}");
    assert!(!saved.contains(&key), "{saved}");
}

/// While the file exists Ctrl-C is the wizard's to handle, so that it
/// can remove the file first.
#[test]
fn the_key_file_is_root_only_and_removed_when_dropped() {
    let fs = fs_with_run();
    let runner = runner(|r| r);
    let ends = Arc::new(AtomicBool::new(true));
    let host = Host {
        sigint_ends: Some(Arc::clone(&ends)),
        ..on(&fs, &runner)
    };
    let key = auth_key();
    let file = KeyFile::write(&host, &key).unwrap();
    let (bytes, meta) = fs.read_nofollow(Path::new(AUTH_KEY_FILE)).unwrap();
    assert_eq!(bytes, key.as_bytes());
    assert_eq!((meta.mode, meta.uid, meta.gid), (0o600, 0, 0));
    let dir = fs.metadata(Path::new("/run/vps-ready")).unwrap();
    assert_eq!((dir.kind, dir.mode, dir.uid), (FileKind::Dir, 0o700, 0));
    assert!(!ends.load(Ordering::SeqCst));
    drop(file);
    assert!(!fs.exists(Path::new(AUTH_KEY_FILE)));
    assert!(ends.load(Ordering::SeqCst));

    // A directory others can write to is not used.
    let open = FileOwner {
        mode: 0o777,
        uid: 0,
        gid: 0,
    };
    let fs = fs_with_run().with_dir("/run/vps-ready", open);
    let host = on(&fs, &runner);
    let err = KeyFile::write(&host, &key).err().unwrap();
    assert!(err.to_string().contains("only root can write to"), "{err}");
    assert!(!fs.exists(Path::new(AUTH_KEY_FILE)));
}

/// A key left by a run that ended without its cleanup goes at the start.
#[test]
fn a_leftover_key_file_is_removed_at_the_start() {
    let root = FileOwner {
        mode: 0o700,
        uid: 0,
        gid: 0,
    };
    let fs = fs_with_run().with_dir("/run/vps-ready", root);
    for path in [AUTH_KEY_FILE, AUTH_KEY_TEMP] {
        fs.write_atomic(Path::new(path), auth_key().as_bytes(), root)
            .unwrap();
    }
    let runner = runner(|r| r);
    let (code, _) = wizard(&on(&fs, &runner), vec![CtrlC], "");
    assert_eq!(code, EXIT_INTERRUPTED);
    assert!(!fs.exists(Path::new(AUTH_KEY_FILE)));
    assert!(!fs.exists(Path::new(AUTH_KEY_TEMP)));
}

/// On the private profile the ports start unchecked, and a domain opens
/// 80 and 443 for Caddy; "Web apps or Docker" keeps Docker.
#[test]
fn a_domain_on_the_private_profile_opens_80_and_443() {
    let fs = fs();
    let runner = runner(|r| r);
    let host = Host {
        facts: |sys| {
            let mut facts = vm(sys)?;
            facts.docker = true;
            facts
                .listeners
                .push(listener(Proto::Tcp, "0.0.0.0", 8080, "app"));
            Ok(facts)
        },
        ..on(&fs, &runner)
    };
    let questions = vec![
        Enter,
        Enter,
        Pick(1),
        Enter,
        Enter,
        Enter,
        Enter,
        Type("app.example.com".into()),
        Type("127.0.0.1:8080".into()),
        Enter,
    ];
    let (text, profile) = scenario("private-domain", &host, questions);
    assert!(
        text.contains(
            "? Open ports besides SSH (only through tailscale0 after step 2) (Space toggles, \
             Enter continues)\n  [ ] 8080/tcp (app)\n"
        ),
        "{text}"
    );
    let parsed = Profile::parse(&profile, host.modules).unwrap();
    let allow = parsed.params("firewall.inbound").unwrap().get("allow");
    let want = toml::Value::Array(WEB_PORTS.iter().map(|&p| p.into()).collect());
    assert_eq!(allow, Some(&want), "{profile}");
    assert!(parsed.params("deploy.docker").is_some(), "{profile}");
    assert!(parsed.params("deploy.proxy").is_some(), "{profile}");
}

/// Taking the VPN module out in the module list is asked again.
#[test]
fn the_private_profile_keeps_its_vpn_module() {
    let fs = fs();
    let runner = runner(|r| r);
    let host = on(&fs, &runner);
    let mut ids: Vec<&str> = host.modules.iter().map(|m| m.id()).collect();
    ids.retain(|id| !["deploy.docker", "deploy.proxy", "deploy.user"].contains(id));
    let without: Vec<&str> = ids
        .iter()
        .copied()
        .filter(|&id| id != "net.tailscale")
        .collect();
    let questions = vec![
        Enter,
        Enter,
        Pick(1),
        Enter,
        Enter,
        Say(true),
        modules(&host, &without),
        modules(&host, &ids),
    ];
    let facts = (host.facts)(host.sys).unwrap();
    let log = Transcript::default();
    let mut script = Script::new(questions, &log);
    let answers = ask(&host, &facts, &mut script, &mut log.clone()).unwrap();
    assert!(script.done());
    assert!(
        log.text()
            .contains("  `ssh_via = \"vpn\"` (the private profile) needs a VPN module: add"),
        "{}",
        log.text()
    );
    assert!(answers.builder.to_toml().contains("net.tailscale"));
}

/// A stand-in for `net.wireguard`, which is not registered yet: it checks
/// a peer as the module does and plans nothing.
struct Wireguard;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Peers {
    peers: Vec<Peer>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Peer {
    name: String,
    public_key: String,
    #[allow(dead_code)]
    host: i64,
}

/// Base64 of 32 bytes: 43 characters, the last one's low 2 bits zero, and `=`.
fn is_key(text: &str) -> bool {
    let b = text.as_bytes();
    b.len() == 44
        && b[43] == b'='
        && b[..43]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/')
        && b"AEIMQUYcgkosw048".contains(&b[42])
}

impl Module for Wireguard {
    fn id(&self) -> &'static str {
        "net.wireguard"
    }
    fn title(&self) -> &'static str {
        "Run a WireGuard server for admin access"
    }
    fn why(&self) -> &'static str {
        "a test stand-in"
    }
    fn applicable(&self, _: &Facts) -> Applicability {
        Applicability::Applicable
    }
    fn check_params(&self, params: &toml::Table) -> Result<(), ModuleError> {
        let Peers { peers } = parse_params(params)?;
        for p in peers {
            let name = &p.name;
            let ok = (1..=32).contains(&name.len())
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
            if !ok {
                return crate::modules::refuse(&format!(
                    "peer name {name:?} is not 1 to 32 lowercase letters, digits and `-`"
                ));
            }
            if !is_key(&p.public_key) {
                return crate::modules::refuse(&format!(
                    "peer {name}: public_key is not a WireGuard key"
                ));
            }
        }
        Ok(())
    }
    fn plan(&self, _: &PlanCx, _: Sys) -> Result<ModuleSteps, ModuleError> {
        Ok(ModuleSteps::default())
    }
}

/// The registry with [`Wireguard`] before `firewall.inbound`, as the VPN
/// modules are.
fn with_wireguard() -> &'static [&'static dyn Module] {
    let mut modules = crate::modules::all().to_vec();
    let at = modules
        .iter()
        .position(|m| m.id() == "firewall.inbound")
        .unwrap();
    modules.insert(at, &Wireguard);
    modules.leak()
}

/// Without `net.wireguard` registered there is no WireGuard choice.
#[test]
fn wireguard_is_offered_only_when_registered() {
    let fs = fs();
    let runner = runner(|r| r);
    let host = on(&fs, &runner);
    let (_, text) = wizard(&host, vec![Enter, Enter, CtrlC], "");
    assert!(!text.contains("WireGuard"), "{text}");
}

#[test]
fn wireguard_asks_for_the_device_again_on_a_bad_value() {
    let fs = fs();
    let runner = runner(|r| r);
    let host = Host {
        modules: with_wireguard(),
        ..on(&fs, &runner)
    };
    let good = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    let questions = vec![
        Enter,
        Enter,
        Pick(2),
        Type("My Laptop".into()),
        Type(good.into()),
        Enter,
        // One bit too many.
        Type("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQF=".into()),
        Enter,
        Type(format!(" {good} ")),
        Enter,
        Enter,
    ];
    let (text, profile) = scenario("wireguard", &host, questions);
    assert!(
        text.contains("  peer name \"My Laptop\" is not 1 to 32"),
        "{text}"
    );
    assert!(
        text.contains("  peer laptop: public_key is not a WireGuard key\n"),
        "{text}"
    );
    assert_eq!(
        profile,
        format!(
            "schema = 1\nextends = \"private\"\n\n[[modules.\"net.wireguard\".peers]]\n\
             host = 2\nname = \"laptop\"\npublic_key = \"{good}\"\n"
        )
    );
}

const TAILNET_IP: &str = "100.64.0.7";

/// `tailscale0` up with [`TAILNET_IP`], and the node logged in.
fn tailnet(facts: &mut Facts) {
    let ip = TAILNET_IP.parse().unwrap();
    facts.interfaces.push(Interface {
        name: "tailscale0".into(),
        kind: None,
        addresses: vec![Address { ip, prefix: 32 }],
        up: true,
    });
    facts.tailscale = Some(Tailscale {
        backend_state: "Running".into(),
        ips: vec![ip],
        key_expiry: None,
        have_node_key: true,
    });
}

/// A login as admin through `tailscale0`.
fn admin_through_tailscale() -> Session {
    Session {
        id: SessionId {
            pid: 913,
            start: 95_000,
        },
        client: "100.100.0.9:50022".parse().unwrap(),
        server: format!("{TAILNET_IP}:22").parse().unwrap(),
        uid: 1001,
        user: Some("admin".into()),
    }
}

const PRIVATE: &str = "schema = 1\nextends = \"private\"\n\n[modules.\"net.tailscale\"]\n";

/// admin with a key.
fn fs_with_admin() -> FakeFs {
    let admin = |mode| FileOwner {
        mode,
        uid: 1001,
        gid: 1001,
    };
    let fs = fs()
        .with_dir("/home/admin", admin(0o755))
        .with_dir("/home/admin/.ssh", admin(0o700));
    let keys = Path::new("/home/admin/.ssh/authorized_keys");
    fs.write_atomic(keys, format!("{KEY}\n").as_bytes(), admin(0o600))
        .unwrap();
    fs
}

/// The step 1 profile in the current directory with `mode` and `uid`, and
/// admin's key, as step 1 left them.
fn fs_with_profile(mode: u32, uid: u32) -> FakeFs {
    let fs = fs_with_admin();
    let owner = FileOwner { mode, uid, gid: 0 };
    fs.write_atomic(&Path::new(CWD).join(SAVE_AS), PRIVATE.as_bytes(), owner)
        .unwrap();
    fs
}

/// admin as step 1 left it, and `tailscaled` enabled.
fn after_step_one(r: FakeRunner) -> FakeRunner {
    r.on(
        "getent",
        ["passwd", "admin"],
        Output::success("admin:x:1001:1001::/home/admin:/bin/bash\n"),
    )
    .on(
        "sudo",
        ["-n", "-l", "-U", "admin"],
        Output::success(
            "User admin may run the following commands on vm:\n    (ALL) NOPASSWD: ALL\n",
        ),
    )
    .on("id", ["-Gn", "admin"], Output::success("admin\n"))
    .on(
        "systemctl",
        ["show", "--property=UnitFileState", "tailscaled.service"],
        Output::success("UnitFileState=enabled\n"),
    )
}

/// The VM with Tailscale up, logged in to as admin from a public address.
fn public_login(sys: Sys) -> anyhow::Result<Facts> {
    let mut facts = vm(sys)?;
    tailnet(&mut facts);
    Ok(facts)
}

/// [`public_login`], but the login comes through `tailscale0`.
fn vpn_login(sys: Sys) -> anyhow::Result<Facts> {
    let mut facts = public_login(sys)?;
    facts.session = Some(admin_through_tailscale());
    Ok(facts)
}

fn step_two_host<'a>(fs: &'a FakeFs, runner: &'a FakeRunner) -> Host<'a> {
    Host {
        facts: vpn_login,
        ..on(fs, runner)
    }
}

/// Tailscale up and this login through it: firewall.inbound limits SSH in
/// this one apply, and the wizard says so.
#[test]
fn a_login_through_tailscale_closes_ssh_in_one_apply() {
    let fs = fs_with_admin();
    let runner = runner(after_step_one);
    let host = step_two_host(&fs, &runner);
    let questions = vec![Enter, Enter, Pick(1), Enter, Enter, Enter];
    let (text, _) = scenario("tailscale-through", &host, questions);
    assert!(
        text.contains("this apply closes SSH to the internet"),
        "{text}"
    );
    assert!(!text.contains("Two steps"), "{text}");
    assert!(
        text.contains("  If tailscale0 stops working, SSH is closed."),
        "{text}"
    );
    assert!(
        text.contains("minutes to log in through tailscale0 from a new"),
        "{text}"
    );
    assert!(text.contains("iifname \"tailscale0\" tcp dport"), "{text}");
}

#[test]
fn step_two_is_offered_through_the_vpn() {
    let fs = fs_with_profile(0o644, 0);
    let runner = runner(after_step_one);
    let host = step_two_host(&fs, &runner);
    let (code, text) = wizard(&host, vec![Say(true)], "n\n");
    assert_eq!(code, 0, "{text}");
    snapshot("step-two", &text);
    assert!(
        text.contains("? Apply step 2: accept SSH only through tailscale0? (y/N) yes\n"),
        "{text}"
    );
    assert!(text.contains("iifname \"tailscale0\""), "{text}");
    assert!(!text.contains("step 1 of 2: SSH stays public"), "{text}");

    // No: the questions follow.
    let (code, text) = wizard(&host, vec![Say(false), CtrlC], "");
    assert_eq!(code, EXIT_INTERRUPTED, "{text}");
    assert!(
        text.ends_with("? What will this server run? ^C\nNothing was changed.\n"),
        "{text}"
    );
}

/// Not offered from a public login, nor for a file others can write.
#[test]
fn step_two_needs_a_login_through_the_vpn_and_roots_file() {
    let runner = runner(after_step_one);
    type Collect = fn(Sys) -> anyhow::Result<Facts>;
    let login: [(_, Collect); 4] = [
        (fs_with_profile(0o644, 0), vpn_login),
        (fs_with_profile(0o644, 0), public_login),
        (fs_with_profile(0o666, 0), vpn_login),
        (fs_with_profile(0o644, 1000), vpn_login),
    ];
    for (i, (fs, facts)) in login.into_iter().enumerate() {
        let host = Host {
            facts,
            ..on(&fs, &runner)
        };
        let facts = (host.facts)(host.sys).unwrap();
        assert_eq!(
            step_two(&host, &facts, Path::new(CWD)).is_some(),
            i == 0,
            "{i}"
        );
    }
}

/// After step 1, the login through the VPN that runs step 2.
#[test]
fn step_one_ends_with_the_login_through_the_vpn() {
    let fs = fs();
    let runner = runner(|r| r);
    let mut builder = ProfileBuilder::new("private").unwrap();
    builder.set_params("net.tailscale", toml::Table::new());
    let done = |host: &Host| {
        let mut out = Vec::new();
        step_one_done(host, &builder, "/root/vps-ready.toml", &mut out).unwrap();
        String::from_utf8(out).unwrap()
    };
    let host = Host {
        facts: public_login,
        ..on(&fs, &runner)
    };
    assert_eq!(
        done(&host),
        "\nStep 2 of 2: SSH is still open to the internet. To close it, log in through\n\
         tailscale0 and apply the same profile again:\n  \
         ssh -t admin@100.64.0.7 sudo vps-ready apply --profile /root/vps-ready.toml\n"
    );
    // Not up yet, e.g. a login still to do by hand.
    let host = on(&fs, &runner);
    assert!(
        done(&host).contains("ssh -t admin@<address of tailscale0> sudo vps-ready"),
        "{}",
        done(&host)
    );
}
