//! The private profile's sites through a Cloudflare Tunnel: the question,
//! the hidden token, and the token file the wizard writes before the plan.

use super::*;
use crate::modules::net_tunnel::placeholder_token;

/// Marks the token's secret, so that a test can look for it anywhere.
/// Base64 of `MARKER-placeholder`, as the token's `s` must be.
const SECRET: &str = "TUFSS0VSLXBsYWNlaG9sZGVy";

fn token() -> String {
    placeholder_token(SECRET)
}

/// The VM with Docker and an app on 8080, so the sites are asked.
fn with_docker(sys: Sys) -> anyhow::Result<Facts> {
    let mut facts = vm(sys)?;
    facts.docker = true;
    facts
        .listeners
        .push(listener(Proto::Tcp, "0.0.0.0", 8080, "app"));
    Ok(facts)
}

fn tunnel_host<'a>(fs: &'a FakeFs, runner: &'a FakeRunner) -> Host<'a> {
    Host {
        facts: with_docker,
        ..on(fs, runner)
    }
}

/// Tailscale without a key, one site, and `reach` at the tunnel question;
/// `then` answers what follows.
fn questions(reach: usize, then: impl IntoIterator<Item = Answer>) -> Vec<Answer> {
    let mut answers = vec![
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
        Pick(reach),
    ];
    answers.extend(then);
    answers
}

fn root(mode: u32) -> FileOwner {
    FileOwner {
        mode,
        uid: 0,
        gid: 0,
    }
}

/// Every file on `fs` but the token's that holds [`SECRET`].
fn holding_secret(fs: &FakeFs, dir: &Path, found: &mut Vec<PathBuf>) {
    for path in fs.read_dir(dir).unwrap() {
        if fs.metadata(&path).unwrap().kind == FileKind::Dir {
            holding_secret(fs, &path, found);
        } else if path != Path::new(TOKEN_FILE) {
            let bytes = fs.read(&path).unwrap_or_default();
            if String::from_utf8_lossy(&bytes).contains(SECRET) {
                found.push(path);
            }
        }
    }
}

/// The tunnel choice adds `net.tunnel` and `behind_tunnel`, opens no port,
/// and asks the token hidden, again on a bad one. The plan sees an empty
/// file; a declined apply removes it, and the saved profile has the path,
/// never the token.
#[test]
fn the_tunnel_puts_the_sites_behind_it_with_no_port() {
    let fs = fs();
    let runner = runner(|r| r);
    let host = tunnel_host(&fs, &runner);
    let answers = questions(
        0,
        [
            Type("not-a-token".into()),
            Type(format!("sudo cloudflared service install {}", token())),
        ],
    );
    let (code, text) = wizard(&host, answers.clone(), "n\n");
    assert_eq!(code, 0, "{text}");
    snapshot("private-tunnel", &text);
    assert!(!text.contains(SECRET) && !text.contains(&token()), "{text}");
    assert!(
        text.contains(
            "? How do visitors reach this site\n  > Through a Cloudflare Tunnel (no public \
             ports; DNS on Cloudflare)\n    Directly, on ports 80 and 443 (Caddy gets the \
             certificate)\n"
        ),
        "{text}"
    );
    assert!(text.contains("  That is not a tunnel token"), "{text}");
    assert!(
        text.contains("? Tunnel token (hidden; Enter to add it later): [hidden]\n"),
        "{text}"
    );
    assert!(!text.contains("are opened for Caddy"), "{text}");
    assert!(text.contains("net.tunnel: "), "{text}");
    // A file outside the transaction, not one of its changes.
    assert!(!text.contains(&format!("+ {TOKEN_FILE}")), "{text}");
    assert!(!fs.exists(Path::new(TOKEN_FILE)), "declined");
    assert!(!fs.exists(Path::new("/etc/vps-ready")), "declined");

    // The plan of the saved answers needs the file in place.
    fs.create_dir(Path::new("/etc/vps-ready"), root(0o755))
        .unwrap();
    fs.create_new(Path::new(TOKEN_FILE), token().as_bytes(), root(0o600))
        .unwrap();
    let saved = round_trip(&host, questions(0, [Say(true)])).to_toml();
    assert!(!saved.contains(SECRET), "{saved}");
    let parsed = Profile::parse(&saved, host.modules).unwrap();
    let tunnel = parsed.params("net.tunnel").unwrap();
    assert_eq!(
        tunnel.get("token_file").and_then(toml::Value::as_str),
        Some(TOKEN_FILE)
    );
    let proxy = parsed.params("deploy.proxy").unwrap();
    assert_eq!(proxy.get("behind_tunnel"), Some(&true.into()), "{saved}");
    let allow = parsed.params("firewall.inbound").unwrap().get("allow");
    assert_eq!(allow, Some(&toml::Value::Array(Vec::new())), "{saved}");
}

/// [`TOKEN_FILE`] is created before the plan with O_EXCL, root's with
/// mode 0600, and gets the token after the yes. It is never a resource, so
/// its bytes are in no other file, the journal included, and it stays
/// after the apply.
#[test]
fn the_token_file_is_never_journaled() {
    let fs = fs()
        .with_file("/proc/sys/kernel/random/boot_id", "a\n")
        .with_file("/proc/uptime", "1000.00 1.00\n");
    // apt ships it: three vendor sources would each plan to create it.
    for dir in ["/etc/systemd/system", "/etc/apt/keyrings"] {
        fs.create_dir_all(Path::new(dir), 0o755).unwrap();
    }
    let runner = runner(|r| {
        r.on("systemd-run", Vec::<String>::new(), Output::success(""))
            .on(
                "/var/lib/vps-ready/bin/vps-ready",
                ["version"],
                Output::success(format!("{}\n", crate::VERSION_INFO)),
            )
            .on("systemctl", Vec::<String>::new(), Output::success(""))
    });
    let host = tunnel_host(&fs, &runner);
    let (_, text) = wizard(&host, questions(0, [Type(token())]), "y\n");
    assert!(!text.contains(SECRET), "{text}");
    assert!(text.contains("Apply "), "{text}");
    assert!(!txns(&fs).is_empty(), "{text}");
    let (bytes, meta) = fs.read_nofollow(Path::new(TOKEN_FILE)).unwrap();
    assert_eq!(bytes, token().as_bytes());
    assert_eq!((meta.mode, meta.uid, meta.gid), (0o600, 0, 0));
    let mut found = Vec::new();
    holding_secret(&fs, Path::new("/"), &mut found);
    assert!(found.is_empty(), "{found:?}");
    for cmd in runner.calls() {
        assert!(!format!("{cmd:?}").contains(SECRET), "{cmd:?}");
    }

    // O_EXCL: the wizard never writes into a file that appeared meanwhile.
    let mut secrets = Secrets::new(&host);
    let other = Zeroizing::new("other".to_owned());
    let err = secrets.with_token(other, Existing::None).err().unwrap();
    assert!(err.to_string().contains(TOKEN_FILE), "{err}");
    drop(secrets);
    assert_eq!(fs.read(Path::new(TOKEN_FILE)).unwrap(), token().as_bytes());
}

/// [`setup_runner`]'s VM: the dead-man timer can be armed.
fn applying_fs() -> FakeFs {
    let fs = fs()
        .with_file("/proc/sys/kernel/random/boot_id", "a\n")
        .with_file("/proc/uptime", "1000.00 1.00\n");
    for dir in ["/etc/systemd/system", "/etc/apt/keyrings"] {
        fs.create_dir_all(Path::new(dir), 0o755).unwrap();
    }
    fs
}

fn setup_runner() -> FakeRunner {
    runner(|r| {
        r.on("systemd-run", Vec::<String>::new(), Output::success(""))
            .on(
                "/var/lib/vps-ready/bin/vps-ready",
                ["version"],
                Output::success(format!("{}\n", crate::VERSION_INFO)),
            )
            .on("systemctl", Vec::<String>::new(), Output::success(""))
    })
}

/// The plan sees [`TOKEN_FILE`] empty, and the token is written only after
/// the yes: a signal held back by then declines, removes the file and ends
/// the wizard with that signal.
#[test]
fn a_signal_at_the_yes_removes_the_token_file() {
    let fs = fs();
    let runner = runner(|r| r);
    let defer = Defer::unregistered();
    defer.note(15);
    let host = Host {
        defer: Some(defer),
        ..tunnel_host(&fs, &runner)
    };
    let (code, text) = wizard(&host, questions(0, [Type(token())]), "y\n");
    assert_eq!(code, 128 + 15, "{text}");
    assert!(
        text.ends_with("[y/N] y\nNothing was changed.\nStopped by signal 15.\n"),
        "{text}"
    );
    assert!(!fs.exists(Path::new(TOKEN_FILE)));
    assert!(!fs.exists(Path::new("/etc/vps-ready")));

    // The file the plan checks holds no token.
    let mut secrets = Secrets::new(&host);
    secrets
        .with_token(Zeroizing::new(token()), Existing::None)
        .unwrap();
    let (bytes, meta) = fs.read_nofollow(Path::new(TOKEN_FILE)).unwrap();
    assert!(bytes.is_empty());
    assert_eq!((meta.mode, meta.uid), (0o600, 0));
    // Declined: never written, and removed.
    drop(secrets);
    assert!(!fs.exists(Path::new(TOKEN_FILE)));
}

/// An error before the engine starts, here a refused plan, removes the
/// file this run created.
#[test]
fn an_error_before_the_apply_removes_the_token_file() {
    let fs = fs();
    let runner = runner(|r| r);
    let host = Host {
        facts: |sys| {
            let mut facts = with_docker(sys)?;
            facts
                .listeners
                .push(listener(Proto::Tcp, "127.0.0.1", 20241, "other"));
            Ok(facts)
        },
        ..on(&fs, &runner)
    };
    let (code, text) = wizard(&host, questions(0, [Type(token())]), "y\n");
    assert_eq!(code, 2, "{text}");
    assert!(
        text.contains("something already listens on 127.0.0.1:20241"),
        "{text}"
    );
    assert!(!fs.exists(Path::new(TOKEN_FILE)));
    assert!(!fs.exists(Path::new("/etc/vps-ready")));
}

/// A file that holds a token, root's and private, is kept on a yes, with
/// no token asked; a declined apply leaves it.
#[test]
fn an_existing_token_file_is_kept_on_a_yes() {
    let fs = fs();
    fs.create_dir(Path::new("/etc/vps-ready"), root(0o755))
        .unwrap();
    fs.create_new(Path::new(TOKEN_FILE), token().as_bytes(), root(0o600))
        .unwrap();
    let runner = runner(|r| r);
    let host = tunnel_host(&fs, &runner);
    let (code, text) = wizard(&host, questions(0, [Say(true)]), "n\n");
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains(&format!(
            "? {TOKEN_FILE} holds a tunnel token. Keep it? (Y/n) yes\n"
        )),
        "{text}"
    );
    assert!(!text.contains("Tunnel token (hidden"), "{text}");
    assert_eq!(fs.read(Path::new(TOKEN_FILE)).unwrap(), token().as_bytes());
}

/// "Keep it? no": the old token stays until the yes, so a declined apply
/// leaves it, and an applied one replaces it.
#[test]
fn a_token_file_is_replaced_only_after_the_yes() {
    let fs = applying_fs();
    fs.create_dir(Path::new("/etc/vps-ready"), root(0o755))
        .unwrap();
    fs.create_new(Path::new(TOKEN_FILE), token().as_bytes(), root(0o600))
        .unwrap();
    let runner = setup_runner();
    let host = tunnel_host(&fs, &runner);
    let new = placeholder_token("bmV3LXBsYWNlaG9sZGVy");
    let answers = questions(0, [Say(false), Type(new.clone())]);
    let (code, text) = wizard(&host, answers.clone(), "n\n");
    assert_eq!(code, 0, "{text}");
    assert!(
        text.ends_with("? [y/N] n\nNothing was changed.\n"),
        "{text}"
    );
    assert_eq!(fs.read(Path::new(TOKEN_FILE)).unwrap(), token().as_bytes());

    let (_, text) = wizard(&host, answers, "y\n");
    assert!(!txns(&fs).is_empty(), "{text}");
    let (bytes, meta) = fs.read_nofollow(Path::new(TOKEN_FILE)).unwrap();
    assert_eq!((bytes, meta.mode), (new.into_bytes(), 0o600));
}

/// A file others can read is emptied for the plan, and its token is never
/// trusted: the pasted one is written after the yes.
#[test]
fn an_unusable_token_file_is_replaced() {
    let fs = fs();
    fs.create_dir(Path::new("/etc/vps-ready"), root(0o755))
        .unwrap();
    fs.create_new(Path::new(TOKEN_FILE), token().as_bytes(), root(0o644))
        .unwrap();
    let runner = runner(|r| r);
    let host = tunnel_host(&fs, &runner);
    let new = placeholder_token("bmV3LXBsYWNlaG9sZGVy");
    let (code, text) = wizard(&host, questions(0, [Type(new)]), "n\n");
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains(&format!(
            "  {TOKEN_FILE} holds no tunnel token that only root can"
        )),
        "{text}"
    );
    let (bytes, meta) = fs.read_nofollow(Path::new(TOKEN_FILE)).unwrap();
    assert!(bytes.is_empty());
    assert_eq!(meta.mode, 0o600);
}

/// A directory where the token goes is refused at the question.
#[test]
fn a_directory_at_the_token_path_is_refused() {
    let fs = fs();
    fs.create_dir_all(Path::new(TOKEN_FILE), 0o700).unwrap();
    let runner = runner(|r| r);
    let host = tunnel_host(&fs, &runner);
    let (code, text) = wizard(&host, questions(0, []), "");
    assert_eq!(code, 2, "{text}");
    assert!(
        text.contains(&format!("error: {TOKEN_FILE} is not a regular file (Dir)")),
        "{text}"
    );
}

/// Enter at the token adds the tunnel without `token_file`: the plan says
/// how to add one later.
#[test]
fn no_token_installs_the_tunnel_for_later() {
    let fs = fs();
    let runner = runner(|r| r);
    let host = tunnel_host(&fs, &runner);
    let answers = questions(0, [Enter]);
    let (code, text) = wizard(&host, answers.clone(), "n\n");
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains("no token_file, so no connector runs"),
        "{text}"
    );
    assert!(!fs.exists(Path::new(TOKEN_FILE)));
    let saved = round_trip(&host, answers).to_toml();
    assert!(saved.contains("[modules.\"net.tunnel\"]\n"), "{saved}");
    assert!(!saved.contains("token_file"), "{saved}");
}

/// Outside the private profile, or where the tunnel does not apply, the
/// question is not asked.
#[test]
fn the_question_is_only_for_the_private_profile() {
    let fs = fs();
    let runner = runner(|r| r);
    let host = tunnel_host(&fs, &runner);
    let answers = vec![
        Enter,
        Enter,
        Enter,
        Enter,
        Enter,
        Enter,
        Type("app.example.com".into()),
        Type("127.0.0.1:8080".into()),
        Enter,
    ];
    let (code, text) = wizard(&host, answers, "n\n");
    assert_eq!(code, 0, "{text}");
    assert!(!text.contains("How do visitors reach"), "{text}");

    // A cloudflared unit vps-ready did not write.
    let host = Host {
        facts: |sys| {
            let mut facts = with_docker(sys)?;
            facts.cloudflared.units = vec!["cloudflared.service".into()];
            Ok(facts)
        },
        ..on(&fs, &runner)
    };
    let mut answers = questions(0, []);
    answers.pop();
    let (code, text) = wizard(&host, answers, "n\n");
    assert_eq!(code, 0, "{text}");
    assert!(!text.contains("How do visitors reach"), "{text}");
    assert!(text.contains("are opened for Caddy"), "{text}");
}
