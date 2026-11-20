//! The private profile's sites through a Cloudflare Tunnel: the question,
//! the hidden token, and the token file the wizard writes before the plan.

use super::*;
use crate::modules::net_tunnel::placeholder_token;

/// Marks the token's secret, so that a test can look for it anywhere.
const SECRET: &str = "MARKER-placeholder-secret";

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
/// and asks the token hidden, again on a bad one. A declined apply removes
/// the file it wrote, and the saved profile has the path, never the token.
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

/// The token is in [`TOKEN_FILE`] before the plan: written with O_EXCL,
/// root's with mode 0600, never a resource, so its bytes are in no other
/// file, the journal included. It stays after the apply.
#[test]
fn the_token_file_is_written_before_the_plan_and_never_journaled() {
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
    let err = TokenFile::write(&fs, "other", false).err().unwrap();
    assert!(err.to_string().contains(TOKEN_FILE), "{err}");
    assert_eq!(fs.read(Path::new(TOKEN_FILE)).unwrap(), token().as_bytes());
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

/// A file others can read, or without a token, is replaced by the pasted
/// one, which stays after a declined apply: the old one cannot come back.
#[test]
fn an_unusable_token_file_is_replaced() {
    let fs = fs();
    fs.create_dir(Path::new("/etc/vps-ready"), root(0o755))
        .unwrap();
    fs.create_new(Path::new(TOKEN_FILE), token().as_bytes(), root(0o644))
        .unwrap();
    let runner = runner(|r| r);
    let host = tunnel_host(&fs, &runner);
    let new = placeholder_token("new-placeholder");
    let (code, text) = wizard(&host, questions(0, [Type(new.clone())]), "n\n");
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains(&format!(
            "  {TOKEN_FILE} holds no tunnel token that only root can"
        )),
        "{text}"
    );
    assert!(
        text.ends_with(&format!(
            "Nothing was changed.\nThe new tunnel token stays in {TOKEN_FILE}.\n"
        )),
        "{text}"
    );
    let (bytes, meta) = fs.read_nofollow(Path::new(TOKEN_FILE)).unwrap();
    assert_eq!((bytes, meta.mode), (new.into_bytes(), 0o600));
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
