//! `export cloud-init` on a [`FakeFs`]: the user-data, and what it refuses.

use std::process::{Command, Stdio};

use yaml_rust2::{Yaml, YamlLoader};

use super::*;
use crate::cli::change::tests::{fixture, host};
use crate::sys::fake::FakeFs;

const CHECKSUMS: &str = "/home/me/checksums.txt";
const PROFILE: &str = "/home/me/vps-ready.toml";
const KEYED: &str = "schema = 1
extends = \"web\"

[modules.\"user.admin\"]
name = \"ops\"
authorized_keys = [\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGroot me@laptop\"]
";

/// The release's `checksums.txt`, as `sha256sum` writes it, with this
/// version's tarballs and the other files it lists.
fn checksums() -> String {
    let v = VERSION_INFO.version;
    format!(
        "{}  vps-ready-{v}-aarch64-unknown-linux-musl.tar.gz\n\
         {}  vps-ready-{v}-x86_64-unknown-linux-musl.tar.gz\n\
         {}  install.sh\n",
        "a1".repeat(32),
        "b2".repeat(32),
        "c3".repeat(32),
    )
}

fn fs(profile: &str, sums: &str) -> FakeFs {
    fixture()
        .with_file(PROFILE, profile)
        .with_file(CHECKSUMS, sums)
}

/// Exit code and stdout, or the error as `main` prints it.
fn export(fs: &FakeFs, spec: &str, base_url: Option<&str>) -> Result<String, String> {
    let mut out = Vec::new();
    cloud_init(&host(fs), spec, Path::new(CHECKSUMS), base_url, &mut out)
        .map(|code| {
            assert_eq!(code, 0);
            String::from_utf8(out).unwrap()
        })
        .map_err(|e| format!("{e:#}"))
}

/// The version in the output, which changes with every release.
fn redact(text: &str) -> String {
    text.replace(VERSION_INFO.version, "<version>")
}

/// The script `runcmd` runs, from the parsed YAML.
fn parsed_script(text: &str) -> (Yaml, String) {
    let doc = YamlLoader::load_from_str(text)
        .unwrap()
        .pop()
        .expect("one document");
    let cmd = &doc["runcmd"][0];
    assert_eq!(cmd[0].as_str(), Some("sh"));
    assert_eq!(cmd[1].as_str(), Some("-c"));
    let script = cmd[2].as_str().unwrap().to_owned();
    (doc, script)
}

#[test]
fn prints_user_data_for_a_profile_file() {
    let fs = fs(KEYED, &checksums());
    let text = export(&fs, PROFILE, None).unwrap();
    insta::assert_snapshot!("cloud-init", redact(&text));
    assert!(text.starts_with("#cloud-config\n"));
    // Far below the 16 KB user-data limit of the smallest provider.
    assert!(text.len() < 4096, "{}", text.len());

    let (doc, script) = parsed_script(&text);
    let file = &doc["write_files"][0];
    assert_eq!(file["path"].as_str(), Some(PROFILE_PATH));
    assert_eq!(file["permissions"].as_str(), Some("0600"));
    assert_eq!(file["content"].as_str(), Some(KEYED));
    assert!(script.contains(&format!("sum={}", "b2".repeat(32))));
    assert!(script.contains(&format!("sum={}", "a1".repeat(32))));
    assert!(script.ends_with(&format!(
        "vps-ready apply --profile {PROFILE_PATH} --yes --deadman=off\n"
    )));
}

#[test]
fn the_script_is_valid_sh() {
    let fs = fs(KEYED, &checksums());
    let (_, script) = parsed_script(&export(&fs, PROFILE, None).unwrap());
    let mut sh = Command::new("sh")
        .arg("-n")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    sh.stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    assert!(sh.wait().unwrap().success(), "{script}");
}

#[test]
fn a_built_in_profile_is_written_as_a_file_that_extends_it() {
    let fs = fs("", &checksums());
    // `web` alone has no keys.
    let err = export(&fs, "web", None).unwrap_err();
    assert!(err.contains("user.admin needs `authorized_keys`"), "{err}");

    // A built-in without user.admin would export; none exists today, so
    // check the text with one that has keys through `extends`.
    let (text, _) = load(&host(&fs), "minimal").unwrap();
    assert_eq!(text, "schema = 1\nextends = \"minimal\"\n");
}

#[test]
fn refuses_line_breaks_that_yaml_would_change() {
    for c in ['\u{85}', '\u{2028}', '\u{2029}', '\u{feff}'] {
        let profile = KEYED.replace("me@laptop", &format!("me{c}@laptop"));
        let err = export(&fs(&profile, &checksums()), PROFILE, None).unwrap_err();
        assert!(
            err.ends_with(&format!(
                "contains U+{:04X}, which YAML would change; remove it",
                u32::from(c)
            )),
            "{err}"
        );
    }
}

#[test]
fn an_indented_profile_keeps_its_text() {
    let profile = format!("\n  # indented\n{KEYED}");
    let fs = fs(&profile, &checksums());
    let text = export(&fs, PROFILE, None).unwrap();
    assert!(text.contains("    content: |2\n"), "{text}");
    let (doc, _) = parsed_script(&text);
    assert_eq!(
        doc["write_files"][0]["content"].as_str(),
        Some(&profile[..])
    );
}

#[test]
fn base_url_replaces_the_release_url() {
    let fs = fs(KEYED, &checksums());
    let v = VERSION_INFO.version;
    let text = export(&fs, PROFILE, Some("http://10.0.2.2:8000/")).unwrap();
    assert!(
        text.contains(&format!("\"http://10.0.2.2:8000/vps-ready-{v}-$t.tar.gz\"")),
        "{text}"
    );
    assert!(!text.contains("github.com"), "{text}");
    // Plain http for a local mirror; the hash still decides.
    assert!(!text.contains("--proto"), "{text}");
    let https = export(&fs, PROFILE, None).unwrap();
    assert!(
        https.contains("curl --proto '=https' --tlsv1.2 -fsSL"),
        "{https}"
    );
    assert!(
        https.contains("wget -q --tries=5 --retry-connrefused -O"),
        "{https}"
    );
    for bad in [
        "ftp://example.com",
        "https://",
        "https:///",
        "https:///x",
        "https://example.com/$(id)",
        "https://example.com/\"x",
        "https://example.com/a b",
        "https://example.com/`id`",
        "https://example.com/\\",
    ] {
        let err = export(&fs, PROFILE, Some(bad)).unwrap_err();
        assert!(err.starts_with("--base-url"), "{bad}: {err}");
    }
}

#[test]
fn refuses_a_profile_without_admin_keys() {
    let fs = fs(
        "schema = 1\nextends = \"web\"\n[modules.\"user.admin\"]\nname = \"ops\"\n",
        &checksums(),
    );
    let err = export(&fs, PROFILE, None).unwrap_err();
    assert_eq!(
        err,
        format!(
            "profile {PROFILE}: user.admin needs `authorized_keys`: at first boot there is \
             no SSH session to copy keys from"
        )
    );
}

#[test]
fn refuses_a_tailscale_auth_key_file() {
    let with = |extra: &str| {
        fs(
            &format!("{KEYED}\n[modules.\"net.tailscale\"]\n{extra}\n"),
            &checksums(),
        )
    };
    let err = export(
        &with("auth_key_file = \"/root/tailscale-auth-key\""),
        PROFILE,
        None,
    )
    .unwrap_err();
    assert!(
        err.starts_with(&format!(
            "profile {PROFILE}: net.tailscale has `auth_key_file`, and nothing at first boot"
        )),
        "{err}"
    );
    assert!(export(&with("hostname = \"web-1\""), PROFILE, None).is_ok());
}

#[test]
fn refuses_checksums_without_a_tarball() {
    let v = VERSION_INFO.version;
    let only_x86: String = checksums()
        .lines()
        .filter(|l| !l.contains("aarch64"))
        .map(|l| format!("{l}\n"))
        .collect();
    // Another release's file, and a line that is not a SHA-256.
    let older = checksums().replace(v, "0.0.1");
    let short = checksums().replace(&"a1".repeat(32), "a1");
    for (sums, arch) in [(only_x86, "aarch64"), (older, "x86_64"), (short, "aarch64")] {
        let fs = fs(KEYED, &sums);
        let err = export(&fs, PROFILE, None).unwrap_err();
        assert_eq!(
            err,
            format!(
                "{CHECKSUMS} has no SHA-256 for vps-ready-{v}-{arch}-unknown-linux-musl.tar.gz; \
                 use the checksums.txt of the v{v} release"
            )
        );
    }
}

#[test]
fn reads_binary_mode_checksums() {
    let sums = checksums().replace("  vps-ready", " *vps-ready");
    assert!(export(&fs(KEYED, &sums), PROFILE, None).is_ok());
}

#[test]
fn refuses_an_invalid_profile() {
    let fs = fs("schema = 1\nextends = \"nope\"\n", &checksums());
    let err = export(&fs, PROFILE, None).unwrap_err();
    assert!(
        err.starts_with(&format!("profile {PROFILE}: cannot extend")),
        "{err}"
    );
    let err = export(&fs, "/nowhere.toml", None).unwrap_err();
    assert!(
        err.starts_with("/nowhere.toml is not a built-in profile"),
        "{err}"
    );
}
