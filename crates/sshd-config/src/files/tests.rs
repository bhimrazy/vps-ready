use std::collections::BTreeMap;

use super::*;

/// Files held in memory, keyed by absolute path.
struct Mem(BTreeMap<PathBuf, String>);

impl Mem {
    fn new(files: &[(&str, &str)]) -> Self {
        Self(
            files
                .iter()
                .map(|(p, c)| (PathBuf::from(p), (*c).to_owned()))
                .collect(),
        )
    }
}

impl Source for Mem {
    fn read(&self, path: &Path) -> io::Result<String> {
        self.0
            .get(path)
            .cloned()
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }

    fn list(&self, dir: &Path) -> io::Result<Vec<String>> {
        let names: Vec<String> = self
            .0
            .keys()
            .filter(|p| p.parent() == Some(dir))
            .filter_map(|p| Some(p.file_name()?.to_string_lossy().into_owned()))
            .collect();
        if names.is_empty() {
            return Err(io::ErrorKind::NotFound.into());
        }
        Ok(names)
    }
}

/// A fixture tree under `testdata/<name>`, addressed by its absolute sshd paths.
struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> Self {
        Self(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("testdata")
                .join(name),
        )
    }

    fn real(&self, path: &Path) -> PathBuf {
        self.0.join(path.strip_prefix("/").unwrap_or(path))
    }
}

impl Source for Fixture {
    fn read(&self, path: &Path) -> io::Result<String> {
        Os.read(&self.real(path))
    }

    fn list(&self, dir: &Path) -> io::Result<Vec<String>> {
        Os.list(&self.real(dir))
    }
}

const MAIN: &str = "/etc/ssh/sshd_config";
const DROP_IN: &str = "/etc/ssh/sshd_config.d/00-vps-ready.conf";
const MANAGED: [&str; 3] = [
    "passwordauthentication",
    "permitrootlogin",
    "pubkeyauthentication",
];

fn read(source: &dyn Source) -> Config {
    Config::read(source, Path::new(MAIN)).unwrap()
}

fn words(line: &str) -> Vec<String> {
    split_line(line).unwrap().unwrap().1
}

#[test]
fn splits_lines() {
    assert_eq!(split_line("").unwrap(), None);
    assert_eq!(split_line("   # comment").unwrap(), None);
    assert_eq!(
        split_line("\tPermitRootLogin   no # why").unwrap(),
        Some(("permitrootlogin".to_owned(), vec!["no".to_owned()]))
    );
    assert_eq!(words("Port=2222"), ["2222"]);
    assert_eq!(words("Port = 2222"), ["2222"]);
    assert_eq!(
        words("AllowUsers alice \"bob smith\" c\\ d"),
        ["alice", "bob smith", "c d"]
    );
    assert_eq!(words("Banner \"/etc/a b\" #x"), ["/etc/a b"]);
    assert_eq!(words("AcceptEnv LANG LC_*"), ["LANG", "LC_*"]);
    assert_eq!(words("PermitTTY"), Vec::<String>::new());
    assert!(split_line("Banner \"/etc/issue").is_err());
}

#[test]
fn globs() {
    let cases = [
        ("*.conf", "50-cloud-init.conf", true),
        ("*.conf", "conf", false),
        ("*.conf", ".hidden.conf", false),
        (".*.conf", ".hidden.conf", true),
        ("??-x", "00-x", true),
        ("??-x", "0-x", false),
        ("[0-4]*", "30-a", true),
        ("[0-4]*", "50-a", false),
        ("[!0-4]*", "50-a", true),
        ("a[", "a[", true),
        ("a\\*", "a*", true),
        ("a\\*", "ab", false),
        ("*a*b*", "xxaxxbxx", true),
        ("*a*b*", "xxbxxaxx", false),
        ("", "", true),
        ("*", "", true),
    ];
    for (pattern, name, want) in cases {
        assert_eq!(glob_match(pattern, name), want, "{pattern} vs {name}");
    }
}

#[test]
fn reads_includes_in_lexical_order() {
    let source = Mem::new(&[
        (MAIN, "Port 22\nInclude sshd_config.d/*.conf\nUsePAM yes\n"),
        ("/etc/ssh/sshd_config.d/50-b.conf", "PermitRootLogin no\n"),
        ("/etc/ssh/sshd_config.d/10-a.conf", "PermitRootLogin yes\n"),
        ("/etc/ssh/sshd_config.d/README", "Port 1\n"),
        ("/etc/ssh/sshd_config.d/.x.conf", "Port 2\n"),
    ]);
    let config = read(&source);
    let order: Vec<(&str, &str)> = config
        .directives()
        .iter()
        .map(|d| (d.keyword.as_str(), d.file.to_str().unwrap()))
        .collect();
    assert_eq!(
        order,
        [
            ("port", MAIN),
            ("include", MAIN),
            ("permitrootlogin", "/etc/ssh/sshd_config.d/10-a.conf"),
            ("permitrootlogin", "/etc/ssh/sshd_config.d/50-b.conf"),
            ("usepam", MAIN),
        ]
    );
    let first = config.first("PermitRootLogin").unwrap();
    assert_eq!(first.args, ["yes"]);
    assert_eq!(first.line, 1);
}

#[test]
fn match_blocks_scope_their_lines() {
    let source = Mem::new(&[(
        MAIN,
        "Match User bob\n  PasswordAuthentication yes\nMatch all\n  X11Forwarding no\n",
    )]);
    let config = read(&source);
    let scoped: Vec<bool> = config.directives().iter().map(|d| d.in_match).collect();
    assert_eq!(scoped, [false, true, true, true]);
    assert_eq!(config.first("passwordauthentication"), None);
    assert_eq!(config.directives()[0].args, ["User", "bob"]);
}

#[test]
fn match_in_an_included_file_ends_with_it() {
    let source = Mem::new(&[
        (MAIN, "Include /etc/ssh/a.conf\nPort 22\n"),
        ("/etc/ssh/a.conf", "Match User bob\nPort 2222\n"),
    ]);
    let config = read(&source);
    let port = config.first("port").unwrap();
    assert_eq!((port.args[0].as_str(), port.line), ("22", 2));
}

#[test]
fn include_inside_match_is_conditional() {
    let source = Mem::new(&[
        (MAIN, "Match User bob\nInclude /etc/ssh/a.conf\n"),
        ("/etc/ssh/a.conf", "Port 2222\n"),
    ]);
    let config = read(&source);
    assert!(
        config
            .directives()
            .iter()
            .all(|d| d.keyword == "match" || d.in_match)
    );
    assert_eq!(config.first("port"), None);
}

#[test]
fn in_match_blocks_names_the_block_of_each_line() {
    let source = Mem::new(&[
        (
            MAIN,
            "PasswordAuthentication no\nInclude /etc/ssh/d/*.conf\n\
             Match Address 192.0.2.0/24\nInclude /etc/ssh/m.conf\n",
        ),
        // A Match block in a drop-in ends with the file.
        (
            "/etc/ssh/d/50-a.conf",
            "Match User bob\n  passwordauthentication yes\n",
        ),
        ("/etc/ssh/d/60-b.conf", "PasswordAuthentication no\n"),
        // Nested includes inherit the Match block of the first Include.
        ("/etc/ssh/m.conf", "Include /etc/ssh/n.conf\n"),
        ("/etc/ssh/n.conf", "PASSWORDAUTHENTICATION=yes\n"),
    ]);
    let config = read(&source);
    let found: Vec<(&str, usize, &str, usize, Vec<String>)> = config
        .in_match_blocks("PasswordAuthentication")
        .map(|(d, m)| {
            (
                d.file.to_str().unwrap(),
                d.line,
                m.file.to_str().unwrap(),
                m.line,
                m.args.clone(),
            )
        })
        .collect();
    assert_eq!(
        found,
        [
            (
                "/etc/ssh/d/50-a.conf",
                2,
                "/etc/ssh/d/50-a.conf",
                1,
                vec!["User".to_owned(), "bob".to_owned()]
            ),
            (
                "/etc/ssh/n.conf",
                1,
                MAIN,
                3,
                vec!["Address".to_owned(), "192.0.2.0/24".to_owned()]
            ),
        ]
    );
    assert_eq!(config.in_match_blocks("x11forwarding").count(), 0);
}

#[test]
fn missing_includes_are_skipped_but_a_missing_main_file_is_an_error() {
    let source = Mem::new(&[(
        MAIN,
        "Include /etc/ssh/none.conf /etc/ssh/none.d/*\nPort 22\n",
    )]);
    assert_eq!(read(&source).directives().len(), 2);
    assert!(matches!(
        Config::read(&Mem::new(&[]), Path::new(MAIN)),
        Err(Error::Io { .. })
    ));
}

#[test]
fn reports_syntax_errors_and_include_loops() {
    let source = Mem::new(&[(MAIN, "Port 22\nBanner \"oops\n")]);
    let err = Config::read(&source, Path::new(MAIN)).unwrap_err();
    assert!(matches!(err, Error::Syntax { line: 2, .. }), "{err}");
    assert_eq!(
        err.to_string(),
        "/etc/ssh/sshd_config:2: unterminated quote"
    );

    let source = Mem::new(&[(MAIN, "Include /etc/ssh/sshd_config\n")]);
    let err = Config::read(&source, Path::new(MAIN)).unwrap_err();
    assert!(matches!(err, Error::TooDeep { .. }), "{err}");
}

#[test]
fn include_check_on_fixtures() {
    let check = |name: &str| read(&Fixture::new(name)).include_check(Path::new(DROP_IN), &MANAGED);

    assert_eq!(check("stock"), IncludeCheck::Covered);
    assert_eq!(check("cloud-init"), IncludeCheck::Covered);
    // other.d/*.conf is read after the whole of sshd_config.d/*.conf.
    assert_eq!(check("include-two-patterns"), IncludeCheck::Covered);
    assert_eq!(check("include-missing"), IncludeCheck::Missing);
    assert_eq!(
        check("include-after-match"),
        IncludeCheck::AfterMatch {
            file: MAIN.into(),
            line: 2
        }
    );
    assert_eq!(
        check("include-after-keyword"),
        IncludeCheck::AfterKeyword {
            keyword: "permitrootlogin".to_owned(),
            file: MAIN.into(),
            line: 1
        }
    );
}

#[test]
fn drop_in_wins_over_cloud_init_on_fixtures() {
    let config = read(&Fixture::new("cloud-init"));
    let first = config.first("passwordauthentication").unwrap();
    assert_eq!(first.file, Path::new(DROP_IN));
    assert_eq!(first.args, ["no"]);

    let later: Vec<_> = config
        .directives()
        .iter()
        .filter(|d| d.keyword == "passwordauthentication")
        .map(|d| d.file.file_name().unwrap().to_str().unwrap())
        .collect();
    assert_eq!(later, ["00-vps-ready.conf", "50-cloud-init.conf"]);
    // `.txt` files are not matched by the `*.conf` glob.
    assert_eq!(
        config
            .directives()
            .iter()
            .filter(|d| d.keyword == "permitrootlogin")
            .count(),
        1
    );
}

#[test]
fn include_check_matches_patterns_not_files() {
    let target = Path::new(DROP_IN);
    let check = |text: &str| read(&Mem::new(&[(MAIN, text)])).include_check(target, &MANAGED);

    assert_eq!(
        check("Include /etc/ssh/sshd_config.d/*.conf"),
        IncludeCheck::Covered
    );
    assert_eq!(check("Include sshd_config.d/*.conf"), IncludeCheck::Covered);
    assert_eq!(
        check("Include /etc/ssh/sshd_config.d/00-*"),
        IncludeCheck::Covered
    );
    assert_eq!(check("Include /etc/ssh/*/*.conf"), IncludeCheck::Covered);
    assert_eq!(
        check("Include /other/*.conf /etc/ssh/sshd_config.d/*"),
        IncludeCheck::Covered
    );
    assert_eq!(
        check("Include /etc/ssh/sshd_config.d/*.cfg"),
        IncludeCheck::Missing
    );
    assert_eq!(check("Include /etc/ssh/*.conf"), IncludeCheck::Missing);
    assert_eq!(
        check("Include /etc/ssh/sshd_config.d/*/*.conf"),
        IncludeCheck::Missing
    );
    // Another keyword before the Include does not matter; a conditional Include does not count.
    assert_eq!(
        check("UsePAM yes\nInclude /etc/ssh/sshd_config.d/*.conf"),
        IncludeCheck::Covered
    );
    assert!(matches!(
        check("Match all\nInclude /etc/ssh/sshd_config.d/*.conf"),
        IncludeCheck::AfterMatch { line: 1, .. }
    ));
    assert_eq!(
        check("Match all\nPasswordAuthentication yes"),
        IncludeCheck::Missing
    );
}

/// A `Match` in a file read earlier ends with that file (checked with
/// `sshd -T -C` on OpenSSH 8.9 to 10.0), so it does not hold the drop-in.
/// A file the same `Include` reads first can still set a keyword first.
#[test]
fn include_check_looks_at_files_read_before_the_target() {
    let target = Path::new(DROP_IN);
    let check = |files: &[(&str, &str)]| read(&Mem::new(files)).include_check(target, &MANAGED);
    let main = (MAIN, "Include /etc/ssh/sshd_config.d/*.conf\n");

    assert_eq!(
        check(&[
            (
                MAIN,
                "Include /etc/ssh/m.conf\nInclude sshd_config.d/*.conf\n"
            ),
            (
                "/etc/ssh/m.conf",
                "Match User bob\nPasswordAuthentication yes\n"
            ),
        ]),
        IncludeCheck::Covered
    );
    assert_eq!(
        check(&[
            main,
            (
                "/etc/ssh/sshd_config.d/00-a.conf",
                "Match User bob\nPermitRootLogin yes\n"
            ),
        ]),
        IncludeCheck::Covered
    );
    assert_eq!(
        check(&[
            main,
            ("/etc/ssh/sshd_config.d/0-a.conf", "PermitRootLogin yes\n"),
            (
                "/etc/ssh/sshd_config.d/50-b.conf",
                "PasswordAuthentication yes\n"
            ),
        ]),
        IncludeCheck::AfterKeyword {
            keyword: "permitrootlogin".to_owned(),
            file: "/etc/ssh/sshd_config.d/0-a.conf".into(),
            line: 1
        }
    );
    // A file read before the target that includes another, which sets a keyword.
    assert_eq!(
        check(&[
            main,
            (
                "/etc/ssh/sshd_config.d/0-a.conf",
                "Include /etc/ssh/x.conf\n"
            ),
            ("/etc/ssh/x.conf", "PasswordAuthentication yes\n"),
        ]),
        IncludeCheck::AfterKeyword {
            keyword: "passwordauthentication".to_owned(),
            file: "/etc/ssh/x.conf".into(),
            line: 1
        }
    );
    // Lines after the expansion are read after the target.
    assert_eq!(
        check(&[
            (
                MAIN,
                "Include /etc/ssh/a.conf\nPasswordAuthentication yes\n"
            ),
            ("/etc/ssh/a.conf", "Include sshd_config.d/*.conf\n"),
        ]),
        IncludeCheck::Covered
    );
    // The target's own lines and later files do not count.
    assert_eq!(
        check(&[
            main,
            (DROP_IN, "PermitRootLogin no\n"),
            ("/etc/ssh/sshd_config.d/50-b.conf", "PermitRootLogin yes\n"),
        ]),
        IncludeCheck::Covered
    );
    // With two patterns, the files of the first are read before those of
    // the second, whichever covers the target.
    let other = (
        "/etc/ssh/other.d/10-later.conf",
        "PasswordAuthentication yes\n",
    );
    assert_eq!(
        check(&[
            (MAIN, "Include sshd_config.d/*.conf other.d/*.conf\n"),
            other
        ]),
        IncludeCheck::Covered
    );
    assert_eq!(
        check(&[
            (MAIN, "Include other.d/*.conf sshd_config.d/*.conf\n"),
            other
        ]),
        IncludeCheck::AfterKeyword {
            keyword: "passwordauthentication".to_owned(),
            file: "/etc/ssh/other.d/10-later.conf".into(),
            line: 1
        }
    );
    // An Include inside a Match of an included file is conditional.
    assert_eq!(
        check(&[
            (MAIN, "Include /etc/ssh/a.conf\n"),
            (
                "/etc/ssh/a.conf",
                "Match User bob\nInclude sshd_config.d/*.conf\n"
            ),
        ]),
        IncludeCheck::AfterMatch {
            file: "/etc/ssh/a.conf".into(),
            line: 1
        }
    );
}

mod props {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn split_line_never_panics(s in "\\PC*") {
            let _ = split_line(&s);
        }

        #[test]
        fn glob_never_panics(p in "[*?\\[\\]!^\\\\a-c.-]{0,12}", n in "[a-c.-]{0,12}") {
            let _ = glob_match(&p, &n);
        }

        #[test]
        fn a_name_without_magic_matches_itself(n in "[a-z0-9][a-z0-9._-]{0,12}") {
            prop_assert!(glob_match(&n, &n));
            prop_assert!(glob_match("*", &n));
        }

        #[test]
        fn reading_any_text_never_panics(
            main in "\\PC{0,200}",
            other in "\\PC{0,200}",
            include in "[a-z/*?.\\[]{0,20}",
        ) {
            let main = format!("{main}\nInclude {include}\n");
            let source = Mem::new(&[
                (MAIN, &main),
                ("/etc/ssh/a.conf", &other),
                ("/etc/ssh/sshd_config.d/b.conf", &other),
            ]);
            if let Ok(config) = Config::read(&source, Path::new(MAIN)) {
                let _ = config.include_check(Path::new(DROP_IN), &MANAGED);
                let _ = config.first("port");
            }
        }

        #[test]
        fn every_directive_comes_from_a_file_line(text in "[A-Za-z =\"#\\n]{0,120}") {
            let source = Mem::new(&[(MAIN, &text)]);
            if let Ok(config) = Config::read(&source, Path::new(MAIN)) {
                let lines = text.lines().count();
                for d in config.directives() {
                    prop_assert!(d.line >= 1 && d.line <= lines);
                    prop_assert_eq!(d.keyword.to_ascii_lowercase(), d.keyword.clone());
                }
            }
        }
    }
}
