use super::*;
use crate::facts::Facts;
use crate::modules::{Applicability, ModuleSteps, PlanCx, all, parse_params};
use crate::sys::Sys;

/// A module with params, unlike the real ones today, that never applies.
struct Takes;

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct TakesParams {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    name: Option<String>,
}

impl Module for Takes {
    fn id(&self) -> &'static str {
        "test.takes"
    }
    fn title(&self) -> &'static str {
        "Takes params"
    }
    fn why(&self) -> &'static str {
        "test"
    }
    fn applicable(&self, _: &Facts) -> Applicability {
        Applicability::NotApplicable {
            reason: "never".into(),
        }
    }
    fn check_params(&self, params: &toml::Table) -> Result<(), ModuleError> {
        parse_params::<TakesParams>(params).map(|_| ())
    }
    fn plan(&self, _: &PlanCx, _: Sys) -> Result<ModuleSteps, ModuleError> {
        Ok(ModuleSteps::default())
    }
}

fn registry() -> Vec<&'static dyn Module> {
    let mut registry = all().to_vec();
    registry.push(&Takes);
    registry
}

fn parse(text: &str) -> Result<Profile, ProfileError> {
    Profile::parse(text, &registry())
}

fn table(text: &str) -> toml::Table {
    toml::from_str(text).unwrap()
}

#[test]
fn built_in_profiles_are_valid() {
    for (name, _) in BUILT_IN {
        let profile = Profile::built_in(name, all()).unwrap().unwrap();
        assert!(profile.params("kernel.sysctl").is_some(), "{name}");
        assert!(profile.params("updates.auto").is_some(), "{name}");
        assert!(profile.params("user.admin").is_some(), "{name}");
    }
    let enables = |name: &str| {
        let profile = Profile::built_in(name, all()).unwrap().unwrap();
        profile.params("ssh.bruteforce").is_some()
    };
    assert!(enables("web"));
    assert!(!enables("minimal"));
    assert!(Profile::built_in("paranoid", all()).unwrap().is_none());
}

#[test]
fn a_profile_enables_the_modules_it_lists() {
    let profile = parse("schema = 1\n[modules.\"test.takes\"]\nallow = [\"22/tcp\"]\n").unwrap();
    assert_eq!(
        profile.params("test.takes"),
        Some(&table("allow = [\"22/tcp\"]"))
    );
    assert_eq!(profile.params("kernel.sysctl"), None);
}

#[test]
fn extends_merges_one_level_and_replaces_lists() {
    let base = "schema = 1\n[modules.\"test.takes\"]\n\
                allow = [\"22/tcp\", \"80/tcp\"]\nname = \"a\"\n\
                [modules.\"kernel.sysctl\"]\n";
    let child = "schema = 1\nextends = \"base\"\n[modules.\"test.takes\"]\n\
                 allow = [\"443/tcp\"]\n[modules.\"updates.auto\"]\n";
    let profile = Profile::parse_with(child, &registry(), &[("base", base)]).unwrap();
    assert_eq!(
        profile.params("test.takes"),
        Some(&table("allow = [\"443/tcp\"]\nname = \"a\""))
    );
    assert!(profile.params("kernel.sysctl").is_some());
    assert!(profile.params("updates.auto").is_some());
}

#[test]
fn extends_a_built_in_profile() {
    let profile = parse("schema = 1\nextends = \"minimal\"\n").unwrap();
    assert_eq!(
        profile,
        Profile::built_in("minimal", all()).unwrap().unwrap()
    );
}

#[test]
fn enabled_false_drops_a_module() {
    let text = "schema = 1\nextends = \"web\"\n[modules.\"updates.auto\"]\nenabled = false\n";
    let profile = parse(text).unwrap();
    assert!(profile.params("updates.auto").is_none());
    assert!(profile.params("kernel.sysctl").is_some());
}

#[test]
fn enabled_must_be_a_boolean() {
    let err = parse("schema = 1\n[modules.\"kernel.sysctl\"]\nenabled = \"no\"\n").unwrap_err();
    assert_eq!(
        err.to_string(),
        "module `kernel.sysctl`: `enabled` must be true or false"
    );
}

#[test]
fn unknown_keys_are_errors() {
    for text in [
        "schema = 1\nextend = \"web\"\n",
        "schema = 1\n[module.\"kernel.sysctl\"]\n",
    ] {
        let err = parse(text).unwrap_err();
        assert!(matches!(err, ProfileError::Parse(_)), "{err}");
        assert!(err.to_string().contains("unknown field"), "{err}");
    }
}

#[test]
fn unknown_modules_and_bases_are_errors() {
    let err = parse("schema = 1\n[modules.\"ssh.sevrer\"]\n").unwrap_err();
    assert!(
        err.to_string().starts_with(
            "unknown module `ssh.sevrer`; modules are user.admin, ssh.server, firewall.inbound, ssh.bruteforce"
        ),
        "{err}"
    );
    let err = parse("schema = 1\nextends = \"paranoid\"\n").unwrap_err();
    assert_eq!(
        err.to_string(),
        "cannot extend `paranoid`; the built-in profiles are minimal and web"
    );
}

#[test]
fn the_schema_is_required_and_checked() {
    assert!(matches!(parse("").unwrap_err(), ProfileError::Parse(_)));
    assert_eq!(
        parse("schema = 2\n").unwrap_err().to_string(),
        "unsupported schema 2; this version reads schema 1"
    );
}

/// `Takes` never applies, as a module does not on some hosts, yet a typo in
/// its section is found.
#[test]
fn params_are_checked_for_modules_that_do_not_apply() {
    let err = parse("schema = 1\n[modules.\"test.takes\"]\nalow = []\n").unwrap_err();
    let text = err.to_string();
    assert!(
        text.starts_with("module `test.takes`: invalid params:")
            && text.contains("unknown field `alow`"),
        "{text}"
    );
}

#[test]
fn params_are_checked_for_disabled_modules() {
    let text = "schema = 1\n[modules.\"test.takes\"]\nenabled = false\nalow = []\n";
    assert!(parse(text).is_err());
}

#[test]
fn modules_without_params_reject_any() {
    let err = parse("schema = 1\n[modules.\"kernel.sysctl\"]\ntypo = 1\n").unwrap_err();
    assert!(err.to_string().contains("unknown field `typo`"), "{err}");
}

fn builder(base: &str) -> ProfileBuilder {
    ProfileBuilder::new(base).unwrap()
}

#[test]
fn a_builder_without_changes_writes_the_built_in() {
    for (name, _) in BUILT_IN {
        let b = builder(name);
        assert_eq!(b.to_toml(), format!("schema = 1\nextends = \"{name}\"\n"));
        let built_in = Profile::built_in(name, all()).unwrap().unwrap();
        assert_eq!(parse(&b.to_toml()).unwrap(), built_in);
        assert_eq!(b.build(&registry()).unwrap(), built_in);
    }
}

#[test]
fn a_builder_writes_only_what_differs() {
    let mut b = builder("web");
    b.set_params(
        "firewall.inbound",
        table("allow = [\"22/tcp\", \"80/tcp\", \"443/tcp\", \"443/udp\", \"5432/tcp\"]"),
    )
    .remove("ssh.bruteforce")
    .set_params("user.admin", table("name = \"alice\""))
    .set_params("kernel.sysctl", toml::Table::new());
    assert_eq!(
        b.to_toml(),
        "schema = 1\nextends = \"web\"\n\n\
         [modules.\"firewall.inbound\"]\n\
         allow = [\"22/tcp\", \"80/tcp\", \"443/tcp\", \"443/udp\", \"5432/tcp\"]\n\n\
         [modules.\"ssh.bruteforce\"]\nenabled = false\n\n\
         [modules.\"user.admin\"]\nname = \"alice\"\n"
    );
}

#[test]
fn removing_a_module_with_params_writes_only_enabled() {
    let mut b = builder("minimal");
    b.remove("firewall.inbound");
    assert_eq!(
        b.to_toml(),
        "schema = 1\nextends = \"minimal\"\n\n\
         [modules.\"firewall.inbound\"]\nenabled = false\n"
    );
}

#[test]
fn a_built_profile_parses_back_the_same() {
    type Change = fn(&mut ProfileBuilder);
    let cases: [(&str, Change); 7] = [
        ("web", |b| {
            b.set_params(
                "firewall.inbound",
                table("allow = [\"22/tcp\", \"5432/tcp\"]"),
            );
        }),
        ("web", |b| {
            b.remove("ssh.bruteforce").remove("user.admin");
        }),
        ("minimal", |b| {
            b.set_params("ssh.bruteforce", toml::Table::new());
        }),
        ("minimal", |b| {
            b.set_params("user.admin", table("name = \"alice\""))
                .set_params("user.admin", table("sudo = \"password\""));
        }),
        // Taken out, then back: `enabled = false` goes with the removal.
        ("web", |b| {
            b.remove("updates.auto")
                .set_params("test.takes", table("name = \"a\""))
                .remove("test.takes")
                .remove("kernel.sysctl")
                .set_params("kernel.sysctl", toml::Table::new());
        }),
        ("web", |b| {
            b.set_params("test.takes", table("allow = [\"x\"]"));
        }),
        ("minimal", |b| {
            b.remove("firewall.inbound")
                .set_params("firewall.inbound", table("allow = [\"22/tcp\"]"));
        }),
    ];
    for (base, change) in cases {
        let mut b = builder(base);
        change(&mut b);
        let text = b.to_toml();
        assert_eq!(
            parse(&text).unwrap(),
            b.build(&registry()).unwrap(),
            "{text}"
        );
    }
}

#[test]
fn a_builder_checks_what_it_builds() {
    assert!(matches!(
        ProfileBuilder::new("paranoid").unwrap_err(),
        ProfileError::UnknownBase(_)
    ));
    let mut b = builder("web");
    b.set_params("kernel.sysctl", table("typo = 1"));
    assert!(matches!(
        b.build(&registry()).unwrap_err(),
        ProfileError::Params { .. }
    ));
}
