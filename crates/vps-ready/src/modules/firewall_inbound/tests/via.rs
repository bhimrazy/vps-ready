//! `ssh_via`: the ruleset, the refusals and notes, and verify.

use super::*;
use crate::facts::{Route, Tailscale};

const WG_CONF: &str = "/etc/wireguard/wg0.conf";

/// The interfaces of `testdata/network/ip-addr.json`: `eth0` with the
/// default route, `wg0` (10.77.0.1), a down `wg1`, `tailscale0`
/// (100.64.0.7).
fn via_facts(server: &str) -> Facts {
    let runner = FakeRunner::new().on(
        "ip",
        ["-j", "-d", "addr"],
        Output::success(std::fs::read(testdata("network/ip-addr.json")).unwrap()),
    );
    let mut facts = facts();
    facts.interfaces = crate::facts::network::interfaces(&runner, &mut Vec::new());
    facts.routes = vec![Route {
        dst: "default".into(),
        dev: Some("eth0".into()),
        gateway: Some("192.0.2.1".parse().unwrap()),
        table: None,
    }];
    facts.session = Some(session(server));
    facts.tailscale = Some(Tailscale {
        backend_state: "Running".into(),
        ips: vec!["100.64.0.7".parse().unwrap()],
        key_expiry: None,
    });
    facts
}

/// `systemctl show --property=UnitFileState` answering `state` for all.
fn units(state: &str) -> FakeRunner {
    FakeRunner::new().on(
        "systemctl",
        ["show", "--property=UnitFileState"],
        Output::success(format!("UnitFileState={state}\n")),
    )
}

/// A host with `wg0.conf`, and the ruleset `loaded` on disk if any.
fn wg_fs(loaded: Option<&str>) -> FakeFs {
    let fs = FakeFs::new()
        .with_file(WG_CONF, "[Interface]\n")
        .with_file("/etc/group", "sudo:x:27:admin\n")
        .with_file("/etc/shadow", "root:*:1::::::\nadmin:!:1::::::\n");
    match loaded {
        Some(text) => fs.with_file(RULESET, text),
        None => fs,
    }
}

fn via_steps(
    facts: &Facts,
    via: &str,
    fs: &FakeFs,
    runner: &FakeRunner,
) -> Result<ModuleSteps, ModuleError> {
    let params = params(&format!(
        "allow = [\"22/tcp\", \"80/tcp\"]\nssh_via = \"{via}\""
    ));
    FirewallInbound.plan(
        &PlanCx {
            facts,
            params: &params,
            planned: &[],
        },
        Sys { fs, runner },
    )
}

fn refused(result: Result<ModuleSteps, ModuleError>) -> String {
    match result {
        Err(ModuleError::Refused(why)) => why,
        other => panic!("{other:?}"),
    }
}

#[test]
fn limits_ssh_to_the_interface_and_leaves_ssh_out_of_allow() {
    let facts = via_facts("10.77.0.1:22");
    let steps = via_steps(&facts, "wg0", &wg_fs(None), &units("enabled")).unwrap();
    let text = ruleset_of(&steps);
    insta::assert_snapshot!("ruleset-via", text);
    assert_eq!(via_of(&text).as_deref(), Some("wg0"));
    assert_eq!(tcp_ports(&text), [80].into());
    insta::assert_yaml_snapshot!("via-notes", steps.notes);

    // Without `ssh_via` the same profile renders as before.
    let plain = steps_of(&facts, "allow = [\"22/tcp\", \"80/tcp\"]");
    assert_eq!(via_of(&plain), None);
    assert_eq!(tcp_ports(&plain), [22, 80].into());
}

fn steps_of(facts: &Facts, text: &str) -> String {
    ruleset_of(&steps(facts, &params(text)).unwrap())
}

#[test]
fn ssh_via_takes_an_interface_name() {
    for good in ["", "wg0", "tailscale0", "nb-mesh.1", "abcdefghijklmno"] {
        let table = params(&format!("ssh_via = \"{good}\""));
        assert!(FirewallInbound.check_params(&table).is_ok(), "{good}");
    }
    for bad in ["wg\"0", "wg 0", "wg*", "abcdefghijklmnop", ".", "..", "wg/0"] {
        let table = params(&format!("ssh_via = {bad:?}"));
        let err = FirewallInbound.check_params(&table).unwrap_err();
        assert!(err.to_string().contains("is not an interface name"), "{bad}: {err}");
    }
}

/// Refusals 1 to 6, each from a fixture; 7 (`--deadman=off`) is the CLI's.
#[test]
fn refuses_a_path_that_may_not_carry_ssh() {
    let fs = wg_fs(None);
    let on = units("enabled");
    let wg = via_facts("10.77.0.1:22");
    // 1. Missing, down, no address.
    assert_eq!(refused(via_steps(&wg, "wg9", &fs, &on)).split(';').next(), Some("wg9 does not exist"));
    assert!(refused(via_steps(&wg, "wg1", &fs, &on)).starts_with("wg1 is down"));
    let mut bare = wg.clone();
    bare.interfaces.iter_mut().for_each(|i| {
        if i.name == "wg0" {
            i.addresses.clear();
        }
    });
    assert!(refused(via_steps(&bare, "wg0", &fs, &on)).starts_with("wg0 has no address"));
    // 2. Not an SSH login.
    let mut console = wg.clone();
    console.session = None;
    assert_eq!(
        refused(via_steps(&console, "wg0", &fs, &on)),
        "`ssh_via` needs an SSH login through wg0, and this is not an SSH login (the console, \
         cloud-init)"
    );
    // 3. A session through the public address.
    let public = via_facts("192.0.2.10:22");
    assert_eq!(
        refused(via_steps(&public, "wg0", &fs, &on)),
        "this SSH session came in on 192.0.2.10, not through wg0: connect through wg0 first \
         and apply from there (`ssh -t admin@10.77.0.1 sudo vps-ready apply ...`)"
    );
    // 4. Not back after a reboot.
    assert_eq!(
        refused(via_steps(&wg, "wg0", &fs, &units("disabled"))),
        "wg-quick@wg0.service is not enabled, so wg0 would not come back after a reboot: \
         `sudo systemctl enable wg-quick@wg0.service`"
    );
    let ts = via_facts("100.64.0.7:22");
    assert!(
        refused(via_steps(&ts, "tailscale0", &fs, &FakeRunner::new()))
            .starts_with("tailscaled.service is not enabled")
    );
    // 5. A Tailscale key that expires, or a state that does not say.
    let mut expiring = ts.clone();
    expiring.tailscale.as_mut().unwrap().key_expiry = Some("2027-05-18T09:30:00Z".into());
    assert!(
        refused(via_steps(&expiring, "tailscale0", &fs, &on))
            .starts_with("this node's Tailscale key expires at 2027-05-18T09:30:00Z")
    );
    let mut unknown = ts.clone();
    unknown.tailscale = None;
    assert!(refused(via_steps(&unknown, "tailscale0", &fs, &on)).contains("is unknown"));
    assert!(via_steps(&ts, "tailscale0", &fs, &on).is_ok());
    // 6. Never private, even with the same rule loaded.
    let loaded = wg_fs(Some("iifname \"eth0\" tcp dport { 22 } accept\n"));
    for (via, why) in [
        ("lo", "lo is loopback"),
        ("docker0", "docker0 is a bridge for containers"),
        ("br-0123", "br-0123 is a bridge for containers"),
        ("eth0", "eth0 holds the host's default route"),
    ] {
        assert_eq!(
            refused(via_steps(&wg, via, &loaded, &on)),
            format!("`ssh_via = \"{via}\"`: {why}, not a private path"),
        );
    }
}

/// When the ruleset on disk already limits SSH to the same interface, the
/// SSH rule does not change, so an apply from the console still works
/// while the VPN is down.
#[test]
fn the_same_ssh_via_turns_refusals_1_to_5_into_notes() {
    let mut console = via_facts("10.77.0.1:22");
    console.session = None;
    console.interfaces.retain(|i| i.name != "wg0");
    let loaded = wg_fs(Some("    iifname \"wg0\" tcp dport { 22 } accept\n"));
    let steps = via_steps(&console, "wg0", &loaded, &units("disabled")).unwrap();
    let not_refused: Vec<&String> = steps
        .notes
        .iter()
        .filter(|n| n.ends_with("(not refused: the loaded ruleset already limits SSH to wg0)"))
        .collect();
    assert_eq!(not_refused.len(), 3, "{:#?}", steps.notes);
    // Another interface on disk is a change: refused.
    let other = wg_fs(Some("    iifname \"tailscale0\" tcp dport { 22 } accept\n"));
    assert!(via_steps(&console, "wg0", &other, &units("enabled")).is_err());
}

#[test]
fn the_console_note_says_whether_a_sudo_user_has_a_password() {
    let facts = via_facts("10.77.0.1:22");
    let last = |fs: &FakeFs| {
        via_steps(&facts, "wg0", fs, &units("enabled"))
            .unwrap()
            .notes
            .pop()
            .unwrap()
    };
    assert!(last(&wg_fs(None)).contains("no sudo user has a password yet"));
    let with = wg_fs(None).with_file("/etc/shadow", "root:*:1::::::\nadmin:$y$j9T$x:1::::::\n");
    assert!(last(&with).contains("admin can log in there"));
    let unreadable = FakeFs::new().with_file(WG_CONF, "");
    assert!(last(&unreadable).contains("if you have not"));
}

#[test]
fn ssh_via_reads_the_planned_ruleset_then_the_one_on_disk() {
    let facts = via_facts("10.77.0.1:22");
    let steps = via_steps(&facts, "wg0", &wg_fs(None), &units("enabled")).unwrap();
    let runner = FakeRunner::new();
    let none = FakeFs::new();
    let sys = |fs| Sys { fs, runner: &runner };
    assert_eq!(ssh_via(&steps.resources, sys(&none)).unwrap().as_deref(), Some("wg0"));
    assert_eq!(ssh_via(&[], sys(&none)).unwrap(), None);
    let disk = FakeFs::new().with_file(RULESET, ruleset_of(&steps));
    assert_eq!(ssh_via(&[], sys(&disk)).unwrap().as_deref(), Some("wg0"));
    let plain = steps_of(&facts, "");
    let disk = FakeFs::new().with_file(RULESET, plain);
    assert_eq!(ssh_via(&[], sys(&disk)).unwrap(), None);
}

/// `nft -j list table inet vps_ready` with [`via_facts`]'s ruleset for
/// `wg0` loaded, on Debian 13.
const LOADED_VIA: &str = "nft/vps-ready-table-via.json";

#[test]
fn verify_reads_back_that_ssh_is_accepted_only_through_the_interface() {
    let json = std::fs::read(testdata(LOADED_VIA)).unwrap();
    let params: Params = parse_params(&params("allow = [\"80/tcp\"]\nssh_via = \"wg0\"")).unwrap();
    let want = Ruleset::new(&via_facts("10.77.0.1:22"), &params);
    assert_eq!(check_loaded(&json, &want), Ok(()));
    // A table that still accepts SSH from anywhere.
    let old = std::fs::read(testdata(LOADED)).unwrap();
    let mut ssh_only = want.clone();
    ssh_only.tcp.clear();
    assert_eq!(
        check_loaded(&old, &ssh_only),
        Err("it accepts tcp/22 on interfaces other than wg0".to_owned())
    );
    // SSH also on another interface, or only on another.
    let text = String::from_utf8(json).unwrap();
    let wrong = text.replace("\"wg0\"", "\"wg1\"");
    assert_eq!(
        check_loaded(wrong.as_bytes(), &want),
        Err("it accepts tcp/22 on interfaces other than wg0".to_owned())
    );
}

proptest! {
    /// Whatever the ports and the interface, the session's port is accepted
    /// on the session's interface, and no SSH port on any other.
    #[test]
    fn the_session_port_is_accepted_on_its_interface(
        session_port in 1..=u16::MAX,
        listen in proptest::collection::vec(1..=u16::MAX, 0..3),
        allow in proptest::collection::vec(1..=u16::MAX, 0..4),
        via in "[a-z][a-z0-9]{0,14}",
    ) {
        prop_assume!(via != "lo" && via != "eth0" && !via.starts_with("br-") && via != "docker0");
        let mut facts = via_facts(&format!("10.77.0.1:{session_port}"));
        facts.ssh.listening = listen;
        let list: Vec<String> = allow.iter().map(|p| format!("\"{p}/tcp\"")).collect();
        let params: Params = parse_params(&params(&format!(
            "allow = [{}]\nssh_via = \"{via}\"",
            list.join(", ")
        )))
        .unwrap();
        let model = Ruleset::new(&facts, &params);
        let text = model.render().unwrap();
        prop_assert_eq!(via_of(&text), Some(via.clone()));
        let line = text
            .lines()
            .find(|l| l.trim_start().starts_with(&format!("iifname \"{via}\" tcp dport")))
            .unwrap();
        let set = line.split_once('{').unwrap().1.split_once('}').unwrap().0;
        let ssh: BTreeSet<u16> = set.split(',').map(|p| p.trim().parse().unwrap()).collect();
        prop_assert!(ssh.contains(&session_port));
        prop_assert!(tcp_ports(&text).is_disjoint(&ssh));
    }
}

fn finding(facts: &Facts, id: &str) -> crate::audit::Finding {
    let control = crate::audit::catalog()
        .unwrap()
        .into_iter()
        .find(|c| c.id == id)
        .unwrap();
    crate::audit::run(vec![control], facts).findings.remove(0)
}

/// What `ssh_via` promises is what SSH-009 checks, and FW-003 does not
/// count SSH on wg0 as open to the internet.
#[test]
fn ssh_009_and_fw_003_pass_on_the_loaded_table() {
    use crate::audit::Outcome;
    let json = std::fs::read(testdata(LOADED_VIA)).unwrap();
    let mut facts = via_facts("10.77.0.1:22");
    facts.firewall = crate::facts::firewall::parse_json(&json);
    facts.ipv6 = true;
    assert_eq!(finding(&facts, "SSH-009").outcome, Outcome::Pass);
    assert_eq!(finding(&facts, "SSH-009").note, None);
    let fw = finding(&facts, "FW-003");
    assert_eq!(fw.outcome, Outcome::Pass);

    // The table before `ssh_via`: SSH from anywhere.
    facts.firewall =
        crate::facts::firewall::parse_json(&std::fs::read(testdata(LOADED)).unwrap());
    assert_eq!(
        finding(&facts, "SSH-009").outcome,
        Outcome::Fail {
            found: "SSH is accepted beyond a VPN: tcp/22 from any interface".into()
        }
    );
    // On a host without a VPN interface it is skipped.
    facts.interfaces.retain(|i| !i.is_vpn());
    assert!(matches!(
        finding(&facts, "SSH-009").outcome,
        Outcome::Skip { .. }
    ));
}

/// An expiring node key under a `tailscale0` rule is warned about in
/// SSH-009 and the plan; with expiry disabled it is not.
#[test]
fn warns_while_ssh_depends_on_an_expiring_tailscale_key() {
    let json = std::fs::read_to_string(testdata(LOADED_VIA))
        .unwrap()
        .replace("\"wg0\"", "\"tailscale0\"");
    let mut facts = via_facts("100.64.0.7:22");
    facts.firewall = crate::facts::firewall::parse_json(json.as_bytes());
    assert_eq!(finding(&facts, "SSH-009").note, None);
    let warned = |facts: &Facts| {
        FirewallInbound
            .notes(facts)
            .iter()
            .any(|n| n.starts_with("warning"))
    };
    assert!(!warned(&facts));
    facts.tailscale.as_mut().unwrap().key_expiry = Some("2027-05-18T09:30:00Z".into());
    let warning = "warning: this node's Tailscale key expires at 2027-05-18T09:30:00Z, and SSH \
                   through tailscale0 stops then; disable key expiry for this machine in the \
                   Tailscale admin console";
    assert_eq!(finding(&facts, "SSH-009").note.as_deref(), Some(warning));
    assert!(warned(&facts));
    // Not while SSH does not depend on it.
    facts.firewall =
        crate::facts::firewall::parse_json(&std::fs::read(testdata(LOADED)).unwrap());
    assert_eq!(finding(&facts, "SSH-009").note, None);
}
