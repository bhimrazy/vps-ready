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
    facts.wireguard.listen_ports = [("wg0".to_owned(), 51820)].into();
    facts.routes = vec![Route {
        dst: "default".into(),
        dev: Some("eth0".into()),
        gateway: Some("192.0.2.1".parse().unwrap()),
        table: None,
    }];
    // From a laptop, not from the host itself.
    facts.session = Some(Session {
        client: "198.51.100.7:51234".parse().unwrap(),
        ..session(server)
    });
    facts.tailscale = Some(Tailscale {
        backend_state: "Running".into(),
        have_node_key: true,
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
    let fs = FakeFs::new().with_file(WG_CONF, "[Interface]\n");
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
    for bad in [
        "wg\"0",
        "wg 0",
        "wg*",
        "abcdefghijklmnop",
        ".",
        "..",
        "wg/0",
    ] {
        let table = params(&format!("ssh_via = {bad:?}"));
        let err = FirewallInbound.check_params(&table).unwrap_err();
        assert!(
            err.to_string().contains("is not an interface name"),
            "{bad}: {err}"
        );
    }
}

/// Refusals 1 to 6, each from a fixture; 7 (`--deadman=off`) is the CLI's.
#[test]
fn refuses_a_path_that_may_not_carry_ssh() {
    let fs = wg_fs(None);
    let on = units("enabled");
    let wg = via_facts("10.77.0.1:22");
    // 1. Missing, down, no address.
    assert_eq!(
        refused(via_steps(&wg, "wg9", &fs, &on)).split(';').next(),
        Some("wg9 does not exist")
    );
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
    // 3. A login from the host itself to wg0's address, over lo.
    let mut own = wg.clone();
    own.session.as_mut().unwrap().client = "10.77.0.1:50000".parse().unwrap();
    assert_eq!(
        refused(via_steps(&own, "wg0", &fs, &on)),
        "this SSH session comes from 10.77.0.1, on this server itself, so wg0 did not carry \
         it: connect through wg0 first and apply from there (`ssh -t admin@10.77.0.1 sudo \
         vps-ready apply ...`)"
    );
    // 4. Not back after a reboot; enabled for this boot only does not count.
    for state in ["disabled", "enabled-runtime"] {
        assert_eq!(
            refused(via_steps(&wg, "wg0", &fs, &units(state))),
            "wg-quick@wg0.service is not enabled, so wg0 would not come back after a reboot: \
             `sudo systemctl enable wg-quick@wg0.service`",
            "{state}"
        );
    }
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
    // Tailscale's interface under another name, by its address.
    let mut renamed = expiring.clone();
    renamed.interfaces.iter_mut().for_each(|i| {
        if i.name == "tailscale0" {
            i.name = "ts1".into();
        }
    });
    renamed.session = Some(Session {
        client: "198.51.100.7:51234".parse().unwrap(),
        ..session("100.64.0.7:22")
    });
    assert!(
        refused(via_steps(&renamed, "ts1", &fs, &on))
            .starts_with("this node's Tailscale key expires")
    );
    assert!(
        refused(via_steps(&renamed, "ts1", &fs, &FakeRunner::new()))
            .starts_with("tailscaled.service is not enabled")
    );
    // 6. Never private, even with the same rule loaded.
    let loaded = wg_fs(Some("iifname \"eth0\" tcp dport { 22 } accept\n"));
    for (via, why) in [
        ("lo", "lo is loopback"),
        (
            "docker0",
            "docker0 is a bridge or link for local containers or guests",
        ),
        (
            "br-0123",
            "br-0123 is a bridge or link for local containers or guests",
        ),
        (
            "virbr0",
            "virbr0 is a bridge or link for local containers or guests",
        ),
        (
            "lxcbr0",
            "lxcbr0 is a bridge or link for local containers or guests",
        ),
        (
            "podman0",
            "podman0 is a bridge or link for local containers or guests",
        ),
        (
            "cni0",
            "cni0 is a bridge or link for local containers or guests",
        ),
        (
            "veth1a2b",
            "veth1a2b is a bridge or link for local containers or guests",
        ),
        ("eth0", "eth0 holds the host's default route"),
    ] {
        assert_eq!(
            refused(via_steps(&wg, via, &loaded, &on)),
            format!("`ssh_via = \"{via}\"`: {why}, not a private path"),
        );
    }
}

/// When the ruleset on disk already has the same SSH rule (interface and
/// ports), it does not change, so an apply from the console is planned
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
        .filter(|n| n.ends_with("(not refused: the loaded ruleset already has this SSH rule)"))
        .collect();
    assert_eq!(not_refused.len(), 3, "{:#?}", steps.notes);
    // Another interface or other ports on disk are a change: refused.
    for rule in [
        "iifname \"tailscale0\" tcp dport { 22 } accept",
        "iifname \"wg0\" tcp dport { 22, 2222 } accept",
    ] {
        let other = wg_fs(Some(&format!("    {rule}\n")));
        assert!(
            via_steps(&console, "wg0", &other, &units("enabled")).is_err(),
            "{rule}"
        );
    }
}

#[test]
fn the_console_note_comes_last() {
    let facts = via_facts("10.77.0.1:22");
    let steps = via_steps(&facts, "wg0", &wg_fs(None), &units("enabled")).unwrap();
    let last = steps.notes.last().unwrap();
    assert!(
        last.starts_with("if wg0 stops working, SSH is closed"),
        "{last}"
    );
    assert!(
        last.contains("make sure a sudo user has one (`sudo passwd admin`)"),
        "{last}"
    );
    assert!(
        last.ends_with("one applied from the console while wg0 is down rolls back"),
        "{last}"
    );
}

#[test]
fn ssh_via_reads_the_planned_ruleset_then_the_one_on_disk() {
    let facts = via_facts("10.77.0.1:22");
    let steps = via_steps(&facts, "wg0", &wg_fs(None), &units("enabled")).unwrap();
    let runner = FakeRunner::new();
    let none = FakeFs::new();
    let sys = |fs| Sys {
        fs,
        runner: &runner,
    };
    assert_eq!(
        ssh_via(&steps.resources, sys(&none)).unwrap().as_deref(),
        Some("wg0")
    );
    assert_eq!(ssh_via(&[], sys(&none)).unwrap(), None);
    let disk = FakeFs::new().with_file(RULESET, ruleset_of(&steps));
    assert_eq!(ssh_via(&[], sys(&disk)).unwrap().as_deref(), Some("wg0"));
    let plain = steps_of(&facts, "");
    let disk = FakeFs::new().with_file(RULESET, plain);
    assert_eq!(ssh_via(&[], sys(&disk)).unwrap(), None);
}

/// `nft -j list table inet vps_ready` with [`via_facts`]'s ruleset for
/// `wg0` loaded, on Debian 13, in a container with no `wg0`: the rule loads
/// before the interface exists.
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

    // The interface the rule names is down or gone: SSH is closed, even on
    // a host with no VPN interface left.
    let mut down = facts.clone();
    down.interfaces.iter_mut().for_each(|i| {
        if i.name == "wg0" {
            i.up = false;
        }
    });
    let fail = |found: &str| Outcome::Fail {
        found: found.to_owned(),
    };
    assert_eq!(
        finding(&down, "SSH-009").outcome,
        fail("SSH is limited to wg0, which is down")
    );
    let mut gone = facts.clone();
    gone.interfaces.retain(|i| !i.is_vpn());
    assert_eq!(
        finding(&gone, "SSH-009").outcome,
        fail("SSH is limited to wg0, which does not exist")
    );

    // The table before `ssh_via`: SSH from anywhere.
    facts.firewall = crate::facts::firewall::parse_json(&std::fs::read(testdata(LOADED)).unwrap());
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

/// The table limits SSH to `name`, a `tun` link with `ip`, on the hosts
/// of [`via_facts`].
fn via_on(name: &str, ip: &str) -> Facts {
    let json = std::fs::read_to_string(testdata(LOADED_VIA)).unwrap();
    let mut facts = via_facts(&format!("{ip}:22"));
    facts.firewall = crate::facts::firewall::parse_json(json.replace("wg0", name).as_bytes());
    facts.ipv6 = true;
    if !facts.interfaces.iter().any(|i| i.name == name) {
        facts.interfaces.push(crate::facts::Interface {
            name: name.into(),
            kind: Some("tun".into()),
            addresses: vec![crate::facts::Address {
                ip: ip.parse().unwrap(),
                prefix: 16,
            }],
            up: true,
        });
    }
    facts
}

/// `ssh_via` on a VPN that is neither WireGuard nor Tailscale (NetBird's
/// `nb0`) is private for SSH-009 and FW-003, with or without another VPN.
#[test]
fn ssh_009_and_fw_003_pass_through_any_vpn_interface() {
    use crate::audit::Outcome;
    let mut facts = via_on("nb0", "10.78.0.1");
    assert_eq!(finding(&facts, "SSH-009").outcome, Outcome::Pass);
    let fw = finding(&facts, "FW-003");
    assert_eq!(fw.outcome, Outcome::Pass);
    assert_eq!(fw.note.as_deref(), Some("no port is open to the internet"));
    facts.interfaces.retain(|i| !i.is_vpn());
    assert_eq!(finding(&facts, "SSH-009").outcome, Outcome::Pass);

    // An interface with the default route is never private.
    let fail = |on: &str| Outcome::Fail {
        found: format!("SSH is accepted beyond a VPN: tcp/22 on {on}"),
    };
    let public = via_on("eth0", "192.0.2.10");
    assert_eq!(finding(&public, "SSH-009").outcome, fail("eth0"));
    // Nor is a second NIC with a public address.
    let public = via_on("eth1", "203.0.113.7");
    assert_eq!(finding(&public, "SSH-009").outcome, fail("eth1"));
    // Nor any without the routes, which could show it is the way out.
    let mut unknown = via_on("nb0", "10.78.0.1");
    unknown.routes.clear();
    assert_eq!(finding(&unknown, "SSH-009").outcome, fail("nb0"));
    unknown.interfaces.retain(|i| !i.is_vpn());
    assert!(matches!(
        finding(&unknown, "SSH-009").outcome,
        Outcome::Skip { .. }
    ));
    // Nor a wildcard, which names no interface that exists.
    let json = std::fs::read_to_string(testdata(LOADED_VIA)).unwrap();
    let mut wildcard = via_on("nb0", "10.78.0.1");
    wildcard.firewall = crate::facts::firewall::parse_json(json.replace("wg0", "nb*").as_bytes());
    assert_eq!(finding(&wildcard, "SSH-009").outcome, fail("nb*"));
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
    // Not running: SSH through it may not work.
    let mut stopped = facts.clone();
    stopped.tailscale.as_mut().unwrap().backend_state = "Stopped".into();
    assert_eq!(
        finding(&stopped, "SSH-009").note.as_deref(),
        Some(
            "warning: SSH is limited to tailscale0, and Tailscale is Stopped, so SSH through it \
             may not work"
        )
    );
    // Not while SSH does not depend on it.
    facts.firewall = crate::facts::firewall::parse_json(&std::fs::read(testdata(LOADED)).unwrap());
    assert_eq!(finding(&facts, "SSH-009").note, None);
}

/// The private profile's `ssh_via = "vpn"`, as the profile resolves it
/// with net.tailscale.
const STAGED: &str = "vpn:tailscale0";

/// Step 1 of the private profile: from a session that does not come
/// through the interface, SSH stays public with a note instead of refusal
/// 3, even before the interface exists.
#[test]
fn a_staged_ssh_via_keeps_ssh_public_until_a_session_comes_through() {
    let fs = FakeFs::new();
    let off = FakeRunner::new();
    let public = via_facts("192.0.2.10:22");
    let mut fresh = public.clone();
    fresh.interfaces.retain(|i| i.name != "tailscale0");
    fresh.tailscale = None;
    let mut first_boot = fresh.clone();
    first_boot.session = None;
    for facts in [&public, &fresh, &first_boot] {
        let steps = via_steps(facts, STAGED, &fs, &off).unwrap();
        let text = ruleset_of(&steps);
        assert_eq!(via_of(&text), None);
        assert_eq!(tcp_ports(&text), [22, 80].into());
        assert!(
            steps.notes[0].starts_with(
                "step 1 of 2: SSH stays public until you apply this profile again from a login \
                 through tailscale0"
            ),
            "{:#?}",
            steps.notes
        );
        assert!(!steps.notes.iter().any(|n| n.contains("SSH is closed")));
    }
    assert_eq!(
        via_steps(&public, STAGED, &fs, &off).unwrap().notes[0],
        "step 1 of 2: SSH stays public until you apply this profile again from a login \
         through tailscale0 (`ssh -t admin@100.64.0.7 sudo vps-ready apply ...`)"
    );
    // A login from the host itself to its own Tailscale address.
    let mut own = via_facts("100.64.0.7:22");
    own.session.as_mut().unwrap().client = "100.64.0.7:50000".parse().unwrap();
    let steps = via_steps(&own, STAGED, &fs, &off).unwrap();
    assert_eq!(via_of(&ruleset_of(&steps)), None);
}

/// Step 2: from a session through the interface it is an explicit
/// `ssh_via`, with its refusals; after that, nothing changes, also from the
/// console.
#[test]
fn a_staged_ssh_via_closes_public_ssh_from_a_session_through_it() {
    let fs = FakeFs::new();
    let on = units("enabled");
    let ts = via_facts("100.64.0.7:22");
    let step2 = via_steps(&ts, STAGED, &fs, &on).unwrap();
    let text = ruleset_of(&step2);
    let explicit = via_steps(&ts, "tailscale0", &fs, &on).unwrap();
    assert_eq!(text, ruleset_of(&explicit));
    assert_eq!(step2.notes, explicit.notes);
    assert_eq!(via_of(&text).as_deref(), Some("tailscale0"));
    assert_eq!(tcp_ports(&text), [80].into());
    // Refusals 4 and 5 as for an explicit `ssh_via`.
    assert!(
        refused(via_steps(&ts, STAGED, &fs, &FakeRunner::new()))
            .starts_with("tailscaled.service is not enabled")
    );
    let mut expiring = ts.clone();
    expiring.tailscale.as_mut().unwrap().key_expiry = Some("2027-05-18T09:30:00Z".into());
    assert!(
        refused(via_steps(&expiring, STAGED, &fs, &on))
            .starts_with("this node's Tailscale key expires")
    );

    // Applied: with the same rule on disk, from the VPN, the console or a
    // public session (a provider's private network), it renders the same.
    let loaded = FakeFs::new().with_file(RULESET, text.as_str());
    let mut console = ts.clone();
    console.session = None;
    for facts in [&ts, &console, &via_facts("192.0.2.10:22")] {
        let again = via_steps(facts, STAGED, &loaded, &on).unwrap();
        assert_eq!(ruleset_of(&again), text);
        assert!(!again.notes.iter().any(|n| n.starts_with("step 1")));
    }
}

/// The two applies of the private profile, as plans: step 1 limits
/// nothing, so `--deadman=off` (first boot) is not refused; step 2 limits
/// SSH, so it is (refusal 7); a third apply plans nothing.
#[test]
fn the_private_profile_takes_two_applies_then_none() {
    let table = params(&format!("ssh_via = \"{STAGED}\""));
    let selected = [Selected {
        module: &FirewallInbound,
        params: &table,
    }];
    let runner = FakeRunner::new().on(
        "systemctl",
        ["show"],
        Output::success("LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n"),
    );
    let fs = FakeFs::new();
    fs.create_dir_all(Path::new("/etc/systemd/system"), 0o755)
        .unwrap();
    let sys = Sys {
        fs: &fs,
        runner: &runner,
    };
    let public = via_facts("192.0.2.10:22");
    let through = via_facts("100.64.0.7:22");

    let step1 = engine::plan(&selected, &public, sys).unwrap();
    assert_eq!(step1.ssh_via, None);
    let step2 = engine::plan(&selected, &through, sys).unwrap();
    assert_eq!(step2.ssh_via.as_deref(), Some("tailscale0"));
    for step in step2.steps() {
        match &step.resource {
            Resource::Directory(d) => fs.create_dir(&d.path, d.owner).unwrap(),
            Resource::File(f) => fs.write_atomic(&f.path, &f.content, f.owner).unwrap(),
            _ => {}
        }
    }
    let mut console = through.clone();
    console.session = None;
    for facts in [&through, &public, &console] {
        let third = engine::plan(&selected, facts, sys).unwrap();
        assert_eq!(third.steps().count(), 0);
        assert_eq!(third.ssh_via.as_deref(), Some("tailscale0"));
    }
}

/// Verify checks the ruleset of the step it planned.
#[test]
fn verify_follows_the_step_of_a_staged_ssh_via() {
    let json = std::fs::read(testdata(LOADED)).unwrap();
    let runner = FakeRunner::new().on(
        "nft",
        ["-j", "list", "table", "inet", "vps_ready"],
        Output::success(json),
    );
    let fs = FakeFs::new();
    let table = params(&format!("ssh_via = \"{STAGED}\""));
    let verify = |facts: &Facts| {
        FirewallInbound.verify(
            &PlanCx {
                facts,
                params: &table,
                planned: &[],
            },
            Sys {
                fs: &fs,
                runner: &runner,
            },
        )
    };
    // The table of `facts()` with no params: SSH public, as in step 1.
    assert_eq!(verify(&via_facts("192.0.2.10:22")), Ok(()));
    let err = verify(&via_facts("100.64.0.7:22")).unwrap_err();
    assert!(err.contains("other than tailscale0"), "{err}");
}

/// After step 2 the loaded table accepts SSH only on tailscale0, and verify
/// passes from the VPN and from the console, as the step stays 2.
#[test]
fn verify_passes_after_step_two() {
    let json = std::fs::read_to_string(testdata(LOADED_VIA))
        .unwrap()
        .replace("\"wg0\"", "\"tailscale0\"");
    let runner = FakeRunner::new().on(
        "nft",
        ["-j", "list", "table", "inet", "vps_ready"],
        Output::success(json),
    );
    let fs = FakeFs::new().with_file(
        RULESET,
        "    iifname \"tailscale0\" tcp dport { 22 } accept\n",
    );
    let table = params(&format!("ssh_via = \"{STAGED}\""));
    let through = via_facts("100.64.0.7:22");
    let mut console = through.clone();
    console.session = None;
    for facts in [&through, &console] {
        let cx = PlanCx {
            facts,
            params: &table,
            planned: &[],
        };
        let sys = Sys {
            fs: &fs,
            runner: &runner,
        };
        assert_eq!(FirewallInbound.verify(&cx, sys), Ok(()));
    }
}

/// With SSH already limited to another interface, step 1 would reopen it
/// publicly, so it is refused unless the session comes through the staged
/// interface (then it is step 2, as an explicit `ssh_via`).
#[test]
fn a_staged_ssh_via_does_not_reopen_ssh_limited_elsewhere() {
    let loaded = wg_fs(Some("    iifname \"tailscale0\" tcp dport { 22 } accept\n"));
    let on = units("enabled");
    let from_tailscale = via_facts("100.64.0.7:22");
    let mut console = from_tailscale.clone();
    console.session = None;
    let public = via_facts("192.0.2.10:22");
    for facts in [&from_tailscale, &console, &public] {
        assert_eq!(
            refused(via_steps(facts, "vpn:wg0", &loaded, &on)),
            "SSH is already limited to tailscale0, and step 1 would reopen it publicly: keep \
             `ssh_via = \"tailscale0\"` while wg0 comes up, then apply this from a login \
             through wg0; or set `ssh_via = \"\"` to reopen it on purpose"
        );
    }
    let from_wg = via_facts("10.77.0.1:22");
    let steps = via_steps(&from_wg, "vpn:wg0", &loaded, &on).unwrap();
    assert_eq!(via_of(&ruleset_of(&steps)).as_deref(), Some("wg0"));
}

/// `ssh_via` on a WireGuard interface whose listen port is unknown (`wg
/// show` failed) is refused unless `allow` has a UDP port, and only a note
/// when the loaded ruleset already has the rule; staged (step 1), the
/// interface's known port is still accepted.
#[test]
fn an_unknown_wireguard_port_under_ssh_via() {
    let mut facts = via_facts("10.77.0.1:22");
    facts.wireguard.listen_ports.clear();
    let fs = wg_fs(None);
    let on = units("enabled");
    let plan = |text: &str, fs: &FakeFs| {
        let params = params(text);
        FirewallInbound.plan(
            &PlanCx {
                facts: &facts,
                params: &params,
                planned: &[],
            },
            Sys { fs, runner: &on },
        )
    };
    let err = refused(plan("ssh_via = \"wg0\"", &fs));
    assert!(
        err.starts_with("wg0 is a WireGuard interface whose listen port vps-ready cannot read"),
        "{err}"
    );
    let steps = plan("ssh_via = \"wg0\"\nallow = [\"51820/udp\"]", &fs).unwrap();
    assert!(
        steps
            .notes
            .iter()
            .any(|n| n.contains("make sure its port is among those `allow` lists (51820/udp)")),
        "{:?}",
        steps.notes
    );
    // The same rule on disk: a note.
    let loaded = wg_fs(Some("    iifname \"wg0\" tcp dport { 22 } accept\n"));
    assert!(plan("ssh_via = \"wg0\"", &loaded).is_ok());

    // Step 1 of a staged ssh_via keeps a known port of the interface.
    let mut public = via_facts("192.0.2.10:22");
    public.wireguard.listen_ports = [("wg0".to_owned(), 51820)].into();
    let staged = params("ssh_via = \"vpn:wg0\"");
    let steps = FirewallInbound
        .plan(
            &PlanCx {
                facts: &public,
                params: &staged,
                planned: &[],
            },
            Sys {
                fs: &fs,
                runner: &on,
            },
        )
        .unwrap();
    let text = ruleset_of(&steps);
    assert!(!text.contains("iifname \"wg0\""), "{text}");
    assert!(text.contains("udp dport { 51820 } accept"), "{text}");
}

/// When the via interface is the managed wg0 that this plan changes, the
/// file's port counts, not the old running one, so the next apply plans
/// nothing.
#[test]
fn the_managed_wg0_port_replaces_the_running_one() {
    use crate::facts::network::{WG0_CONF, WG0_HEADER};
    let mut facts = via_facts("10.77.0.1:22");
    facts.wireguard.listen_ports = [("wg0".to_owned(), 51820)].into();
    let planned = [Resource::File(File {
        path: WG0_CONF.into(),
        content: format!(
            "{WG0_HEADER} x\n[Interface]\nAddress = 10.77.0.1/24\nListenPort = 51821\n"
        )
        .into_bytes(),
        owner: root(0o600),
        validate: None,
        describe: None,
    })];
    let params = params("ssh_via = \"wg0\"");
    let fs = wg_fs(None);
    let steps = FirewallInbound
        .plan(
            &PlanCx {
                facts: &facts,
                params: &params,
                planned: &planned,
            },
            Sys {
                fs: &fs,
                runner: &units("enabled"),
            },
        )
        .unwrap();
    let text = ruleset_of(&steps);
    assert!(text.contains("udp dport { 51821 } accept"), "{text}");
    assert!(!text.contains("51820"), "{text}");
}

/// The same `ssh_via` rule loaded with the interface's UDP port, and the
/// port unknown now (`wg show` failed): the port the loaded ruleset accepts
/// stays, so the ruleset does not change.
#[test]
fn a_loaded_wireguard_port_is_kept_when_the_port_is_unknown() {
    let mut facts = via_facts("10.77.0.1:22");
    let params = params("ssh_via = \"wg0\"");
    let on = units("enabled");
    let plan = |facts: &Facts, fs: &FakeFs| {
        FirewallInbound
            .plan(
                &PlanCx {
                    facts,
                    params: &params,
                    planned: &[],
                },
                Sys { fs, runner: &on },
            )
            .unwrap()
    };
    let known = plan(&facts, &wg_fs(None));
    let loaded = ruleset_of(&known);
    assert!(loaded.contains("udp dport { 51820 } accept"), "{loaded}");
    let fs = wg_fs(Some(&loaded));
    facts.wireguard.listen_ports.clear();
    let unknown = plan(&facts, &fs);
    assert_eq!(ruleset_of(&unknown), loaded);
    let file = unknown
        .resources
        .iter()
        .find(|r| r.id() == format!("file:{RULESET}"))
        .unwrap();
    let runner = FakeRunner::new();
    assert_eq!(
        file.diff(Sys {
            fs: &fs,
            runner: &runner
        })
        .unwrap(),
        None
    );
    assert!(
        unknown.notes.iter().any(|n| n
            .ends_with("the WireGuard UDP ports the loaded ruleset accepts stay accepted: 51820")),
        "{:?}",
        unknown.notes
    );
}
