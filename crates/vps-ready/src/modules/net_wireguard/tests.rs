//! `net.wireguard` on [`FakeFs`], with dpkg, apt, systemctl, `wg` and
//! `wg-quick` simulated by [`Host`]. Keys are made up at run time.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use super::*;
use crate::engine::{
    self, ApplyOutcome, Deadman, Engine, EngineError, Plan, Selected, StateDir, Target, Who,
};
use crate::facts::fixtures::host;
use crate::facts::network::interfaces;
use crate::facts::{Address, Interface, Route, Session, SessionId};
use crate::modules::firewall_inbound::RULESET;
use crate::resource::sysctl::BOOT_ID;
use crate::resource::{ResourceError, WgState};
use crate::sys::fake::{FakeFs, FakeRunner};
use crate::sys::{FileKind, Fs, Output, Runner};

const STATE: &str = "/var/lib/vps-ready";
const MACHINE: &str = "4f1c0d6e2b8a4c3d9e7f6a5b4c3d2e1f\n";

/// Base64 of 32 bytes, for keys made up at run time.
fn b64(bytes: [u8; 32]) -> String {
    const ABC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let v = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(ABC[(v >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    while !out.len().is_multiple_of(4) {
        out.push('=');
    }
    out
}

/// A peer's public key: 32 bytes of `n`.
fn peer_key(n: u8) -> String {
    b64([n; 32])
}

fn peers(list: &[(&str, u8, u8)]) -> String {
    let items: Vec<String> = list
        .iter()
        .map(|(name, key, host)| {
            format!(
                "{{ name = \"{name}\", public_key = \"{}\", host = {host} }}",
                peer_key(*key)
            )
        })
        .collect();
    format!("peers = [{}]", items.join(", "))
}

/// The running `wg0`: its state and the public key `PostUp` loaded, `None`
/// when cleared.
#[derive(Debug, Clone)]
struct Wg0 {
    state: WgState,
    public_key: Option<String>,
}

/// A Debian host where installing `wireguard-tools` creates
/// `/etc/wireguard`, `wg genkey` makes a new key each time, and starting
/// `wg-quick@wg0` brings up `wg0` from `wg0.conf` and loads the key.
struct Host<'a> {
    fs: &'a FakeFs,
    installed: Mutex<bool>,
    /// `wg-quick@wg0.service`: enabled, active.
    unit: Mutex<(bool, bool)>,
    wg0: Mutex<Option<Wg0>>,
    /// Private key text to public key, for `wg pubkey`.
    keys: Mutex<BTreeMap<String, String>>,
    calls: Mutex<Vec<Cmd>>,
}

impl<'a> Host<'a> {
    fn new(fs: &'a FakeFs) -> Self {
        Self {
            fs,
            installed: Mutex::new(false),
            unit: Mutex::new((false, false)),
            wg0: Mutex::new(None),
            keys: Mutex::new(BTreeMap::new()),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Every `wg set` run, without the program.
    fn sets(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.program == "wg" && c.args.first().is_some_and(|a| a == "set"))
            .map(|c| c.args.join(" "))
            .collect()
    }

    /// Every private key `wg genkey` made.
    fn private_keys(&self) -> Vec<String> {
        self.keys.lock().unwrap().keys().cloned().collect()
    }

    fn up(&self) {
        let text = String::from_utf8(self.fs.read(Path::new(WG0_CONF)).unwrap()).unwrap();
        let conf = parse_conf(&text).unwrap();
        let key = String::from_utf8(self.fs.read(Path::new(KEY)).unwrap()).unwrap();
        let public_key = self.keys.lock().unwrap().get(key.trim()).cloned();
        *self.wg0.lock().unwrap() = Some(Wg0 {
            state: WgState {
                port: conf.port,
                peers: conf
                    .peers
                    .into_iter()
                    .map(|(_, key, ip)| (key, vec![ip]))
                    .collect(),
            },
            public_key,
        });
    }
}

fn no_device() -> Output {
    Output {
        status: 1,
        stdout: Vec::new(),
        stderr: b"Unable to access interface: No such device\n".to_vec(),
    }
}

impl Runner for Host<'_> {
    fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
        self.calls.lock().unwrap().push(cmd.clone());
        let args: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        assert!(
            !args.contains(&"private-key") && !args.contains(&"syncconf"),
            "{cmd:?}"
        );
        let out = match (cmd.program.as_str(), &args[..]) {
            ("dpkg-query", [.., PACKAGE]) => Output::success(if *self.installed.lock().unwrap() {
                "installed"
            } else {
                "not-installed"
            }),
            ("apt-get", [.., "update"]) => Output::success(""),
            ("apt-get", [.., PACKAGE]) => {
                *self.installed.lock().unwrap() = true;
                if !self.fs.exists(Path::new(WIREGUARD_DIR)) {
                    self.fs
                        .create_dir(Path::new(WIREGUARD_DIR), root(0o700))
                        .unwrap();
                }
                Output::success("")
            }
            ("systemctl", ["show", _, UNIT]) => {
                let (enabled, active) = *self.unit.lock().unwrap();
                Output::success(format!(
                    "LoadState=loaded\nUnitFileState={}\nActiveState={}\n",
                    if enabled { "enabled" } else { "disabled" },
                    if active { "active" } else { "inactive" }
                ))
            }
            ("systemctl", ["daemon-reload"]) => Output::success(""),
            // The dead-man timer, its boot hook and the binary's copy.
            ("systemd-run", _) => Output::success(""),
            ("systemctl", [.., other]) if other.starts_with("vps-ready-") => Output::success(""),
            (copy, ["version"]) if copy.ends_with("/vps-ready") => {
                Output::success(format!("{}\n", crate::VERSION_INFO))
            }
            ("systemctl", [verb, UNIT]) => {
                let mut unit = self.unit.lock().unwrap();
                match *verb {
                    "enable" => unit.0 = true,
                    "disable" => unit.0 = false,
                    "start" => {
                        unit.1 = true;
                        drop(unit);
                        self.up();
                    }
                    "stop" => {
                        unit.1 = false;
                        *self.wg0.lock().unwrap() = None;
                    }
                    other => panic!("systemctl {other}"),
                }
                Output::success("")
            }
            ("wg", ["genkey"]) => {
                let (path, mode) = cmd.stdout.clone().expect("genkey writes to a file");
                assert_eq!(mode, 0o600);
                if self.fs.exists(&path) {
                    return Err(SysError::Io {
                        context: path.display().to_string(),
                        source: std::io::ErrorKind::AlreadyExists.into(),
                    });
                }
                let mut keys = self.keys.lock().unwrap();
                let n = u8::try_from(0xa0 + keys.len()).unwrap();
                let private = b64([n; 32]);
                keys.insert(private.clone(), b64([!n; 32]));
                self.fs
                    .write_atomic(&path, format!("{private}\n").as_bytes(), root(mode))
                    .unwrap();
                Output::success("")
            }
            ("wg", ["pubkey"]) => {
                let path = cmd.stdin.clone().expect("pubkey reads a file");
                let text = String::from_utf8(self.fs.read(&path)?).unwrap();
                match self.keys.lock().unwrap().get(text.trim()) {
                    Some(public) => Output::success(format!("{public}\n")),
                    None => Output {
                        status: 1,
                        stdout: Vec::new(),
                        stderr: b"Key is not the correct length or format\n".to_vec(),
                    },
                }
            }
            ("wg", ["show", INTERFACE, what]) => {
                let wg0 = self.wg0.lock().unwrap();
                let Some(wg0) = wg0.as_ref() else {
                    return Ok(no_device());
                };
                Output::success(match *what {
                    "listen-port" => format!("{}\n", wg0.state.port),
                    "allowed-ips" => wg0
                        .state
                        .peers
                        .iter()
                        .map(|(k, ips)| format!("{k}\t{}\n", ips.join(" ")))
                        .collect(),
                    "public-key" => format!("{}\n", wg0.public_key.as_deref().unwrap_or("(none)")),
                    other => panic!("wg show {other}"),
                })
            }
            ("wg", ["set", INTERFACE, rest @ ..]) => {
                let mut wg0 = self.wg0.lock().unwrap();
                let state = &mut wg0.as_mut().unwrap().state;
                match rest {
                    ["peer", key, "remove"] => {
                        state.peers.remove(*key);
                    }
                    ["peer", key, "allowed-ips", ips] => {
                        let ips: Vec<String> = ips.split(',').map(str::to_owned).collect();
                        // An address belongs to one peer at a time.
                        for other in state.peers.values_mut() {
                            other.retain(|ip| !ips.contains(ip));
                        }
                        state.peers.insert((*key).to_owned(), ips);
                    }
                    ["listen-port", port] => state.port = port.parse().unwrap(),
                    other => panic!("wg set {other:?}"),
                }
                Output::success("")
            }
            ("wg-quick", ["strip", INTERFACE]) => Output::success(""),
            (other, _) => return Err(SysError::NotFound(other.to_owned())),
        };
        Ok(out)
    }
}

/// `/etc`, systemd's directory and a machine ID.
fn fs() -> FakeFs {
    FakeFs::new()
        .with_dir("/", root(0o755))
        .with_dir("/etc", root(0o755))
        .with_dir("/etc/systemd", root(0o755))
        .with_dir("/etc/systemd/system", root(0o755))
        .with_file(MACHINE_ID, MACHINE)
}

/// The captured Debian 13 host with a WireGuard module, applied from a
/// public SSH session.
fn facts() -> Facts {
    let mut facts = host("debian-13", &[]);
    facts.wireguard.module = Some(true);
    facts.session = Some(session("192.0.2.10:22", "198.51.100.7:51234"));
    facts
}

fn session(server: &str, client: &str) -> Session {
    Session {
        id: SessionId {
            pid: 902,
            start: 4200,
        },
        client: client.parse().unwrap(),
        server: server.parse().unwrap(),
        uid: 1000,
        user: Some("admin".into()),
    }
}

/// `facts` as they are once `wg0` is up with `server`: the interface, and
/// a managed `wg0.conf`.
fn with_wg0(mut facts: Facts, server: &str) -> Facts {
    facts.interfaces.push(Interface {
        name: INTERFACE.into(),
        kind: Some("wireguard".into()),
        addresses: vec![Address {
            ip: server.parse().unwrap(),
            prefix: 24,
        }],
        up: true,
    });
    facts.wireguard.dir = WireguardDir::Read {
        files: Vec::new(),
        wg0_managed: Some(true),
    };
    facts
}

fn table(params: &str) -> toml::Table {
    toml::from_str(params).unwrap()
}

const ADDRESS: &str = "address = \"10.86.12.1/24\"";

fn try_steps(
    facts: &Facts,
    fs: &FakeFs,
    runner: &dyn Runner,
    params: &str,
) -> Result<ModuleSteps, ModuleError> {
    NetWireguard.plan(
        &PlanCx {
            facts,
            params: &table(params),
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

fn plan<'a>(
    fs: &FakeFs,
    runner: &dyn Runner,
    facts: &'a Facts,
    params: &'a toml::Table,
) -> Plan<'a> {
    let selected = Selected {
        module: &NetWireguard,
        params,
    };
    engine::plan(&[selected], facts, Sys { fs, runner }).unwrap()
}

fn change_ids(plan: &Plan) -> Vec<String> {
    plan.steps().map(|s| s.change.id.clone()).collect()
}

fn file_text(steps: &ModuleSteps, path: &str) -> String {
    steps
        .resources
        .iter()
        .find_map(|r| match r {
            Resource::File(f) if f.path == Path::new(path) => {
                Some(String::from_utf8(f.content.clone()).unwrap())
            }
            _ => None,
        })
        .unwrap()
}

const FRESH: [&str; 7] = [
    "package:wireguard-tools",
    "directory:/etc/wireguard",
    "wireguard-key:/etc/wireguard/wg0.key",
    "file:/etc/wireguard/wg0.conf",
    "directory:/etc/systemd/system/wg-quick@wg0.service.d",
    "file:/etc/systemd/system/wg-quick@wg0.service.d/10-vps-ready.conf",
    "service:wg-quick@wg0.service",
];

#[test]
fn applicability() {
    let mut facts = facts();
    assert_eq!(NetWireguard.applicable(&facts), Applicability::Applicable);
    assert!(!NetWireguard.needs_deadman());
    let reason = |facts: &Facts| match NetWireguard.applicable(facts) {
        Applicability::NotApplicable { reason } => reason,
        Applicability::Applicable => panic!("applicable"),
    };
    // A hand-made setup: its config, or an interface without our file.
    facts.wireguard.dir = WireguardDir::Read {
        files: Vec::new(),
        wg0_managed: Some(false),
    };
    assert!(reason(&facts).contains("was not written by vps-ready"));
    let mut hand = with_wg0(self::facts(), "10.77.0.1");
    hand.wireguard.dir = WireguardDir::Missing;
    assert!(reason(&hand).starts_with("a wg0 interface exists that vps-ready did not set up"));
    let ours = with_wg0(self::facts(), "10.77.0.1");
    assert_eq!(NetWireguard.applicable(&ours), Applicability::Applicable);
    let mut dir = self::facts();
    dir.wireguard.dir = WireguardDir::Unreadable;
    assert!(reason(&dir).contains("only by root"));
    // No kernel module, as in a container.
    let mut container = self::facts();
    container.wireguard.module = Some(false);
    assert!(reason(&container).starts_with("the kernel has no WireGuard module"));
    container.wireguard.module = None;
    assert!(reason(&container).contains("is unknown"));
    let mut other = self::facts();
    other.init = Init::Unknown;
    assert_eq!(reason(&other), "it needs systemd, to run wg-quick@wg0");
}

#[test]
fn plan_on_a_fresh_host_snapshot() {
    let fs = fs();
    let runner = Host::new(&fs);
    let facts = facts();
    let params = table(&format!("{ADDRESS}\n{}", peers(&[("laptop", 1, 2)])));
    let plan = plan(&fs, &runner, &facts, &params);
    assert_eq!(change_ids(&plan), FRESH);
    insta::assert_yaml_snapshot!(plan);
}

#[test]
fn rendered_files() {
    let fs = fs();
    let runner = Host::new(&fs);
    let params = format!(
        "{ADDRESS}\nendpoint = \"203.0.113.10\"\n{}",
        peers(&[("laptop", 1, 2), ("phone", 2, 3)])
    );
    let steps = try_steps(&facts(), &fs, &runner, &params).unwrap();
    let conf = file_text(&steps, WG0_CONF);
    assert!(!conf.contains("PrivateKey"), "{conf}");
    insta::assert_snapshot!("wg0-conf", conf);
    insta::assert_snapshot!("drop-in", file_text(&steps, DROP_IN));
    let Some(Resource::File(file)) = steps.resources.iter().find(|r| r.id().ends_with(".conf"))
    else {
        panic!()
    };
    assert_eq!(file.owner, root(0o600));
    assert_eq!(steps.reloads, [Reload::DaemonReload]);
}

#[test]
fn sha256_test_vectors() {
    let hex = |b: [u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    assert_eq!(
        hex(sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // Two blocks.
    assert_eq!(
        hex(sha256(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn derived_subnet_is_stable_per_machine_and_differs_between_two() {
    let a = Subnet::derived(MACHINE);
    assert_eq!(a, Subnet::derived(MACHINE.trim()));
    let b = Subnet::derived("0123456789abcdef0123456789abcdef");
    assert_ne!(a, b);
    for s in [a, b] {
        assert_eq!(s.server.octets()[0], 10);
        assert_eq!(s.server.octets()[3], 1);
        assert_eq!(s.prefix, 24);
    }
    // The plan says where it came from.
    let fs = fs();
    let runner = Host::new(&fs);
    let steps = try_steps(&facts(), &fs, &runner, "").unwrap();
    assert!(
        steps.notes[0].starts_with(&format!("the tunnel subnet {a} is derived from")),
        "{:?}",
        steps.notes
    );
    // Without a machine ID, `address` is needed.
    let bare = FakeFs::new();
    let err = refused(try_steps(&facts(), &bare, &runner, ""));
    assert!(err.contains("set `address`"), "{err}");
}

#[test]
fn subnet_parsing() {
    for bad in [
        "10.86.12.1",
        "10.86.12.1/25",
        "10.86.12.1/7",
        "fd00::1/64",
        "10.86.12.0/24",
        "10.86.12.255/24",
        "x/24",
    ] {
        assert!(Subnet::parse(bad).is_err(), "{bad}");
    }
    let s = Subnet::parse("10.86.12.1/24").unwrap();
    assert_eq!(s.to_string(), "10.86.12.0/24");
    assert_eq!(s.peer(7), Ipv4Addr::new(10, 86, 12, 7));
    let wide = Subnet::parse("10.86.12.1/16").unwrap();
    assert_eq!(wide.peer(2), Ipv4Addr::new(10, 86, 0, 2));
}

#[test]
fn collisions_are_refused_and_the_gateway_noted() {
    let fs = fs();
    let runner = Host::new(&fs);
    let mut facts = facts();
    facts.routes.push(Route {
        dst: "10.86.0.0/16".into(),
        dev: Some("eth1".into()),
        gateway: None,
        table: None,
    });
    let err = refused(try_steps(&facts, &fs, &runner, ADDRESS));
    assert_eq!(
        err,
        "the WireGuard subnet 10.86.12.0/24 overlaps the route 10.86.0.0/16 via eth1; set \
         `address` in [modules.\"net.wireguard\"] to a subnet that is free here"
    );
    let mut facts = self::facts();
    facts.interfaces.push(Interface {
        name: "eth1".into(),
        kind: None,
        addresses: vec![Address {
            ip: "10.86.12.200".parse().unwrap(),
            prefix: 22,
        }],
        up: true,
    });
    let err = refused(try_steps(&facts, &fs, &runner, ADDRESS));
    assert!(err.contains("overlaps 10.86.12.200/22 on eth1"), "{err}");
    // wg0's own address and routes do not count.
    let ours = with_wg0(self::facts(), "10.86.12.1");
    assert!(try_steps(&ours, &fs, &runner, ADDRESS).is_ok());

    let mut cloud = self::facts();
    for r in &mut cloud.routes {
        if r.dst == "default" {
            r.gateway = Some("10.0.2.2".parse().unwrap());
        }
    }
    let steps = try_steps(&cloud, &fs, &runner, ADDRESS).unwrap();
    assert!(
        steps
            .notes
            .iter()
            .any(|n| n.starts_with("the default gateway 10.0.2.2 is in 10.0.0.0/8")),
        "{:?}",
        steps.notes
    );
}

#[test]
fn peer_checks() {
    let check = |text: &str| NetWireguard.check_params(&table(text));
    let peer = |name: &str, key: &str, host: &str| {
        format!("peers = [{{ name = \"{name}\", public_key = \"{key}\", host = {host} }}]")
    };
    let good = peer_key(1);
    assert!(check(&peer("laptop", &good, "2")).is_ok());
    assert!(check("").is_ok());
    let short = b64([1; 32]).replace('=', "");
    let wrong_len = &good[4..];
    let low_bits = format!("{}B=", &good[..42]);
    for (text, why) in [
        (peer("laptop", "not-base64!", "2"), "is not a WireGuard key"),
        (peer("laptop", wrong_len, "2"), "is not a WireGuard key"),
        (peer("laptop", &short, "2"), "is not a WireGuard key"),
        (peer("laptop", &low_bits, "2"), "is not a WireGuard key"),
        (peer("Laptop", &good, "2"), "is not 1 to 32 lowercase"),
        (peer("laptop", &good, "1"), "host 1 is outside 2 to 254"),
        (peer("laptop", &good, "255"), "host 255 is outside 2 to 254"),
        (peer("laptop", &good, "300"), "host 300 is outside"),
        (
            format!("peers = [{{ name = \"laptop\", public_key = \"{good}\" }}]"),
            "missing field `host`",
        ),
        (
            format!("{}\n", peers(&[("a", 1, 2), ("a", 2, 3)])),
            "two peers are named a",
        ),
        (
            format!("{}\n", peers(&[("a", 1, 2), ("b", 1, 3)])),
            "peer b has the public key of another peer",
        ),
        (
            format!("{}\n", peers(&[("a", 1, 2), ("b", 2, 2)])),
            "peer b has the host of another peer",
        ),
        ("port = 0".to_owned(), "port 0 is not a port"),
        ("endpoint = \"a b\"".to_owned(), "is not an IP address"),
        (
            "address = \"10.86.12.1/25\"".to_owned(),
            "prefix of 8 to 24",
        ),
    ] {
        let err = check(&text).unwrap_err().to_string();
        assert!(err.contains(why), "{text}: {err}");
    }
    for endpoint in ["203.0.113.10", "2001:db8::10", "vpn.example.com"] {
        assert!(
            check(&format!("endpoint = \"{endpoint}\"")).is_ok(),
            "{endpoint}"
        );
    }
}

/// `wg genkey` writes to a new file with mode 0600 (`O_EXCL` in the real
/// runner); a key `wg pubkey` rejects is removed and fails the apply.
#[test]
fn key_generation() {
    let fs = fs().with_dir(WIREGUARD_DIR, root(0o700));
    let runner = Host::new(&fs);
    let key = WireguardKey { path: KEY.into() };
    let sys = Sys {
        fs: &fs,
        runner: &runner,
    };
    Resource::WireguardKey(key.clone()).apply(sys).unwrap();
    let genkey = runner
        .calls
        .lock()
        .unwrap()
        .iter()
        .find(|c| c.args == ["genkey"])
        .cloned()
        .unwrap();
    assert_eq!(genkey.stdout, Some((PathBuf::from(KEY), 0o600)));
    let meta = fs.metadata(Path::new(KEY)).unwrap();
    assert_eq!((meta.kind, meta.mode, meta.uid), (FileKind::File, 0o600, 0));
    // Kept as it is on the next apply.
    let first = fs.read(Path::new(KEY)).unwrap();
    assert_eq!(Resource::WireguardKey(key.clone()).diff(sys).unwrap(), None);
    Resource::WireguardKey(key.clone()).apply(sys).unwrap();
    assert_eq!(fs.read(Path::new(KEY)).unwrap(), first);

    // A key `wg pubkey` rejects: removed, and the apply fails.
    let fs = self::fs().with_dir(WIREGUARD_DIR, root(0o700));
    let rejecting = Rejecting(Host::new(&fs));
    let sys = Sys {
        fs: &fs,
        runner: &rejecting,
    };
    let err = Resource::WireguardKey(key.clone()).apply(sys).unwrap_err();
    assert!(matches!(err, ResourceError::Command { .. }));
    let secret = rejecting.0.private_keys().pop().unwrap();
    assert!(!format!("{err} {err:?}").contains(&secret));
    assert!(!fs.exists(Path::new(KEY)));

    // A file that appeared since the check (O_EXCL refused it) is not
    // removed: it is not vps-ready's.
    struct Raced<'a>(&'a FakeFs);
    impl Runner for Raced<'_> {
        fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
            assert_eq!(cmd.args, ["genkey"]);
            self.0
                .write_atomic(Path::new(KEY), b"theirs\n", root(0o600))
                .unwrap();
            Err(SysError::from_io(
                KEY,
                std::io::ErrorKind::AlreadyExists.into(),
            ))
        }
    }
    let fs = self::fs().with_dir(WIREGUARD_DIR, root(0o700));
    let raced = Raced(&fs);
    let sys = Sys {
        fs: &fs,
        runner: &raced,
    };
    let err = Resource::WireguardKey(key).apply(sys).unwrap_err();
    assert!(
        matches!(err, ResourceError::Sys(SysError::Io { .. })),
        "{err:?}"
    );
    assert_eq!(fs.read(Path::new(KEY)).unwrap(), b"theirs\n");
}

/// [`Host`] whose `wg pubkey` rejects every key.
struct Rejecting<'a>(Host<'a>);

impl Runner for Rejecting<'_> {
    fn run(&self, cmd: &Cmd) -> Result<Output, SysError> {
        if cmd.args == ["pubkey"] {
            return Ok(Output {
                status: 1,
                stdout: Vec::new(),
                stderr: b"Key is not the correct length or format\n".to_vec(),
            });
        }
        self.0.run(cmd)
    }
}

/// A key file that is not usable is refused, not replaced.
#[test]
fn an_unsafe_key_file_is_refused() {
    let runner = FakeRunner::new();
    let cases = [
        (0o644, 0, "its mode 0644 lets other users read it"),
        (0o600, 1000, "it is owned by uid 1000, not root"),
    ];
    for (mode, uid, why) in cases {
        let fs = fs().with_dir(WIREGUARD_DIR, root(0o700));
        fs.write_atomic(Path::new(KEY), b"k\n", FileOwner { mode, uid, gid: 0 })
            .unwrap();
        let key = Resource::WireguardKey(WireguardKey { path: KEY.into() });
        let err = key
            .diff(Sys {
                fs: &fs,
                runner: &runner,
            })
            .unwrap_err();
        assert!(err.to_string().contains(why), "{err}");
    }
    let fs = fs().with_symlink(KEY, "/root/key");
    let key = Resource::WireguardKey(WireguardKey { path: KEY.into() });
    let err = key
        .diff(Sys {
            fs: &fs,
            runner: &runner,
        })
        .unwrap_err();
    assert!(err.to_string().contains("it is a symlink"), "{err}");
}

/// [`FakeFs`] that fails the test on any read of the key file: only the
/// `wg pubkey` stand-in, which reads the inner `FakeFs`, may read it.
struct Guarded<'a>(&'a FakeFs);

impl Guarded<'_> {
    fn check(path: &Path) {
        assert_ne!(path, Path::new(KEY), "vps-ready read the private key");
    }
}

impl Fs for Guarded<'_> {
    fn read(&self, path: &Path) -> Result<Vec<u8>, SysError> {
        Self::check(path);
        self.0.read(path)
    }
    fn read_nofollow(&self, path: &Path) -> Result<(Vec<u8>, crate::sys::FileMeta), SysError> {
        Self::check(path);
        self.0.read_nofollow(path)
    }
    fn exists(&self, path: &Path) -> bool {
        self.0.exists(path)
    }
    fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>, SysError> {
        self.0.read_dir(path)
    }
    fn metadata(&self, path: &Path) -> Result<crate::sys::FileMeta, SysError> {
        self.0.metadata(path)
    }
    fn read_link(&self, path: &Path) -> Result<PathBuf, SysError> {
        self.0.read_link(path)
    }
    fn write_atomic(&self, path: &Path, bytes: &[u8], owner: FileOwner) -> Result<(), SysError> {
        self.0.write_atomic(path, bytes, owner)
    }
    fn write(&self, path: &Path, bytes: &[u8]) -> Result<(), SysError> {
        self.0.write(path, bytes)
    }
    fn append_sync(&self, path: &Path, bytes: &[u8]) -> Result<(), SysError> {
        self.0.append_sync(path, bytes)
    }
    fn remove(&self, path: &Path) -> Result<(), SysError> {
        self.0.remove(path)
    }
    fn create_dir_all(&self, path: &Path, mode: u32) -> Result<(), SysError> {
        self.0.create_dir_all(path, mode)
    }
    fn create_dir(&self, path: &Path, owner: FileOwner) -> Result<(), SysError> {
        self.0.create_dir(path, owner)
    }
    fn remove_dir(&self, path: &Path) -> Result<(), SysError> {
        self.0.remove_dir(path)
    }
    fn sync_dir(&self, path: &Path) -> Result<(), SysError> {
        self.0.sync_dir(path)
    }
    fn try_lock(&self, path: &Path) -> Result<crate::sys::FsLock, SysError> {
        self.0.try_lock(path)
    }
}

/// Every byte the engine wrote (the journal, `files/<n>`), the plans, the
/// progress lines, the client configs, freshly collected facts and every
/// command run carry no trace of the generated private key, and nothing
/// but the `wg pubkey` stand-in reads its file.
#[test]
fn the_private_key_is_nowhere_but_its_file() {
    let inner = armable();
    let fs = Guarded(&inner);
    let runner = Host::new(&inner);
    let sys = Sys {
        fs: &fs,
        runner: &runner,
    };
    let state = StateDir::create(&fs, STATE, 0).unwrap();
    let engine = Engine::lock(&state, sys).unwrap();
    let mut progress = Vec::new();
    let facts = facts();
    let params = table(&format!("{ADDRESS}\n{}", peers(&[("laptop", 1, 2)])));
    let first = engine::plan(
        &[Selected {
            module: &NetWireguard,
            params: &params,
        }],
        &facts,
        sys,
    )
    .unwrap();
    engine
        .apply(&first, &Deadman::default(), &mut |p| {
            progress.push(format!("{p:?}"));
        })
        .unwrap();
    // A peer change on the running wg0, then a rollback of it.
    let up = with_wg0(self::facts(), "10.86.12.1");
    let more = table(&format!(
        "{ADDRESS}\n{}",
        peers(&[("laptop", 1, 2), ("phone", 2, 3)])
    ));
    let second = engine::plan(
        &[Selected {
            module: &NetWireguard,
            params: &more,
        }],
        &up,
        sys,
    )
    .unwrap();
    engine
        .apply(&second, &Deadman::default(), &mut |p| {
            progress.push(format!("{p:?}"));
        })
        .unwrap();
    engine
        .rollback(Target::Last, &mut |p| progress.push(format!("{p:?}")))
        .unwrap();
    let (configs, _) = clients(sys, &up, None).unwrap();
    let collected = crate::facts::collect(&fs, &runner, &crate::facts::Env::default()).unwrap();

    let secrets = runner.private_keys();
    assert_eq!(secrets.len(), 1);
    let secret = &secrets[0];
    let texts = [
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&second).unwrap(),
        progress.join("\n"),
        configs,
        serde_json::to_string(&collected).unwrap(),
    ];
    for text in &texts {
        assert!(!text.contains(secret.as_str()));
    }
    for cmd in runner.calls.lock().unwrap().iter() {
        assert!(!format!("{cmd:?}").contains(secret), "{cmd:?}");
    }
    let mut seen = 0;
    walk(&inner, Path::new("/"), &mut |path, bytes| {
        if path == Path::new(KEY) {
            return;
        }
        seen += 1;
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains(secret.as_str()), "{}", path.display());
        assert!(!text.contains("PrivateKey"), "{}", path.display());
    });
    // The journals and their `files/<n>` copies were among them.
    assert!(seen > 10, "{seen}");
}

fn walk(fs: &FakeFs, dir: &Path, each: &mut dyn FnMut(&Path, &[u8])) {
    for path in fs.read_dir(dir).unwrap() {
        if fs.metadata(&path).unwrap().kind == FileKind::Dir {
            walk(fs, &path, each);
        } else if fs.metadata(&path).unwrap().kind == FileKind::File {
            each(&path, &fs.read(&path).unwrap());
        }
    }
}

fn engine_on<'a>(fs: &'a FakeFs, runner: &'a dyn Runner) -> (StateDir, Sys<'a>) {
    (StateDir::create(fs, STATE, 0).unwrap(), Sys { fs, runner })
}

#[test]
fn sync_argv_for_each_change_and_never_a_private_key() {
    let now = WgState {
        port: 51820,
        peers: [
            (peer_key(1), vec!["10.86.12.2/32".to_owned()]),
            (peer_key(2), vec!["10.86.12.3/32".to_owned()]),
            (peer_key(3), vec!["10.86.12.4/32".to_owned()]),
        ]
        .into(),
    };
    let want = WgState {
        port: 51821,
        peers: [
            (peer_key(1), vec!["10.86.12.2/32".to_owned()]),
            (peer_key(2), vec!["10.86.12.9/32".to_owned()]),
            (peer_key(4), vec!["10.86.12.5/32".to_owned()]),
        ]
        .into(),
    };
    let cmds = crate::resource::wireguard::set_commands(INTERFACE, &now, &want);
    let argv: Vec<String> = cmds.iter().map(|c| c.args.join(" ")).collect();
    assert_eq!(
        argv,
        [
            format!("set wg0 peer {} remove", peer_key(3)),
            format!("set wg0 peer {} allowed-ips 10.86.12.9/32", peer_key(2)),
            format!("set wg0 peer {} allowed-ips 10.86.12.5/32", peer_key(4)),
            "set wg0 listen-port 51821".to_owned(),
        ]
    );
    for cmd in &cmds {
        assert_eq!(cmd.program, "wg");
        assert!(cmd.stdin.is_none() && cmd.stdout.is_none());
        assert!(!cmd.args.iter().any(|a| a.contains("private")));
    }
}

/// Fresh apply, then the same plan is empty; a peer change runs `wg set`
/// only, and the key `PostUp` loaded stays.
#[test]
fn apply_then_plan_is_empty_and_peers_change_with_wg_set() {
    let fs = fs();
    let runner = Host::new(&fs);
    let facts = facts();
    let params = table(&format!("{ADDRESS}\n{}", peers(&[("laptop", 1, 2)])));
    let first = plan(&fs, &runner, &facts, &params);
    let (state, sys) = engine_on(&fs, &runner);
    let engine = Engine::lock(&state, sys).unwrap();
    let outcome = engine
        .apply(&first, &Deadman::default(), &mut |_| {})
        .unwrap();
    assert!(
        matches!(outcome, ApplyOutcome::Applied { .. }),
        "{outcome:?}"
    );
    let key = runner.wg0.lock().unwrap().clone().unwrap().public_key;
    assert!(key.is_some());

    let up = with_wg0(self::facts(), "10.86.12.1");
    let again = plan(&fs, &runner, &up, &params);
    assert!(change_ids(&again).is_empty(), "{:?}", change_ids(&again));

    let more = table(&format!(
        "{ADDRESS}\nport = 51821\n{}",
        peers(&[("phone", 2, 3)])
    ));
    let next = plan(&fs, &runner, &up, &more);
    assert_eq!(
        change_ids(&next),
        ["file:/etc/wireguard/wg0.conf", "wireguard:wg0"]
    );
    let sync = &next.steps().last().unwrap().change.summary;
    assert_eq!(
        sync,
        &format!(
            "update the running wg0 with `wg set`: remove peer {}, add peer phone \
             (10.86.12.3/32), listen port 51820 -> 51821",
            peer_key(1)
        )
    );
    engine
        .apply(&next, &Deadman::default(), &mut |_| {})
        .unwrap();
    let wg0 = runner.wg0.lock().unwrap().clone().unwrap();
    assert_eq!(wg0.public_key, key);
    assert_eq!(wg0.state.port, 51821);
    assert_eq!(
        runner.sets(),
        [
            format!("set wg0 peer {} remove", peer_key(1)),
            format!("set wg0 peer {} allowed-ips 10.86.12.3/32", peer_key(2)),
            "set wg0 listen-port 51821".to_owned(),
        ]
    );
    // Rolling the change back puts the running wg0 back too.
    engine.rollback(Target::Last, &mut |_| {}).unwrap();
    let wg0 = runner.wg0.lock().unwrap().clone().unwrap();
    assert_eq!(wg0.state.port, 51820);
    assert_eq!(wg0.state.peers.keys().collect::<Vec<_>>(), [&peer_key(1)]);
    assert_eq!(wg0.public_key, key);
}

/// Someone ran `wg set` by hand: the plan has the sync, which puts the
/// running wg0 back to the file.
#[test]
fn runtime_drift_plans_the_sync() {
    let fs = fs();
    let runner = Host::new(&fs);
    let facts = facts();
    let params = table(&format!("{ADDRESS}\n{}", peers(&[("laptop", 1, 2)])));
    let first = plan(&fs, &runner, &facts, &params);
    let (state, sys) = engine_on(&fs, &runner);
    let engine = Engine::lock(&state, sys).unwrap();
    engine
        .apply(&first, &Deadman::default(), &mut |_| {})
        .unwrap();
    runner
        .run(&wg([
            "set",
            INTERFACE,
            "peer",
            &peer_key(9),
            "allowed-ips",
            "10.86.12.50/32",
        ]))
        .unwrap();
    let up = with_wg0(self::facts(), "10.86.12.1");
    let drift = plan(&fs, &runner, &up, &params);
    assert_eq!(change_ids(&drift), ["wireguard:wg0"]);
    engine
        .apply(&drift, &Deadman::default(), &mut |_| {})
        .unwrap();
    let wg0 = runner.wg0.lock().unwrap().clone().unwrap();
    assert!(!wg0.state.peers.contains_key(&peer_key(9)));
    // And verify reads it back.
    let cx = PlanCx {
        facts: &up,
        params: &params,
        planned: &[],
    };
    assert_eq!(NetWireguard.verify(&cx, sys), Ok(()));
    runner
        .run(&wg([
            "set",
            INTERFACE,
            "peer",
            &peer_key(9),
            "allowed-ips",
            "10.86.12.50/32",
        ]))
        .unwrap();
    let err = NetWireguard.verify(&cx, sys).unwrap_err();
    assert!(err.starts_with("wg0 differs from wg0.conf"));
}

/// A key cleared from the running wg0 (as `wg syncconf` would) fails verify.
#[test]
fn verify_needs_the_key_loaded() {
    let fs = fs();
    let runner = Host::new(&fs);
    let facts = facts();
    let params = table(ADDRESS);
    let first = plan(&fs, &runner, &facts, &params);
    let (state, sys) = engine_on(&fs, &runner);
    Engine::lock(&state, sys)
        .unwrap()
        .apply(&first, &Deadman::default(), &mut |_| {})
        .unwrap();
    runner.wg0.lock().unwrap().as_mut().unwrap().public_key = None;
    let cx = PlanCx {
        facts: &facts,
        params: &params,
        planned: &[],
    };
    let err = NetWireguard.verify(&cx, sys).unwrap_err();
    assert!(err.contains("its PostUp did not load it"));
}

#[test]
fn an_address_change_on_a_live_wg0_is_refused() {
    let fs = fs();
    let runner = Host::new(&fs);
    let up = with_wg0(facts(), "10.86.12.1");
    let err = refused(try_steps(&up, &fs, &runner, "address = \"10.86.13.1/24\""));
    assert!(
        err.starts_with(
            "wg0 is up with 10.86.12.1/24, and the address 10.86.13.1/24 takes a restart"
        ),
        "{err}"
    );
    assert!(err.contains("sudo systemctl stop wg-quick@wg0"), "{err}");
    assert!(try_steps(&up, &fs, &runner, ADDRESS).is_ok());
}

/// Rollback keeps the generated key and nothing else under /etc; the next
/// apply brings back the same public key.
#[test]
fn rollback_leaves_only_the_key_and_the_next_apply_reuses_it() {
    let fs = fs();
    let before: Vec<PathBuf> = etc(&fs);
    let runner = Host::new(&fs);
    let facts = facts();
    let params = table(&format!("{ADDRESS}\n{}", peers(&[("laptop", 1, 2)])));
    let first = plan(&fs, &runner, &facts, &params);
    let (state, sys) = engine_on(&fs, &runner);
    let engine = Engine::lock(&state, sys).unwrap();
    engine
        .apply(&first, &Deadman::default(), &mut |_| {})
        .unwrap();
    let key = runner.wg0.lock().unwrap().clone().unwrap().public_key;
    engine.rollback(Target::Last, &mut |_| {}).unwrap();
    assert!(runner.wg0.lock().unwrap().is_none());
    assert_eq!(*runner.unit.lock().unwrap(), (false, false));
    let mut left = etc(&fs);
    left.retain(|p| !before.contains(p));
    // The package made /etc/wireguard, and the key is kept in it.
    assert_eq!(left, [PathBuf::from(WIREGUARD_DIR), PathBuf::from(KEY)]);

    let again = plan(&fs, &runner, &facts, &params);
    assert!(
        !change_ids(&again)
            .iter()
            .any(|id| id.starts_with("wireguard-key")),
        "{:?}",
        change_ids(&again)
    );
    engine
        .apply(&again, &Deadman::default(), &mut |_| {})
        .unwrap();
    assert_eq!(runner.wg0.lock().unwrap().clone().unwrap().public_key, key);
    assert_eq!(runner.private_keys().len(), 1);
}

/// Every path under `/etc`.
fn etc(fs: &FakeFs) -> Vec<PathBuf> {
    let mut out = Vec::new();
    fn go(fs: &FakeFs, dir: &Path, out: &mut Vec<PathBuf>) {
        for path in fs.read_dir(dir).unwrap() {
            out.push(path.clone());
            if fs.metadata(&path).unwrap().kind == FileKind::Dir {
                go(fs, &path, out);
            }
        }
    }
    go(fs, Path::new("/etc"), &mut out);
    out
}

/// `fs()` with a loaded ruleset that limits SSH to `via`, on a host that
/// can arm the timer.
fn armable_via(via: Option<&str>) -> FakeFs {
    let fs = fs()
        .with_dir("/etc/vps-ready", root(0o755))
        .with_file(BOOT_ID, "a\n")
        .with_file("/proc/uptime", "1000.25 900.00\n")
        .with_dir("/usr", root(0o755))
        .with_dir("/usr/local", root(0o755))
        .with_dir("/usr/local/bin", root(0o755));
    if let Some(via) = via {
        let rule = format!("    iifname \"{via}\" tcp dport {{ 22 }} accept\n");
        fs.write_atomic(Path::new(RULESET), rule.as_bytes(), root(0o644))
            .unwrap();
    }
    fs.write_atomic(Path::new(BIN), b"\x7fELF", root(0o755))
        .unwrap();
    fs
}

fn armable() -> FakeFs {
    armable_via(None)
}

const BIN: &str = "/usr/local/bin/vps-ready";

fn armed() -> Deadman {
    Deadman {
        binary: BIN.into(),
        ..Deadman::default()
    }
}

/// Brings up wg0 from a first apply without `ssh_via`, then writes the
/// ruleset limiting SSH to `via`.
fn set_up(fs: &FakeFs, runner: &Host, via: &str, params: &toml::Table) {
    let facts = facts();
    let first = plan(fs, runner, &facts, params);
    let (state, sys) = engine_on(fs, runner);
    Engine::lock(&state, sys)
        .unwrap()
        .apply(&first, &Deadman::default(), &mut |_| {})
        .unwrap();
    if !fs.exists(Path::new("/etc/vps-ready")) {
        fs.create_dir(Path::new("/etc/vps-ready"), root(0o755))
            .unwrap();
    }
    let rule = format!("    iifname \"{via}\" tcp dport {{ 22 }} accept\n");
    fs.write_atomic(Path::new(RULESET), rule.as_bytes(), root(0o644))
        .unwrap();
}

/// Under a loaded ruleset that limits SSH to wg0, a change arms the timer,
/// is force-restored and records `ssh_via`; under another interface, or
/// none, it does not.
#[test]
fn under_ssh_via_wg0_a_change_arms_the_timer() {
    let base = table(&format!("{ADDRESS}\n{}", peers(&[("laptop", 1, 2)])));
    let more = table(&format!(
        "{ADDRESS}\n{}",
        peers(&[("laptop", 1, 2), ("phone", 2, 3)])
    ));
    for (via, arms) in [("wg0", true), ("tailscale0", false)] {
        let fs = armable();
        let runner = Host::new(&fs);
        set_up(&fs, &runner, via, &base);
        let up = with_wg0(facts(), "10.86.12.1");
        let next = plan(&fs, &runner, &up, &more);
        assert!(!change_ids(&next).is_empty());
        assert_eq!(next.ssh_via.as_deref(), Some(via));
        assert_eq!(next.needs_deadman(), arms, "{via}");
        assert_eq!(next.modules[0].force_restore(), arms, "{via}");
        if !arms {
            continue;
        }
        let (state, sys) = engine_on(&fs, &runner);
        let outcome = Engine::lock(&state, sys)
            .unwrap()
            .apply(&next, &armed(), &mut |_| {})
            .unwrap();
        let ApplyOutcome::Pending { txn, .. } = outcome else {
            panic!("{outcome:?}");
        };
        let journal = fs
            .read(Path::new(&format!("{STATE}/txn/{txn}/journal.jsonl")))
            .unwrap();
        let journal = String::from_utf8(journal).unwrap();
        assert!(journal.contains(r#""ssh_via":"wg0""#), "{journal}");
        assert!(
            journal
                .lines()
                .filter(|l| l.contains(r#""event":"backup""#))
                .all(|l| l.contains(r#""force_restore":true"#)),
            "{journal}"
        );
    }
    // No ruleset at all.
    let fs = fs();
    let runner = Host::new(&fs);
    let fresh = facts();
    assert!(!plan(&fs, &runner, &fresh, &base).needs_deadman());
}

/// From a session through wg0, a change to its own peer is refused:
/// removing it, changing its key or its `host`. Other peers can change.
#[test]
fn the_sessions_own_peer_cannot_change() {
    let fs = fs();
    let runner = Host::new(&fs);
    let base = table(&format!(
        "{ADDRESS}\n{}",
        peers(&[("laptop", 1, 2), ("phone", 2, 3)])
    ));
    set_up(&fs, &runner, "wg0", &base);
    let mut up = with_wg0(facts(), "10.86.12.1");
    up.session = Some(session("10.86.12.1:22", "10.86.12.2:40000"));
    let p = |list: &[(&str, u8, u8)]| format!("{ADDRESS}\n{}", peers(list));
    for change in [
        p(&[("phone", 2, 3)]),
        p(&[("laptop", 7, 2), ("phone", 2, 3)]),
        p(&[("laptop", 1, 4), ("phone", 2, 3)]),
    ] {
        let err = refused(try_steps(&up, &fs, &runner, &change));
        assert!(
            err.starts_with("this session comes through wg0 from 10.86.12.2, the peer with key"),
            "{err}"
        );
    }
    assert!(try_steps(&up, &fs, &runner, &p(&[("laptop", 1, 2)])).is_ok());
    assert!(
        try_steps(
            &up,
            &fs,
            &runner,
            &p(&[("mylaptop", 1, 2), ("phone", 2, 5)])
        )
        .is_ok()
    );
}

/// Under `ssh_via = "wg0"`, a rollback that stops the `wg-quick@wg0` it
/// started is refused whatever the session; from a session through wg0,
/// one that removes its peer is refused.
#[test]
fn a_rollback_that_cuts_wg0_is_refused() {
    let base = table(&format!("{ADDRESS}\n{}", peers(&[("laptop", 1, 2)])));
    let fs = armable();
    let runner = Host::new(&fs);
    let facts = self::facts();
    let first = plan(&fs, &runner, &facts, &base);
    let (state, sys) = engine_on(&fs, &runner);
    let engine = Engine::lock(&state, sys).unwrap();
    engine
        .apply(&first, &Deadman::default(), &mut |_| {})
        .unwrap();
    let rule = "    iifname \"wg0\" tcp dport { 22 } accept\n";
    fs.write_atomic(Path::new(RULESET), rule.as_bytes(), root(0o644))
        .unwrap();
    let err = engine
        .rollback_by(Target::Last, &Who::default(), &mut |_| {})
        .unwrap_err();
    assert!(
        matches!(&err, EngineError::CutsWireguard { via: Some(v), pending: false, .. } if v == "wg0"),
        "{err:?}"
    );
    assert!(err.to_string().contains("remove `ssh_via`"), "{err}");
    assert_eq!(*runner.unit.lock().unwrap(), (true, true));

    // Without `ssh_via`: refused only from a session through wg0.
    fs.remove(Path::new(RULESET)).unwrap();
    let wg0 = [iface("eth0", "192.0.2.10"), iface(INTERFACE, "10.86.12.1")];
    let through = Who {
        server: Some("10.86.12.1".parse().unwrap()),
        client: Some("10.86.12.2".parse().unwrap()),
        interfaces: &wg0,
        ..Who::default()
    };
    let err = engine
        .rollback_by(Target::Last, &through, &mut |_| {})
        .unwrap_err();
    assert!(
        matches!(err, EngineError::CutsWireguard { via: None, .. }),
        "{err:?}"
    );
    assert!(err.to_string().contains("provider's console"), "{err}");
    engine
        .rollback_by(Target::Last, &Who::default(), &mut |_| {})
        .unwrap();
    assert_eq!(*runner.unit.lock().unwrap(), (false, false));
}

/// A rollback that would take this session's peer off the running wg0
/// is refused from that session.
#[test]
fn a_rollback_that_drops_the_sessions_peer_is_refused() {
    let fs = fs();
    let runner = Host::new(&fs);
    let base = table(&format!("{ADDRESS}\n{}", peers(&[("laptop", 1, 2)])));
    set_up(&fs, &runner, "eth0", &base);
    fs.remove(Path::new(RULESET)).unwrap();
    let up = with_wg0(facts(), "10.86.12.1");
    let more = table(&format!(
        "{ADDRESS}\n{}",
        peers(&[("laptop", 1, 2), ("phone", 2, 3)])
    ));
    let next = plan(&fs, &runner, &up, &more);
    let (state, sys) = engine_on(&fs, &runner);
    let engine = Engine::lock(&state, sys).unwrap();
    engine
        .apply(&next, &Deadman::default(), &mut |_| {})
        .unwrap();
    let wg0 = [iface(INTERFACE, "10.86.12.1")];
    let who = |client: &'static str| Who {
        server: Some("10.86.12.1".parse().unwrap()),
        client: Some(client.parse().unwrap()),
        interfaces: &wg0,
        ..Who::default()
    };
    let err = engine
        .rollback_by(Target::Last, &who("10.86.12.3"), &mut |_| {})
        .unwrap_err();
    assert!(
        matches!(err, EngineError::CutsWireguard { via: None, .. }),
        "{err:?}"
    );
    // From laptop, whose peer stays, it runs.
    engine
        .rollback_by(Target::Last, &who("10.86.12.2"), &mut |_| {})
        .unwrap();
}

fn iface(name: &str, ip: &str) -> Interface {
    Interface {
        name: name.into(),
        kind: None,
        addresses: vec![Address {
            ip: ip.parse().unwrap(),
            prefix: 24,
        }],
        up: true,
    }
}

#[test]
fn client_configs_and_the_endpoint() {
    let fs = fs();
    let runner = Host::new(&fs);
    let facts = facts();
    let params = table(&format!(
        "{ADDRESS}\n{}",
        peers(&[("laptop", 1, 2), ("phone", 2, 3)])
    ));
    let first = plan(&fs, &runner, &facts, &params);
    let (state, sys) = engine_on(&fs, &runner);
    Engine::lock(&state, sys)
        .unwrap()
        .apply(&first, &Deadman::default(), &mut |_| {})
        .unwrap();
    let server_key = runner
        .wg0
        .lock()
        .unwrap()
        .clone()
        .unwrap()
        .public_key
        .unwrap();
    // The session's server address is public: it is the endpoint.
    let (text, note) = clients(sys, &facts, Some("laptop")).unwrap();
    assert_eq!(note, None);
    insta::assert_snapshot!(
        "client-config",
        text.replace(&server_key, "<server public key>")
    );
    let (all, _) = clients(sys, &facts, None).unwrap();
    assert_eq!(all.matches("[Interface]").count(), 2);
    let err = clients(sys, &facts, Some("tablet")).unwrap_err();
    assert!(err.ends_with("its peers are: laptop, phone"), "{err}");

    // NATed: no public address anywhere, so a placeholder and a note.
    let mut nat = facts.clone();
    nat.session = Some(session("10.0.2.15:22", "10.0.2.2:40000"));
    for i in &mut nat.interfaces {
        i.addresses.retain(|a| !is_public(a.ip));
    }
    let (text, note) = clients(sys, &nat, Some("laptop")).unwrap();
    assert!(
        text.contains("Endpoint = <this server's public address>:51820"),
        "{text}"
    );
    assert!(note.is_some());

    // `endpoint` wins, an IPv6 one in brackets.
    let conf = Conf {
        server: Ipv4Addr::new(10, 86, 12, 1),
        port: 51820,
        endpoint: Some("2001:db8::10".into()),
        peers: Vec::new(),
    };
    assert_eq!(endpoint(&conf, &nat).0, "[2001:db8::10]:51820");
    let named = Conf {
        endpoint: Some("vpn.example.com".into()),
        ..conf
    };
    assert_eq!(endpoint(&named, &nat).0, "vpn.example.com:51820");
}

#[test]
fn parse_conf_reads_only_its_own_files() {
    let params: Params = parse_params(&table(&format!(
        "{ADDRESS}\nendpoint = \"203.0.113.10\"\n{}",
        peers(&[("laptop", 1, 2)])
    )))
    .unwrap();
    let text = render(&params, Subnet::parse("10.86.12.1/24").unwrap());
    let conf = parse_conf(&text).unwrap();
    assert_eq!(conf.server, Ipv4Addr::new(10, 86, 12, 1));
    assert_eq!(conf.port, 51820);
    assert_eq!(conf.endpoint.as_deref(), Some("203.0.113.10"));
    assert_eq!(
        conf.peers,
        [("laptop".to_owned(), peer_key(1), "10.86.12.2/32".to_owned())]
    );
    assert_eq!(parse_conf("[Interface]\nAddress = 10.0.0.1/24\n"), None);
}

/// Planned in the same plan, or on disk with the header; never a
/// hand-made file.
#[test]
fn managed_port_for_the_firewall() {
    let fs = fs();
    let runner = FakeRunner::new();
    let sys = Sys {
        fs: &fs,
        runner: &runner,
    };
    assert_eq!(managed_port(&[], sys).unwrap(), None);
    let host = Host::new(&fs);
    let steps = try_steps(&facts(), &fs, &host, &format!("{ADDRESS}\nport = 51900")).unwrap();
    assert_eq!(managed_port(&steps.resources, sys).unwrap(), Some(51900));
    let fs = self::fs().with_file(WG0_CONF, "[Interface]\nListenPort = 51820\n");
    let sys = Sys {
        fs: &fs,
        runner: &runner,
    };
    assert_eq!(managed_port(&[], sys).unwrap(), None);
    let ours = file_text(&steps, WG0_CONF);
    let fs = self::fs().with_file(WG0_CONF, ours);
    let sys = Sys {
        fs: &fs,
        runner: &runner,
    };
    assert_eq!(managed_port(&[], sys).unwrap(), Some(51900));
}

/// The interfaces fixture has a hand-made wg0 (10.77.0.1).
#[test]
fn a_hand_made_wg0_is_left_alone() {
    let runner = FakeRunner::new().on(
        "ip",
        ["-j", "-d", "addr"],
        Output::success(
            std::fs::read(crate::facts::fixtures::testdata("network/ip-addr.json")).unwrap(),
        ),
    );
    let mut facts = facts();
    facts.interfaces = interfaces(&runner, &mut Vec::new());
    assert!(matches!(
        NetWireguard.applicable(&facts),
        Applicability::NotApplicable { .. }
    ));
}

/// The planned ruleset of `plan`, and `firewall.inbound`'s notes.
fn firewall_of(plan: &Plan) -> (String, Vec<String>) {
    let module = plan
        .modules
        .iter()
        .find(|m| m.id == "firewall.inbound")
        .unwrap();
    let text = module
        .changes()
        .iter()
        .find_map(|s| match &s.resource {
            Resource::File(f) if f.path == Path::new(RULESET) => {
                Some(String::from_utf8(f.content.clone()).unwrap())
            }
            _ => None,
        })
        .unwrap_or_default();
    (text, module.notes.clone())
}

/// `extends = "private"` with net.wireguard: step 1, from a public
/// session, brings up wg0, opens its port and keeps SSH public; step 2,
/// the same profile from a login through wg0, limits SSH to it.
#[test]
fn the_private_profile_with_wireguard_in_two_steps() {
    use crate::config::Profile;
    let text = format!(
        "schema = 1\nextends = \"private\"\n[modules.\"net.wireguard\"]\n{ADDRESS}\n{}\n",
        peers(&[("laptop", 1, 2)])
    );
    let profile = Profile::parse(&text, crate::modules::all()).unwrap();
    let selected = |id: &str| Selected {
        module: *crate::modules::all().iter().find(|m| m.id() == id).unwrap(),
        params: profile.params(id).unwrap(),
    };
    let modules = [selected("net.wireguard"), selected("firewall.inbound")];
    let fs = fs();
    let runner = Host::new(&fs);

    let public = facts();
    let step1 = engine::plan(
        &modules,
        &public,
        Sys {
            fs: &fs,
            runner: &runner,
        },
    )
    .unwrap();
    let (ruleset, notes) = firewall_of(&step1);
    assert!(!ruleset.contains("iifname \"wg0\""), "{ruleset}");
    assert!(ruleset.contains("udp dport { 51820 } accept"), "{ruleset}");
    assert!(
        notes
            .iter()
            .any(|n| n.starts_with("step 1 of 2: SSH stays public")),
        "{notes:?}"
    );
    assert_eq!(step1.ssh_via, None);
    let (state, sys) = engine_on(&fs, &runner);
    let engine = Engine::lock(&state, sys).unwrap();
    // `firewall.inbound` arms the timer; without a binary, apply it
    // without, as a first boot would.
    let off = Deadman {
        off: true,
        ..Deadman::default()
    };
    let first = engine::plan(&[modules[0]], &public, sys).unwrap();
    engine.apply(&first, &off, &mut |_| {}).unwrap();

    let mut through = with_wg0(facts(), "10.86.12.1");
    through.session = Some(session("10.86.12.1:22", "10.86.12.2:40000"));
    let step2 = engine::plan(&modules, &through, sys).unwrap();
    let (ruleset, notes) = firewall_of(&step2);
    assert!(
        ruleset.contains("iifname \"wg0\" tcp dport { 22 } accept"),
        "{ruleset}\n{notes:?}"
    );
    assert!(ruleset.contains("udp dport { 51820 } accept"), "{ruleset}");
    assert_eq!(step2.ssh_via.as_deref(), Some(INTERFACE));
    // net.wireguard itself has nothing to change by then.
    assert!(step2.modules[0].changes().is_empty());
}

/// A `wg0.conf` of ours that someone gave a `PrivateKey` line is no
/// longer ours: not applicable through the facts, refused if planned
/// anyway, and never parsed for the firewall or the client config.
#[test]
fn a_private_key_added_to_wg0_conf_is_never_diffed_or_copied() {
    let fs = fs().with_dir(WIREGUARD_DIR, root(0o700));
    let runner = Host::new(&fs);
    let params: Params = parse_params(&table(ADDRESS)).unwrap();
    let ours = render(&params, Subnet::parse("10.86.12.1/24").unwrap());
    // Made up at run time, as a hand edit would add it.
    let leaked = format!("{ours}privatekey= {}\n", b64([0x5c; 32]));
    fs.write_atomic(Path::new(WG0_CONF), leaked.as_bytes(), root(0o600))
        .unwrap();
    let mut notices = Vec::new();
    let facts_now = crate::facts::network::wireguard(&fs, &FakeRunner::new(), &mut notices);
    assert!(matches!(
        facts_now.dir,
        WireguardDir::Read {
            wg0_managed: Some(false),
            ..
        }
    ));
    let mut facts = facts();
    facts.wireguard.dir = facts_now.dir;
    assert!(matches!(
        NetWireguard.applicable(&facts),
        Applicability::NotApplicable { .. }
    ));
    let err = refused(try_steps(&self::facts(), &fs, &runner, ADDRESS));
    assert!(err.contains("has a PrivateKey line"), "{err}");
    assert!(!err.contains(&b64([0x5c; 32])));
    let sys = Sys {
        fs: &fs,
        runner: &runner,
    };
    assert_eq!(managed_port(&[], sys).unwrap(), None);
    assert_eq!(parse_conf(&leaked), None);
    for line in [
        "PrivateKey = x",
        "  privateKEY=x",
        "PrivateKey\t= x",
        "Private Key = x",
    ] {
        assert!(private_key_line(line.as_bytes()), "{line}");
    }
    assert!(!private_key_line(
        b"PostUp = wg set %i private-key /etc/wireguard/%i.key\n"
    ));
}

/// A peer cannot take the server's own tunnel address.
#[test]
fn a_peer_cannot_have_the_servers_address() {
    let check = |text: &str| NetWireguard.check_params(&table(text));
    let err = check(&format!(
        "address = \"10.86.12.5/24\"\n{}",
        peers(&[("laptop", 1, 5)])
    ))
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("host 5 is this server's own tunnel address, 10.86.12.5"),
        "{err}"
    );
    // With a /16, host 5 is 10.86.0.5.
    assert!(
        check(&format!(
            "address = \"10.86.0.5/16\"\n{}",
            peers(&[("laptop", 1, 5)])
        ))
        .is_err()
    );
    assert!(
        check(&format!(
            "address = \"10.86.12.5/16\"\n{}",
            peers(&[("laptop", 1, 5)])
        ))
        .is_ok()
    );
}

/// `uninitialized`, which an image has before its first boot, would give
/// every server the same subnet.
#[test]
fn the_machine_id_must_be_32_hex_digits() {
    for id in [
        "uninitialized\n",
        "4F1C0D6E2B8A4C3D9E7F6A5B4C3D2E1F\n",
        "abc\n",
    ] {
        let fs = FakeFs::new().with_file(MACHINE_ID, id);
        let runner = Host::new(&fs);
        let err = refused(try_steps(&facts(), &fs, &runner, ""));
        assert!(err.contains("not 32 hex digits"), "{id}: {err}");
    }
}

/// From a session through wg0, a port change would cut it until the
/// client's Endpoint changes; a peer whose allowed IPs were widened by
/// hand is still the session's.
#[test]
fn a_port_change_or_a_widened_peer_from_a_wg0_session() {
    let fs = fs();
    let runner = Host::new(&fs);
    let base = table(&format!(
        "{ADDRESS}\n{}",
        peers(&[("laptop", 1, 2), ("phone", 2, 3)])
    ));
    set_up(&fs, &runner, "wg0", &base);
    let mut up = with_wg0(facts(), "10.86.12.1");
    up.session = Some(session("10.86.12.1:22", "10.86.12.2:40000"));
    let p = |extra: &str, list: &[(&str, u8, u8)]| format!("{ADDRESS}\n{extra}\n{}", peers(list));
    let err = refused(try_steps(
        &up,
        &fs,
        &runner,
        &p("port = 51821", &[("laptop", 1, 2), ("phone", 2, 3)]),
    ));
    assert!(err.contains("changing `port` from 51820 to 51821"), "{err}");
    // Widened by hand: the laptop peer holds 10.86.12.0/28.
    runner
        .run(&wg([
            "set",
            INTERFACE,
            "peer",
            &peer_key(1),
            "allowed-ips",
            "10.86.12.0/28",
        ]))
        .unwrap();
    let err = refused(try_steps(&up, &fs, &runner, &p("", &[("phone", 2, 3)])));
    assert!(err.starts_with("this session comes through wg0"), "{err}");
    assert!(try_steps(&up, &fs, &runner, &p("", &[("laptop", 1, 2)])).is_ok());
}

/// The rollback guard: a port change that a rollback would undo cuts a
/// session through wg0 as well.
#[test]
fn a_rollback_that_moves_the_port_is_refused_from_wg0() {
    use crate::engine::{Event, Record};
    use crate::resource::Backup;
    let state = |port| WgState {
        port,
        peers: [(peer_key(1), vec!["10.86.12.2/32".to_owned()])].into(),
    };
    let backup = |before: WgState, after: WgState| Record {
        at: 0,
        event: Event::Backup {
            resource: "wireguard:wg0".into(),
            backup: Backup::WireguardSync {
                interface: INTERFACE.into(),
                before: Some(before),
                after,
            },
            force_restore: false,
        },
    };
    let client = "10.86.12.2".parse().unwrap();
    let cuts = crate::engine::drops_peer_for_tests;
    assert!(cuts(&[backup(state(51820), state(51821))], client));
    assert!(!cuts(&[backup(state(51820), state(51820))], client));
    // A peer change under a widened allowed IP of the same key keeps it.
    let mut wide = state(51820);
    wide.peers
        .insert(peer_key(1), vec!["10.86.12.0/28".to_owned()]);
    assert!(!cuts(&[backup(wide, state(51820))], client));
}

/// What the plan says about a running wg0 it cannot fix: gone while the
/// unit is active, or running without its key.
#[test]
fn notes_for_a_wg0_gone_or_without_its_key() {
    let fs = fs();
    let runner = Host::new(&fs);
    let base = table(ADDRESS);
    set_up(&fs, &runner, "eth0", &base);
    let up = with_wg0(facts(), "10.86.12.1");
    runner.wg0.lock().unwrap().as_mut().unwrap().public_key = None;
    let steps = try_steps(&up, &fs, &runner, ADDRESS).unwrap();
    assert!(
        steps
            .notes
            .iter()
            .any(|n| n.starts_with("wg0 runs without a private key")),
        "{:?}",
        steps.notes
    );
    // Deleted by hand: the oneshot unit stays active.
    *runner.wg0.lock().unwrap() = None;
    let gone = with_wg0(facts(), "10.86.12.1");
    let mut gone = gone;
    gone.interfaces.retain(|i| i.name != INTERFACE);
    let steps = try_steps(&gone, &fs, &runner, ADDRESS).unwrap();
    assert!(
        steps
            .notes
            .iter()
            .any(|n| n.starts_with("wg-quick@wg0 is active but wg0 is gone")),
        "{:?}",
        steps.notes
    );
}
