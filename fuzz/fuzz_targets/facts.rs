//! `detect` and `audit` on a host whose files and command output come from
//! the fuzzer: os-release, `/proc`, sysctl, `sshd -T`, `ssh -V`, `ss`,
//! `systemctl show`, `apt-config`, the SSH session's process tree.

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use vps_ready::facts::Env;
use vps_ready::sys::Output;
use vps_ready::sys::fake::{FakeFs, FakeRunner};

const FILES: [&str; 13] = [
    "/etc/os-release",
    "/proc/1/comm",
    "/etc/ssh/sshd_config",
    "/etc/ssh/sshd_config.d/a.conf",
    "/proc/sys/kernel/kptr_restrict",
    "/proc/sys/net/ipv4/conf/eth0/rp_filter",
    "/proc/net/if_inet6",
    "/etc/ufw/ufw.conf",
    // The session walk starts at pid 100; its parent is meant to be 101.
    "/proc/100/status",
    "/proc/100/environ",
    "/proc/101/status",
    "/proc/101/cmdline",
    "/proc/101/stat",
];

/// Program, argument prefix, and whether the slot is stderr.
const COMMANDS: [(&str, &[&str], bool); 6] = [
    ("sshd", &["-T"], false),
    ("ssh", &["-V"], true),
    ("ss", &[], false),
    ("systemctl", &["show", "--property=Listen"], false),
    ("systemctl", &["show"], false),
    ("apt-config", &[], false),
];

fuzz_target!(|data: &[u8]| {
    let slots = common::slots::<{ FILES.len() + COMMANDS.len() }>(data);
    let (files, outputs) = slots.split_at(FILES.len());

    let mut fs = FakeFs::new().with_file("/etc/passwd", "root:x:0:0::/root:/bin/sh\n");
    for (path, contents) in FILES.iter().zip(files) {
        if let Some(contents) = contents {
            fs = fs.with_file(*path, *contents);
        }
    }
    let mut runner = FakeRunner::new();
    for (&(program, args, stderr), out) in COMMANDS.iter().zip(outputs) {
        if let Some(out) = out {
            let output = if stderr {
                Output {
                    stderr: out.to_vec(),
                    ..Output::default()
                }
            } else {
                Output::success(*out)
            };
            runner = runner.on(program, args.iter().copied(), output);
        }
    }

    common::detect_and_audit(&fs, &runner, &Env { pid: Some(100) });
});
