//! The firewall: `nft -j list ruleset` JSON, merged with the `multiport`
//! rules of `iptables-save`, then the firewall controls of `audit`.

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use vps_ready::facts::Env;
use vps_ready::sys::Output;
use vps_ready::sys::fake::{FakeFs, FakeRunner};

fuzz_target!(|data: &[u8]| {
    let [nft, v4, v6, tables] = common::slots::<4>(data);
    let Some(nft) = nft else { return };

    let mut runner = FakeRunner::new().on("nft", ["-j"], Output::success(nft));
    for (program, out) in [("iptables-save", v4), ("ip6tables-save", v6)] {
        if let Some(out) = out {
            runner = runner.on(program, ["-t"], Output::success(out));
        }
    }
    let mut fs = FakeFs::new();
    if let Some(tables) = tables {
        fs = fs.with_file("/proc/net/ip_tables_names", tables);
    }

    common::detect_and_audit(&fs, &runner, &Env::default());
});
