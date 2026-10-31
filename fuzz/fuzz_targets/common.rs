//! Helpers shared by the fuzz targets.

#![allow(dead_code)] // Not every target uses every helper.

use std::sync::LazyLock;

use vps_ready::audit::{self, Control};
use vps_ready::facts::{self, Env};
use vps_ready::sys::fake::{FakeFs, FakeRunner};

/// Separates slots. 0xFF never occurs in UTF-8, so it cannot clash with text.
const SEP: u8 = 0xFF;

/// The first `N` slots of `data`; missing ones are `None`.
pub fn slots<const N: usize>(data: &[u8]) -> [Option<&[u8]>; N] {
    let mut parts = data.split(|&b| b == SEP);
    std::array::from_fn(|_| parts.next())
}

/// Parsed once: the catalog is embedded, not fuzzer input.
static CATALOG: LazyLock<Vec<Control>> = LazyLock::new(|| audit::catalog().unwrap_or_default());

/// Runs `detect` and `audit` against the fake host.
pub fn detect_and_audit(fs: &FakeFs, runner: &FakeRunner, env: &Env) {
    if let Ok(facts) = facts::collect(fs, runner, env) {
        let _ = audit::run(CATALOG.clone(), &facts);
    }
}
