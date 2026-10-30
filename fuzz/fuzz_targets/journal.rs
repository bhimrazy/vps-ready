//! The transaction journal, read back after a crash or a reboot.

#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use vps_ready::engine::journal;

fuzz_target!(|data: &[u8]| {
    if let Ok(records) = journal::parse(Path::new("journal"), data) {
        let _ = journal::is_unfinished(&records);
    }
});
