//! `sshd_config` and its `Include` files: line splitting, quoting, glob
//! expansion and the include-order check.

#![no_main]

mod common;

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use libfuzzer_sys::fuzz_target;
use sshd_config::{Config, Source};

const FILES: [&str; 4] = [
    "/etc/ssh/sshd_config",
    "/etc/ssh/sshd_config.d/10-a.conf",
    "/etc/ssh/sshd_config.d/50-b.conf",
    "/etc/ssh/extra/c.conf",
];

struct Mem(BTreeMap<PathBuf, String>);

impl Source for Mem {
    fn read(&self, path: &Path) -> io::Result<String> {
        self.0
            .get(path)
            .cloned()
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }

    fn list(&self, dir: &Path) -> io::Result<Vec<String>> {
        Ok(self
            .0
            .keys()
            .filter(|p| p.parent() == Some(dir))
            .filter_map(|p| Some(p.file_name()?.to_string_lossy().into_owned()))
            .collect())
    }
}

fuzz_target!(|data: &[u8]| {
    let files = FILES
        .iter()
        .zip(common::slots::<4>(data))
        .filter_map(|(path, text)| {
            Some((
                PathBuf::from(path),
                String::from_utf8_lossy(text?).into_owned(),
            ))
        })
        .collect();
    let Ok(config) = Config::read(&Mem(files), Path::new(FILES[0])) else {
        return;
    };
    let _ = config.first("port");
    let _ = config.include_check(
        Path::new("/etc/ssh/sshd_config.d/00-vps-ready.conf"),
        &["PasswordAuthentication", "Port"],
    );
});
