# sshd-config

Read OpenSSH server configuration: `sshd_config` with its `Include` files, and the output of `sshd -T`.

- `effective::SshdConfig` parses `sshd -T`, the settings sshd actually uses.
- `files::Config` reads `sshd_config` and every file it includes, in the order sshd reads them. It answers which file sets a keyword first, and whether a drop-in such as `/etc/ssh/sshd_config.d/00-local.conf` is read before any `Match` block and before any line that would override it.

```rust
use std::path::Path;
use sshd_config::{Config, Error, IncludeCheck, Os};

fn main() -> Result<(), Error> {
    let config = Config::read(&Os, Path::new("/etc/ssh/sshd_config"))?;
    if let Some(d) = config.first("passwordauthentication") {
        println!("set by {}:{}", d.file.display(), d.line);
    }
    let drop_in = Path::new("/etc/ssh/sshd_config.d/00-local.conf");
    let check = config.include_check(drop_in, &["permitrootlogin"]);
    println!("read early enough: {}", check == IncludeCheck::Covered);
    Ok(())
}
```

It is not a validator or a linter: unknown keywords are kept as they are, and nothing is rendered or written. It is the parser [vps-ready](https://github.com/bhimrazy/vps-ready) uses, published from the same repository; expect API changes before 1.0.

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
