# vpsready

The [`vps-ready`](https://crates.io/crates/vps-ready) command, installed under the name `vpsready`.

This crate contains no code of its own: it runs `vps_ready::cli::main()` and is published from the same repository and release workflow as `vps-ready`, so the name cannot be taken by an unrelated crate.

```sh
cargo install vps-ready --locked    # installs `vps-ready`
cargo install vpsready --locked     # installs `vpsready`, the same tool
```

Until v0.1.0 only pre-releases exist, and `cargo install` skips them by default: add `--version 0.1.0-alpha.5` (or the latest alpha).

See the [vps-ready README](https://github.com/bhimrazy/vps-ready#readme) for documentation.
