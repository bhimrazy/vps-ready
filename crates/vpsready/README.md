# vpsready

The [`vps-ready`](https://crates.io/crates/vps-ready) command, installed under the name `vpsready`.

This crate contains no code of its own: it runs `vps_ready::cli::main()` and is published from the same repository and release workflow as `vps-ready`, so the name cannot be taken by an unrelated crate.

```sh
cargo install vps-ready --locked    # installs `vps-ready`
cargo install vpsready --locked     # installs `vpsready`, the same tool
```

See the [vps-ready README](https://github.com/bhimrazy/vps-ready#readme) for documentation.
