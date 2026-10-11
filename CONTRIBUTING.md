# Contributing

Thanks for helping. `vps-ready` changes SSH and firewall settings on real
servers, so correctness and reviewability matter more than speed.

## Development setup

1. Install Rust with [rustup](https://rustup.rs). `rust-toolchain.toml` pins
   the stable channel, clippy, rustfmt and the musl targets.
2. Install [cargo-deny](https://github.com/EmbarkStudios/cargo-deny):
   `cargo install cargo-deny --locked`.
3. Run `make check` (fmt, clippy, tests, cargo-deny) before pushing.

`make build-musl` builds the static Linux binaries; it works from macOS too
(see `.cargo/config.toml`).

## Commits

- Sign off every commit (`git commit -s`) to certify the
  [Developer Certificate of Origin](https://developercertificate.org). There is no CLA.
- Use conventional prefixes: `feat`, `fix`, `docs`, `ci`, `test`, `refactor`, `chore`.

## Adding a module

A module is one directory under `crates/vps-ready/src/modules/<name>/` plus one
registration line. Modules only describe the desired state and how to check
it; the engine owns planning, applying, snapshots and rollback, so a module
never writes files or restarts services itself.

## Tests

- Unit tests and an `insta` snapshot for every module.
- A container test for anything that touches the system.
- A VM test for anything involving SSH, the firewall or the engine.

See `test/README.md` for the layers.

## Lint policy

No `unwrap`, `expect` or `panic!` outside tests (enforced by clippy, see
`[workspace.lints]` in `Cargo.toml`). No `unsafe`. Return errors with context
instead.

## Review

Changes to security-relevant paths (the engine, the `ssh` and `firewall`
modules, `.github/`, `scripts/`) need two reviews once there are two maintainers.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
