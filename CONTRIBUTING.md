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

A module is a type that implements the `Module` trait in
`crates/vps-ready/src/modules/mod.rs`, in its own file or directory under
`crates/vps-ready/src/modules/`, plus one entry in `modules::all()`. It only
describes the desired state: `plan` returns `Resource`s (`File`, `Sysctl`,
`Package`), and the engine owns planning, applying, snapshots and rollback, so
a module never writes files or restarts services itself. `plan` may read the
system but never writes.

1. Implement `id`, `title`, `why`, `applicable` and `plan` (and `notes` for
   anything the module deliberately leaves alone). `kernel_sysctl/` and
   `updates_auto.rs` are the patterns to follow.
2. Register it in `modules::all()`. The order is the apply order.
3. Add `fix = "<id>"` to every control in `src/audit/controls/*.toml` that the
   module fixes. `audit` then prints the `apply --module <id>` hint, and a test
   checks that each `fix` names a registered module.

Required tests, run against a tempdir or the fakes, never the real host:

- a plan snapshot (`insta`);
- apply, then plan: the plan is empty;
- apply, then rollback: the tree is exactly as it was;
- audit and fix agree: after apply, every control with your `fix` passes.

Modules that cannot run in a container also need a note in the PR on how you
tried them on a throwaway VM.

## Tests

- Unit tests and, where output is rendered, an `insta` snapshot.
- Container tests run in CI on every PR, and VM tests on PRs that touch the engine or modules (see [docs/testing.md](docs/testing.md)). Say in the PR how you tried a change that touches the system.

## Working on the site

The website (landing page and docs) lives in `site/` and needs Node 22.22 or later (CI uses 24):

```sh
cd site
npm ci
npm run dev    # or `npm run build`, which also checks internal links
```

Most docs pages are generated from `docs/*.md` (and the controls catalog) by `site/scripts/sync-docs.mjs` before every dev or build run. Edit the source in `docs/`, never the generated files under `site/src/content/docs/docs/` (they are listed in `site/.gitignore`). A new `docs/*.md` needs an entry in the script's page map, or the build fails.

A pull request that touches the site uploads the built site as a `site-preview` artifact, kept for 7 days. To view it, download it from the `pages` run's summary page and serve it with any static server:

```sh
unzip site-preview.zip -d site-preview
python3 -m http.server -d site-preview   # http://localhost:8000
```

## Lint policy

No `unwrap`, `expect` or `panic!` outside tests (enforced by clippy, see
`[workspace.lints]` in `Cargo.toml`). No `unsafe`. Return errors with context
instead.

## Review

Changes to security-relevant paths (the engine, the `ssh` and `firewall`
modules, `.github/`, `scripts/`) need two reviews once there are two maintainers.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
