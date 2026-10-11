# Tests

`vpsready` is tested in four layers, from fastest to most realistic:

1. **Unit tests** (`cargo test`): parsers and planners against the fakes in
   `crates/vpsready/src/sys/fake.rs`, plus `insta` snapshots.
2. **Fixture tests**: `detect`/`audit` against file trees under
   `crates/vpsready/testdata/`, read through a rooted `RealFs`.
3. **Container tests**: the static binary inside distro containers, for
   anything that reads or changes the system without touching SSH or the network.
4. **VM tests**: full VMs for SSH, firewall, the engine and the dead-man switch,
   where a lockout must be observable and recoverable.

## Host fixtures

`test/images/<distro>/Containerfile` builds a systemd + OpenSSH image that
behaves like a fresh VPS. `test/capture-host-fixtures.sh <distro>` boots one
(512 MB, 1 CPU, removed afterwards), logs in over SSH once, and records the
exact commands the facts code runs into `crates/vpsready/testdata/hosts/<distro>/`.
Unit tests replay them with `FakeRunner::from_fixture`.

```sh
docker build -f test/images/debian-13/Containerfile -t vpsready-test:debian-13 test/images/debian-13
test/capture-host-fixtures.sh debian-13
```

Re-capture when a probe's argv changes, then review the snapshot diff with
`cargo insta review`. Running the container tests in CI comes next; VM tests in M3.
