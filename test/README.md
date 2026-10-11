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

Container images (`test/images/`) arrive in M1; VM tests in M3.
