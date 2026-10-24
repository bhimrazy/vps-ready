# Tests

The test layers are described in [docs/testing.md](../docs/testing.md). This
directory holds the host fixtures and the tooling to re-capture them.

## Host fixtures

`test/images/Containerfile` builds a systemd + OpenSSH image that behaves
like a fresh VPS, from the base image given as `BASE`. `test/capture-host-fixtures.sh <distro>` boots one
(512 MB, 1 CPU, removed afterwards), logs in over SSH once, and records the
exact commands the facts code runs into `crates/vps-ready/testdata/hosts/<distro>/`.
Unit tests replay them with `FakeRunner::from_fixture`.

```sh
docker build -f test/images/Containerfile --build-arg BASE=debian:13 -t vps-ready-test:debian-13 test/images
test/capture-host-fixtures.sh debian-13
```

Re-capture when a probe's argv changes, then review the snapshot diff with
`cargo insta review`.

## Container tests

`test/container-audit.sh <distro> [binary]` boots the same image, copies in a
Linux binary, logs in over SSH once, and runs `detect` and `audit` as root,
asserting on the `--json` output with `jq`. The binary comes from the second
argument, then `$VPS_READY_BIN`, then `target/release/vps-ready`. It must match the
container's CPU architecture; the static musl build runs on every distro. CI runs
it for four distros against the x86_64 musl artifact.

`test/container-apply.sh <distro> [binary]` runs the `updates.auto` cycle in a
fresh container: `apply --yes`, `plan --json` shows no changes, `UPD-001`
passes, `history` shows the transaction, `rollback --last`, and the managed files
match their state before. It needs network access for `apt-get`.

```sh
cargo build --release --target aarch64-unknown-linux-musl   # x86_64-... on Intel
docker build -f test/images/Containerfile --build-arg BASE=ubuntu:24.04 -t vps-ready-test:ubuntu-24.04 test/images
test/container-audit.sh ubuntu-24.04 target/aarch64-unknown-linux-musl/release/vps-ready
test/container-apply.sh ubuntu-24.04 target/aarch64-unknown-linux-musl/release/vps-ready
```

## VM tests

`test/vm-cycle.sh <distro> <binary> <image>` boots a cloud image with QEMU and
KVM (2 vCPUs, 2 GiB, a copy-on-write overlay over the image), seeds a user
and a throwaway SSH key with cloud-init, and drives the VM over SSH. It runs
`kernel.sysctl` apply and rollback in the same boot and across a reboot, then
the `updates.auto` cycle, then the dead-man switch: an unconfirmed apply of
the test module `test.deadman` reverts at its deadline, also after an edit
during the window, and at boot after a reboot. That module exists only in a
binary built with `--features vps-ready/testing`. It needs `/dev/kvm`, `qemu-system-x86_64`,
`qemu-img`, `cloud-localds` (cloud-image-utils), `ssh` and `jq`. The `vm`
workflow pins the images and runs it on four distros.

Without KVM, for example on a Mac, pass `-` as the image and point
`VM_SSH_CONFIG` at an ssh config whose `Host vm` reaches a user with
passwordless sudo, such as a Lima VM's. The cycle changes that VM's kernel
settings and apt configuration, so use a throwaway one.

```sh
limactl create --name=vpsr-dev --cpus=1 --memory=1 --disk=10 --mount-none template:ubuntu-24.04
limactl start vpsr-dev
sed -e 's/^Host .*/Host vm/' -e '/Control/d' ~/.lima/vpsr-dev/ssh.config >/tmp/vm.ssh_config
cargo build --release --target aarch64-unknown-linux-musl --features vps-ready/testing
VM_SSH_CONFIG=/tmp/vm.ssh_config test/vm-cycle.sh ubuntu-24.04 target/aarch64-unknown-linux-musl/release/vps-ready -
limactl delete --force vpsr-dev
```
