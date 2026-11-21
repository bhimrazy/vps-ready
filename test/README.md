# Tests

This directory holds the container image, the container and VM test scripts, and the tooling to re-capture host fixtures. What is tested and why is in [docs/design.md](../docs/design.md#testing).

## Host fixtures

`test/images/Containerfile` builds a systemd and OpenSSH image that behaves like a fresh VPS, from the base image given as `BASE`. `test/capture-host-fixtures.sh <distro>` boots one (512 MB, 1 CPU, removed afterwards), logs in over SSH once, and records the exact commands the facts code runs into `crates/vps-ready/testdata/hosts/<distro>/`. Unit tests replay them with `FakeRunner::from_fixture`.

```sh
docker build -f test/images/Containerfile --build-arg BASE=debian:13 -t vps-ready-test:debian-13 test/images
test/capture-host-fixtures.sh debian-13
```

Re-capture when a probe's argv changes, then review the snapshot diff with `cargo insta review`.

## Container tests

Each `test/container-<name>.sh <distro> [binary]` boots the same image, copies in a Linux binary, logs in over SSH once and runs one cycle as root, asserting on `--json` output with `jq`. The binary comes from the second argument, then `$VPS_READY_BIN`, then `target/release/vps-ready`, and must match the container's CPU architecture; the static musl build runs on every distro. All but `container-audit.sh` need network access for apt and the vendor repositories.

```sh
cargo build --release --target aarch64-unknown-linux-musl   # x86_64-... on Intel
docker build -f test/images/Containerfile --build-arg BASE=ubuntu:24.04 -t vps-ready-test:ubuntu-24.04 test/images
test/container-audit.sh ubuntu-24.04 target/aarch64-unknown-linux-musl/release/vps-ready
test/container-apply.sh ubuntu-24.04 target/aarch64-unknown-linux-musl/release/vps-ready
```

CI runs every script on Ubuntu 22.04 and 24.04 and Debian 12 and 13 against the x86_64 musl build.

## VM tests

`test/vm-cycle.sh <distro> <binary> <image> [cycle]` boots a cloud image with QEMU and KVM (2 vCPUs, 2 GiB, a copy-on-write overlay), seeds a user and a throwaway SSH key with cloud-init, and drives the VM over SSH. Without a cycle it runs the default set; `cloud-init`, `private-access` and `tunnel` run one cycle on a fresh boot. The binary must be built with `--features vps-ready/testing`, which adds the `test.deadman` module the dead-man cycles apply.

It needs `/dev/kvm`, `qemu-system-x86_64`, `qemu-img`, `cloud-localds` (cloud-image-utils), `ssh` and `jq`, plus `python3` for the `cloud-init` cycle. It installs `expect` and `curl` in the VM, and the VM needs network access for the vendor repositories. The `private-access` cycle uses the runner as the WireGuard peer, so it needs the runner's sudo and WireGuard.

Without KVM, for example on a Mac, pass `-` as the image and point `VM_SSH_CONFIG` at an ssh config whose `Host vm` reaches a user with passwordless sudo, such as a Lima VM's. The cycle changes that VM's kernel settings and apt configuration and installs packages, so use a throwaway one. `private-access` does not run this way.

```sh
limactl create --name=vpsr-dev --cpus=1 --memory=1 --disk=10 --mount-none template:ubuntu-24.04
limactl start vpsr-dev
sed -e 's/^Host .*/Host vm/' -e '/Control/d' ~/.lima/vpsr-dev/ssh.config >/tmp/vm.ssh_config
cargo build --release --target aarch64-unknown-linux-musl --features vps-ready/testing
VM_SSH_CONFIG=/tmp/vm.ssh_config test/vm-cycle.sh ubuntu-24.04 target/aarch64-unknown-linux-musl/release/vps-ready -
limactl delete --force vpsr-dev
```

The `vm` workflow pins the images by URL and checksum and runs each cycle as its own job on the four distros.
