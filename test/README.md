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
`test/container-bruteforce.sh <distro> [binary]` runs the same kind of cycle
for `ssh.bruteforce`: the jail runs, reads the journal and bans into
nftables, `SSH-008` passes, and rollback removes the drop-in.
`test/container-admin.sh <distro> [binary]` runs `user.admin`: apply waits
for a confirm, a new login as another sudo user cannot confirm, a new login as
the admin (with the key copied from root) confirms with `sudo vps-ready
confirm`, and `rollback --last` removes the account; a second apply with
`--deadman 1m` is rolled back by the timer. It then applies `deploy.user`
with a forced command: the drop-in passes `visudo -cf`, the deploy key runs
only that command, a second apply with another command leaves only the key
forced to it, and two `rollback --last` runs restore the first and then remove
the account.
`test/container-docker.sh <distro> [binary]` installs Docker with
`deploy.docker` from Docker's repository: the next plan is empty, live-restore
is on, `docker run -p 8080:80` answers on 127.0.0.1 and not on the container's
own address, and `rollback --last` removes the source, the key and
`daemon.json`, keeps the packages and restarts Docker with its defaults. It
needs network access.
`test/container-proxy.sh <distro> [binary]` installs Caddy with
`deploy.proxy` from Caddy's repository for one site, `app.localhost`, which
Caddy serves from its own CA: the next plan is empty, the package kept our
Caddyfile (its own is `Caddyfile.dpkg-dist`), HTTPS through Caddy reaches an
upstream on 127.0.0.1, and `rollback --last` removes the source, the key and
the Caddyfile, keeps the package and stops and disables Caddy. A second apply
starts Caddy again, and a second rollback undoes it. It needs network access.

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
during the window, and at boot after a reboot; and `confirm` is refused from
the applying session, an older session and a `ControlMaster` connection, and
accepted from a new login. Those sessions are real `ssh` logins from inside
the VM to its own sshd, since the connection that drives the VM may not be
one (Lima's shell uses vsock). That module exists only in a
binary built with `--features vps-ready/testing`. Then `ssh.server`: the
`minimal` profile confirmed by the admin it creates, then an unconfirmed apply
that refuses new root logins during the window (also through `ssh.socket`) and
reverts at its deadline after an edit. Last, the wizard: `test/vm-wizard.exp`
answers `sudo vps-ready` with its defaults over a real login, as the cycle's
user and as root, and a new login as the admin confirms. Then the deploy
modules: the `web` profile with `deploy.proxy` for `app.localhost` and
`deploy.user` with a forced command, confirmed by the new admin; a container
published with `-p 8080:80` answers through Caddy and not on the VM's own
address, the deploy key runs only its command, and `rollback --last` removes
Docker's and Caddy's sources, keys and config files and the deploy user, and
disables Caddy. It needs `/dev/kvm`, `qemu-system-x86_64`, `qemu-img`,
`cloud-localds` (cloud-image-utils), `ssh` and `jq`; it installs `expect` and
`curl` in the VM, and the VM needs network access for Docker's and Caddy's
repositories. The `vm` workflow pins the images and
runs it on four distros.

Without KVM, for example on a Mac, pass `-` as the image and point
`VM_SSH_CONFIG` at an ssh config whose `Host vm` reaches a user with
passwordless sudo, such as a Lima VM's. The cycle changes that VM's kernel
settings and apt configuration and installs `expect`, `curl`, Docker and
Caddy, so use a throwaway one.

```sh
limactl create --name=vpsr-dev --cpus=1 --memory=1 --disk=10 --mount-none template:ubuntu-24.04
limactl start vpsr-dev
sed -e 's/^Host .*/Host vm/' -e '/Control/d' ~/.lima/vpsr-dev/ssh.config >/tmp/vm.ssh_config
cargo build --release --target aarch64-unknown-linux-musl --features vps-ready/testing
VM_SSH_CONFIG=/tmp/vm.ssh_config test/vm-cycle.sh ubuntu-24.04 target/aarch64-unknown-linux-musl/release/vps-ready -
limactl delete --force vpsr-dev
```
