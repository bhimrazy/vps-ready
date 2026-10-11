#!/bin/sh
# Capture a real host as a unit-test fixture, from a systemd test container.
#
# Usage: test/capture-host-fixtures.sh <distro>      e.g. ubuntu-24.04
# Needs: docker, and the test image for <distro>:
#   docker build -f test/images/Containerfile --build-arg BASE=ubuntu:24.04 -t vpsready-test:ubuntu-24.04 test/images
#
# Writes crates/vpsready/testdata/hosts/<distro>/:
#   root/...        files the facts code reads (os-release, /proc/1/comm)
#   commands.tsv    name, exit code, then the exact argv, tab-separated.
#                   Several entries can share an argv (scenarios); the first wins
#                   by default, so the plain capture comes before the scenarios.
#   cmd/<name>.stdout, cmd/<name>.stderr
#   env             SSH_CONNECTION as seen by a real SSH login
# The container is capped at 512 MB and 1 CPU and is removed afterwards.
set -eu
cd "$(dirname "$0")/.."

distro=${1:?usage: $0 <distro>}
image="vpsready-test:$distro"
out="crates/vpsready/testdata/hosts/$distro"
name="vpsready-capture-$distro-$$"
tmp=$(mktemp -d)

cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT
# POSIX sh keeps running after a trapped signal; exit so a Ctrl-C during boot
# cannot reach the step that replaces the committed fixtures.
trap 'exit 130' INT TERM

docker run -d --name "$name" --privileged --cgroupns=private \
  --memory 512m --cpus 1 --tmpfs /run --tmpfs /run/lock "$image" >/dev/null

# Wait for systemd to finish booting ("degraded" is normal in a container).
i=0
until state=$(docker exec "$name" systemctl is-system-running 2>/dev/null); \
      [ "$state" = running ] || [ "$state" = degraded ]; do
  i=$((i + 1)); [ "$i" -lt 60 ] || { echo "boot timeout ($state)" >&2; exit 1; }
  sleep 1
done

rm -rf "$out"; mkdir -p "$out/cmd" "$out/root/etc" "$out/root/proc/1"
: >"$tmp/plain.tsv"; : >"$tmp/scenarios.tsv"

# record <tsv> <name> <argv...>: run argv in the container exactly, no shell.
record() {
  tsv=$1; n=$2; shift 2
  set +e
  docker exec "$name" "$@" >"$out/cmd/$n.stdout" 2>"$out/cmd/$n.stderr"
  rc=$?
  set -e
  [ -s "$out/cmd/$n.stdout" ] || rm -f "$out/cmd/$n.stdout"
  [ -s "$out/cmd/$n.stderr" ] || rm -f "$out/cmd/$n.stderr"
  { printf '%s\t%s' "$n" "$rc"; printf '\t%s' "$@"; printf '\n'; } >>"$tsv"
}
capture()  { record "$tmp/plain.tsv" "$@"; }
scenario() { record "$tmp/scenarios.tsv" "$@"; }

# Before anyone has logged in. On Ubuntu with ssh.socket, sshd has not run yet
# and port 22 is held by systemd alone.
scenario sshd-T-before-login    sshd -T
scenario listeners-before-login ss -tulnpH

# Log in over SSH once, as on a VPS, and keep the SSH_CONNECTION it sees.
docker exec "$name" sh -c '
  useradd -m -s /bin/bash -G sudo admin
  install -d -m 700 /root/.ssh
  ssh-keygen -q -t ed25519 -N "" -f /root/.ssh/id_ed25519
  install -d -m 700 -o admin -g admin /home/admin/.ssh
  install -m 600 -o admin -g admin /root/.ssh/id_ed25519.pub /home/admin/.ssh/authorized_keys
'
conn=$(docker exec "$name" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR -i /root/.ssh/id_ed25519 admin@127.0.0.1 'echo "$SSH_CONNECTION"')
printf 'SSH_CONNECTION=%s\n' "$conn" >"$out/env"

docker exec "$name" cat /etc/os-release >"$out/root/etc/os-release"
docker exec "$name" cat /proc/1/comm >"$out/root/proc/1/comm"

capture virt-container systemd-detect-virt --container
capture virt-vm        systemd-detect-virt --vm
capture ssh-version    ssh -V
capture sshd-T         sshd -T
capture ssh-units      systemctl show --property=Id,LoadState,ActiveState,UnitFileState ssh.socket sshd.socket ssh.service sshd.service
capture listeners      ss -tulnpH

# First match wins. A cloud provider's 50-cloud-init.conf turns passwords on;
# a later 99- drop-in cannot turn them off, an earlier 00- drop-in can.
docker exec "$name" sh -c '
  echo "PasswordAuthentication yes" >/etc/ssh/sshd_config.d/50-cloud-init.conf
  echo "PasswordAuthentication no"  >/etc/ssh/sshd_config.d/99-late.conf'
scenario sshd-T-dropin-99 sshd -T
docker exec "$name" mv /etc/ssh/sshd_config.d/99-late.conf /etc/ssh/sshd_config.d/00-vpsready.conf
scenario sshd-T-dropin-00 sshd -T

cat "$tmp/plain.tsv" "$tmp/scenarios.tsv" >"$out/commands.tsv"
echo "captured $(wc -l <"$out/commands.tsv" | tr -d ' ') commands into $out"
