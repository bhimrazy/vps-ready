#!/bin/sh
# Capture a real host as a unit-test fixture, from a systemd test container
# or a VM.
#
# Usage: test/capture-host-fixtures.sh <distro> [ssh-config]      e.g. ubuntu-24.04
# Needs: docker, and the test image for <distro>:
#   docker build -f test/images/Containerfile --build-arg BASE=ubuntu:24.04 -t vps-ready-test:ubuntu-24.04 test/images
# With <ssh-config>, it captures the VM whose `Host vm` reaches a user with
# passwordless sudo instead, as test/vm-cycle.sh's `fixtures` cycle does. A VM
# already has a login, so the before-login scenarios are left out, and the
# sshd drop-ins the scenarios write are put back afterwards.
#
# Writes crates/vps-ready/testdata/hosts/<distro>/:
#   root/...        files the facts code reads (os-release, /proc/1/comm,
#                   /proc/net/if_inet6, /etc/ssh/sshd_config and its drop-ins)
#   commands.tsv    name, exit code, then the exact argv, tab-separated.
#                   Several entries can share an argv (scenarios); the first wins
#                   by default, so the plain capture comes before the scenarios.
#   cmd/<name>.stdout, cmd/<name>.stderr
# The container is capped at 512 MB and 1 CPU and is removed afterwards.
set -eu
cd "$(dirname "$0")/.."

distro=${1:?usage: $0 <distro> [ssh-config]}
sshcfg=${2:-}
image="vps-ready-test:$distro"
out="crates/vps-ready/testdata/hosts/$distro"
name="vps-ready-capture-$distro-$$"
tmp=$(mktemp -d)

# x <argv...>: runs argv on the host as root, exactly: over SSH, each word is
# quoted for the remote shell.
if [ -n "$sshcfg" ]; then
  x() {
    cmd=
    for a; do cmd="$cmd '$(printf '%s' "$a" | sed "s/'/'\\\\''/g")'"; done
    ssh -F "$sshcfg" -o BatchMode=yes vm "sudo$cmd"
  }
  cleanup() { rm -rf "$tmp"; }
else
  x() { docker exec "$name" "$@"; }
  cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$tmp"; }
fi
trap cleanup EXIT
# POSIX sh keeps running after a trapped signal; exit so a Ctrl-C during boot
# cannot reach the step that replaces the committed fixtures.
trap 'exit 130' INT TERM

if [ -z "$sshcfg" ]; then
  docker run -d --name "$name" --privileged --cgroupns=private \
    --memory 512m --cpus 1 --tmpfs /run --tmpfs /run/lock "$image" >/dev/null

  # Wait for systemd to finish booting ("degraded" is normal in a container).
  i=0
  until state=$(x systemctl is-system-running 2>/dev/null); \
        [ "$state" = running ] || [ "$state" = degraded ]; do
    i=$((i + 1)); [ "$i" -lt 60 ] || { echo "boot timeout ($state)" >&2; exit 1; }
    sleep 1
  done
fi

rm -rf "$out"; mkdir -p "$out/cmd" "$out/root/etc" "$out/root/proc/1" "$out/root/proc/net"
: >"$tmp/plain.tsv"; : >"$tmp/scenarios.tsv"

# record <tsv> <name> <argv...>: run argv in the container exactly, no shell.
record() {
  tsv=$1; n=$2; shift 2
  set +e
  x "$@" >"$out/cmd/$n.stdout" 2>"$out/cmd/$n.stderr"
  rc=$?
  set -e
  [ -s "$out/cmd/$n.stdout" ] || rm -f "$out/cmd/$n.stdout"
  [ -s "$out/cmd/$n.stderr" ] || rm -f "$out/cmd/$n.stderr"
  { printf '%s\t%s' "$n" "$rc"; printf '\t%s' "$@"; printf '\n'; } >>"$tsv"
}
capture()  { record "$tmp/plain.tsv" "$@"; }
scenario() { record "$tmp/scenarios.tsv" "$@"; }

if [ -z "$sshcfg" ]; then
  # Before anyone has logged in. On Ubuntu with ssh.socket, sshd has not run
  # yet and port 22 is held by systemd alone.
  scenario sshd-T-before-login    sshd -T
  scenario listeners-before-login ss -tulnpH

  # Log in over SSH once, as on a VPS.
  x sh -c '
    useradd -m -s /bin/bash -G sudo admin
    install -d -m 700 /root/.ssh
    ssh-keygen -q -t ed25519 -N "" -f /root/.ssh/id_ed25519
    install -d -m 700 -o admin -g admin /home/admin/.ssh
    install -m 600 -o admin -g admin /root/.ssh/id_ed25519.pub /home/admin/.ssh/authorized_keys
  '
  x ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR -i /root/.ssh/id_ed25519 admin@127.0.0.1 true
fi

x cat /etc/os-release >"$out/root/etc/os-release"
x cat /proc/1/comm >"$out/root/proc/1/comm"
x cat /proc/net/if_inet6 >"$out/root/proc/net/if_inet6"
mkdir -p "$out/root/etc/ssh"
x cat /etc/ssh/sshd_config >"$out/root/etc/ssh/sshd_config"
x tar -C /etc/ssh -cf - sshd_config.d >"$tmp/dropins.tar"
tar -C "$out/root/etc/ssh" -xf "$tmp/dropins.tar"

# A VM has its own kernel: the settings in facts/sysctl.rs (KEYS, and
# CONF_KEYS for each interface), the running release, the names of the
# kernels in /boot (as empty files), and whether AppArmor is on.
if [ -n "$sshcfg" ]; then
  mkdir -p "$out/root/sys/module/apparmor/parameters"
  x cat /sys/module/apparmor/parameters/enabled >"$out/root/sys/module/apparmor/parameters/enabled"
  keys="fs/protected_fifos fs/protected_hardlinks fs/protected_regular fs/protected_symlinks
    fs/suid_dumpable kernel/dmesg_restrict kernel/kptr_restrict kernel/perf_event_paranoid
    kernel/randomize_va_space kernel/unprivileged_bpf_disabled kernel/yama/ptrace_scope
    net/ipv4/icmp_echo_ignore_broadcasts net/ipv4/tcp_syncookies net/mptcp/enabled kernel/osrelease"
  for dir in $(x ls /proc/sys/net/ipv4/conf); do
    for k in accept_redirects forwarding rp_filter send_redirects accept_source_route; do
      keys="$keys net/ipv4/conf/$dir/$k"
    done
  done
  for k in $keys; do
    mkdir -p "$out/root/proc/sys/$(dirname "$k")"
    x cat "/proc/sys/$k" >"$out/root/proc/sys/$k" 2>/dev/null || rm -f "$out/root/proc/sys/$k"
  done
  mkdir -p "$out/root/boot"
  for f in $(x ls /boot); do
    case $f in vmlinuz-*) : >"$out/root/boot/$f" ;; esac
  done
fi

capture virt-container systemd-detect-virt --container
capture virt-vm        systemd-detect-virt --vm
capture ssh-version    ssh -V
capture sshd-T         sshd -T
capture ssh-units      systemctl show --property=Id,LoadState,ActiveState,UnitFileState ssh.socket sshd.socket ssh.service sshd.service
capture ssh-socket-listen systemctl show --property=Listen ssh.socket
capture listeners      ss -tulnpH
capture nft            nft -j list ruleset
capture firewall-units systemctl show --property=Id,LoadState,ActiveState,UnitFileState firewalld.service nftables.service
capture apt-periodic   apt-config dump APT::Periodic
capture apt-units      systemctl show --property=Id,LoadState,ActiveState,UnitFileState apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service
capture ip-addr         ip -j -d addr
capture ip-route        ip -j route show table all
capture docker-packages dpkg-query -W '--showformat=${Package} ${db:Status-Status} ${Version}\n' docker-ce docker.io podman-docker containerd runc

# First match wins. A cloud provider's 50-cloud-init.conf turns passwords on;
# a later 99- drop-in cannot turn them off, an earlier 00- drop-in can.
x sh -c '
  echo "PasswordAuthentication yes" >/etc/ssh/sshd_config.d/50-cloud-init.conf
  echo "PasswordAuthentication no"  >/etc/ssh/sshd_config.d/99-late.conf'
scenario sshd-T-dropin-99 sshd -T
x mv /etc/ssh/sshd_config.d/99-late.conf /etc/ssh/sshd_config.d/00-vps-ready.conf
scenario sshd-T-dropin-00 sshd -T
if [ -n "$sshcfg" ]; then
  x sh -c 'rm -rf /etc/ssh/sshd_config.d && tar -C /etc/ssh -xpf -' <"$tmp/dropins.tar"
fi

cat "$tmp/plain.tsv" "$tmp/scenarios.tsv" >"$out/commands.tsv"
echo "captured $(wc -l <"$out/commands.tsv" | tr -d ' ') commands into $out"
