#!/bin/sh
# Apply, reboot and roll back with the real binary in a KVM virtual machine.
#
# Usage: test/vm-cycle.sh <distro> <binary> <image>     e.g. ubuntu-24.04
#   <image> is a cloud image (qcow2). The script boots it with QEMU and KVM
#   (2 vCPUs, 2 GiB, a copy-on-write overlay, so the image is not changed),
#   seeds a throwaway SSH key and a passwordless sudo user with cloud-init,
#   and drives the VM over SSH on 127.0.0.1:$VM_SSH_PORT (default 2222).
#   The binary must match the VM's CPU; CI uses the x86_64 musl build.
# Needs: qemu-system-x86_64, qemu-img, cloud-localds, ssh, jq, and /dev/kvm.
#
#   To run the cycle against a VM you already have, pass "-" as <image> and
#   set VM_SSH_CONFIG to an ssh config whose `Host vm` reaches a user with
#   passwordless sudo. The cycle changes that VM's settings.
#
# Cycles:
#   kernel.sysctl, same boot: weaken five keys -> apply -> the controls pass
#     -> rollback --last -> the keys are weak again and the drop-in is gone.
#   kernel.sysctl, across a reboot: weaken -> plan -> apply -> reboot -> every
#     control the module fixes passes and the plan is empty -> rollback --last
#     exits 0 and removes the drop-in -> reboot -> the keys have the values
#     they had at the first boot.
#   updates.auto: apply -> the plan is empty and UPD-001 passes -> rollback
#     --last -> the apt.conf.d files match their state before.
set -eu
cd "$(dirname "$0")/.."

usage="usage: $0 <distro> <binary> <image|->"
distro=${1:?$usage}
bin=${2:?$usage}
image=${3:?$usage}
port=${VM_SSH_PORT:-2222}
tmp=$(mktemp -d)
pid=

[ -f "$bin" ] || { echo "binary not found: $bin" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

cleanup() {
  rc=$?
  if [ -n "$pid" ]; then
    if [ "$rc" -ne 0 ] && [ -f "$tmp/console.log" ]; then
      echo "== $distro: last lines of the serial console" >&2
      tail -n 40 "$tmp/console.log" >&2
    fi
    kill "$pid" 2>/dev/null || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT
# POSIX sh keeps running after a trapped signal; exit so Ctrl-C stops the run.
trap 'exit 130' INT TERM

die() { echo "FAIL [$distro]: $*" >&2; exit 1; }

if [ "$image" = - ]; then
  sshcfg=${VM_SSH_CONFIG:?set VM_SSH_CONFIG when <image> is -}
else
  [ -f "$image" ] || { echo "image not found: $image" >&2; exit 2; }
  [ -w /dev/kvm ] || { echo "/dev/kvm is missing or not writable" >&2; exit 2; }

  ssh-keygen -q -t ed25519 -N "" -C vps-ready-ci -f "$tmp/id"
  cat >"$tmp/user-data" <<EOF
#cloud-config
users:
  - name: ci
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $(cat "$tmp/id.pub")
EOF
  printf 'instance-id: vps-ready-%s\nlocal-hostname: vps-ready-vm\n' "$distro" >"$tmp/meta-data"
  cloud-localds "$tmp/seed.img" "$tmp/user-data" "$tmp/meta-data"
  qemu-img create -q -f qcow2 -F qcow2 -b "$(realpath "$image")" "$tmp/disk.qcow2" 10G

  qemu-system-x86_64 -enable-kvm -cpu host -smp 2 -m 2048 \
    -drive file="$tmp/disk.qcow2",if=virtio,format=qcow2 \
    -drive file="$tmp/seed.img",if=virtio,format=raw \
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:"$port"-:22 \
    -device virtio-net-pci,netdev=net0 \
    -display none -serial file:"$tmp/console.log" \
    -daemonize -pidfile "$tmp/qemu.pid"
  pid=$(cat "$tmp/qemu.pid")

  sshcfg=$tmp/ssh_config
  cat >"$sshcfg" <<EOF
Host vm
  HostName 127.0.0.1
  Port $port
  User ci
  IdentityFile $tmp/id
  IdentitiesOnly yes
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
EOF
fi

vm() { ssh -F "$sshcfg" -o BatchMode=yes -o ConnectTimeout=5 vm "$@"; }
vr() { vm sudo vps-ready "$@"; }

# wait_ssh <seconds>: wait until a login works.
wait_ssh() {
  i=0
  until vm true 2>/dev/null; do
    i=$((i + 5)); [ "$i" -lt "$1" ] || die "no SSH after $1 s"
    sleep 5
  done
}

boot_id() { vm cat /proc/sys/kernel/random/boot_id; }

# Reboot and wait until the VM is back with a new boot ID.
reboot_vm() {
  old=$(boot_id)
  vm sudo systemctl reboot || true
  i=0
  until new=$(boot_id 2>/dev/null) && [ "$new" != "$old" ]; do
    i=$((i + 5)); [ "$i" -lt 300 ] || die "VM did not come back after reboot"
    sleep 5
  done
}

# Weak values for keys that cloud images already harden, so the module has
# work to do. Ubuntu's boot config sets fs.protected_regular to 2, which is
# neither the weak nor the applied value after a reboot.
weak_keys="kernel.kptr_restrict=0 kernel.dmesg_restrict=0 fs.protected_fifos=0 fs.protected_regular=0 net.ipv4.conf.all.accept_source_route=1"
weaken() { for kv in $weak_keys; do vm sudo sysctl -q -w "$kv"; done; }
# The running values of those keys, as "key = value" lines.
key_values() { for kv in $weak_keys; do vm sudo sysctl "${kv%=*}"; done; }
# expect_keys weak|hardened: hardened means no longer the weak value; the
# controls check the exact values.
expect_keys() {
  for kv in $weak_keys; do
    key=${kv%=*}; weak=${kv#*=}; got=$(vm sudo sysctl -n "$key")
    if [ "$1" = weak ]; then
      [ "$got" = "$weak" ] || die "$key is $got, expected $weak"
    else
      [ "$got" != "$weak" ] || die "$key is still $weak"
    fi
  done
}

# Every KRN-* and NET-* control the module fixes passes.
expect_sysctl_controls_pass() {
  rc=0; vr audit --json >"$tmp/audit.json" || rc=$?
  [ "$rc" -le 1 ] || die "audit exited $rc, expected 0 or 1"
  jq -r '.findings[] | select(.fix == "kernel.sysctl") | "\(.id) \(.status)"' "$tmp/audit.json"
  jq -e '[.findings[] | select(.fix == "kernel.sysctl" and .status != "pass")] | length == 0' \
    "$tmp/audit.json" >/dev/null || die "a kernel.sysctl control does not pass"
}

expect_empty_plan() {
  rc=0; vr plan --json --module "$1" >"$tmp/plan.json" || rc=$?
  [ "$rc" -eq 0 ] || die "plan exited $rc, expected 0"
  jq -e '[.modules[].changes | length] | add == 0' "$tmp/plan.json" >/dev/null ||
    { cat "$tmp/plan.json"; die "plan for $1 still has changes"; }
}

expect_newest() {
  vr history --json >"$tmp/history.json"
  jq -e --arg s "$1" '.[0].state == $s' "$tmp/history.json" >/dev/null ||
    { vr history; die "newest transaction is not $1"; }
}

dropin=/etc/sysctl.d/90-vps-ready.conf
apt_conf=/etc/apt/apt.conf.d

echo "== $distro: waiting for SSH and cloud-init"
wait_ssh 300
# "degraded" or a cloud-init error should not stop the cycle; it only waits.
vm sudo cloud-init status --wait >/dev/null 2>&1 || true
vm cat /etc/os-release | grep PRETTY_NAME
vm uname -r

vm 'cat >/tmp/vps-ready' <"$bin"
vm sudo install -m 755 /tmp/vps-ready /usr/local/bin/vps-ready

echo "== $distro: vps-ready audit"
rc=0; vr audit || rc=$?
[ "$rc" -le 1 ] || die "audit exited $rc, expected 0 or 1"
vr audit --json >"$tmp/audit.json" || true
jq -e '[.findings[] | select(.id | test("^(KRN|NET)-"))
       | select(.status == "skip" or .status == "unknown")] | length == 0' "$tmp/audit.json" >/dev/null ||
  die "a KRN or NET control was not checked"
vm test ! -e "$dropin" || die "$dropin exists before apply"
key_values >"$tmp/boot-defaults.txt"

echo "== $distro: kernel.sysctl, same boot"
weaken
rc=0; vr apply --yes --module kernel.sysctl || rc=$?
[ "$rc" -eq 0 ] || die "apply exited $rc, expected 0"
expect_keys hardened
expect_sysctl_controls_pass
rc=0; vr rollback --last || rc=$?
[ "$rc" -eq 0 ] || die "rollback exited $rc, expected 0"
expect_newest rolled-back
expect_keys weak
vm test ! -e "$dropin" || die "$dropin still exists after rollback"

echo "== $distro: kernel.sysctl, across a reboot"
weaken
echo "== $distro: vps-ready plan --module kernel.sysctl"
rc=0; vr plan --module kernel.sysctl || rc=$?
[ "$rc" -eq 0 ] || die "plan exited $rc, expected 0"
rc=0; vr apply --yes --module kernel.sysctl || rc=$?
[ "$rc" -eq 0 ] || die "apply exited $rc, expected 0"
vm cat "$dropin"
echo "== $distro: rebooting"
reboot_vm
expect_keys hardened
expect_sysctl_controls_pass
expect_empty_plan kernel.sysctl

echo "== $distro: vps-ready rollback --last after the reboot"
# Kernel settings are left to the boot config, so they change at the next boot.
rc=0; vr rollback --last >"$tmp/rollback.out" || rc=$?
cat "$tmp/rollback.out"
[ "$rc" -eq 0 ] || die "rollback after reboot exited $rc, expected 0"
grep -q 'keep their running value until the next boot' "$tmp/rollback.out" ||
  die "rollback did not list the kernel settings left until the next boot"
expect_newest rolled-back
vm test ! -e "$dropin" || die "$dropin still exists after rollback"
echo "== $distro: rebooting"
reboot_vm
key_values >"$tmp/after.txt"
diff "$tmp/boot-defaults.txt" "$tmp/after.txt" ||
  die "kernel settings differ from the boot defaults after rollback and reboot"

echo "== $distro: updates.auto"
vm "cd $apt_conf && test ! -e 52vps-ready && sha256sum * >/tmp/apt-before.sha"
rc=0; vr apply --yes --module updates.auto || rc=$?
[ "$rc" -eq 0 ] || die "apply exited $rc, expected 0"
expect_empty_plan updates.auto
rc=0; vr audit --json >"$tmp/audit.json" || rc=$?
[ "$rc" -le 1 ] || die "audit exited $rc, expected 0 or 1"
jq -e '.findings[] | select(.id == "UPD-001" and .status == "pass")' "$tmp/audit.json" >/dev/null ||
  die "UPD-001 is not pass after apply"
expect_newest applied
rc=0; vr rollback --last || rc=$?
[ "$rc" -eq 0 ] || die "rollback exited $rc, expected 0"
expect_newest rolled-back
vm "cd $apt_conf && test ! -e 52vps-ready && sha256sum -c --quiet /tmp/apt-before.sha" ||
  die "apt.conf.d files differ from the state before apply"

echo "== $distro: vps-ready history"
vr history
echo "OK [$distro]"
