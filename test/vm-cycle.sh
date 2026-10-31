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
#   The dead-man switch, with the test module `test.deadman` (the binary must
#   be built with `--features testing`) and `--deadman 1m`:
#     apply runs in the background, since it waits for a confirm.
#     timeout: apply, do not confirm -> within the deadline + 10 s the file is
#       gone, the reason is deadman-timeout, the boot hook is disabled, logins
#       work and apply exited 1.
#     edited: apply, edit the file during the window -> it is still reverted,
#       and the edit is in files/1.during.
#     confirm: over real SSH logins as the cycle's user to the VM's own sshd,
#       confirm is refused from the applying session, from a session opened
#       before apply and through a ControlMaster connection; `--extend` works
#       from any session; a new login confirms, apply exits 0, the hook and
#       timers are off. (The admin and port rules are covered by unit tests;
#       the admin rule gets a VM check with user.admin.)
#     reboot: `systemd-analyze verify` of the boot hook finds no ordering
#       cycle; apply, reboot during the window -> rolled back with
#       deadman-reboot, and the hook finished before sshd started.
#   ssh.server, applied and confirmed from real logins to the VM's own sshd:
#     profile minimal (user.admin, ssh.server, firewall.inbound and the
#     rest) with a new admin: during the window a new root login is refused
#     and sshd offers no password method -> confirm as the admin -> the
#     SSH-001..007 and FW-001 controls pass, the admin logs in and root
#     does not -> rollback removes the drop-in, the table and the admin, and
#     root logs in again.
#     --module ssh.server, not confirmed: a new root login is refused (the
#     reload reached new logins, also through ssh.socket); the drop-in is
#     edited -> at the deadline it is gone and the edit is in files/1.during.
#     A `Match User <user>` block with `PermitRootLogin yes` read before the
#     drop-in -> verify (`sshd -T -C`) fails and apply rolls back.
#   The wizard, `sudo vps-ready` on a terminal over a real login, driven by
#   test/vm-wizard.exp (expect is installed in the VM): Enter at every
#   question, `y` to apply, confirmed from a new login; the wizard exits 0
#   and the `--profile` of its "Next time" line plans no changes.
#     as the cycle's user: the session user is the admin -> rollback.
#     as root with a key: a new admin with root's key (`admin`, or
#     `sysadmin` where an `admin` group exists, as on Ubuntu); root no
#     longer logs in -> rollback removes the admin, and root logs in again.
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

# The keepalive ends a session the guest dropped without closing it.
vm() {
  ssh -F "$sshcfg" -o BatchMode=yes -o ConnectTimeout=5 \
    -o ServerAliveInterval=5 -o ServerAliveCountMax=3 vm "$@"
}
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
  # Reboot a second later so that this SSH session ends first.
  vm sudo systemd-run -q --on-active=1 systemctl reboot
  i=0
  until new=$(boot_id 2>/dev/null) && [ "$new" != "$old" ]; do
    i=$((i + 5)); [ "$i" -lt 300 ] || die "VM did not come back after reboot"
    sleep 5
  done
  echo "back after about $i s"
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

deadman_file=/etc/vps-ready-deadman-test.conf
hook=vps-ready-deadman.service

# expect_pending: waits until the newest transaction waits for a confirm.
expect_pending() {
  i=0
  until vr history --json >"$tmp/history.json" && jq -e '.[0].state == "pending-confirm"' "$tmp/history.json" >/dev/null; do
    i=$((i + 1)); [ "$i" -le 60 ] || { vr history; die "not pending within 60 s"; }
    sleep 1
  done
  txn=$(jq -r '.[0].id' "$tmp/history.json")
}

# Applies test.deadman with a 1-minute window in the background: apply
# waits for a confirm, and its exit code lands in /tmp/vr-apply.rc.
apply_deadman() {
  vm test ! -e "$deadman_file" || die "$deadman_file exists before apply"
  vm "rm -f /tmp/vr-apply.rc; setsid -f sh -c 'sudo vps-ready apply --yes --module test.deadman --deadman 1m >/tmp/vr-apply.out 2>&1; echo \$? >/tmp/vr-apply.rc' </dev/null >/dev/null 2>&1"
  expect_pending
  vm test -e "$deadman_file" || die "$deadman_file is missing after apply"
  [ "$(vm systemctl is-enabled "$hook")" = enabled ] || die "$hook is not enabled"
}

# expect_rc <file> <code>: waits up to 30 s for the exit code in <file>.
expect_rc() {
  i=0
  until rc=$(vm cat "$1" 2>/dev/null) && [ -n "$rc" ]; do
    i=$((i + 1)); [ "$i" -le 30 ] || die "no exit code in $1 after 30 s"
    sleep 1
  done
  [ "$rc" -eq "$2" ] || { vm cat "${1%.rc}.out" || true; die "$1 is $rc, expected $2"; }
}

# expect_reverted <reason>: the newest transaction was rolled back for it,
# the file is gone and the boot hook disabled.
expect_reverted() {
  expect_newest rolled-back
  jq -e --arg r "$1" '.[0].reason == $r' "$tmp/history.json" >/dev/null ||
    { vr history; die "rolled back, but not with reason $1"; }
  vm test ! -e "$deadman_file" || die "$deadman_file still exists"
  [ "$(vm systemctl is-enabled "$hook" || true)" = disabled ] || die "$hook is still enabled"
}

# Waits for the timer: the window plus 10 s.
wait_deadman() {
  i=0
  until vr history --json >"$tmp/history.json" && jq -e '.[0].state == "rolled-back"' "$tmp/history.json" >/dev/null; do
    i=$((i + 5)); [ "$i" -le 70 ] || { vr history; die "not rolled back within 70 s"; }
    sleep 5
  done
  echo "rolled back after about $i s"
}

echo "== $distro: dead-man switch, timeout"
apply_deadman
wait_deadman
expect_reverted deadman-timeout
# apply saw the rollback while it waited.
expect_rc /tmp/vr-apply.rc 1
vm true || die "no login after the dead-man rollback"

echo "== $distro: dead-man switch, edited during the window"
apply_deadman
vm "echo edited during the window | sudo tee $deadman_file >/dev/null"
wait_deadman
expect_reverted deadman-timeout
expect_rc /tmp/vr-apply.rc 1
during=/var/lib/vps-ready/txn/$txn/files/1.during
[ "$(vm sudo cat "$during")" = "edited during the window" ] || die "$during does not hold the edit"

# Real SSH logins from inside the VM to its own sshd, for the session rules:
# the connection the cycle drives the VM through may not be one (Lima's
# shell uses vsock). With a key of the user's own.
echo "== $distro: SSH logins to localhost"
user=$(vm id -un)
vm 'test -f ~/.ssh/vr_local || ssh-keygen -q -t ed25519 -N "" -C vr-local -f ~/.ssh/vr_local'
# shellcheck disable=SC2016 # expanded in the VM
vm 'grep -qF "$(cat ~/.ssh/vr_local.pub)" ~/.ssh/authorized_keys || cat ~/.ssh/vr_local.pub >>~/.ssh/authorized_keys'
# Writes /tmp/vr-ssh again after a reboot clears /tmp.
write_vr_ssh() {
  vm 'cat >/tmp/vr-ssh' <<'SH'
#!/bin/sh
# ssh to this host's own sshd with the cycle's key; arguments as for ssh.
exec ssh -i "$HOME/.ssh/vr_local" -o BatchMode=yes -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p 22 "$@"
SH
}
write_vr_ssh
# local_ssh <ssh args...>: ssh from inside the VM to its own sshd.
local_ssh() { vm sh /tmp/vr-ssh "$@"; }
[ "$(local_ssh -o ControlPath=none "$user@127.0.0.1" id -un)" = "$user" ] || die "no SSH login to localhost as $user"

echo "== $distro: dead-man switch, confirm only from a new login"
vm "rm -f /tmp/vr-go /tmp/vr-*.rc /tmp/vr-*.out /tmp/vr-cm"
# Opened before apply: a ControlMaster connection, and a session that runs
# confirm once /tmp/vr-go exists.
vm "sh /tmp/vr-ssh -o ControlMaster=yes -o ControlPath=/tmp/vr-cm -o ControlPersist=600 -fN $user@127.0.0.1 </dev/null >/dev/null 2>&1" ||
  die "no ControlMaster connection"
vm 'cat >/tmp/vr-old.sh' <<'SH'
sh /tmp/vr-ssh -o ControlPath=none "$1@127.0.0.1" \
  'while [ ! -e /tmp/vr-go ]; do sleep 1; done; sudo vps-ready confirm >/tmp/vr-old.out 2>&1; echo $? >/tmp/vr-old.rc'
SH
vm "setsid -f sh /tmp/vr-old.sh $user </dev/null >/dev/null 2>&1"
# The applying session: apply in the background, then confirm from the same
# login once it is pending. apply's exit code lands in /tmp/vr-apply.rc.
vm 'cat >/tmp/vr-apply.sh' <<'SH'
sh /tmp/vr-ssh -o ControlPath=none "$1@127.0.0.1" '
  sudo vps-ready apply --yes --module test.deadman --deadman 2m >/tmp/vr-apply.out 2>&1 &
  until sudo vps-ready history --json | grep -q pending-confirm; do sleep 1; done
  sudo vps-ready confirm >/tmp/vr-same.out 2>&1; echo $? >/tmp/vr-same.rc
  wait $!; echo $? >/tmp/vr-apply.rc'
SH
vm test ! -e "$deadman_file" || die "$deadman_file exists before apply"
vm "setsid -f sh /tmp/vr-apply.sh $user </dev/null >/dev/null 2>&1"
expect_pending

expect_rc /tmp/vr-same.rc 2
vm cat /tmp/vr-same.out
vm grep -q "'this is the SSH session that applied the changes'" /tmp/vr-same.out ||
  die "the applying session was not refused as the same session"
vm touch /tmp/vr-go
expect_rc /tmp/vr-old.rc 2
vm cat /tmp/vr-old.out
vm grep -q "'started before the changes went live'" /tmp/vr-old.out ||
  die "the session opened before apply was not refused as old"
rc=0; local_ssh -o ControlPath=/tmp/vr-cm "$user@127.0.0.1" sudo vps-ready confirm >"$tmp/cm.out" 2>&1 || rc=$?
cat "$tmp/cm.out"
[ "$rc" -eq 2 ] || die "confirm through ControlMaster exited $rc, expected 2"
grep -q 'started before the changes went live' "$tmp/cm.out" ||
  die "the ControlMaster connection was not refused as old"
expect_newest pending-confirm

# --extend works from any session.
rc=0; vr confirm --extend 3m || rc=$?
[ "$rc" -eq 0 ] || die "confirm --extend exited $rc, expected 0"
vr history

rc=0; local_ssh -o ControlPath=none "$user@127.0.0.1" sudo vps-ready confirm || rc=$?
[ "$rc" -eq 0 ] || die "confirm from a new login exited $rc, expected 0"
expect_newest confirmed
expect_rc /tmp/vr-apply.rc 0
vm test -e "$deadman_file" || die "$deadman_file is gone after the confirm"
[ "$(vm systemctl is-enabled "$hook" || true)" = disabled ] || die "$hook is still enabled after the confirm"
units=$(vm "systemctl list-units --all --plain --no-legend 'vps-ready-deadman-$txn-*'" | grep -v ' inactive ' || true)
[ -z "$units" ] || { echo "$units"; die "a dead-man unit is still active after the confirm"; }
local_ssh -o ControlPath=/tmp/vr-cm -O exit "$user@127.0.0.1" 2>/dev/null || true
rc=0; vr rollback --last || rc=$?
[ "$rc" -eq 0 ] || die "rollback of the confirmed transaction exited $rc, expected 0"
vm test ! -e "$deadman_file" || die "$deadman_file still exists after rollback"

echo "== $distro: dead-man switch, reboot during the window"
# The hook unit exists from the first apply. No ordering cycle may be found:
# systemd would break it by dropping a unit, perhaps ssh.socket.
vm sudo systemd-analyze verify "/etc/systemd/system/$hook" >"$tmp/verify.txt" 2>&1 || true
cat "$tmp/verify.txt"
if grep -qi 'cycle' "$tmp/verify.txt" || grep -q "$hook" "$tmp/verify.txt"; then
  die "systemd-analyze verify reports a problem with $hook"
fi
apply_deadman
echo "== $distro: rebooting"
reboot_vm
vr history --json >"$tmp/history.json"
expect_reverted deadman-reboot
# The hook finished before systemd started anything of sshd's. From the
# journal: the disabled hook is unloaded after it ran, so `systemctl show`
# has no timestamps for it.
vm sudo journalctl -b -o json "UNIT=$hook" JOB_RESULT=done >"$tmp/hook.json"
done_at=$(jq -r .__MONOTONIC_TIMESTAMP "$tmp/hook.json" | tail -n 1)
[ -n "$done_at" ] || die "$hook did not finish at boot"
vm sudo journalctl -b -o json UNIT=ssh.service + UNIT=ssh.socket >"$tmp/ssh.json"
first=$(jq -r .__MONOTONIC_TIMESTAMP "$tmp/ssh.json" | head -n 1)
[ -n "$first" ] || die "no ssh.service or ssh.socket in the boot's journal"
[ "$done_at" -lt "$first" ] || die "sshd started at $first us, before $hook finished at $done_at us"
echo "$hook finished at $done_at us, sshd's first unit started at $first us"
vm sudo journalctl -b -u "$hook" --no-pager | tail -n 20

ssh_dropin=/etc/ssh/sshd_config.d/00-vps-ready.conf
admin=vradmin
write_vr_ssh
# Root gets the cycle's key, so a new login shows whether sshd reloaded.
vm 'sudo install -d -m 700 /root/.ssh && sudo install -m 600 ~/.ssh/vr_local.pub /root/.ssh/authorized_keys'
root_login() { local_ssh -o ControlPath=none root@127.0.0.1 true 2>/dev/null; }
# A login that offers only passwords; sshd lists the methods it accepts.
password_methods() {
  local_ssh -o ControlPath=none -o PubkeyAuthentication=no \
    -o PreferredAuthentications=password,keyboard-interactive "$user@127.0.0.1" true 2>&1 | tail -n 1 || true
}
# apply_session <args>: runs `vps-ready apply --yes <args>` from a new login
# as the user, in the background; its exit code lands in /tmp/vr-apply.rc.
apply_session() {
  vm "rm -f /tmp/vr-apply.rc; setsid -f sh -c 'sh /tmp/vr-ssh -o ControlPath=none $user@127.0.0.1 sudo vps-ready apply --yes $* >/tmp/vr-apply.out 2>&1; echo \$? >/tmp/vr-apply.rc' </dev/null >/dev/null 2>&1"
  expect_pending
}

echo "== $distro: profile minimal, confirmed by the new admin"
root_login || die "root cannot log in before apply"
vm test ! -e "$ssh_dropin" || die "$ssh_dropin exists before apply"
printf 'schema = 1\nextends = "minimal"\n[modules."user.admin"]\nname = "%s"\n' "$admin" | vm 'cat >/tmp/vr-minimal.toml'
apply_session --profile /tmp/vr-minimal.toml --deadman 2m
vm cat "$ssh_dropin"
! root_login || die "root still logs in over a new login during the window"
password_methods
! password_methods | grep -q password || die "sshd still offers password logins"
rc=0; local_ssh -o ControlPath=none "$admin@127.0.0.1" sudo vps-ready confirm || rc=$?
[ "$rc" -eq 0 ] || die "confirm as $admin exited $rc, expected 0"
expect_newest confirmed
expect_rc /tmp/vr-apply.rc 0
rc=0; vr audit --json >"$tmp/audit.json" || rc=$?
[ "$rc" -le 1 ] || die "audit exited $rc, expected 0 or 1"
fixed='.fix == "ssh.server" or .fix == "firewall.inbound"'
jq -r ".findings[] | select($fixed) | \"\(.id) \(.status)\"" "$tmp/audit.json"
jq -e "[.findings[] | select(($fixed) and .status != \"pass\")] | length == 0" \
  "$tmp/audit.json" >/dev/null || die "an ssh.server or firewall.inbound control does not pass after the confirm"
expect_empty_plan ssh.server
! root_login || die "root logs in after the confirm"
local_ssh -o ControlPath=none "$admin@127.0.0.1" true || die "$admin cannot log in after the confirm"
# `userdel` fails while the admin has processes, e.g. its systemd --user.
i=0
while vm pgrep -u "$admin" >/dev/null; do
  i=$((i + 1)); [ "$i" -le 30 ] || die "$admin still has processes after 30 s"
  sleep 1
done
rc=0; vr rollback --last || rc=$?
[ "$rc" -eq 0 ] || die "rollback of the confirmed transaction exited $rc, expected 0"
vm test ! -e "$ssh_dropin" || die "$ssh_dropin still exists after rollback"
! vm sudo nft list table inet vps_ready >/dev/null 2>&1 || die "the vps_ready table is still loaded after rollback"
! vm id "$admin" >/dev/null 2>&1 || die "$admin still exists after rollback"
root_login || die "root cannot log in after the rollback"

echo "== $distro: ssh.server, edited during the window and not confirmed"
apply_session --module ssh.server --deadman 1m
vm cat "$ssh_dropin"
[ "$(vm sudo sshd -T | awk '$1 == "permitrootlogin" { print $2 }')" = no ] ||
  die "sshd -T does not show permitrootlogin no"
# The reload reaches new logins (with ssh.socket too); open ones stay.
! root_login || die "root still logs in over a new login"
vm true || die "the open connection was cut"
vm "echo 'PermitRootLogin yes' | sudo tee $ssh_dropin >/dev/null"
wait_deadman
expect_reverted deadman-timeout
expect_rc /tmp/vr-apply.rc 1
vm test ! -e "$ssh_dropin" || die "$ssh_dropin still exists"
during=/var/lib/vps-ready/txn/$txn/files/1.during
[ "$(vm sudo cat "$during")" = "PermitRootLogin yes" ] || die "$during does not hold the edit"
root_login || die "root cannot log in after the rollback"

echo "== $distro: ssh.server, a Match block for the admin fails verify"
# Read before the drop-in, but only for the admin's own connection, which
# verify checks with `sshd -T -C`.
match_conf=/etc/ssh/sshd_config.d/01-match.conf
printf 'Match User %s\n  PermitRootLogin yes\n' "$user" | vm "sudo tee $match_conf >/dev/null"
rc=0; local_ssh -o ControlPath=none "$user@127.0.0.1" sudo vps-ready apply --yes --module ssh.server --deadman 1m || rc=$?
[ "$rc" -eq 1 ] || { vm sudo rm -f "$match_conf"; die "apply exited $rc, expected 1 (rolled back)"; }
vm sudo rm -f "$match_conf"
expect_newest rolled-back
jq -e '.[0].reason == "verify-failed"' "$tmp/history.json" >/dev/null ||
  { vr history; die "rolled back, but not with reason verify-failed"; }
vm test ! -e "$ssh_dropin" || die "$ssh_dropin still exists"

# expect drives the wizard; the VM gets it, the runner does not need it.
vm 'sudo apt-get -qq -o DPkg::Lock::Timeout=120 update && sudo DEBIAN_FRONTEND=noninteractive apt-get -qq -o DPkg::Lock::Timeout=120 install expect >/dev/null' ||
  die "cannot install expect"
vm 'cat >/tmp/vr-wizard.exp' <test/vm-wizard.exp
wizard_fail() { vm cat /tmp/vr-wizard.out || true; die "$1"; }
# wizard <login> <admin>: `sudo vps-ready` over a new login as <login>,
# under expect: every default, `y` to apply. In the background, since apply
# waits for a confirm; returns soon after it is pending. The transcript lands in
# /tmp/vr-wizard.out and the exit code in /tmp/vr-wizard.rc.
wizard() {
  vm "rm -f /tmp/vr-wizard.rc; setsid -f sh -c 'expect /tmp/vr-wizard.exp $2 sh /tmp/vr-ssh -tt -o ControlPath=none $1@127.0.0.1 sudo NO_COLOR=1 vps-ready >/tmp/vr-wizard.out 2>&1; echo \$? >/tmp/vr-wizard.rc' </dev/null >/dev/null 2>&1"
  i=0
  until vr history --json >"$tmp/history.json" && jq -e '.[0].state == "pending-confirm"' "$tmp/history.json" >/dev/null; do
    vm test ! -e /tmp/vr-wizard.rc || wizard_fail "the wizard ended before its changes were pending"
    i=$((i + 1)); [ "$i" -le 120 ] || wizard_fail "not pending within 120 s"
    sleep 1
  done
  # A login in the second the changes went live counts as old.
  sleep 2
}
# wizard_done <admin>: confirms as <admin> from a new login; the wizard
# exits 0 and printed the ssh line for <admin>. Sets $profile to what its
# "Next time" line passes to --profile.
wizard_done() {
  rc=0; local_ssh -o ControlPath=none "$1@127.0.0.1" sudo vps-ready confirm || rc=$?
  [ "$rc" -eq 0 ] || wizard_fail "confirm as $1 exited $rc, expected 0"
  expect_newest confirmed
  expect_rc /tmp/vr-wizard.rc 0
  vm cat /tmp/vr-wizard.out | tr -d '\r' >"$tmp/wizard.out"
  cat "$tmp/wizard.out"
  grep -qF -- "-p 22 $1@127.0.0.1 sudo vps-ready confirm" "$tmp/wizard.out" ||
    die "the wizard's ssh line does not log in as $1"
  profile=$(sed -n 's/^  sudo vps-ready apply --profile //p' "$tmp/wizard.out")
  [ -n "$profile" ] || die "no \"Next time\" command"
}
# expect_no_changes <user>: the "Next time" profile, planned from a new
# login as <user>, has nothing to do.
expect_no_changes() {
  rc=0; local_ssh -o ControlPath=none "$1@127.0.0.1" sudo vps-ready plan --json --profile "$profile" >"$tmp/plan.json" || rc=$?
  [ "$rc" -eq 0 ] || die "plan --profile $profile exited $rc, expected 0"
  jq -e '[.modules[].changes | length] | add == 0' "$tmp/plan.json" >/dev/null ||
    { cat "$tmp/plan.json"; die "plan --profile $profile still has changes"; }
}

echo "== $distro: the wizard, as $user"
wizard "$user" "$user"
wizard_done "$user"
grep -q "existing account (the one you logged in as)" "$tmp/wizard.out" ||
  die "the wizard did not make $user, the session user, the admin"
expect_no_changes "$user"
rc=0; vr rollback --last || rc=$?
[ "$rc" -eq 0 ] || die "rollback of the wizard's transaction exited $rc, expected 0"
vm test ! -e "$ssh_dropin" || die "$ssh_dropin still exists after rollback"
# A saved profile is root's; vps-ready.toml would be asked about next time.
case $profile in /*) vm sudo rm -f "$profile" ;; esac
root_login || die "root cannot log in after the rollback"

# Ubuntu's images have an `admin` group and no such user, so the wizard
# offers `sysadmin` there.
case $distro in ubuntu-*) new="sysadmin" ;; *) new="admin" ;; esac
echo "== $distro: the wizard, as root (new admin $new)"
! vm id "$new" >/dev/null 2>&1 || die "$new exists before the wizard"
wizard root "$new"
wizard_done "$new"
grep -q "new account: logs in with 1 key copied from /root/.ssh/authorized_keys" "$tmp/wizard.out" ||
  die "the wizard did not offer a new admin with root's key"
[ "$(vm sudo cat "/home/$new/.ssh/authorized_keys")" = "$(vm cat .ssh/vr_local.pub)" ] ||
  die "$new does not have root's key"
# A name other than the built-in default is saved to a file.
case $new:$profile in
  admin:minimal | sysadmin:/root/vps-ready.toml) ;;
  *) die "the \"Next time\" line has --profile $profile, not the one for $new" ;;
esac
expect_no_changes "$new"
! root_login || die "root logs in after the confirm"
i=0
while vm pgrep -u "$new" >/dev/null; do
  i=$((i + 1)); [ "$i" -le 30 ] || die "$new still has processes after 30 s"
  sleep 1
done
rc=0; vr rollback --last || rc=$?
[ "$rc" -eq 0 ] || die "rollback of the wizard's transaction exited $rc, expected 0"
! vm id "$new" >/dev/null 2>&1 || die "$new still exists after rollback"
root_login || die "root cannot log in after the rollback"
case $profile in /*) vm sudo rm -f "$profile" ;; esac
vm sudo rm -f /root/.ssh/authorized_keys

echo "== $distro: vps-ready history"
vr history
echo "OK [$distro]"
