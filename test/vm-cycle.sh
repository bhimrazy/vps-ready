#!/bin/sh
# Apply, reboot and roll back with the real binary in a KVM virtual machine.
#
# Usage: test/vm-cycle.sh <distro> <binary> <image> [cloud-init|private-access|tunnel|fixtures]
#   e.g. ubuntu-24.04
#   <image> is a cloud image (qcow2). The script boots it with QEMU and KVM
#   (2 vCPUs, 2 GiB, a copy-on-write overlay, so the image is not changed),
#   seeds a throwaway SSH key and a passwordless sudo user with cloud-init,
#   and drives the VM over SSH on 127.0.0.1:$VM_SSH_PORT (default 2222).
#   The binary must match the VM's CPU; CI uses the x86_64 musl build.
#   With `cloud-init`, `private-access` or `tunnel`, it runs only that cycle
#   below. With `fixtures`, it only captures the fresh VM with
#   test/capture-host-fixtures.sh, into crates/vps-ready/testdata/hosts/<distro>.
# Needs: qemu-system-x86_64, qemu-img, cloud-localds, ssh, jq, and /dev/kvm;
#   python3 for the cloud-init cycle.
#
#   To run the cycle against a VM you already have, pass "-" as <image> and
#   set VM_SSH_CONFIG to an ssh config whose `Host vm` reaches a user with
#   passwordless sudo. The cycle changes that VM's settings. The cloud-init
#   cycle needs an image, since it boots fresh overlays.
#
# Cycles:
#   sudo (sudo-rs on Ubuntu 26.04): detect under sudo finds the session and
#     SUDO_USER is set; visudo -cf accepts a valid drop-in and rejects a
#     broken one; sudo -n -l -U exits 0 and lists rules for a NOPASSWD user
#     and a member of sudo (who needs a password), none for a user without;
#     apply --deadman=off of ssh.server is refused, naming this login.
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
#       before apply, through a ControlMaster connection and from a new
#       login to 127.0.0.1; `--extend` works from any session; a new login
#       to the VM's own address confirms, apply exits 0, the hook and
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
#   Deploy, a test profile: `web` (with deploy.docker), deploy.proxy for
#   app.localhost (Caddy serves it from its own CA) and deploy.user with a key
#   forced to a root-owned command, confirmed by the new admin -> a container
#   published with `-p 8080:80` answers through Caddy over HTTPS and not on the
#   VM's own address; the deploy key runs only its command, and sudo with an
#   argument is refused -> rollback removes Docker's and Caddy's sources, keys
#   and config files and the deploy user, Caddy is disabled, and the cycle's
#   user still logs in.
#   cloud-init (only with the `cloud-init` argument): a profile whose admin
#   key is the job's, exported with `export cloud-init --base-url` and a
#   checksums.txt of a tarball made from <binary>, served from the runner on
#   10.0.2.2:$VM_HTTP_PORT (default 8321), and booted as multipart user-data
#   with the seed's own part. Nobody logs in until cloud-init's final message
#   is on the serial console, since `--deadman=off` refuses while anyone is
#   logged in. Then: curl or wget, sha256sum and tar exist; as the admin, `cloud-init
#   status` is done, `history` shows one transaction applied without the
#   timer, SSH-001..007 and FW-001 pass, root does not log in, and the
#   exported profile plans nothing. A second fresh boot with a tampered
#   tarball: `sha256sum -c` fails, nothing is installed or applied, and
#   `cloud-init status` is error.
#   private-access (only with the `private-access` argument; needs a Linux
#   runner with sudo, the wireguard kernel module and wireguard-tools):
#   net.wireguard in the VM, whose peer is the runner, reached through
#   QEMU's UDP forward of 127.0.0.1:$VM_WG_PORT (default 51820). Then, with
#   `--deadman`:
#     net.wireguard and firewall.inbound from the public session, confirmed
#       from a new public login: the client config is printed, wg0 has the
#       key of wg0.key, the firewall accepts its port, wg0.conf and the state
#       directory hold no private key, `systemctl reload` fails (the
#       drop-in), and the plan is empty; NET-008 passes;
#     whether `wg syncconf` with a key-less file keeps the key, on a
#       separate interface, printed;
#     ssh_via from the public session is refused, with the command to run
#       through wg0;
#     not confirmed: during the window a new public login fails, and at the
#       deadline public SSH works again;
#     confirmed through wg0: a new public login fails, a public session
#       opened before stays up, a confirm from a login from the VM to its
#       own address or to wg0's is refused as local, and one through wg0
#       confirms; SSH-009, FW-003 and NET-008 pass;
#     under ssh_via a second peer plans only net.wireguard and arms the
#       timer; not confirmed, the dead-man takes the peer off wg0 again;
#       confirmed through wg0, a wg0 session opened before stays up with the
#       key intact; moving this session's own peer is refused;
#     after a reboot public SSH stays closed and SSH through wg0 works with
#       the same key, and `systemd-analyze verify` finds no ordering cycle;
#     rollback --last until the start: public SSH reopens, stopping wg0 is
#       refused through wg0 and done from public SSH, the key stays, and a
#       new apply brings back the same public key.
#   tunnel (only with the `tunnel` argument): net.tunnel with a placeholder
#   token file and no Cloudflare account. LoadCredential= hands the file to
#   a sandboxed DynamicUser process byte for byte; the connector unit starts,
#   cloudflared reads the credential and rejects the token (not "no such
#   file" or "permission denied"), so the apply fails and rolls back, with
#   the address filter in effect. The units, config, source and key are
#   gone, the package and the token file stay, and the token's bytes are in
#   none of the plan, the apply output, the boot's journal, /etc, /root
#   (but its own file) or /var/lib/vps-ready.
set -eu
cd "$(dirname "$0")/.."

usage="usage: $0 <distro> <binary> <image|-> [cloud-init|private-access|tunnel|fixtures]"
distro=${1:?$usage}
bin=${2:?$usage}
image=${3:?$usage}
cycle=${4:-all}
port=${VM_SSH_PORT:-2222}
http_port=${VM_HTTP_PORT:-8321}
wg_port=${VM_WG_PORT:-51820}
tmp=$(mktemp -d)
pid=
www_pid=
wg_link=

[ -f "$bin" ] || { echo "binary not found: $bin" >&2; exit 2; }
case $cycle in all | cloud-init | private-access | tunnel | fixtures) ;; *) echo "$usage" >&2; exit 2 ;; esac
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
  [ -z "$www_pid" ] || kill "$www_pid" 2>/dev/null || true
  [ -z "$wg_link" ] || sudo ip link del "$wg_link" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT
# POSIX sh keeps running after a trapped signal; exit so Ctrl-C stops the run.
trap 'exit 130' INT TERM

die() { echo "FAIL [$distro]: $*" >&2; exit 1; }
# For the harness's own apt calls in the VM, in case the seed's 80ci is missing.
apt_retry="-o Acquire::Retries=5 -o Acquire::http::Timeout=30"

# boot <user-data>: boots a fresh overlay of the image with this user-data,
# after stopping the VM booted before. The console log starts empty.
boot() {
  if [ -n "$pid" ]; then
    kill "$pid"
    while kill -0 "$pid" 2>/dev/null; do sleep 1; done
    pid=
  fi
  cloud-localds "$tmp/seed.img" "$1" "$tmp/meta-data"
  rm -f "$tmp/disk.qcow2"
  qemu-img create -q -f qcow2 -F qcow2 -b "$(realpath "$image")" "$tmp/disk.qcow2" 10G
  qemu-system-x86_64 -enable-kvm -cpu host -smp 2 -m 2048 \
    -drive file="$tmp/disk.qcow2",if=virtio,format=qcow2 \
    -drive file="$tmp/seed.img",if=virtio,format=raw \
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:"$port"-:22,hostfwd=udp:127.0.0.1:"$wg_port"-:51820 \
    -device virtio-net-pci,netdev=net0 \
    -display none -serial file:"$tmp/console.log" \
    -daemonize -pidfile "$tmp/qemu.pid"
  pid=$(cat "$tmp/qemu.pid")
}

if [ "$image" = - ]; then
  [ "$cycle" = all ] || { echo "the $cycle cycle needs an image" >&2; exit 2; }
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
# CI only: retry flaky mirrors. UPD-001 reads only apt's Periodic settings.
write_files:
  - path: /etc/apt/apt.conf.d/80ci
    content: |
      Acquire::Retries "5";
      Acquire::http::Timeout "30";
      Acquire::https::Timeout "30";
EOF
  printf 'instance-id: vps-ready-%s\nlocal-hostname: vps-ready-vm\n' "$distro" >"$tmp/meta-data"
  [ "$cycle" = cloud-init ] || boot "$tmp/user-data"

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

# expect_pending: waits until the newest transaction waits for a confirm.
expect_pending() {
  i=0
  until vr history --json >"$tmp/history.json" && jq -e '.[0].state == "pending-confirm"' "$tmp/history.json" >/dev/null; do
    i=$((i + 1)); [ "$i" -le 60 ] || { vr history; die "not pending within 60 s"; }
    sleep 1
  done
  txn=$(jq -r '.[0].id' "$tmp/history.json")
}

expect_newest() {
  vr history --json >"$tmp/history.json"
  jq -e --arg s "$1" '.[0].state == $s' "$tmp/history.json" >/dev/null ||
    { vr history; die "newest transaction is not $1"; }
}

dropin=/etc/sysctl.d/90-vps-ready.conf
apt_conf=/etc/apt/apt.conf.d

# multipart <part>...: MIME multipart user-data of cloud-config parts, which
# cloud-init merges.
multipart() {
  printf 'Content-Type: multipart/mixed; boundary="vps-ready-part"\nMIME-Version: 1.0\n'
  for part; do
    printf '\n--vps-ready-part\nContent-Type: text/cloud-config; charset="us-ascii"\n\n'
    cat "$part"
  done
  printf '\n--vps-ready-part--\n'
}

# wait_first_boot: waits for cloud-init's final message on the serial
# console. Nobody may log in before: `--deadman=off` would refuse.
wait_first_boot() {
  i=0
  until grep -q 'Cloud-init v\. .* finished at' "$tmp/console.log" 2>/dev/null; do
    i=$((i + 5)); [ "$i" -lt 900 ] || die "cloud-init did not finish within 900 s"
    sleep 5
  done
  echo "first boot finished after about $i s"
}

cloud_init_cycle() {
  admin=ops
  as_admin() { ssh -F "$sshcfg" -o BatchMode=yes -o ConnectTimeout=5 -l "$admin" vm "$@"; }
  version=$("$bin" version --json | jq -r .version)
  name=vps-ready-$version-x86_64-unknown-linux-musl
  mkdir -p "$tmp/www" "$tmp/$name"
  cp "$bin" "$tmp/$name/vps-ready"
  tar -C "$tmp" -czf "$tmp/www/$name.tar.gz" "$name"
  (cd "$tmp/www" && sha256sum "$name.tar.gz") >"$tmp/checksums.txt"
  # export needs both architectures; the VM fetches only its own.
  printf '%s  vps-ready-%s-aarch64-unknown-linux-musl.tar.gz\n' \
    "$(echo aarch64 | sha256sum | cut -d' ' -f1)" "$version" >>"$tmp/checksums.txt"
  printf '%s\n' 'schema = 1' 'extends = "minimal"' '[modules."user.admin"]' \
    "name = \"$admin\"" "authorized_keys = [\"$(cat "$tmp/id.pub")\"]" >"$tmp/profile.toml"
  "$bin" export cloud-init --profile "$tmp/profile.toml" --checksums "$tmp/checksums.txt" \
    --base-url "http://10.0.2.2:$http_port" >"$tmp/export.yaml"
  cat "$tmp/export.yaml"
  multipart "$tmp/user-data" "$tmp/export.yaml" >"$tmp/first-boot"
  python3 -m http.server --bind 127.0.0.1 --directory "$tmp/www" "$http_port" >/dev/null 2>&1 &
  www_pid=$!

  echo "== $distro: cloud-init, first boot"
  boot "$tmp/first-boot"
  wait_first_boot
  wait_ssh 120
  # As the seed's user, so a missing tool shows even if nothing was applied.
  vm 'command -v curl || command -v wget' >/dev/null || die "neither curl nor wget is on the image"
  for tool in sha256sum tar; do
    vm command -v "$tool" >/dev/null || die "$tool is not on the image"
  done
  status=$(as_admin cloud-init status --wait || true)
  echo "$status"
  case $status in *"status: done"*) ;; *) as_admin sudo tail -n 40 /var/log/cloud-init-output.log; die "cloud-init did not end done" ;; esac
  as_admin sudo vps-ready history
  as_admin sudo vps-ready history --json >"$tmp/history.json"
  jq -e 'length == 1 and .[0].state == "applied" and .[0].without_timer == true' "$tmp/history.json" >/dev/null ||
    die "history does not show one transaction applied without the timer"
  rc=0; as_admin sudo vps-ready audit --json >"$tmp/audit.json" || rc=$?
  [ "$rc" -le 1 ] || die "audit exited $rc, expected 0 or 1"
  ids='.id | test("^(SSH-00[1-7]|FW-001)$")'
  jq -r ".findings[] | select($ids) | \"\(.id) \(.status)\"" "$tmp/audit.json"
  jq -e "[.findings[] | select(($ids) and .status != \"pass\")] | length == 0" "$tmp/audit.json" >/dev/null ||
    die "an SSH-001..007 or FW-001 control does not pass after first boot"
  as_admin sudo sshd -T | grep -qx 'permitrootlogin no' || die "sshd -T does not show permitrootlogin no"
  # Root gets the admin's key: sshd itself must refuse it.
  as_admin 'sudo install -d -m 700 /root/.ssh && sudo cp ~/.ssh/authorized_keys /root/.ssh/'
  ! ssh -F "$sshcfg" -o BatchMode=yes -o ConnectTimeout=5 -l root vm true 2>/dev/null ||
    die "root logs in after first boot"
  rc=0; as_admin sudo vps-ready plan --json --profile /etc/vps-ready/profile.toml >"$tmp/plan.json" || rc=$?
  [ "$rc" -eq 0 ] || die "plan exited $rc, expected 0"
  jq -e '[.modules[].changes | length] | add == 0' "$tmp/plan.json" >/dev/null ||
    { cat "$tmp/plan.json"; die "the exported profile still plans changes"; }

  echo "== $distro: cloud-init, a tampered tarball"
  printf x >>"$tmp/www/$name.tar.gz"
  boot "$tmp/first-boot"
  wait_first_boot
  wait_ssh 120
  status=$(vm cloud-init status --wait || true)
  echo "$status"
  case $status in *"status: error"*) ;; *) die "cloud-init status is not error" ;; esac
  vm sudo grep -q 'FAILED' /var/log/cloud-init-output.log || die "sha256sum -c did not fail"
  vm test ! -e /usr/local/bin/vps-ready || die "vps-ready was installed"
  vm sudo test ! -e /var/lib/vps-ready || die "vps-ready applied something"
  vm test ! -e /etc/ssh/sshd_config.d/00-vps-ready.conf || die "the sshd drop-in exists"
  ! vm id "$admin" >/dev/null 2>&1 || die "$admin exists"
}

if [ "$cycle" = cloud-init ]; then
  cloud_init_cycle
  echo "OK [$distro]"
  exit 0
fi

# The VM over its public path, whatever `vm` is redefined to.
pvm() {
  ssh -F "$sshcfg" -o BatchMode=yes -o ConnectTimeout=5 \
    -o ServerAliveInterval=5 -o ServerAliveCountMax=3 vm "$@"
}
# no_public_login <when>: a new login on the forwarded public port fails.
# QEMU accepts the TCP connection itself, so `timeout` ends the wait for
# the banner.
no_public_login() {
  ! timeout 20 ssh -F "$sshcfg" -o BatchMode=yes -o ConnectTimeout=5 vm true 2>/dev/null ||
    die "a new public login works $1"
}

private_access_cycle() {
  command -v wg >/dev/null || { echo "wg (wireguard-tools) is required" >&2; exit 2; }
  echo "== $distro: private access, waiting for SSH and cloud-init"
  wait_ssh 300
  pvm sudo cloud-init status --wait >/dev/null 2>&1 || true
  pvm 'cat >/tmp/vps-ready' <"$bin"
  pvm sudo install -m 755 /tmp/vps-ready /usr/local/bin/vps-ready

  # The runner is the peer laptop (host 2). Its key is made here and never
  # leaves the runner; the VM's is made by `wg genkey` in the VM.
  (umask 077 && wg genkey >"$tmp/wg.key")
  runner_pub=$(wg pubkey <"$tmp/wg.key")
  phone_pub=$(wg genkey | wg pubkey)
  peers() { printf 'peers = [%s]\n' "$1"; }
  laptop="{ name = \"laptop\", public_key = \"$runner_pub\", host = 2 }"
  phone="{ name = \"phone\", public_key = \"$phone_pub\", host = 3 }"
  # The QEMU network is 10.0.2.0/24, and some runners use 10.1.0.0/16, so
  # the subnet is fixed here; the derived one is covered by unit tests.
  wg_module() { printf '%s\n' '[modules."net.wireguard"]' 'address = "10.77.0.1/24"'; peers "$1"; }

  echo "== $distro: net.wireguard and firewall.inbound from the public session"
  { echo 'schema = 1'; wg_module "$laptop"; echo '[modules."firewall.inbound"]'; } |
    pvm 'cat >/tmp/wg.toml'
  pvm sudo vps-ready apply --yes --profile /tmp/wg.toml --deadman 2m </dev/null >"$tmp/apply.out" 2>&1 &
  apply_pid=$!
  expect_pending
  # A login in the same second as go-live does not count as new.
  sleep 2
  rc=0; pvm sudo vps-ready confirm || rc=$?
  [ "$rc" -eq 0 ] || die "confirm from a new public login exited $rc, expected 0"
  rc=0; wait "$apply_pid" || rc=$?
  cat "$tmp/apply.out"
  [ "$rc" -eq 0 ] || die "the WireGuard apply exited $rc, expected 0"
  grep -q 'WireGuard client configs' "$tmp/apply.out" || die "apply did not print the client config"
  pvm sudo vps-ready wireguard-config laptop >"$tmp/client.conf" || die "wireguard-config failed"
  cat "$tmp/client.conf"
  vm_pub=$(sed -n 's/^PublicKey = //p' "$tmp/client.conf")
  grep -qx 'Address = 10.77.0.2/32' "$tmp/client.conf" || die "the client config has the wrong Address"
  grep -qx 'AllowedIPs = 10.77.0.1/32' "$tmp/client.conf" || die "the client config has the wrong AllowedIPs"
  [ "$(pvm sudo wg show wg0 public-key)" = "$vm_pub" ] || die "wg0 does not have the key of wg0.key"
  # nft lists a one-port set without braces.
  pvm sudo nft list table inet vps_ready >"$tmp/table.nft"
  grep -Eq 'udp dport (\{ )?51820( \})? accept' "$tmp/table.nft" ||
    { cat "$tmp/table.nft"; die "the firewall does not accept WireGuard's port"; }
  pvm sudo grep -q PrivateKey /etc/wireguard/wg0.conf && die "wg0.conf holds a PrivateKey"
  pvm "sudo sh -c '! grep -rqF -e \"\$(cat /etc/wireguard/wg0.key)\" /var/lib/vps-ready'" ||
    die "the private key is in vps-ready's state directory"
  # The drop-in: a reload fails instead of clearing the key.
  ! pvm sudo systemctl reload wg-quick@wg0 2>/dev/null || die "systemctl reload wg-quick@wg0 worked"
  [ "$(pvm sudo wg show wg0 public-key)" = "$vm_pub" ] || die "the reload attempt changed the key"
  expect_empty_wg() {
    rc=0; pvm sudo vps-ready plan --json --profile "$1" >"$tmp/plan.json" || rc=$?
    [ "$rc" -eq 0 ] || die "plan exited $rc, expected 0"
    jq -e '[.modules[] | .changes // [] | length] | add == 0' "$tmp/plan.json" >/dev/null ||
      { jq . "$tmp/plan.json"; die "plan of $1 has changes after apply"; }
  }
  expect_empty_wg /tmp/wg.toml

  # Precondition of the drop-in, on a separate interface: does `wg
  # syncconf` with a file that has no PrivateKey keep the key PostUp
  # loaded? The result is printed; the drop-in stays either way. The files
  # are in /etc/wireguard: on Ubuntu 26.04, wg-quick run as root gets
  # "Permission denied" reading a config in /tmp.
  echo "== $distro: wg syncconf with a key-less config"
  pvm "sudo sh -c 'umask 077; wg genkey >/etc/wireguard/wgpre.key; printf \"%s\n\" \"[Interface]\" \"Address = 10.78.0.1/24\" \"ListenPort = 51830\" \"PostUp = wg set %i private-key /etc/wireguard/wgpre.key\" >/etc/wireguard/wgpre.conf'"
  pvm sudo wg-quick up /etc/wireguard/wgpre.conf >"$tmp/wgpre.out" 2>&1 ||
    { cat "$tmp/wgpre.out"; die "wg-quick up wgpre failed"; }
  pre=$(pvm sudo wg show wgpre public-key)
  pvm "sudo bash -c 'wg syncconf wgpre <(wg-quick strip /etc/wireguard/wgpre.conf)'" || die "wg syncconf failed"
  post=$(pvm sudo wg show wgpre public-key)
  if [ "$post" = "$pre" ]; then
    echo "syncconf precondition [$distro]: the key is KEPT"
  else
    echo "syncconf precondition [$distro]: the key is CLEARED ($post)"
  fi
  pvm sudo wg-quick down /etc/wireguard/wgpre.conf >/dev/null 2>&1 || true
  pvm sudo rm -f /etc/wireguard/wgpre.conf /etc/wireguard/wgpre.key

  echo "== $distro: the runner's side of the tunnel"
  wg_link=vrwg
  sudo ip link add "$wg_link" type wireguard
  sudo wg set "$wg_link" private-key "$tmp/wg.key" peer "$vm_pub" \
    endpoint "127.0.0.1:$wg_port" allowed-ips 10.77.0.1/32 persistent-keepalive 5
  sudo ip addr add 10.77.0.2/24 dev "$wg_link"
  sudo ip link set "$wg_link" up
  sed -e 's/^Host vm$/Host vmwg/' -e 's/^  HostName .*/  HostName 10.77.0.1/' \
    -e 's/^  Port .*/  Port 22/' "$sshcfg" >"$tmp/ssh_config_wg"
  cat "$tmp/ssh_config_wg" >>"$sshcfg"
  # From here on `vm`, and so `vr` and the helpers, go through wg0.
  vm() {
    ssh -F "$sshcfg" -o BatchMode=yes -o ConnectTimeout=5 \
      -o ServerAliveInterval=5 -o ServerAliveCountMax=3 vmwg "$@"
  }
  wait_ssh 60
  rc=0; vr audit --json >"$tmp/audit.json" || rc=$?
  [ "$rc" -le 1 ] || die "audit exited $rc, expected 0 or 1"
  jq -e '.findings[] | select(.id == "NET-008" and .status == "pass")' "$tmp/audit.json" >/dev/null ||
    die "NET-008 does not pass"
  printf '%s\n' 'schema = 1' '[modules."firewall.inbound"]' 'ssh_via = "wg0"' |
    pvm 'cat >/tmp/via.toml'

  echo "== $distro: ssh_via from the public session is refused"
  rc=0; pvm sudo vps-ready apply --yes --profile /tmp/via.toml >"$tmp/public.out" 2>&1 || rc=$?
  cat "$tmp/public.out"
  [ "$rc" -eq 2 ] || die "apply from the public session exited $rc, expected 2"
  grep -q 'not through wg0: connect through wg0 first' "$tmp/public.out" ||
    die "apply from the public session was not refused as not through wg0"
  grep -q 'ssh -t ci@10.77.0.1 sudo vps-ready apply' "$tmp/public.out" ||
    die "the refusal does not give the command through wg0"
  vr history --json >"$tmp/history.json"
  [ "$(jq length "$tmp/history.json")" -eq 1 ] || die "the refused apply left a transaction"

  echo "== $distro: ssh_via through wg0, not confirmed"
  vm sudo vps-ready apply --yes --profile /tmp/via.toml --deadman 1m </dev/null >"$tmp/apply.out" 2>&1 &
  apply_pid=$!
  expect_pending
  no_public_login "during the window"
  i=0
  until pvm true 2>/dev/null; do
    i=$((i + 5)); [ "$i" -le 90 ] || die "public SSH did not come back after the deadline"
    sleep 5
  done
  echo "public SSH back after about $i s"
  rc=0; wait "$apply_pid" || rc=$?
  [ "$rc" -eq 1 ] || { cat "$tmp/apply.out"; die "the unconfirmed apply exited $rc, expected 1"; }
  expect_newest rolled-back

  echo "== $distro: ssh_via through wg0, confirmed"
  pvm 'test -f ~/.ssh/vr_local || ssh-keygen -q -t ed25519 -N "" -C vr-local -f ~/.ssh/vr_local'
  # shellcheck disable=SC2016 # expanded in the VM
  pvm 'grep -qF "$(cat ~/.ssh/vr_local.pub)" ~/.ssh/authorized_keys || cat ~/.ssh/vr_local.pub >>~/.ssh/authorized_keys'
  self_ip=$(pvm ip -4 -o route get 192.0.2.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')
  [ -n "$self_ip" ] || die "no IPv4 address on the VM's default route"
  # A public session opened before apply: established, so it stays up.
  pvm 'sleep 45; echo still here' >"$tmp/old-public.out" 2>&1 &
  old_pid=$!
  vm sudo vps-ready apply --yes --profile /tmp/via.toml --deadman 2m </dev/null >"$tmp/apply.out" 2>&1 &
  apply_pid=$!
  expect_pending
  sleep 2
  no_public_login "after ssh_via"
  # New logins from the VM to its own addresses, wg0's too, arrive on lo,
  # which the firewall accepts; confirm refuses them all the same.
  for to in "$self_ip" 10.77.0.1; do
    rc=0; vm "ssh -i ~/.ssh/vr_local -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR ci@$to sudo vps-ready confirm" >"$tmp/local.out" 2>&1 || rc=$?
    cat "$tmp/local.out"
    [ "$rc" -eq 2 ] || die "confirm from a login to $to exited $rc, expected 2"
    grep -q "comes from $to, on this server itself" "$tmp/local.out" ||
      die "the login from the VM to $to was not refused as local"
  done
  rc=0; vm sudo vps-ready confirm || rc=$?
  [ "$rc" -eq 0 ] || die "confirm through wg0 exited $rc, expected 0"
  rc=0; wait "$apply_pid" || rc=$?
  [ "$rc" -eq 0 ] || { cat "$tmp/apply.out"; die "the confirmed apply exited $rc, expected 0"; }
  wait "$old_pid" || true
  grep -q 'still here' "$tmp/old-public.out" || die "the public session opened before apply did not stay up"
  rc=0; vr audit --json >"$tmp/audit.json" || rc=$?
  [ "$rc" -le 1 ] || die "audit exited $rc, expected 0 or 1"
  ids='.id == "SSH-009" or .id == "FW-003" or .id == "NET-008"'
  jq -r ".findings[] | select($ids) | \"\(.id) \(.status) \(.note // \"\")\"" "$tmp/audit.json"
  jq -e "[.findings[] | select(($ids) and .status == \"pass\")] | length == 3" "$tmp/audit.json" >/dev/null ||
    die "SSH-009, FW-003 or NET-008 does not pass under ssh_via"

  echo "== $distro: under ssh_via, a second peer through wg0"
  { echo 'schema = 1'; wg_module "$laptop, $phone"; printf '%s\n' '[modules."firewall.inbound"]' 'ssh_via = "wg0"'; } |
    vm 'cat >/tmp/wg2.toml'
  rc=0; vr plan --json --profile /tmp/wg2.toml >"$tmp/plan.json" || rc=$?
  [ "$rc" -eq 0 ] || die "plan of the second peer exited $rc, expected 0"
  jq -e '[.modules[] | select((.changes // []) | length > 0) | .id] == ["net.wireguard"]' \
    "$tmp/plan.json" >/dev/null || { jq . "$tmp/plan.json"; die "the peer change plans more than net.wireguard"; }

  # Not confirmed: the dead-man takes the peer off the running wg0 again.
  vm sudo vps-ready apply --yes --profile /tmp/wg2.toml --deadman 1m </dev/null >"$tmp/apply.out" 2>&1 &
  apply_pid=$!
  expect_pending
  vm sudo wg show wg0 peers | grep -qx "$phone_pub" || die "the second peer is not on wg0"
  rc=0; wait "$apply_pid" || rc=$?
  [ "$rc" -eq 1 ] || { cat "$tmp/apply.out"; die "the unconfirmed peer apply exited $rc, expected 1"; }
  expect_newest rolled-back
  ! vm sudo wg show wg0 peers | grep -qx "$phone_pub" || die "the dead-man left the second peer on wg0"
  [ "$(vm sudo wg show wg0 public-key)" = "$vm_pub" ] || die "the dead-man rollback changed wg0's key"

  # Confirmed: a session through wg0 opened before the apply stays up and
  # keeps carrying data (a line a second).
  vm 'while sleep 1; do echo tick; done' >"$tmp/ticks" 2>&1 &
  old_pid=$!
  vm sudo vps-ready apply --yes --profile /tmp/wg2.toml --deadman 2m </dev/null >"$tmp/apply.out" 2>&1 &
  apply_pid=$!
  expect_pending
  vm sudo wg show wg0 peers | grep -qx "$phone_pub" || die "the second peer is not on wg0"
  [ "$(vm sudo wg show wg0 public-key)" = "$vm_pub" ] || die "adding a peer changed wg0's key"
  sleep 2
  rc=0; vm sudo vps-ready confirm || rc=$?
  [ "$rc" -eq 0 ] || die "confirm through wg0 exited $rc, expected 0"
  rc=0; wait "$apply_pid" || rc=$?
  [ "$rc" -eq 0 ] || { cat "$tmp/apply.out"; die "the peer apply exited $rc, expected 0"; }
  kill -0 "$old_pid" 2>/dev/null || die "the wg0 session did not survive the peer change"
  before=$(wc -l <"$tmp/ticks")
  sleep 25
  after=$(wc -l <"$tmp/ticks")
  [ "$after" -gt "$before" ] || die "the wg0 session stopped carrying data after the peer change"
  kill "$old_pid" 2>/dev/null || true
  # Moving this session's own peer is refused.
  laptop4="{ name = \"laptop\", public_key = \"$runner_pub\", host = 4 }"
  { echo 'schema = 1'; wg_module "$laptop4, $phone"; printf '%s\n' '[modules."firewall.inbound"]' 'ssh_via = "wg0"'; } |
    vm 'cat >/tmp/wg3.toml'
  rc=0; vr apply --yes --profile /tmp/wg3.toml >"$tmp/own.out" 2>&1 || rc=$?
  cat "$tmp/own.out"
  [ "$rc" -eq 2 ] || die "changing this session's own peer exited $rc, expected 2"
  grep -q 'this session comes through wg0 from 10.77.0.2' "$tmp/own.out" ||
    die "changing this session's own peer was not refused"

  echo "== $distro: ssh_via across a reboot"
  vm sudo systemd-analyze verify /etc/systemd/system/vps-ready-firewall.service \
    wg-quick@wg0.service >"$tmp/verify.txt" 2>&1 || true
  cat "$tmp/verify.txt"
  ! grep -qi 'cycle' "$tmp/verify.txt" || die "systemd-analyze verify reports an ordering cycle"
  reboot_vm
  no_public_login "after the reboot"
  [ "$(vm systemctl is-active wg-quick@wg0)" = active ] || die "wg-quick@wg0 is not active after the reboot"
  [ "$(vm sudo wg show wg0 public-key)" = "$vm_pub" ] || die "wg0 came back with another key"
  expect_newest confirmed

  echo "== $distro: rollback --last until the start"
  # The peer change, then ssh_via, through wg0; public SSH then reopens.
  for _ in 1 2; do
    rc=0; vr rollback --last || rc=$?
    [ "$rc" -eq 0 ] || die "rollback through wg0 exited $rc, expected 0"
  done
  pvm true || die "no public login after rolling back ssh_via"
  # Stopping wg0 from a session through it is refused.
  rc=0; vr rollback --last >"$tmp/cut.out" 2>&1 || rc=$?
  cat "$tmp/cut.out"
  [ "$rc" -eq 2 ] || die "a rollback that stops wg0 from wg0 exited $rc, expected 2"
  grep -q 'stops wg-quick@wg0' "$tmp/cut.out" || die "the rollback that stops wg0 was not refused"
  rc=0; pvm sudo vps-ready rollback --last || rc=$?
  [ "$rc" -eq 0 ] || die "the last rollback exited $rc, expected 0"
  ! pvm ip link show wg0 >/dev/null 2>&1 || die "wg0 is still there after the rollback"
  pvm sudo test -f /etc/wireguard/wg0.key || die "the rollback removed the key"
  pvm sudo test ! -e /etc/wireguard/wg0.conf || die "wg0.conf is left after the rollback"
  { echo 'schema = 1'; wg_module "$laptop"; } | pvm 'cat >/tmp/wgonly.toml'
  rc=0; pvm sudo vps-ready apply --yes --profile /tmp/wgonly.toml || rc=$?
  [ "$rc" -eq 0 ] || die "applying net.wireguard again exited $rc, expected 0"
  [ "$(pvm sudo wg show wg0 public-key)" = "$vm_pub" ] || die "the new apply did not reuse the key"
  # The runner's side gave up its handshakes while wg0 was gone; new
  # traffic starts one again.
  wait_ssh 60
}

tunnel_cycle() {
  echo "== $distro: tunnel, waiting for SSH and cloud-init"
  wait_ssh 300
  vm sudo cloud-init status --wait >/dev/null 2>&1 || true
  vm 'cat >/tmp/vps-ready' <"$bin"
  vm sudo install -m 755 /tmp/vps-ready /usr/local/bin/vps-ready

  # Not a token: cloudflared rejects it before it connects anywhere. Sent on
  # stdin, so that no command line (which sudo logs) carries it.
  marker=vps-ready-placeholder-not-a-tunnel-token
  printf '%s' "$marker" | vm "sudo sh -c 'umask 077 && cat >/root/cloudflared-token'"
  sum=$(vm sudo sha256sum /root/cloudflared-token | cut -d' ' -f1)

  echo "== $distro: LoadCredential= reaches a DynamicUser process"
  # The connector unit's sandbox without the address filter; only a hash
  # of the credential is printed.
  vm 'sudo tee /usr/local/sbin/vr-cred-hash >/dev/null' <<'EOF'
sha256sum <"$CREDENTIALS_DIRECTORY/token"
EOF
  got=$(vm sudo systemd-run --quiet --wait --pipe -p DynamicUser=yes \
    -p LoadCredential=token:/root/cloudflared-token -p NoNewPrivileges=yes \
    -p ProtectSystem=strict -p ProtectHome=yes -p PrivateTmp=yes -p CapabilityBoundingSet= \
    /bin/sh /usr/local/sbin/vr-cred-hash | cut -d' ' -f1)
  vm sudo rm -f /usr/local/sbin/vr-cred-hash
  [ "$got" = "$sum" ] || die "a DynamicUser process reads another credential (got '${got}')"

  printf '%s\n' 'schema = 1' '[modules."net.tunnel"]' 'token_file = "/root/cloudflared-token"' |
    vm 'cat >/tmp/tunnel.toml'
  vr plan --json --profile /tmp/tunnel.toml >"$tmp/tunnel-plan.json"
  jq -e '.modules[] | select(.id == "net.tunnel") | .changes[] |
    select(.id == "service:vps-ready-cloudflared.service")' "$tmp/tunnel-plan.json" >/dev/null ||
    die "the plan does not start the connector"

  echo "== $distro: apply with the placeholder token"
  rc=0; vr apply --yes --profile /tmp/tunnel.toml >"$tmp/tunnel-apply.out" 2>&1 || rc=$?
  cat "$tmp/tunnel-apply.out"
  [ "$rc" -ne 0 ] || die "apply with a placeholder token succeeded"
  grep -q 'vps-ready-cloudflared.service' "$tmp/tunnel-apply.out" ||
    die "apply does not name the connector"
  expect_newest rolled-back
  vm sudo journalctl -b -u vps-ready-cloudflared.service --no-pager -o cat >"$tmp/connector.log"
  cat "$tmp/connector.log"
  grep -q 'Tunnel token is not valid' "$tmp/connector.log" ||
    die "cloudflared did not read the token and reject it"
  ! grep -Eiq 'failed to read token file|no such file|permission denied' "$tmp/connector.log" ||
    die "cloudflared could not read the credential"
  ! grep -Eiq 'ERR.*(config|yaml)' "$tmp/connector.log" || die "cloudflared logged a config error"
  ! grep -q 'BPF/cgroup firewalling' "$tmp/connector.log" || die "the address filter is not in effect"

  echo "== $distro: the rollback removed the connector"
  for f in /etc/systemd/system/vps-ready-cloudflared.service \
           /etc/systemd/system/vps-ready-cloudflared-restart.service \
           /etc/systemd/system/vps-ready-cloudflared-restart.path \
           /etc/vps-ready/cloudflared.yml /etc/vps-ready/cloudflared-restart.sh \
           /etc/apt/sources.list.d/cloudflared.sources /etc/apt/keyrings/cloudflared.asc \
           /etc/apt/apt.conf.d/52vps-ready-cloudflared; do
    vm test ! -e "$f" || die "$f is left after the rollback"
  done
  # Restart=on-failure may have queued another start; the rollback stops it
  # and clears the failure.
  for u in vps-ready-cloudflared.service vps-ready-cloudflared-restart.path; do
    state=$(vm systemctl show --property=ActiveState --value "$u")
    [ "$state" = inactive ] || die "$u is $state after the rollback, not inactive"
    [ "$(vm systemctl is-enabled "$u" 2>/dev/null || true)" != enabled ] || die "$u is still enabled"
  done
  ! vm systemctl --failed --plain --no-legend | grep -q vps-ready-cloudflared ||
    die "the connector is left in systemctl --failed"
  vm sudo test -f /root/cloudflared-token || die "the rollback removed the token file"
  # Quoted for the VM's shell, which gets the command as one string.
  vm "dpkg-query -W -f '\${Status}\n' cloudflared" | grep -q 'install ok installed' ||
    die "cloudflared should stay installed"

  echo "== $distro: the token is nowhere else"
  ! grep -q "$marker" "$tmp/tunnel-plan.json" "$tmp/tunnel-apply.out" ||
    die "the token is in the plan or the output"
  ! vm sudo journalctl -b --no-pager -o cat | grep -q "$marker" || die "the token is in the journal"
  ! vm sudo grep -rqs "$marker" /var/lib/vps-ready || die "the token is in vps-ready's journal"
  ! vm sudo grep -rqs --exclude=cloudflared-token "$marker" /etc /root ||
    die "the token is in a file other than its own"
}

if [ "$cycle" = tunnel ]; then
  tunnel_cycle
  echo "OK [$distro]"
  exit 0
fi

if [ "$cycle" = private-access ]; then
  private_access_cycle
  echo "OK [$distro]"
  exit 0
fi

echo "== $distro: waiting for SSH and cloud-init"
wait_ssh 300
# "degraded" or a cloud-init error should not stop the cycle; it only waits.
vm sudo cloud-init status --wait >/dev/null 2>&1 || true
vm cat /etc/os-release | grep PRETTY_NAME
vm uname -r
vm systemctl --version | head -n 1
vm ssh -V

if [ "$cycle" = fixtures ]; then
  test/capture-host-fixtures.sh "$distro" "$sshcfg"
  echo "OK [$distro]"
  exit 0
fi

vm 'cat >/tmp/vps-ready' <"$bin"
vm sudo install -m 755 /tmp/vps-ready /usr/local/bin/vps-ready

# What vps-ready relies on from sudo (sudo-rs on Ubuntu 26.04): the session
# found through sudo's process tree, SUDO_USER, `visudo -cf` on a drop-in,
# and `sudo -n -l -U` exiting 0 for a user with or without rules.
echo "== $distro: sudo"
vm sudo -V | head -n 1
vr detect --json >"$tmp/detect.json"
jq -e '.session.user == "ci"' "$tmp/detect.json" >/dev/null ||
  { jq .session "$tmp/detect.json"; die "detect under sudo does not find ci's session"; }
[ "$(vm sudo printenv SUDO_USER)" = ci ] || die "sudo does not set SUDO_USER"
vm "echo 'ci ALL=(ALL:ALL) NOPASSWD: ALL' >/tmp/vr-sudoers-ok"
vm "echo 'ci ALL=(ALL:ALL NOPASSWD: ALL' >/tmp/vr-sudoers-bad"
vm sudo visudo -cf /tmp/vr-sudoers-ok >/dev/null || die "visudo -cf rejects a valid drop-in"
! vm sudo visudo -cf /tmp/vr-sudoers-bad >/dev/null 2>&1 || die "visudo -cf accepts a broken drop-in"
vm rm -f /tmp/vr-sudoers-ok /tmp/vr-sudoers-bad
# sudo_l <user>: `sudo -n -l -U <user>` as vps-ready runs it, into sudo-l.out.
sudo_l() {
  rc=0; vm sudo env LC_ALL=C sudo -n -l -U "$1" >"$tmp/sudo-l.out" 2>&1 || rc=$?
  [ "$rc" -eq 0 ] || { cat "$tmp/sudo-l.out"; die "sudo -n -l -U $1 exited $rc, expected 0"; }
}
has_rules() { grep -q ' may run the following commands on ' "$tmp/sudo-l.out"; }
sudo_l ci
has_rules || { cat "$tmp/sudo-l.out"; die "sudo -l -U ci lists no rules"; }
vm sudo useradd -m -s /bin/bash vr-sudo
sudo_l vr-sudo
cat "$tmp/sudo-l.out"
! has_rules || { cat "$tmp/sudo-l.out"; die "a user without rules has rules"; }
# The sudo group: user.admin's `sudo = "password"`.
vm sudo usermod -aG sudo vr-sudo
sudo_l vr-sudo
has_rules || { cat "$tmp/sudo-l.out"; die "sudo -l -U lists no rules for a member of sudo"; }
! vm sudo -u vr-sudo sudo -n true 2>/dev/null || die "sudo without a password for a member of sudo"
vm sudo userdel -r vr-sudo 2>/dev/null
# `--deadman=off` on a change that arms the timer sees this login.
rc=0; vr apply --yes --module ssh.server --deadman=off >"$tmp/off.out" 2>&1 || rc=$?
cat "$tmp/off.out"
[ "$rc" -eq 2 ] || die "apply --deadman=off from a login exited $rc, expected 2"
grep -q 'someone is logged in (.*ci@' "$tmp/off.out" || die "apply --deadman=off did not name this login"

echo "== $distro: vps-ready audit"
rc=0; vr audit || rc=$?
[ "$rc" -le 1 ] || die "audit exited $rc, expected 0 or 1"
vr audit --json >"$tmp/audit.json" || true
jq -e '[.findings[] | select((.id | test("^(KRN|NET)-")) and .id != "NET-008")
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

# Waits for the timer: the window plus 30 s.
wait_deadman() {
  i=0
  until vr history --json >"$tmp/history.json" && jq -e '.[0].state == "rolled-back"' "$tmp/history.json" >/dev/null; do
    # AccuracySec=1s, but a loaded VM fires the timer late.
    i=$((i + 5)); [ "$i" -le 90 ] || { vr history; die "not rolled back within 90 s"; }
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
# confirm refuses a client on loopback, so the confirming logins go to the
# VM's own address on its default route instead.
self_ip=$(vm ip -4 -o route get 192.0.2.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')
[ -n "$self_ip" ] || die "no IPv4 address on the VM's default route"

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

rc=0; local_ssh -o ControlPath=none "$user@127.0.0.1" sudo vps-ready confirm >"$tmp/lo.out" 2>&1 || rc=$?
cat "$tmp/lo.out"
[ "$rc" -eq 2 ] || die "confirm from a login to 127.0.0.1 exited $rc, expected 2"
grep -q 'comes from 127.0.0.1' "$tmp/lo.out" || die "the login to 127.0.0.1 was not refused as local"

rc=0; local_ssh -o ControlPath=none "$user@$self_ip" sudo vps-ready confirm || rc=$?
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

# ipopts_connect: whether a TCP connection to sshd on 127.0.0.1 whose SYN
# carries IPv4 options (four NOPs) gets through, within 3 s.
ipopts_connect() {
  vm python3 - <<'PY'
import socket
c = socket.socket()
c.settimeout(3)
c.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, b"\x01\x01\x01\x01")
c.connect(("127.0.0.1", 22))
PY
}
ipopts_connect || die "a SYN with IP options does not connect before apply"

echo "== $distro: profile minimal, confirmed by the new admin"
root_login || die "root cannot log in before apply"
vm test ! -e "$ssh_dropin" || die "$ssh_dropin exists before apply"
printf 'schema = 1\nextends = "minimal"\n[modules."user.admin"]\nname = "%s"\n' "$admin" | vm 'cat >/tmp/vr-minimal.toml'
apply_session --profile /tmp/vr-minimal.toml --deadman 2m
vm cat "$ssh_dropin"
! root_login || die "root still logs in over a new login during the window"
password_methods
! password_methods | grep -q password || die "sshd still offers password logins"
# A login in the second the changes went live counts as old.
sleep 2
rc=0; local_ssh -o ControlPath=none "$admin@$self_ip" sudo vps-ready confirm || rc=$?
[ "$rc" -eq 0 ] || die "confirm as $admin exited $rc, expected 0"
expect_newest confirmed
expect_rc /tmp/vr-apply.rc 0
rc=0; vr audit --json >"$tmp/audit.json" || rc=$?
[ "$rc" -le 1 ] || die "audit exited $rc, expected 0 or 1"
fixed='.fix == "ssh.server" or .fix == "firewall.inbound"'
jq -r ".findings[] | select($fixed) | \"\(.id) \(.status)\"" "$tmp/audit.json"
jq -e "[.findings[] | select(($fixed) and .status != \"pass\")] | length == 0" \
  "$tmp/audit.json" >/dev/null || die "an ssh.server or firewall.inbound control does not pass after the confirm"
jq -r '.findings[] | select(.id == "FW-003") | "FW-003 \(.status): \(.note)"' "$tmp/audit.json"
jq -e '.findings[] | select(.id == "FW-003" and .status == "pass")' "$tmp/audit.json" >/dev/null ||
  die "FW-003 does not pass after the confirm"
expect_empty_plan ssh.server
vm sudo nft list chain inet vps_ready prerouting | grep -q 'ip hdrlength > 5 .*drop' ||
  die "the prerouting chain does not drop IPv4 TCP with IP options"
! ipopts_connect 2>/dev/null || die "a SYN with IP options connects after apply"
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
ipopts_connect || die "a SYN with IP options does not connect after rollback"
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

# expect drives the wizard and curl the deploy cycle; the VM gets them, the
# runner does not need them.
vm "sudo apt-get -qq -o DPkg::Lock::Timeout=120 $apt_retry update && sudo DEBIAN_FRONTEND=noninteractive apt-get -qq -o DPkg::Lock::Timeout=120 $apt_retry install expect curl >/dev/null" ||
  die "cannot install expect and curl"
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
  rc=0; local_ssh -o ControlPath=none "$1@$self_ip" sudo vps-ready confirm || rc=$?
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

echo "== $distro: deploy profile, confirmed by the new admin"
deploy_cmd=/usr/local/bin/deploy-app
# Runs as deploy and re-runs itself as root with sudo, which the drop-in
# allows only without arguments.
vm "sudo tee $deploy_cmd >/dev/null" <<'SH'
#!/bin/sh
[ "$(id -u)" -eq 0 ] || exec sudo /usr/local/bin/deploy-app
echo "deployed as $(id -un)"
SH
vm sudo chmod 755 "$deploy_cmd"
vm 'test -f ~/.ssh/vr_deploy || ssh-keygen -q -t ed25519 -N "" -C ci@example.com -f ~/.ssh/vr_deploy'
dkey=$(vm cat .ssh/vr_deploy.pub)
printf '%s\n' 'schema = 1' 'extends = "web"' \
  '[modules."user.admin"]' "name = \"$admin\"" \
  '[modules."deploy.proxy"]' 'sites = [{ domain = "app.localhost", upstream = "127.0.0.1:8080" }]' \
  '[modules."deploy.user"]' "keys = [\"$dkey\"]" "command = \"$deploy_cmd\"" |
  vm 'cat >/tmp/vr-deploy.toml'
deploy_files="/etc/apt/sources.list.d/docker.sources /etc/apt/keyrings/docker.asc /etc/docker/daemon.json
  /etc/apt/sources.list.d/caddy.sources /etc/apt/keyrings/caddy.asc /etc/caddy/Caddyfile
  /etc/sudoers.d/90-vps-ready-deploy"
for f in $deploy_files; do vm test ! -e "$f" || die "$f exists before apply"; done
# As apply_session, with a longer wait: apply installs Docker, Caddy and fail2ban.
vm "rm -f /tmp/vr-apply.rc; setsid -f sh -c 'sh /tmp/vr-ssh -o ControlPath=none $user@127.0.0.1 sudo vps-ready apply --yes --profile /tmp/vr-deploy.toml --deadman 5m >/tmp/vr-apply.out 2>&1; echo \$? >/tmp/vr-apply.rc' </dev/null >/dev/null 2>&1"
i=0
until vr history --json >"$tmp/history.json" && jq -e '.[0].state == "pending-confirm"' "$tmp/history.json" >/dev/null; do
  vm test ! -e /tmp/vr-apply.rc || { vm cat /tmp/vr-apply.out; die "apply ended before its changes were pending"; }
  i=$((i + 5)); [ "$i" -le 600 ] || { vm cat /tmp/vr-apply.out; die "not pending within 600 s"; }
  sleep 5
done
# A login in the second the changes went live counts as old.
sleep 2
rc=0; local_ssh -o ControlPath=none "$admin@$self_ip" sudo vps-ready confirm || rc=$?
[ "$rc" -eq 0 ] || die "confirm as $admin exited $rc, expected 0"
expect_newest confirmed
expect_rc /tmp/vr-apply.rc 0

# The app image holds only Caddy's own binary, which is static, so no
# registry is involved (ECR's mirror refused CI's runners with "Data limit
# exceeded").
# shellcheck disable=SC2016 # expanded in the VM
vm 'd=$(mktemp -d) && install -d -m 1777 "$d/tmp" && cp /usr/bin/caddy "$d/" &&
  sudo tar -C "$d" -c . | sudo docker import -c "ENV HOME=/tmp" - vr-app >/dev/null && rm -rf "$d"' ||
  die "cannot build the app image"
vm sudo docker run -d --name app -p 8080:80 vr-app \
  /caddy respond --listen :80 "'hello from the container'" >/dev/null || die "docker run failed"
ports=$(vm sudo docker port app 80/tcp)
[ "$ports" = "127.0.0.1:8080" ] || die "the port is published on $ports, expected 127.0.0.1:8080 only"
body=$(vm curl -fsS -k --retry 10 --retry-delay 1 --retry-all-errors \
  --resolve app.localhost:443:127.0.0.1 https://app.localhost/) || die "HTTPS through Caddy failed"
echo "$body"
[ "$body" = "hello from the container" ] || die "unexpected answer through Caddy: $body"
if vm curl -sS --max-time 3 "http://$self_ip:8080/" >/dev/null 2>&1; then
  die "the container answers on $self_ip:8080"
fi
echo "$self_ip:8080: no answer"

# deploy_login <command>: a new login with the deploy key, asking for <command>.
deploy_login() {
  vm ssh -i .ssh/vr_deploy -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ControlPath=none deploy@127.0.0.1 "$1"
}
for cmd in id 'cat /etc/shadow'; do
  out=$(deploy_login "$cmd") || die "the deploy login asking for $cmd failed"
  [ "$out" = "deployed as root" ] || die "the deploy key asking for $cmd ran something else: $out"
done
if vm sudo -u deploy sudo -n "$deploy_cmd" x >/dev/null 2>&1; then
  die "deploy may run its command as root with an argument"
fi

vm sudo docker rm -f app >/dev/null
vm sudo docker rmi vr-app >/dev/null
# `userdel` fails while an account has processes, e.g. its systemd --user.
i=0
while vm pgrep -u "$admin,deploy" >/dev/null; do
  i=$((i + 1)); [ "$i" -le 30 ] || die "$admin or deploy still has processes after 30 s"
  sleep 1
done
rc=0; vr rollback --last || rc=$?
[ "$rc" -eq 0 ] || die "rollback of the deploy profile exited $rc, expected 0"
expect_newest rolled-back
for f in $deploy_files; do vm test ! -e "$f" || die "$f is left after rollback"; done
! vm id deploy >/dev/null 2>&1 || die "deploy still exists after rollback"
! vm id "$admin" >/dev/null 2>&1 || die "$admin still exists after rollback"
state=$(vm systemctl is-enabled caddy.service || true)
[ "$state" = disabled ] || die "Caddy is $state after rollback, expected disabled"
local_ssh -o ControlPath=none "$user@$self_ip" true || die "$user cannot log in after the rollback"
vm sudo rm -f "$deploy_cmd" /tmp/vr-deploy.toml

echo "== $distro: vps-ready history"
vr history
echo "OK [$distro]"
