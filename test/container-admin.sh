#!/bin/sh
# Apply, confirm and roll back user.admin with the real binary in a systemd
# test container.
#
# Usage: test/container-admin.sh <distro> [binary]      e.g. debian-13
#   Same binary and image requirements as test/container-audit.sh. Needs docker
#   and jq; no network access.
#
# Root gets two keys, one restricted with `command=` as on Ubuntu and AWS
# images; a user `other` has the same key and sudo. Cycle 1: apply --module
# user.admin waits for a confirm -> the admin exists with only the plain key,
# the sudoers drop-in is 0440 and valid, and the printed ssh line names the
# admin -> confirm over a new SSH login as `other` is refused (not the admin)
# -> `sudo vps-ready confirm` over a new login as the admin succeeds and apply
# exits 0 -> rollback --last removes the account, its keys and the drop-in,
# and keeps its home directory. Cycle 2: apply --deadman 1m, no confirm -> the
# timer rolls it back (deadman-timeout) and apply exits 1.
# The container is capped at 1 GB and 1 CPU and is removed afterwards.
set -eu
cd "$(dirname "$0")/.."

distro=${1:?usage: $0 <distro> [binary]}
bin=${2:-${VPS_READY_BIN:-target/release/vps-ready}}
image="vps-ready-test:$distro"
name="vps-ready-admin-$distro-$$"
tmp=$(mktemp -d)
sudoers=/etc/sudoers.d/90-vps-ready-admin

[ -f "$bin" ] || { echo "binary not found: $bin" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT
# POSIX sh keeps running after a trapped signal; exit so Ctrl-C stops the run.
trap 'exit 130' INT TERM

docker run -d --name "$name" --privileged --cgroupns=private \
  --memory 1g --cpus 1 --tmpfs /run --tmpfs /run/lock "$image" >/dev/null

# Wait for systemd to finish booting ("degraded" is normal in a container).
i=0
until state=$(docker exec "$name" systemctl is-system-running 2>/dev/null); \
      [ "$state" = running ] || [ "$state" = degraded ]; do
  i=$((i + 1)); [ "$i" -lt 60 ] || { echo "boot timeout ($state)" >&2; exit 1; }
  sleep 1
done

docker cp "$bin" "$name:/usr/local/bin/vps-ready"
# The dead-man switch refuses a binary root does not own.
docker exec "$name" chown root:root /usr/local/bin/vps-ready
docker exec "$name" chmod 755 /usr/local/bin/vps-ready

vr() { docker exec "$name" vps-ready "$@"; }
die() { echo "FAIL [$distro]: $*" >&2; exit 1; }
newest() { vr history --json | jq -r "$1"; }
# A new SSH login to the container's own sshd as user $1, running the rest.
login() {
  user=$1; shift
  docker exec "$name" ssh -i /root/test_key -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=QUIET -o ControlPath=none "$user@127.0.0.1" "$@"
}
# Starts apply in the background; its output and exit code land in
# /tmp/apply.out and /tmp/apply.rc. Waits until it is pending-confirm.
apply_bg() {
  docker exec "$name" rm -f /tmp/apply.out /tmp/apply.rc
  docker exec -d "$name" sh -c \
    "vps-ready apply --yes --module user.admin $* >/tmp/apply.out 2>&1; echo \$? >/tmp/apply.rc"
  i=0
  until [ "$(newest '.[0].state // empty' 2>/dev/null)" = pending-confirm ]; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || { docker exec "$name" cat /tmp/apply.out; die "apply did not get to pending-confirm"; }
    sleep 1
  done
}
# Waits for the background apply to exit and checks its code.
apply_rc() {
  i=0
  until docker exec "$name" test -s /tmp/apply.rc; do
    i=$((i + 1)); [ "$i" -lt 120 ] || die "apply did not exit"
    sleep 1
  done
  rc=$(docker exec "$name" cat /tmp/apply.rc)
  [ "$rc" -eq "$1" ] || { docker exec "$name" cat /tmp/apply.out; die "apply exited $rc, expected $1"; }
}

# Root's keys: the restricted one first, as cloud images have it. `other`
# logs in with the same key and has sudo, but is not the planned admin.
docker exec "$name" sh -c '
  set -e
  mkdir -p -m 700 /root/.ssh
  ssh-keygen -q -t ed25519 -N "" -C admin-test -f /root/test_key
  ssh-keygen -q -t ed25519 -N "" -C cloud -f /root/cloud_key
  { printf "no-port-forwarding,command=\"echo Please login as the user debian\" "
    cat /root/cloud_key.pub; cat /root/test_key.pub; } >/root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
  useradd --create-home --shell /bin/bash other
  install -d -m 700 -o other -g other /home/other/.ssh
  install -m 600 -o other -g other /root/test_key.pub /home/other/.ssh/authorized_keys
  echo "other ALL=(ALL:ALL) NOPASSWD: ALL" >/etc/sudoers.d/other
  chmod 440 /etc/sudoers.d/other
  systemctl start ssh.socket 2>/dev/null || systemctl start ssh.service'
key=$(docker exec "$name" cat /root/test_key.pub)

echo "== $distro: before"
docker exec "$name" sh -c '! getent passwd admin >/dev/null' || die "admin exists before apply"
docker exec "$name" sh -c "test ! -e $sudoers" || die "$sudoers exists before apply"

echo "== $distro: vps-ready apply --yes --module user.admin, in the background"
apply_bg
docker exec "$name" cat /tmp/apply.out
docker exec "$name" grep -q 'admin@' /tmp/apply.out || die "the printed ssh line does not name admin"
txn=$(newest '.[0].id')
docker exec "$name" tail -n 1 "/var/lib/vps-ready/txn/$txn/journal.jsonl" |
  jq -e '.state == "pending-confirm" and .admins == ["admin"]' >/dev/null ||
  die "the pending-confirm record does not name admin as the admin"
docker exec "$name" getent passwd admin
[ "$(docker exec "$name" cat /home/admin/.ssh/authorized_keys)" = "$key" ] ||
  die "authorized_keys is not exactly root's plain key"
[ "$(docker exec "$name" stat -c '%a %U:%G' "$sudoers")" = "440 root:root" ] ||
  die "$sudoers is not 0440 root:root"
docker exec "$name" visudo -c >/dev/null || die "visudo -c fails"

echo "== $distro: vps-ready plan --json --module user.admin"
rc=0; vr plan --json --module user.admin >"$tmp/plan.json" || rc=$?
[ "$rc" -eq 0 ] || die "plan exited $rc, expected 0"
jq -e '[.modules[].changes | length] | add == 0' "$tmp/plan.json" >/dev/null ||
  { cat "$tmp/plan.json"; die "plan still has changes after apply"; }

echo "== $distro: confirm from a new login as other is refused"
rc=0; login other sudo vps-ready confirm >"$tmp/other.out" 2>&1 || rc=$?
cat "$tmp/other.out"
[ "$rc" -eq 2 ] || die "confirm as other exited $rc, expected 2"
grep -q "the changes give SSH keys to admin" "$tmp/other.out" || die "the refusal does not name the admin"
[ "$(newest '.[0].state')" = pending-confirm ] || die "the refusal changed the transaction"

echo "== $distro: ssh admin@127.0.0.1 sudo vps-ready confirm"
rc=0; login admin sudo vps-ready confirm || rc=$?
[ "$rc" -eq 0 ] || die "confirm as admin exited $rc, expected 0"
apply_rc 0
[ "$(newest '.[0].state')" = confirmed ] || die "newest transaction is not confirmed"
docker exec "$name" sh -c 'systemctl is-enabled vps-ready-deadman.service' 2>/dev/null |
  grep -qx disabled || die "the boot hook is still enabled after confirm"

echo "== $distro: vps-ready rollback --last"
rc=0; vr rollback --last || rc=$?
[ "$rc" -eq 0 ] || die "rollback exited $rc, expected 0"
[ "$(newest '.[0].state + " " + .[0].reason')" = "rolled-back manual" ] ||
  die "newest transaction is not rolled back (manual)"
docker exec "$name" sh -c '! getent passwd admin >/dev/null' || die "admin is still there"
docker exec "$name" sh -c "test ! -e $sudoers" || die "$sudoers is still there"
docker exec "$name" test -d /home/admin || die "the home directory should stay"
docker exec "$name" test ! -e /home/admin/.ssh || die "/home/admin/.ssh is still there"
# userdel leaves the home directory, so the next useradd warns but works.
docker exec "$name" rm -rf /home/admin

echo "== $distro: vps-ready apply --yes --module user.admin --deadman 1m, no confirm"
apply_bg --deadman 1m
docker exec "$name" getent passwd admin >/dev/null || die "admin was not created"
apply_rc 1
[ "$(newest '.[0].state + " " + .[0].reason')" = "rolled-back deadman-timeout" ] ||
  { vr history; die "the timer did not roll back"; }
docker exec "$name" sh -c '! getent passwd admin >/dev/null' || die "admin is still there"
docker exec "$name" sh -c "test ! -e $sudoers" || die "$sudoers is still there"
docker exec "$name" sh -c 'systemctl is-enabled vps-ready-deadman.service' 2>/dev/null |
  grep -qx disabled || die "the boot hook is still enabled"

echo "OK [$distro]"
