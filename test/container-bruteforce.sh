#!/bin/sh
# Apply and roll back ssh.bruteforce with the real binary in a systemd test container.
#
# Usage: test/container-bruteforce.sh <distro> [binary]      e.g. debian-13
#   Same binary and image requirements as test/container-audit.sh. Needs docker
#   and jq. `apply` runs apt-get, so the container needs network access.
#
# Cycle: apply --yes -> plan has no changes -> fail2ban's sshd jail runs and
# reads failed logins from the journal -> a ban lands in nftables'
# `inet f2b-table` -> SSH-008 passes -> history shows "applied" ->
# rollback --last -> the drop-in is gone. The packages stay installed by
# design, and fail2ban stays enabled, as their install left it.
# The container is capped at 1 GB and 1 CPU and is removed afterwards.
set -eu
cd "$(dirname "$0")/.."

distro=${1:?usage: $0 <distro> [binary]}
bin=${2:-${VPS_READY_BIN:-target/release/vps-ready}}
image="vps-ready-test:$distro"
name="vps-ready-bruteforce-$distro-$$"
tmp=$(mktemp -d)
drop_in=/etc/fail2ban/jail.d/90-vps-ready.local
# RFC 5737 documentation address.
ban=192.0.2.77

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
docker exec "$name" chmod 755 /usr/local/bin/vps-ready

vr() { docker exec "$name" vps-ready "$@"; }
die() { echo "FAIL [$distro]: $*" >&2; exit 1; }

echo "== $distro: before"
docker exec "$name" sh -c "test ! -e $drop_in" || die "$drop_in exists before apply"

echo "== $distro: vps-ready apply --yes --module ssh.bruteforce"
rc=0; vr apply --yes --module ssh.bruteforce || rc=$?
[ "$rc" -eq 0 ] || die "apply exited $rc, expected 0"
docker exec "$name" cat "$drop_in"

echo "== $distro: vps-ready plan --json --module ssh.bruteforce"
rc=0; vr plan --json --module ssh.bruteforce >"$tmp/plan.json" || rc=$?
[ "$rc" -eq 0 ] || die "plan exited $rc, expected 0"
jq -e '[.modules[].changes | length] | add == 0' "$tmp/plan.json" >/dev/null ||
  { cat "$tmp/plan.json"; die "plan still has changes after apply"; }

# The restart returns before the jails are up.
echo "== $distro: fail2ban-client status sshd"
i=0
until docker exec "$name" fail2ban-client status sshd >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 30 ] || die "the sshd jail is not running"
  sleep 1
done
docker exec "$name" fail2ban-client status sshd
docker exec "$name" systemctl is-enabled fail2ban.service >/dev/null ||
  die "fail2ban.service is not enabled"
docker exec "$name" fail2ban-client -d >"$tmp/dump.txt"
grep -q "'sshd', 'systemd'" "$tmp/dump.txt" ||
  { grep "'add', 'sshd'" "$tmp/dump.txt" >&2; die "the sshd jail does not read the journal"; }

# Failed logins from loopback count once neither ignoreip nor ignoreself
# exempts it; two stay below the default maxretry of 5, so nothing is banned.
echo "== $distro: failed logins reach the jail"
docker exec "$name" fail2ban-client set sshd delignoreip 127.0.0.1/8 >/dev/null
docker exec "$name" fail2ban-client set sshd ignoreself false >/dev/null
for _ in 1 2; do
  docker exec "$name" ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=QUIET vpsr-nobody@127.0.0.1 true || true
done
i=0
until docker exec "$name" fail2ban-client status sshd | grep -Eq 'Total failed:[[:space:]]+[1-9]'; do
  i=$((i + 1)); [ "$i" -lt 30 ] || die "the sshd jail saw no failed login"
  sleep 1
done
docker exec "$name" fail2ban-client set sshd ignoreself true >/dev/null
docker exec "$name" fail2ban-client set sshd addignoreip 127.0.0.1/8 >/dev/null

echo "== $distro: ban $ban"
docker exec "$name" fail2ban-client set sshd banip "$ban" >/dev/null
docker exec "$name" nft list table inet f2b-table | grep -q "$ban" ||
  die "$ban is not in nftables' inet f2b-table"
docker exec "$name" fail2ban-client set sshd unbanip "$ban" >/dev/null

echo "== $distro: vps-ready audit --json"
rc=0; vr audit --json >"$tmp/audit.json" || rc=$?
[ "$rc" -le 1 ] || die "audit exited $rc, expected 0 or 1"
jq -r '.findings[] | select(.id == "SSH-008") | "SSH-008 \(.status)"' "$tmp/audit.json"
jq -e '.findings[] | select(.id == "SSH-008" and .status == "pass")' "$tmp/audit.json" >/dev/null ||
  die "SSH-008 is not pass after apply"
vr detect --json | jq -e '.ssh.fail2ban == true' >/dev/null ||
  die "detect does not see the sshd jail"

echo "== $distro: vps-ready history"
vr history
vr history --json >"$tmp/history.json"
jq -e '.[0] | .state == "applied" and .modules == ["ssh.bruteforce"]' "$tmp/history.json" >/dev/null ||
  die "newest transaction is not applied"

echo "== $distro: vps-ready rollback --last"
rc=0; vr rollback --last || rc=$?
[ "$rc" -eq 0 ] || die "rollback exited $rc, expected 0"
vr history --json >"$tmp/history.json"
jq -e '.[0].state == "rolled-back"' "$tmp/history.json" >/dev/null ||
  die "newest transaction is not rolled back"
docker exec "$name" sh -c "test ! -e $drop_in" || die "$drop_in is still there"
for pkg in fail2ban python3-systemd nftables; do
  docker exec "$name" dpkg-query -W -f '${Status}\n' "$pkg" | grep -q 'install ok installed' ||
    die "$pkg should stay installed"
done

echo "OK [$distro]"
