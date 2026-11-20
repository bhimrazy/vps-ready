#!/bin/sh
# Apply and roll back net.tunnel with the real binary in a systemd test container.
#
# Usage: test/container-tunnel.sh <distro> [binary]  e.g. debian-13
#   Same binary and image requirements as test/container-audit.sh. Needs docker
#   and jq. `apply` installs cloudflared from pkg.cloudflare.com, so the
#   container needs network access. No Cloudflare account is used.
#
# Cycle:
# 1. apply --yes with updates.auto and net.tunnel without a token -> plan has
#    no changes -> cloudflared is at least 2025.4.0 -> unattended-upgrade
#    --dry-run lists origin=cloudflared,codename=any.
# 2. a placeholder token: apply fails within the start timeout, names the
#    connector and rolls back; cloudflared logged no config error.
# 3. the restart script: `sh -n`, then with a connector held on another
#    binary it retries and fails with its message.
# 4. the path unit: with a stand-in connector on the real binary, reinstall
#    cloudflared ten times; each time the restart service ends successfully
#    and the connector runs the new /usr/bin/cloudflared.
# 5. rollback --last -> the source, key and origin file are gone, the package
#    stays.
# The container is capped at 1 GB and 1 CPU and is removed afterwards.
set -eu
cd "$(dirname "$0")/.."

distro=${1:?usage: $0 <distro> [binary]}
bin=${2:-${VPS_READY_BIN:-target/release/vps-ready}}
image="vps-ready-test:$distro"
name="vps-ready-tunnel-$distro-$$"
tmp=$(mktemp -d)

[ -f "$bin" ] || { echo "binary not found: $bin" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

cleanup() { docker rm -f -v "$name" >/dev/null 2>&1 || true; rm -rf "$tmp"; }
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
docker exec "$name" rm -f /usr/sbin/policy-rc.d

vr() { docker exec "$name" vps-ready "$@"; }
ct() { docker exec "$name" "$@"; }
die() { echo "FAIL [$distro]: $*" >&2; exit 1; }
managed="/etc/apt/sources.list.d/cloudflared.sources /etc/apt/keyrings/cloudflared.asc
  /etc/apt/apt.conf.d/52vps-ready-cloudflared"
connector="/etc/vps-ready/cloudflared.yml /etc/vps-ready/cloudflared-restart.sh
  /etc/systemd/system/vps-ready-cloudflared.service
  /etc/systemd/system/vps-ready-cloudflared-restart.service
  /etc/systemd/system/vps-ready-cloudflared-restart.path"

for f in $managed $connector; do ct test ! -e "$f" || die "$f exists before apply"; done

cat >"$tmp/tunnel.toml" <<'EOF'
schema = 1

[modules."updates.auto"]

[modules."net.tunnel"]
EOF
cat >"$tmp/token.toml" <<'EOF'
schema = 1

[modules."net.tunnel"]
token_file = "/root/cloudflared-token"
EOF
docker cp "$tmp/tunnel.toml" "$name:/root/tunnel.toml"
docker cp "$tmp/token.toml" "$name:/root/token.toml"

echo "== $distro: vps-ready apply --yes --profile tunnel.toml (no token)"
rc=0; vr apply --yes --profile /root/tunnel.toml || rc=$?
[ "$rc" -eq 0 ] || die "apply exited $rc, expected 0"
rc=0; vr plan --json --profile /root/tunnel.toml >"$tmp/plan.json" || rc=$?
[ "$rc" -eq 0 ] || die "plan exited $rc, expected 0"
jq -e '[.modules[].changes | length] | add == 0' "$tmp/plan.json" >/dev/null ||
  die "plan still has changes after apply"
jq -e '.modules[] | select(.id == "net.tunnel") | .notes[] |
  select(startswith("no token_file"))' "$tmp/plan.json" >/dev/null ||
  die "plan does not say how to add a token"
for f in $connector; do ct test ! -e "$f" || die "$f exists without a token"; done

version=$(ct cloudflared --version | awk '{print $3}')
echo "cloudflared $version"
oldest=$(printf '%s\n2025.4.0\n' "$version" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)
[ "$oldest" = 2025.4.0 ] || die "cloudflared $version is older than 2025.4.0"

echo "== $distro: unattended-upgrade --dry-run"
ct unattended-upgrade --dry-run --debug >"$tmp/uu.log" 2>&1 || {
  cat "$tmp/uu.log"; die "unattended-upgrade --dry-run failed"
}
grep -q "origin=cloudflared,codename=any" "$tmp/uu.log" || {
  cat "$tmp/uu.log"; die "unattended-upgrade does not list the cloudflared origin"
}

echo "== $distro: a placeholder token does not connect"
ct sh -c 'umask 077 && echo placeholder-not-a-tunnel-token >/root/cloudflared-token'
vr plan --json --profile /root/token.toml >"$tmp/token-plan.json" || true
start=$(date +%s)
rc=0; vr apply --yes --profile /root/token.toml >"$tmp/apply.log" 2>&1 || rc=$?
took=$(( $(date +%s) - start ))
cat "$tmp/apply.log"
[ "$rc" -ne 0 ] || die "apply with a placeholder token succeeded"
grep -q vps-ready-cloudflared.service "$tmp/apply.log" || die "apply does not name the connector"
[ "$took" -lt 120 ] || die "the failed start took ${took}s"
for f in $connector; do ct test ! -e "$f" || die "$f is left after the rollback"; done
[ "$(ct systemctl is-active vps-ready-cloudflared.service || true)" != active ] ||
  die "the connector still runs"
ct journalctl -b -u vps-ready-cloudflared.service --no-pager -o cat >"$tmp/connector.log" || true
cat "$tmp/connector.log"
! grep -Eiq 'ERR.*(config|yaml)' "$tmp/connector.log" || die "cloudflared logged a config error"
# A container may not pass LoadCredential= on (seen on all four images), so
# the connector can fail before it reads its config: check the config with
# cloudflared run directly, which reads the same token file and rejects it.
planned_config=$(jq -r '.modules[] | select(.id == "net.tunnel") | .changes[] |
  select(.id == "file:/etc/vps-ready/cloudflared.yml") | .diff' "$tmp/token-plan.json" |
  sed -n 's/^+//p')
[ -n "$planned_config" ] || die "the plan has no cloudflared.yml"
printf '%s\n' "$planned_config" >"$tmp/cloudflared.yml"
ct mkdir -p /etc/vps-ready
docker cp "$tmp/cloudflared.yml" "$name:/etc/vps-ready/cloudflared.yml"
ct timeout 30 cloudflared tunnel --config /etc/vps-ready/cloudflared.yml \
  --metrics 127.0.0.1:20241 run --token-file /root/cloudflared-token >"$tmp/direct.log" 2>&1 || true
cat "$tmp/direct.log"
! grep -Eiq 'ERR.*(config|yaml)' "$tmp/direct.log" || die "cloudflared rejects the config"
grep -q 'token is not valid' "$tmp/direct.log" || die "cloudflared did not read the token file"
! grep -q placeholder-not-a-tunnel-token "$tmp/apply.log" "$tmp/token-plan.json" ||
  die "the token is in vps-ready's output"
! ct grep -rq placeholder-not-a-tunnel-token /var/lib/vps-ready || die "the token is in the journal"

# The planned file at `path`, from the plan's diff of a new file.
planned() {
  jq -r --arg id "file:$1" '.modules[] | select(.id == "net.tunnel") | .changes[] |
    select(.id == $id) | .diff' "$tmp/token-plan.json" | sed -n 's/^+//p'
}
for f in /etc/vps-ready/cloudflared-restart.sh \
         /etc/systemd/system/vps-ready-cloudflared-restart.service \
         /etc/systemd/system/vps-ready-cloudflared-restart.path; do
  planned "$f" >"$tmp/file"
  [ -s "$tmp/file" ] || die "the plan has no $f"
  ct mkdir -p "$(dirname "$f")"
  docker cp "$tmp/file" "$name:$f"
done

echo "== $distro: the restart script with a connector on another binary"
ct sh -n /etc/vps-ready/cloudflared-restart.sh || die "the restart script fails sh -n"
# The failed start leaves the unit loaded as failed, without its file.
ct systemctl daemon-reload
ct systemctl reset-failed vps-ready-cloudflared.service 2>/dev/null || true
ct systemd-run --unit=vps-ready-cloudflared.service /bin/sleep infinity >/dev/null
rc=0; ct sh /etc/vps-ready/cloudflared-restart.sh 2>"$tmp/stale.log" || rc=$?
cat "$tmp/stale.log"
[ "$rc" -ne 0 ] || die "the restart script passed with a stale binary"
grep -q 'cloudflared runs an old binary' "$tmp/stale.log" || die "no old-binary message"
ct systemctl stop vps-ready-cloudflared.service
ct systemctl reset-failed vps-ready-cloudflared.service 2>/dev/null || true

echo "== $distro: the path unit restarts the connector after each reinstall"
# A stand-in connector on the real binary that needs no account; the start
# job takes a few seconds, as a connector's does under Type=notify.
ct systemd-run --unit=vps-ready-cloudflared.service -p 'ExecStartPost=/bin/sleep 3' \
  /usr/bin/cloudflared access tcp --hostname tunnel.example.com --url 127.0.0.1:12345 >/dev/null
sleep 4
[ "$(ct systemctl is-active vps-ready-cloudflared.service)" = active ] ||
  die "the stand-in connector does not run"
ct systemctl daemon-reload
ct systemctl enable --now vps-ready-cloudflared-restart.path >/dev/null 2>&1
same() {
  pid=$(ct systemctl show --property=MainPID --value vps-ready-cloudflared.service)
  [ "${pid:-0}" != 0 ] &&
    [ "$(ct stat -L -c %d:%i "/proc/$pid/exe")" = "$(ct stat -L -c %d:%i /usr/bin/cloudflared)" ]
}
exited() {
  ct systemctl show --property=ExecMainExitTimestampMonotonic --value \
    vps-ready-cloudflared-restart.service
}
n=1
while [ "$n" -le 10 ]; do
  before=$(exited)
  ct apt-get install -y -q --reinstall cloudflared >/dev/null
  i=0
  while [ "$(exited)" = "$before" ] ||
        [ "$(ct systemctl is-active vps-ready-cloudflared-restart.service || true)" != inactive ]; do
    i=$((i + 1)); [ "$i" -lt 180 ] || die "run $n: the restart service did not finish"
    sleep 1
  done
  result=$(ct systemctl show --property=Result --value vps-ready-cloudflared-restart.service)
  [ "$result" = success ] || {
    ct journalctl -u vps-ready-cloudflared-restart.service --no-pager | tail -20
    die "run $n: the restart service ended with $result"
  }
  same || die "run $n: the connector runs an old binary"
  echo "run $n: restarted on the new binary"
  n=$((n + 1))
done
ct systemctl disable --now vps-ready-cloudflared-restart.path >/dev/null 2>&1
ct systemctl stop vps-ready-cloudflared.service
for f in /etc/vps-ready/cloudflared-restart.sh \
         /etc/systemd/system/vps-ready-cloudflared-restart.service \
         /etc/systemd/system/vps-ready-cloudflared-restart.path; do
  ct rm -f "$f"
done

echo "== $distro: vps-ready rollback --last"
rc=0; vr rollback --last || rc=$?
[ "$rc" -eq 0 ] || die "rollback exited $rc, expected 0"
for f in $managed; do ct test ! -e "$f" || die "$f is left after rollback"; done
# shellcheck disable=SC2016 # dpkg-query's format, not the shell's
ct dpkg-query -W -f '${Status}\n' cloudflared | grep -q 'install ok installed' ||
  die "cloudflared should stay installed"

echo "OK [$distro]"
