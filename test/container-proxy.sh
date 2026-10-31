#!/bin/sh
# Apply and roll back deploy.proxy with the real binary in a systemd test container.
#
# Usage: test/container-proxy.sh <distro> [binary]      e.g. ubuntu-24.04
#   Same binary and image requirements as test/container-audit.sh. Needs docker
#   and jq. `apply` installs Caddy from its repository on Cloudsmith and the
#   test installs curl, so the container needs network access.
#
# Cycle: apply --yes with one site -> plan has no changes -> the installed
# package kept our Caddyfile (its own is Caddyfile.dpkg-dist) -> HTTPS through
# Caddy reaches an upstream on 127.0.0.1 -> rollback --last -> Caddy's source,
# key and Caddyfile are gone, the package stays and Caddy is stopped and
# disabled -> apply again starts Caddy -> rollback --last again.
# The site is app.localhost, for which Caddy uses its own CA (as `tls internal`
# would), so no ACME CA is involved. The container is capped at 1 GB and 1 CPU
# and is removed afterwards.
set -eu
cd "$(dirname "$0")/.."

distro=${1:?usage: $0 <distro> [binary]}
bin=${2:-${VPS_READY_BIN:-target/release/vps-ready}}
image="vps-ready-test:$distro"
name="vps-ready-proxy-$distro-$$"
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
# Docker's base images keep a package from starting its service; a VPS does not.
docker exec "$name" rm -f /usr/sbin/policy-rc.d

vr() { docker exec "$name" vps-ready "$@"; }
ct() { docker exec "$name" "$@"; }
die() { echo "FAIL [$distro]: $*" >&2; exit 1; }
managed="/etc/apt/sources.list.d/caddy.sources /etc/apt/keyrings/caddy.asc /etc/caddy/Caddyfile"

for f in $managed; do ct test ! -e "$f" || die "$f exists before apply"; done

echo "== $distro: install curl"
ct sh -c 'apt-get update -qq && apt-get install -y -qq --no-install-recommends curl >/dev/null'

cat >"$tmp/proxy.toml" <<'EOF'
schema = 1

[modules."deploy.proxy"]
sites = [{ domain = "app.localhost", upstream = "127.0.0.1:8080" }]
EOF
docker cp "$tmp/proxy.toml" "$name:/root/proxy.toml"

echo "== $distro: vps-ready apply --yes --profile proxy.toml"
rc=0; vr apply --yes --profile /root/proxy.toml || rc=$?
[ "$rc" -eq 0 ] || die "apply exited $rc, expected 0"

echo "== $distro: vps-ready plan --json --profile proxy.toml"
rc=0; vr plan --json --profile /root/proxy.toml >"$tmp/plan.json" || rc=$?
[ "$rc" -eq 0 ] || die "plan exited $rc, expected 0"
jq -e '[.modules[].changes | length] | add == 0' "$tmp/plan.json" >/dev/null ||
  die "plan still has changes after apply"

echo "== $distro: Caddy after apply"
ct caddy version
first=$(ct head -n 1 /etc/caddy/Caddyfile)
case $first in
  "# Written by vps-ready (deploy.proxy)."*) ;;
  *) die "the package replaced the Caddyfile: $first" ;;
esac
[ "$(ct systemctl is-active caddy.service)" = active ] || die "Caddy is not running"
# dpkg kept our Caddyfile and put the package's beside it.
etc=$(ct ls /etc/caddy | tr '\n' ' ')
[ "$etc" = "Caddyfile Caddyfile.dpkg-dist " ] || die "/etc/caddy holds: $etc"

# The upstream: a second Caddy without an admin endpoint, answering on
# 127.0.0.1:8080 as a container published by deploy.docker would.
cat >"$tmp/upstream.json" <<'EOF'
{"admin": {"disabled": true},
 "apps": {"http": {"servers": {"up": {"listen": ["127.0.0.1:8080"],
   "routes": [{"handle": [{"handler": "static_response", "body": "hello from upstream"}]}]}}}}}
EOF
docker cp "$tmp/upstream.json" "$name:/root/upstream.json"
docker exec -d "$name" caddy run --config /root/upstream.json

body=$(ct curl -fsS -k --retry 10 --retry-delay 1 --retry-all-errors \
  --resolve app.localhost:443:127.0.0.1 https://app.localhost/) ||
  die "HTTPS through Caddy failed"
echo "$body"
[ "$body" = "hello from upstream" ] || die "unexpected answer: $body"

echo "== $distro: vps-ready rollback --last"
rc=0; vr rollback --last || rc=$?
[ "$rc" -eq 0 ] || die "rollback exited $rc, expected 0"
for f in $managed; do ct test ! -e "$f" || die "$f is left after rollback"; done
ct dpkg-query -W -f '${Status}\n' caddy | grep -q 'install ok installed' ||
  die "caddy should stay installed"
state=$(ct systemctl is-active caddy.service || true)
[ "$state" = inactive ] || die "Caddy is $state after rollback, expected inactive"
state=$(ct systemctl is-enabled caddy.service || true)
[ "$state" = disabled ] || die "Caddy is $state after rollback, expected disabled"
etc=$(ct ls /etc/caddy | tr '\n' ' ')
[ "$etc" = "Caddyfile.dpkg-dist " ] || die "/etc/caddy holds after rollback: $etc"

# Caddy is installed and stopped now: apply must start it, not only reload a
# running one.
echo "== $distro: vps-ready apply --yes --profile proxy.toml, after the rollback"
rc=0; vr apply --yes --profile /root/proxy.toml || rc=$?
[ "$rc" -eq 0 ] || die "second apply exited $rc, expected 0"
[ "$(ct systemctl is-active caddy.service)" = active ] ||
  die "Caddy is not running after the second apply"
body=$(ct curl -fsS -k --retry 10 --retry-delay 1 --retry-all-errors \
  --resolve app.localhost:443:127.0.0.1 https://app.localhost/) ||
  die "HTTPS through Caddy failed after the second apply"
[ "$body" = "hello from upstream" ] || die "unexpected answer: $body"

echo "== $distro: vps-ready rollback --last, again"
rc=0; vr rollback --last || rc=$?
[ "$rc" -eq 0 ] || die "second rollback exited $rc, expected 0"
for f in $managed; do ct test ! -e "$f" || die "$f is left after the second rollback"; done

echo "OK [$distro]"
