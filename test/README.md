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
