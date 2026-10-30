---
title: Supported platforms
description: The distros, init systems and architectures vps-ready runs on today, and what is planned.
sidebar:
  label: Platforms
  order: 3
---

| Family | Distros | Firewall | Init | Status |
|---|---|---|---|---|
| Debian | Ubuntu 22.04, 24.04; Debian 12, 13 | nftables, its own table | systemd | since v0.2 |
| RHEL | Rocky and Alma 9, 10; Fedora | firewalld | systemd | planned, v0.6 |
| Alpine | 3.2x | nftables | OpenRC | planned, v0.6 |

Ubuntu 26.04 is next for the Debian family.

**Architectures:** x86_64 and arm64 (aarch64), as static musl binaries with no dependencies.

**On other Linux distros** `detect` and `audit` still run and report what they can read. The modules that change things show as not applicable in the plan, with the reason.

**The safety net needs systemd.** The admin user, SSH server config and firewall modules are only offered where systemd is running.

**Containers:** kernel settings belong to the host, so the kernel controls are skipped and `kernel.sysctl` does nothing inside one.

**Out of scope:** Windows, BSD, Kubernetes nodes and managing a fleet of servers.
