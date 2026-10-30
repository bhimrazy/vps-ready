---
title: Quick start
description: Audit a server, read the plan, apply it behind the safety timer, confirm from a new login, and undo it.
---

Run these on the server, as root or with `sudo`. Start with `audit`: it changes nothing.

## 1. Audit

```sh
sudo vps-ready audit          # failures and unknowns; --all also lists the passing controls
```

Each control has a stable ID, a severity and the reason it matters. `--json` prints the complete result, and the exit code is 0 only when no control fails or is unknown, so it works in CI.

## 2. Plan

```sh
sudo vps-ready plan
```

`plan` prints a diff of every file and setting that would change, with a one-line reason and a reversibility label for each. Nothing is written.

## 3. Apply

```sh
sudo vps-ready apply                   # kernel settings and automatic updates
sudo vps-ready apply --profile minimal # also an admin user, SSH hardening and a firewall
```

`apply` shows the plan, asks, then applies. A plain `apply` leaves out the modules that can lock you out. With `--profile minimal` (or `web`), it starts the safety timer before the first change and ends like this, with your own admin user, address and port:

```text
Changes are live. Open a NEW terminal and run:

    ssh -t -o ControlPath=none -p 22 admin@203.0.113.10 sudo vps-ready confirm

If no new session confirms by 14:07:30 UTC (5:00 left), every change is rolled back.
More time: sudo vps-ready confirm --extend
```

## 4. Confirm

Run that command from a **new** terminal. If the new login works, `confirm` succeeds and `apply` exits 0. If it does not, wait: after 5 minutes (or at the next boot) every change rolls back on its own and the old login works again.

Your open terminal proves nothing, because SSH server reloads and connection tracking keep existing sessions alive. tmux, screen, mosh and connections shared through `ControlMaster` count as old sessions, which is why the command sets `ControlPath=none`.

## 5. Undo

```sh
sudo vps-ready history         # list transactions
sudo vps-ready rollback --last # undo the last one
```

Every change is journaled, so you can undo a transaction at any time, not only while the safety timer runs.

## Exit codes of apply

| Code | Meaning |
|---|---|
| 0 | Applied, or confirmed |
| 1 | Failed or rolled back |
| 2 | Error |
| 3 | Rollback did not complete |
| 4 | Still pending: you pressed Ctrl-C while it waited, and the timer keeps running |

## Next

- See what each module changes, and why, in [Security controls](/docs/guides/security-controls/).
- Read how the safety timer works in [Architecture](/docs/guides/architecture/#dead-man-switch-the-headline-feature).
