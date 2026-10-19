# Cisco Config Backup

A Python tool that backs up Cisco **running-config** (and optionally startup-config /
version) over SSH with [netmiko](https://github.com/ktbyers/netmiko), saves timestamped
files, and diffs each pull against the previous backup.

Aimed at lab and portfolio use: GNS3, EVE-NG, Cisco CML, or physical gear in a Cisco
lab (for example ECPI's). Credentials never live in the inventory or the source code.

## Features

- **Inventory** in YAML or CSV (`name`, `host`, `device_type`, optional `port`)
- **Credentials** from `NETMIKO_USERNAME` / `NETMIKO_PASSWORD` / `NETMIKO_SECRET`,
  optional per-device env overrides, or an interactive `getpass` prompt
- Pulls `show running-config` (plus optional `show startup-config` and `show version`)
- Saves to `backups/<device>/<device>_YYYY-MM-DD_HHMMSS.cfg`
- **Diffs** against the previous backup with `difflib` (skips volatile lines like
  `! Last configuration change` and `ntp clock-period`); writes a `.diff` file when
  something changed; skips saving when unchanged unless `--always-save`
- **Concurrent** backups with a worker limit; auth/timeout failures are isolated per
  device
- **`--check-startup`** flags devices whose running config differs from startup
  (unsaved changes — a common real-world footgun)
- **`--keep N`** retention, **`--json`** summary, and an offline **`demo`** mode

## Responsible use & security

- Only connect to devices **you own** or are **authorized** to manage.
- Sample inventory hosts are synthetic RFC 1918 addresses. Do not point this at
  production without change control.
- **Backups contain secrets**: enable secrets (type 5/type 7), usernames, ACLs, SNMP
  communities, and VPN keys. The `backups/` folder is in `.gitignore` for that reason —
  never commit it.
- Cisco **type 7** passwords are trivially reversible; **type 5** enable secrets are
  hashed but still sensitive. Treat backup files like production credentials.
- Prefer a read-only TACACS/RADIUS or local account for automation when your lab
  supports it.

## Quick start (Linux)

Python 3.10+ and pip:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Offline walkthrough (no devices, no SSH):
python3 backup.py demo

# Point inventory.yaml at your lab, then:
export NETMIKO_USERNAME=admin
export NETMIKO_PASSWORD='your-lab-password'
export NETMIKO_SECRET='your-enable-secret'   # optional

python3 backup.py backup -i inventory.yaml
python3 backup.py backup --check-startup --version-info --keep 10 --json report.json
```

Without env vars the tool prompts with `getpass` (unless you pass `--no-prompt`).

### Inventory examples

YAML (`inventory.yaml`):

```yaml
- name: R1-CORE
  host: 192.168.10.1
  device_type: cisco_ios
  port: 22
- name: SW1-ACCESS
  host: 192.168.10.2
  device_type: cisco_ios
```

CSV (`inventory.csv`) with the same columns is also supported. Optional per-device
credential env names: `username_env`, `password_env`, `secret_env`.

### Netmiko device types

| `device_type` | Platform |
|---------------|----------|
| `cisco_ios` | Classic IOS / IOS-XE switches & routers |
| `cisco_xe` | IOS-XE (explicit) |
| `cisco_nxos` | Nexus NX-OS |
| `cisco_asa` | ASA firewalls |
| `cisco_xr` | IOS-XR |

Use the value that matches your image; wrong types often fail during the enable or
paging negotiation.

## Pointing it at a real lab

1. **GNS3 / EVE-NG / Cisco CML** — build a small topology (router + switch), enable SSH
   (`ip domain-name lab.local`, `crypto key generate rsa`, `line vty 0 4` /
   `login local` / `transport input ssh`), and give each device a reachable management
   IP on your lab LAN.
2. **Physical Cisco lab (e.g. ECPI)** — use the rack's management addresses, confirm
   SSH from your seat, and put only those RFC 1918 addresses in the inventory.
3. Copy `inventory.yaml`, set the three `NETMIKO_*` variables, and run
   `python3 backup.py backup --check-startup`.
4. Re-run after a change; the summary shows `Changed: yes` and a short unified diff.

## Demo (offline)

`demo` uses a fake connection class and the synthetic IOS configs in `sample_configs/`
(a router with OSPF/ACLs and a switch with VLANs). It runs two passes so you can see a
real diff and an unsaved-change warning — no network required:

```text
$ python3 backup.py demo
Started          : 2026-10-18T20:12:46
Duration         : 0.00 s
Devices          : 2
Succeeded        : 2
Changed          : 1
Errors           : 0
Note             : pass 1: initial backups of R1-CORE and SW1-ACCESS
Note             : pass 2: simulated change on R1-CORE (ACL + interface description)
Note             : demo backups written under /tmp/cfg-demo2

Device         Host             Status     Changed  File
--------------------------------------------------------
R1-CORE        192.168.10.1     unsaved    yes      …cfg-demo2/R1-CORE/R1-CORE_2026-10-18_113000.cfg
  └ +2 / -1 lines
  └ - description Uplink to SW1 - synthetic lab
  └ + description Uplink to SW1 - synthetic lab (upgraded link)
  └ + deny   ip any 10.66.66.0 0.0.0.255
  └ running differs from startup (unsaved changes)
SW1-ACCESS     192.168.10.2     unchanged  no       …mo2/SW1-ACCESS/SW1-ACCESS_2026-10-18_100000.cfg
  └ no changes since last backup

=== Diff: R1-CORE ===
--- R1-CORE_2026-10-18_100000.cfg
+++ R1-CORE_2026-10-18_113000.cfg
@@ -22,7 +22,7 @@
  ip address 10.255.0.1 255.255.255.255
 !
 interface GigabitEthernet0/0
- description Uplink to SW1 - synthetic lab
+ description Uplink to SW1 - synthetic lab (upgraded link)
  ip address 10.10.10.1 255.255.255.252
  ip ospf network point-to-point
  duplex auto
@@ -56,6 +56,7 @@
  deny   ip any 192.0.2.0 0.0.0.255
  deny   ip any 198.51.100.0 0.0.0.255
  deny   ip any 203.0.113.0 0.0.0.255
+ deny   ip any 10.66.66.0 0.0.0.255
  permit ip any any
 !
 ip route 0.0.0.0 0.0.0.0 172.16.20.2
```

## CLI reference

```bash
python3 backup.py backup [options]
  -i / --inventory PATH   YAML or CSV (default: inventory.yaml)
  -o / --output DIR       backup root (default: backups)
  --workers N             concurrent devices (default: 4)
  --timeout SECONDS       connect/command timeout (default: 30)
  --always-save           save even when unchanged
  --no-diff               skip writing .diff files
  --startup               also save show startup-config
  --version-info          also save show version
  --check-startup         flag running vs startup drift
  --keep N                retain only N backups per device
  --json FILE             write JSON summary
  --no-prompt             fail if credentials env vars are missing

python3 backup.py demo [-o DIR]
```

Exit codes: `0` success, `1` if any device errored, `2` bad input / usage.

## Sample data

| Path | Purpose |
|------|---------|
| `inventory.yaml` / `inventory.csv` | Synthetic lab inventory (RFC 1918 hosts) |
| `sample_configs/r1_running.cfg` | Synthetic IOS router config |
| `sample_configs/r1_running_changed.cfg` | Same router after a simulated change |
| `sample_configs/sw1_running.cfg` | Synthetic IOS switch config (VLANs) |
| `sample_configs/*_version.txt` | Fake `show version` output |

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest                            # netmiko is mocked; no SSH attempted
ruff check . && ruff format --check .
```

Project layout:

```text
backup.py              # CLI + library
tests/                 # pytest (inventory, creds, diff, mocked netmiko, demo)
sample_configs/        # synthetic IOS configs for demo/tests
inventory.yaml         # example YAML inventory
inventory.csv          # example CSV inventory
conftest.py
pyproject.toml
requirements.txt
```

## Skills demonstrated

- Network automation with **netmiko** (SSH, enable mode, `show running-config`)
- Inventory-driven design (YAML/CSV), env-based secrets, and `getpass`
- Config normalization and **difflib** change detection (ignoring volatile IOS lines)
- Concurrent device jobs with per-device error isolation
- Operational details: unsaved running vs startup, backup retention, JSON reporting
- Offline demo with a fake connection class; pytest mocks of `ConnectHandler`;
  ruff + GitHub Actions CI across Python 3.10–3.12

## Resume bullet

- Built a Python Cisco config backup tool with netmiko that pulls running/startup
  configs from an inventory, stores timestamped backups, and diffs each run with
  volatile IOS lines stripped, including concurrent workers and `--check-startup` for
  unsaved changes.
- Added offline demo mode with synthetic IOS router/switch configs, pytest coverage that
  mocks ConnectHandler (no live SSH), ruff linting, and GitHub Actions CI across
  Python 3.10–3.12; credentials come from environment variables or getpass only.

## License

MIT
