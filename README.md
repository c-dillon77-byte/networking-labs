# networking-labs

![CI](https://github.com/c-dillon77-byte/networking-labs/actions/workflows/ci.yml/badge.svg)

Small, practical **Python tools for everyday network administration**, the kind of tasks an IT support or
junior network technician does: subnetting, checking which hosts and services are up, backing up switch and
router configs, and turning CLI output into usable data.

Each tool lives in its own folder with its own README, `requirements.txt` and `tests/`.

## Project index

| Project | What it demonstrates | Status |
|---|---|---|
| [`subnet-calculator/`](subnet-calculator/) | IPv4 subnetting (network/broadcast, usable host range, CIDR ↔ mask, VLSM splits) using Python's `ipaddress` module, with unit tests | ✅ Complete |
| [`ping-port-sweep/`](ping-port-sweep/) | Checking host reachability and open TCP ports across a lab subnet; timeouts, concurrency, CSV output | ✅ Complete |
| [`config-backup/`](config-backup/) | Automated SSH config backups from Cisco devices with **netmiko**: inventory file, credentials from environment variables (never hard-coded), timestamped backup files, change diffs | ✅ Complete |
| `cisco-config-backup/` | Automated SSH config backups from Cisco devices with **netmiko**: inventory file, credentials from environment variables (never hard-coded), timestamped backup files | 🟡 Planned |
| `show-command-parser/` | Parsing `show ip interface brief` / `show vlan` style output into structured data (CSV/JSON), tested against saved sample output | 🟡 Planned |

*Status key: 🟡 Planned · 🟢 In progress · 🔵 In review · ✅ Complete*

## How to run

Requires Python 3.10+.

```bash
git clone https://github.com/c-dillon77-byte/networking-labs.git
cd networking-labs
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

cd <project-folder>              # e.g. subnet-calculator
pip install -r requirements.txt
python <script>.py --help
```

Run the checks the same way CI does:

```bash
pip install ruff pytest
ruff check . && ruff format --check .
cd <project-folder> && python -m pytest -q
```

## Lab environment

The scanning and device tools are meant for my own lab network (see [HomeLab](https://github.com/c-dillon77-byte/HomeLab))
or simulated devices. Only scan or connect to networks and devices you own or are explicitly authorized to manage.

## Repository layout

```text
networking-labs/
├── <project>/
│   ├── README.md
│   ├── requirements.txt
│   ├── <script>.py
│   └── tests/
├── .github/workflows/ci.yml   # ruff + pytest for every project folder
├── pyproject.toml
└── LICENSE (MIT)
```

Part of my [IT portfolio](https://github.com/c-dillon77-byte/it-portfolio).
