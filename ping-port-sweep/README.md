# Ping & Port Sweep

A command-line **host discovery** and **TCP port scanner** written in pure Python
(standard library only, 3.10+). It does the same jobs you would do with `ping` and
`nmap -sT`, with safety rails aimed at lab and portfolio use:

- **Discover** live hosts across a CIDR, an address range, or a file of targets
- Prefer the system **`ping`** (with the right Linux / macOS / Windows flags); fall
  back to a **TCP connect probe** when ICMP is blocked or `ping` is missing
- **Scan** open TCP ports with `socket.connect_ex` (no root needed), including a
  built-in **common ports** preset and optional banner grabbing
- Run probes **concurrently** (`concurrent.futures`) with a configurable worker count
  and per-probe timeout
- Print a neat table, and save **`--json`** / **`--csv`** reports with a summary
  (hosts up, open ports, duration)
- **Refuse** public/internet targets and oversized ranges unless you pass an
  explicit override flag

## Responsible use

Only scan networks **you own** or have **written authorization** to test.
Unauthorized scanning can be illegal and disruptive.

By default this tool only allows:

- RFC 1918 private ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Loopback: `127.0.0.0/8`
- RFC 5737 documentation ranges: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`

Anything else requires `--i-own-this-network` (and prints a warning). Sweeps larger
than a **/16** (65,536 addresses) need `--allow-large`. Hostnames are never
resolved, so you cannot accidentally scan whatever a name points to today.

## Quick start (Linux)

Requires Python 3.10+. Nothing to install to run it. On a typical Linux lab box:

```bash
# Clone / enter this folder, then:
python3 sweep.py demo                                 # works offline, no root

# Discover a private lab subnet (ICMP, falls back to TCP)
python3 sweep.py discover 192.168.10.0/28 --timeout 0.5 --workers 32

# Same, TCP-only (useful when ICMP is filtered)
python3 sweep.py discover 192.168.10.0/28 --method tcp

# Targets from a file
python3 sweep.py discover --file sample_targets.txt -q

# Discover + scan common ports on whatever is up
python3 sweep.py scan 192.168.10.0/28 -p common --banners

# Ports by list or range; skip ping and scan every target
python3 sweep.py scan 127.0.0.1 --skip-discovery -p 22,80,443,8000-8010

# Save machine-readable reports
python3 sweep.py scan 192.168.10.0/28 -p common --json report.json --csv report.csv
```

Invalid input prints `error: ...` to stderr and exits with status 2 (no traceback).

### macOS / Windows notes

`ping` flags differ by OS; the tool picks them for you:

| OS | One-packet ping (built automatically) |
|----|----------------------------------------|
| Linux | `ping -c 1 -W <seconds>` |
| macOS | `ping -c 1 -W <milliseconds>` |
| Windows | `ping -n 1 -w <milliseconds>` |

If `ping` is missing or ICMP is blocked, `--method auto` (the default) falls back
to a short TCP connect against ports 22, 80, 443, 445, and 3389.

## Demo (offline)

`demo` needs no network and no root. It loads a simulated ICMP sweep from
`sample_results.json`, then opens a few local TCP listeners on `127.0.0.1`, scans
them, and grabs banners. Ports are ephemeral, so numbers change each run:

```text
$ python3 sweep.py demo
Command          : demo
Started (UTC)    : 2026-10-19T00:05:58Z
Duration         : 0.01 s
Hosts probed     : 7
Hosts up         : 5
Open ports       : 3
Note             : host discovery loaded from sample_results.json (simulated; no ICMP used)
Note             : TCP connect scan of 127.0.0.1 on demo ports [40141, 37193, 37637] (plus closed :1)

=== Simulated host sweep (from sample_results.json) ===
Host             Status Method        Latency Detail
----------------------------------------------------
192.168.10.1     UP     simulated      0.8 ms gateway
192.168.10.2     UP     simulated      1.2 ms lab-pc
192.168.10.3     down   simulated           - 
192.168.10.4     UP     simulated      2.4 ms printer
192.168.10.5     down   simulated           - 
192.168.10.6     UP     simulated      1.1 ms nas

=== Live TCP scan of 127.0.0.1 demo listeners ===
Host             Status Method        Latency Detail
----------------------------------------------------
127.0.0.1        UP     tcp            1.1 ms port 40141 open

Host              Port Service         Latency Banner
-----------------------------------------------------
127.0.0.1        40141                  0.3 ms demo-service-1
127.0.0.1        37193                  0.4 ms demo-service-2
127.0.0.1        37637                  0.3 ms demo-service-3
```

## Example: discover + scan with reports

Against a lab `/29` you own (output shape; hosts will match your network):

```bash
python3 sweep.py scan 192.168.10.0/29 -p common --json lab.json --csv lab.csv -q
```

JSON shape (trimmed):

```json
{
  "command": "scan",
  "started_at": "2026-10-19T00:00:00Z",
  "duration_s": 1.25,
  "hosts_probed": 6,
  "hosts_up": 2,
  "open_ports": 3,
  "notes": ["scanned 20 port(s) on 2 host(s); method=auto"],
  "hosts": [
    {"host": "192.168.10.1", "alive": true, "method": "icmp", "latency_ms": 0.8, "detail": ""},
    {"host": "192.168.10.2", "alive": false, "method": "icmp", "latency_ms": null, "detail": ""}
  ],
  "ports": [
    {"host": "192.168.10.1", "port": 22, "open": true, "service": "ssh", "banner": "", "latency_ms": 1.1}
  ]
}
```

## Sample data

| File | Purpose |
|------|---------|
| `sample_targets.txt` | Synthetic private/loopback targets for `discover` / `scan --file` |
| `sample_results.json` | Simulated ICMP sweep used by `demo` |

All addresses are RFC 1918, loopback, or RFC 5737. No hostnames, credentials, or
employer info.

## Using it as a library

```python
from sweep import discover_hosts, expand_targets, parse_ports, scan_ports

hosts = expand_targets(["192.168.10.0/29"])
alive = discover_hosts(hosts, method="tcp", timeout_s=0.5, workers=32, progress=False)
up = [h.host for h in alive if h.alive]
ports = scan_ports(up, parse_ports("22,80,443"), banners=True, progress=False)
```

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # pytest + ruff (dev only)
pytest                            # run from this folder; no ICMP / no internet needed
ruff check . && ruff format --check .
```

CI and local tests **mock** `subprocess` / `ping` and use **local sockets** for port
checks, so they pass on GitHub Actions runners that cannot ping.

Project layout:

```text
sweep.py               # all logic + CLI
tests/                 # pytest suite (parsing, safety, mocked ICMP, local TCP, CLI, demo)
conftest.py            # puts this folder on sys.path so `pytest` works from here
pyproject.toml         # project metadata, pytest and ruff config
requirements.txt       # dev dependencies (runtime is stdlib only)
sample_targets.txt     # example targets for --file
sample_results.json    # simulated sweep for demo mode
```

## Skills demonstrated

- Host discovery with system `ping` (cross-platform flags) and TCP fallback
- TCP connect scanning (`socket`), common-port presets, optional banner grab
- Concurrent I/O with `concurrent.futures`, timeouts, and progress reporting
- Safety controls: RFC 1918 / documentation allow-list, size caps, explicit overrides
- Structured reporting (tables, JSON, CSV) and a self-contained offline demo
- Python standard library only; pytest with mocks and local sockets; ruff lint/format;
  GitHub Actions CI across Python 3.10–3.12

## Resume bullet

- Built a Python ping-sweep and TCP port scanner (stdlib only) with concurrent probes,
  ICMP-or-TCP host discovery, a common-ports preset, optional banner grabbing, and
  JSON/CSV reports, gated by RFC 1918/documentation allow-lists and scan-size caps.
- Wrote a pytest suite that mocks ICMP and uses local sockets (no network required),
  with ruff linting and GitHub Actions CI across Python 3.10–3.12; includes an offline
  demo that spins up localhost listeners and replays a simulated sweep.

## License

MIT
