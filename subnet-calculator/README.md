# Subnet Calculator & VLSM Planner

A command-line IPv4 subnetting tool in pure Python (standard library only). It answers
the questions that come up when you design or troubleshoot a network, the same way you
work them out by hand for the CCNA:

- **What network is this address in?** Takes an IP with a prefix (`192.168.10.77/26`) or
  with a dotted mask, either as one argument or two (`192.168.10.77 255.255.255.192`). It shows the
  input address and whether it is a host, network, or broadcast address, plus the network,
  prefix length, netmask, **binary mask**, wildcard mask, broadcast, usable host range, host
  counts, **legacy IP class** (A/B/C/D/E), and address scope (RFC 1918 private, RFC 5737
  documentation, CGNAT, loopback, link-local, multicast, public).
- **How big a subnet do I need for N hosts?** `--hosts N` returns the smallest prefix and
  mask, and with `--network` it places the subnet inside a given block.
- **How do I carve a block evenly?** `split` divides it into equal subnets.
- **How do I fit segments of different sizes?** `vlsm` allocates right-sized,
  non-overlapping subnets largest-first and reports spare hosts and space used.
- **Need it in a script?** Add `--json` to `info`, `split`, `vlsm`, `hosts`, or `batch`.

## Quick start

Requires Python 3.10+. Nothing to install to run it.

```bash
python3 subnet_calc.py demo                                    # guided walkthrough
python3 subnet_calc.py info 192.168.10.77 255.255.255.192      # IP + dotted mask (two args)
python3 subnet_calc.py info 192.168.10.77/26                   # CIDR form
python3 subnet_calc.py info 10.0.0.0/8 172.16.5.130/27         # several at once
python3 subnet_calc.py --hosts 50                              # smallest subnet for 50 hosts
python3 subnet_calc.py --hosts 50 --network 192.168.10.0/24    # ...placed in a network
python3 subnet_calc.py hosts 50 192.168.10.0/24                # same, subcommand form
python3 subnet_calc.py split 172.16.0.0/22 24                  # equal subnets
python3 subnet_calc.py vlsm 192.168.10.0/24 Sales=60 Engineering=28 Guest-WiFi=25 Mgmt=10 WAN-Link=2
python3 subnet_calc.py vlsm --file vlsm_example.txt            # requirements from a file
python3 subnet_calc.py batch sample_inputs.txt                 # info for every line of a file
python3 subnet_calc.py vlsm --file vlsm_example.txt --json     # JSON output
```

`--json` works either before or after the subcommand. A bare IP without a prefix or mask is
rejected. Invalid input prints `error: ...` to stderr and exits with status 2 (and prints no
JSON).

## Example output

### `info`: host address with a dotted mask

```text
$ python3 subnet_calc.py info 192.168.10.77 255.255.255.192
Input address     : 192.168.10.77 (host address)
Network           : 192.168.10.64/26
Prefix length     : /26
Netmask           : 255.255.255.192
Binary mask       : 11111111.11111111.11111111.11000000
Wildcard          : 0.0.0.63
Broadcast         : 192.168.10.127
Host range        : 192.168.10.65 - 192.168.10.126
Total addresses   : 64
Usable hosts      : 62
IP class (legacy) : C (classful default /24)
Scope             : Private (RFC 1918)
```

The IP class is shown for reference only. Classful addressing was replaced by CIDR (RFC 4632).

### `--hosts`: smallest subnet for N hosts

```text
$ python3 subnet_calc.py --hosts 50 --network 192.168.10.0/24
Hosts requested   : 50
Smallest fit      : /26
Netmask           : 255.255.255.192
Binary mask       : 11111111.11111111.11111111.11000000
Wildcard          : 0.0.0.63
Block size        : 64 addresses
Usable hosts      : 62 (12 spare)
Base network      : 192.168.10.0/24
First subnet      : 192.168.10.0/26 (192.168.10.1 - 192.168.10.62)
Subnets available : 4
```

### `vlsm`: plan a small office

```text
$ python3 subnet_calc.py vlsm 192.168.10.0/24 Sales=60 Engineering=28 Guest-WiFi=25 Mgmt=10 WAN-Link=2
VLSM plan for 192.168.10.0/24
Name            Need Subnet               Mask             Host range                        Usable Spare
---------------------------------------------------------------------------------------------------------
Sales             60 192.168.10.0/26      255.255.255.192  192.168.10.1 - 192.168.10.62          62     2
Engineering       28 192.168.10.64/27     255.255.255.224  192.168.10.65 - 192.168.10.94         30     2
Guest-WiFi        25 192.168.10.96/27     255.255.255.224  192.168.10.97 - 192.168.10.126        30     5
Mgmt              10 192.168.10.128/28    255.255.255.240  192.168.10.129 - 192.168.10.142       14     4
WAN-Link           2 192.168.10.144/31    255.255.255.254  192.168.10.144 - 192.168.10.145        2     0

Address space used: 146 of 256 (57.0%)
```

### `--json` (trimmed)

```text
$ python3 subnet_calc.py split 172.16.0.0/22 24 --json
{
  "network": "172.16.0.0/22",
  "new_prefix": 24,
  "count": 4,
  "subnets": [
    {
      "subnet": "172.16.0.0/24",
      "netmask": "255.255.255.0",
      "broadcast": "172.16.0.255",
      "first_host": "172.16.0.1",
      "last_host": "172.16.0.254",
      "usable_hosts": 254
    },
    "... 3 more ..."
  ]
}
```

JSON shapes: `info`/`batch` return a list of objects (one per input), while `split`, `vlsm`,
and `hosts` each return a single object.

## How the math works

1. **Hosts to prefix:** `prefix = 32 - ceil(log2(hosts + 2))`. The +2 covers the network
   and broadcast addresses. A point-to-point link needing 2 hosts gets a **/31** (RFC 3021),
   and a single host gets a **/32**.
2. **Wildcard mask** = `255.255.255.255 - netmask`, the inverse mask used in Cisco ACLs
   and OSPF `network` statements.
3. **VLSM:** sort requirements largest-first (ties broken by name so output is
   deterministic), then walk the base block and align each subnet to its natural boundary.
   Largest-first keeps every block aligned, so nothing overlaps or fragments. If a subnet
   would run past the end of the block, you get a clear "out of space" error.

## Sample data files

| File | Format | Used by |
|------|--------|---------|
| `sample_inputs.txt` | one network per line (CIDR or `IP MASK`), `#` comments allowed | `batch` |
| `vlsm_example.txt` | first line base network, then `NAME=HOSTS` lines | `vlsm --file` |

All sample and demo addresses are synthetic: RFC 1918 private ranges (10/8, 172.16/12,
192.168/16) and RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24). The test suite also checks scope labels against a few well-known
special-purpose and public blocks.

## Using it as a library

```python
from subnet_calc import hosts_fit, split_network, subnet_info, vlsm_allocate

subnet_info("192.168.10.77 255.255.255.192").cidr  # '192.168.10.64/26'
hosts_fit(50, "192.168.10.0/24").first_subnet  # '192.168.10.0/26'
[str(n) for n in split_network("172.16.0.0/22", 24)]  # ['172.16.0.0/24', ...]
for a in vlsm_allocate("10.50.0.0/22", {"HQ": 200, "Branch": 100}):
    print(a.name, a.subnet, a.usable_hosts, a.wasted)
```

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # pytest + ruff (dev only)
pytest                            # run from this folder
ruff check . && ruff format --check .
```

Project layout:

```text
subnet_calc.py        # all logic + CLI
tests/                # pytest suite: parsing, IP+mask args, /31 /32 edge cases, binary mask,
                      # legacy class, --hosts, split, VLSM, JSON output, CLI, sample files
conftest.py           # puts this folder on sys.path so `pytest` works from here
pyproject.toml        # project metadata, pytest and ruff config
requirements.txt      # dev dependencies (runtime is stdlib only)
sample_inputs.txt     # sample networks for `batch`
vlsm_example.txt      # sample VLSM requirements
```

## Skills demonstrated

- **CCNA-style subnetting:** network/broadcast/host range, prefix length vs. dotted and
  binary masks, host counts, /31 point-to-point links, and legacy classful addressing
- **VLSM design:** largest-first allocation with boundary alignment and waste reporting
- **Wildcard masks** for Cisco **ACLs** and **OSPF** `network` statements
- **Python standard library:** `ipaddress`, `argparse`, `json`, `dataclasses`, `pathlib`,
  with no third-party runtime dependencies
- **Testing and quality:** a `pytest` suite covering edge cases, CLI, and JSON contracts,
  with `ruff` lint/format, tested on Python 3.10–3.12

## Resume bullet

- Built a Python command-line IPv4 subnet calculator and VLSM planner (standard library only) that
  computes network/broadcast addresses, host ranges, binary and wildcard masks, and smallest-fit
  subnets, and allocates non-overlapping variable-length subnets, with JSON output for automation.
- Wrote a 98-test pytest suite (edge cases such as /31 and /32, CLI, and JSON output) with ruff
  linting and formatting checks, run automatically by GitHub Actions CI on Python 3.10–3.12.

## License

MIT
